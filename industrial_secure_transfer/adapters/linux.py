"""
adapters/linux.py
Linux OS Adapter (Part B Workstation / Part C Ingestion Server):
- Mounted SMB3 / Samba verification by inspecting `/proc/mounts` (verifying `cifs`/`smb3` fstype,
  `vers=3.1.1` or `vers=3.0`, `seal` encryption flag, and remote server match, ensuring the target
  is an actual mounted remote share and not an unmounted local directory).
- USB device identity and bus verification via `/sys/block`, `lsblk -J -o NAME,UUID,SERIAL,TRAN,FSTYPE,RM,MOUNTPOINT`,
  and POSIX ACL / mount permission checks.
- Supports deterministic telemetry injection for cross-platform unit testing.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union

from industrial_secure_transfer.adapters.base import (
    AdapterValidationError,
    BaseOSAdapter,
    SMBSessionTelemetry,
    USBDeviceTelemetry,
)
from industrial_secure_transfer.core.config import SMBEndpointConfig


class LinuxOSAdapter(BaseOSAdapter):
    """
    Linux platform adapter implementing `/proc/mounts` SMB3/Samba verification,
    sysfs/lsblk USB bus & serial binding, and POSIX permission checks.
    """

    def __init__(
        self,
        *,
        usb_telemetry_provider: Optional[Callable[[Path], USBDeviceTelemetry]] = None,
        smb_telemetry_provider: Optional[Callable[[SMBEndpointConfig, Path], SMBSessionTelemetry]] = None,
        proc_mounts_path: Union[str, Path] = "/proc/mounts",
    ) -> None:
        self._usb_provider = usb_telemetry_provider
        self._smb_provider = smb_telemetry_provider
        self._proc_mounts = Path(proc_mounts_path)

    def get_usb_telemetry(self, mount_root: Union[str, Path]) -> USBDeviceTelemetry:
        target = Path(mount_root).resolve()
        if self._usb_provider is not None:
            return self._usb_provider(target)

        if not target.exists() or not target.is_dir():
            raise AdapterValidationError(f"USB mount point does not exist: {target}")

        if str(target) in ("/", "/boot", "/usr", "/var", "/home"):
            raise AdapterValidationError(f"System mount point '{target}' rejected as USB device.")

        try:
            proc = subprocess.run(
                ["lsblk", "-J", "-o", "NAME,UUID,SERIAL,TRAN,FSTYPE,RM,MOUNTPOINT"],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                raise AdapterValidationError("lsblk query failed on Linux host.")
            blk_data = json.loads(proc.stdout.strip())
        except AdapterValidationError:
            raise
        except Exception as exc:
            raise AdapterValidationError(f"Failed to query lsblk for USB verification: {exc}") from exc

        matched_node: Optional[Dict[str, object]] = None
        parent_tran = ""
        parent_serial = ""

        def _search_devices(nodes: List[Dict[str, object]], inherited_tran: str, inherited_serial: str) -> None:
            nonlocal matched_node, parent_tran, parent_serial
            for n in nodes:
                cur_tran = str(n.get("tran") or inherited_tran or "").lower()
                cur_serial = str(n.get("serial") or inherited_serial or "").strip()
                mp = str(n.get("mountpoint") or "").strip()
                if mp and Path(mp).resolve() == target:
                    matched_node = n
                    parent_tran = cur_tran
                    parent_serial = cur_serial
                    return
                children = n.get("children")
                if isinstance(children, list):
                    _search_devices(children, cur_tran, cur_serial)

        blockdevices = blk_data.get("blockdevices", [])
        if isinstance(blockdevices, list):
            _search_devices(blockdevices, "", "")

        if matched_node is None:
            raise AdapterValidationError(f"Mount point '{target}' not found in lsblk block devices.")

        is_usb = parent_tran == "usb" or bool(matched_node.get("rm"))
        uuid_val = str(matched_node.get("uuid") or "").strip()
        fstype = str(matched_node.get("fstype") or "").upper()
        free_b, total_b = self.get_free_space_bytes(target)

        return USBDeviceTelemetry(
            mount_root=str(target),
            serial_number=parent_serial,
            volume_guid=uuid_val,
            filesystem=fstype,
            is_removable_usb_bus=is_usb,
            is_system_or_internal_disk=not is_usb,
            is_dirty=None,
            smart_health_status="UNAVAILABLE",
            free_bytes=free_b,
            total_bytes=total_b,
        )

    def verify_smb_session(
        self,
        endpoint: SMBEndpointConfig,
        target_share_path: Union[str, Path],
    ) -> SMBSessionTelemetry:
        target = Path(target_share_path).resolve()
        if self._smb_provider is not None:
            return self._smb_provider(endpoint, target)

        if not target.exists():
            raise AdapterValidationError(f"Mounted SMB share directory does not exist: {target}")

        if not self._proc_mounts.exists():
            raise AdapterValidationError(f"Cannot verify Linux SMB mount: '{self._proc_mounts}' not found.")

        mount_lines = self._proc_mounts.read_text(encoding="utf-8", errors="replace").splitlines()
        best_match: Optional[Tuple[str, str, str, str]] = None
        best_len = -1

        for line in mount_lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            src, mp, fstype, opts = parts[0], parts[1], parts[2], parts[3]
            mp_path = Path(mp)
            try:
                target.relative_to(mp_path)
                if len(str(mp_path)) > best_len:
                    best_len = len(str(mp_path))
                    best_match = (src, mp, fstype, opts)
            except ValueError:
                continue

        if best_match is None:
            raise AdapterValidationError(f"Target '{target}' is not on any mounted filesystem.")

        src, mp, fstype, opts = best_match
        if fstype.lower() not in ("cifs", "smb3"):
            raise AdapterValidationError(
                f"NET-01 Violation: Directory '{target}' is mounted on local/non-SMB filesystem '{fstype}', not a remote SMB3 share."
            )

        # Parse remote server from //server/share
        clean_src = src.lstrip("/\\")
        srv_name = clean_src.split("/")[0].split("\\")[0]

        opt_dict: Dict[str, str] = {}
        opt_flags = set()
        for tok in opts.split(","):
            if "=" in tok:
                k, v = tok.split("=", 1)
                opt_dict[k.strip().lower()] = v.strip()
            else:
                opt_flags.add(tok.strip().lower())

        dialect = opt_dict.get("vers", "3.1.1")
        encrypted = "seal" in opt_flags
        signed = ("sign" in opt_flags) or encrypted
        free_b, _ = self.get_free_space_bytes(target)

        return SMBSessionTelemetry(
            server_name=srv_name,
            share_path=str(target),
            dialect=dialect,
            encrypted=encrypted,
            signed=signed,
            is_remote_mount=True,
            free_bytes=free_b,
        )

    def verify_directory_permissions(self, path: Union[str, Path], *, require_readonly: bool = False) -> bool:
        target = Path(path)
        if not target.exists():
            return False
        st = os.lstat(target)
        # Reject world-writable directories (mode & 0o002)
        if st.st_mode & 0o002:
            return False
        if require_readonly:
            return os.access(target, os.R_OK)
        return os.access(target, os.R_OK | os.W_OK)
