"""
adapters/windows.py
Windows 10 / Windows Server OS Adapter:
- Physical USB device verification via Win32 kernel32 APIs (`GetDriveTypeW`, `GetVolumeInformationW`,
  `GetVolumeNameForVolumeMountPointW`) and WMI/CIM or hardware serial query.
- Dirty-bit verification via read-only `fsutil dirty query <drive>` (no chkdsk repair flags ever invoked).
- Native UNC SMB 3.1.1 session verification via `Get-SmbConnection` read-only inspection.
- Supports deterministic hardware telemetry injection for isolated offline unit/adversarial testing
  while defaulting to live Win32 / PowerShell inspection in production.
"""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple, Union

from industrial_secure_transfer.adapters.base import (
    AdapterValidationError,
    BaseOSAdapter,
    SMBSessionTelemetry,
    USBDeviceTelemetry,
)
from industrial_secure_transfer.core.config import SMBEndpointConfig

DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4


class WindowsOSAdapter(BaseOSAdapter):
    """
    Windows platform adapter implementing native USB volume/bus binding,
    `fsutil dirty query`, and `Get-SmbConnection` verification.
    """

    def __init__(
        self,
        *,
        usb_telemetry_provider: Optional[Callable[[Path], USBDeviceTelemetry]] = None,
        smb_telemetry_provider: Optional[Callable[[SMBEndpointConfig, Path], SMBSessionTelemetry]] = None,
    ) -> None:
        self._usb_provider = usb_telemetry_provider
        self._smb_provider = smb_telemetry_provider

    @staticmethod
    def _extract_drive_root(path: Path) -> str:
        drive = path.drive
        if not drive and len(str(path)) >= 2 and str(path)[1] == ":":
            drive = str(path)[:2]
        if not drive:
            raise AdapterValidationError(f"Path '{path}' does not have a valid Windows drive root.")
        return f"{drive.upper()}\\"

    def _query_win32_volume_info(self, drive_root: str) -> Tuple[str, int, str]:
        """
        Calls Win32 `GetVolumeInformationW` to obtain (volume_label, volume_serial_dword, filesystem_name).
        """
        if sys.platform != "win32":
            raise AdapterValidationError("Win32 volume API called on non-Windows platform.")

        kernel32 = ctypes.windll.kernel32
        vol_name_buf = ctypes.create_unicode_buffer(261)
        fs_name_buf = ctypes.create_unicode_buffer(261)
        serial_num = ctypes.c_ulong(0)
        max_comp_len = ctypes.c_ulong(0)
        fs_flags = ctypes.c_ulong(0)

        res = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(drive_root),
            vol_name_buf,
            ctypes.sizeof(vol_name_buf),
            ctypes.byref(serial_num),
            ctypes.byref(max_comp_len),
            ctypes.byref(fs_flags),
            fs_name_buf,
            ctypes.sizeof(fs_name_buf),
        )
        if not res:
            raise AdapterValidationError(f"GetVolumeInformationW failed for drive '{drive_root}'.")
        return vol_name_buf.value, serial_num.value, fs_name_buf.value

    def _query_win32_volume_guid(self, drive_root: str) -> str:
        """Calls Win32 `GetVolumeNameForVolumeMountPointW` to obtain `\\\\?\\Volume{GUID}\\`."""
        if sys.platform != "win32":
            raise AdapterValidationError("Win32 volume GUID API called on non-Windows platform.")
        kernel32 = ctypes.windll.kernel32
        guid_buf = ctypes.create_unicode_buffer(100)
        res = kernel32.GetVolumeNameForVolumeMountPointW(
            ctypes.c_wchar_p(drive_root),
            guid_buf,
            len(guid_buf),
        )
        if not res:
            raise AdapterValidationError(f"GetVolumeNameForVolumeMountPointW failed for '{drive_root}'.")
        return guid_buf.value.strip()

    def _query_fsutil_dirty_bit(self, drive_letter_colon: str) -> Optional[bool]:
        """
        Executes read-only `fsutil dirty query <X:>` (Section 11 reference [6]).
        Returns True if dirty, False if NOT dirty, or None if elevation/telemetry unavailable.
        Never invokes chkdsk or any repair flag.
        """
        try:
            proc = subprocess.run(
                ["fsutil", "dirty", "query", drive_letter_colon],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            out = (proc.stdout or "") + " " + (proc.stderr or "")
            out_lower = out.lower()
            if "is not dirty" in out_lower:
                return False
            if "is dirty" in out_lower:
                return True
            return None
        except Exception:
            return None

    def _query_usb_bus_and_serial(self, drive_letter_colon: str, fallback_vsn: int) -> Tuple[bool, str, str]:
        """
        Queries Windows storage/disk association to verify USB bus type, physical serial number,
        and SMART operational status.
        """
        ps_script = (
            f"$p = Get-Partition -DriveLetter '{drive_letter_colon[0]}' -ErrorAction Stop; "
            "$d = Get-Disk -Number $p.DiskNumber -ErrorAction Stop; "
            "[PSCustomObject]@{BusType=$d.BusType; SerialNumber=$d.SerialNumber; "
            "HealthStatus=$d.HealthStatus; IsSystem=$d.IsSystem; IsBoot=$d.IsBoot} | ConvertTo-Json -Compress"
        )
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout.strip())
                bus_type = str(data.get("BusType", "")).upper()
                serial = str(data.get("SerialNumber", "")).strip() or f"{fallback_vsn:08X}"
                health_raw = str(data.get("HealthStatus", "UNAVAILABLE")).upper()
                health = "PASSED" if health_raw == "HEALTHY" else ("FAILED" if health_raw in ("UNHEALTHY", "WARNING") else "UNAVAILABLE")
                is_usb = bus_type == "USB"
                return is_usb, serial, health
        except Exception:
            pass
        return False, f"{fallback_vsn:08X}", "UNAVAILABLE"

    def get_usb_telemetry(self, mount_root: Union[str, Path]) -> USBDeviceTelemetry:
        target = Path(mount_root)
        if self._usb_provider is not None:
            return self._usb_provider(target)

        if not target.exists():
            raise AdapterValidationError(f"USB mount root does not exist: {target}")

        drive_root = self._extract_drive_root(target)
        drive_colon = drive_root[:2]
        sys_drive = os.environ.get("SystemDrive", "C:").upper()

        if sys.platform != "win32":
            raise AdapterValidationError("Live WindowsOSAdapter requires win32 or a configured telemetry provider.")

        drive_type = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive_root))
        _, vsn, fs_name = self._query_win32_volume_info(drive_root)
        vol_guid = self._query_win32_volume_guid(drive_root)
        is_dirty = self._query_fsutil_dirty_bit(drive_colon)
        is_usb_bus, hw_serial, smart_status = self._query_usb_bus_and_serial(drive_colon, vsn)

        is_removable = (drive_type == DRIVE_REMOVABLE) or is_usb_bus
        is_sys_or_internal = (drive_colon == sys_drive) or (not is_removable)
        free_b, total_b = self.get_free_space_bytes(target)

        return USBDeviceTelemetry(
            mount_root=drive_root,
            serial_number=hw_serial,
            volume_guid=vol_guid,
            filesystem=fs_name.upper(),
            is_removable_usb_bus=is_removable,
            is_system_or_internal_disk=is_sys_or_internal,
            is_dirty=is_dirty,
            smart_health_status=smart_status,
            free_bytes=free_b,
            total_bytes=total_b,
        )

    def verify_smb_session(
        self,
        endpoint: SMBEndpointConfig,
        target_share_path: Union[str, Path],
    ) -> SMBSessionTelemetry:
        target = Path(target_share_path)
        if self._smb_provider is not None:
            return self._smb_provider(endpoint, target)

        raw_str = str(target_share_path)
        is_unc = raw_str.startswith("\\\\") or raw_str.startswith("//")
        if not target.exists():
            raise AdapterValidationError(f"SMB target share path is unreachable: {target_share_path}")

        ps_cmd = (
            "Get-SmbConnection | Select-Object ServerName,ShareName,Dialect,Signed,Encrypted | ConvertTo-Json -Compress"
        )
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10.0,
                check=False,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                raise AdapterValidationError("No active Windows SMB sessions returned by Get-SmbConnection.")
            parsed = json.loads(proc.stdout.strip())
            rows = parsed if isinstance(parsed, list) else [parsed]
        except AdapterValidationError:
            raise
        except Exception as exc:
            raise AdapterValidationError(f"Failed to query Get-SmbConnection: {exc}") from exc

        # Extract target share name from UNC path (e.g., \\server\IndustrialIncoming -> IndustrialIncoming)
        unc_parts = [p for p in raw_str.replace("/", "\\").split("\\") if p]
        expected_share = unc_parts[1].lower() if len(unc_parts) >= 2 else ""

        matched: Optional[Dict[str, object]] = None
        for r in rows:
            srv = str(r.get("ServerName", ""))
            sh_name = str(r.get("ShareName", ""))
            if srv.lower() == endpoint.server_name.lower():
                if expected_share and sh_name.lower() == expected_share:
                    matched = r
                    break
                elif not expected_share and sh_name.upper() != "IPC$":
                    matched = r
                    break
        if matched is None:
            # Fallback to any non-IPC$ connection to the server if share name differs
            for r in rows:
                if (
                    str(r.get("ServerName", "")).lower() == endpoint.server_name.lower()
                    and str(r.get("ShareName", "")).upper() != "IPC$"
                ):
                    matched = r
                    break

        if matched is None:
            raise AdapterValidationError(
                f"No active SMB connection found for server '{endpoint.server_name}'."
            )

        free_b, _ = self.get_free_space_bytes(target)
        return SMBSessionTelemetry(
            server_name=str(matched.get("ServerName", "")),
            share_path=raw_str,
            dialect=str(matched.get("Dialect", "")),
            encrypted=bool(matched.get("Encrypted", False)),
            signed=bool(matched.get("Signed", False)),
            is_remote_mount=is_unc,
            free_bytes=free_b,
        )

    def verify_directory_permissions(self, path: Union[str, Path], *, require_readonly: bool = False) -> bool:
        target = Path(path)
        if not target.exists():
            return False
        if require_readonly:
            return os.access(target, os.R_OK)
        return os.access(target, os.R_OK | os.W_OK)
