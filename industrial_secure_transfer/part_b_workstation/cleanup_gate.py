"""
part_b_workstation/cleanup_gate.py
Part B ONLY — Isolated, Restricted USB Cleanup Security Gate (Section 4, Section 12, SAF-03):
- NEVER imported or bundled in Part A Exporter.
- Never accepts arbitrary user-supplied paths, drive letters, wildcards, or recursive directory deletion.
- Contains NO formatting or partitioning functionality.
- Enforces 7 mandatory sequential hardware & cryptographic checks before unlinking any single file:
  1. Verifies physical USB device serial, volume GUID, removable USB bus, and non-OS/non-internal disk status via OS adapter.
  2. Verifies the signed `COMMITTED` server receipt is already durably persisted at `USB:\\Receipts\\<transferId>.receipt.json`
     on that same physical USB volume.
  3. Verifies the Ed25519 server signature on the persisted receipt against `trusted_server_keys`,
     and confirms `status == "COMMITTED"` (`QUARANTINED` or `EXPORTED_TO_USB` never authorizes cleanup).
  4. Reads and cryptographically verifies the signed outer manifest at
     `USB:\\Transfers\\<transferId>\\<attemptId>\\manifest.signed.json` and confirms its SHA-256 digest
     matches `receipt.manifest_hash` and `receipt.sender_id`.
  5. Derives the exact allowlisted set of application-created encrypted chunk files from the verified outer manifest
     plus verified `USB:\\Diagnostics\\PROBE-*.bin` files.
  6. Explicitly protects `Application\\`, `Configuration\\`, `Certificates\\`, `Receipts\\`, and `Logs\\` —
     and rejects any unknown/extra files or symlinks/reparse points.
  7. Re-verifies the physical USB volume serial + GUID immediately before EACH individual `os.unlink()` call
     to prevent TOCTOU device-swap attacks, and verifies the receipt file remains intact on the USB after cleanup.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import ed25519

from industrial_secure_transfer.adapters.base import BaseOSAdapter
from industrial_secure_transfer.core.config import AuthorizedUSBDevice
from industrial_secure_transfer.core.crypto import (
    canonical_json_bytes,
    parse_strict_json,
    sha256_hex,
    sha256_stream,
)
from industrial_secure_transfer.core.packaging import verify_outer_manifest_envelope
from industrial_secure_transfer.core.safety import (
    SafetyViolationError,
    has_multiple_hardlinks,
    is_reparse_point_or_symlink,
    safe_readonly_open,
    validate_confined_path,
)
from industrial_secure_transfer.transports.smb_transport import (
    verify_server_receipt_document,
)

PROTECTED_TOP_LEVEL_PREFIXES = (
    "application",
    "configuration",
    "certificates",
    "receipts",
    "logs",
)


class CleanupGateBlockedError(SafetyViolationError):
    """Raised whenever any mandatory USB cleanup security gate condition fails (fail closed)."""


@dataclass(frozen=True)
class CleanupExecutionReport:
    transfer_id: str
    attempt_id: str
    usb_serial_number: str
    usb_volume_guid: str
    deleted_payload_files: Tuple[str, ...]
    deleted_probe_files: Tuple[str, ...]
    retained_receipt_path: str


class RestrictedUSBCleanupGate:
    """
    Isolated Part B-only USB cleanup component.
    Can only delete exact, manifest-enumerated encrypted payload chunks and verified diagnostic probes
    on an authorized physical USB volume AFTER verifying a persisted signed COMMITTED receipt on that same USB.
    """

    def __init__(
        self,
        *,
        adapter: BaseOSAdapter,
        authorized_usb_devices: Tuple[AuthorizedUSBDevice, ...],
        trusted_sender_keys: Dict[str, ed25519.Ed25519PublicKey],
        trusted_server_keys: Dict[str, ed25519.Ed25519PublicKey],
    ) -> None:
        if not authorized_usb_devices:
            raise CleanupGateBlockedError("No authorized USB devices configured for cleanup gate.")
        if not trusted_server_keys:
            raise CleanupGateBlockedError("No trusted server signing keys configured for cleanup gate.")
        self._adapter = adapter
        self._authorized_devices = authorized_usb_devices
        self._trusted_sender_keys = dict(trusted_sender_keys)
        self._trusted_server_keys = dict(trusted_server_keys)

    def _verify_bound_usb_identity(
        self,
        usb_root: Path,
        expected_serial: Optional[str] = None,
        expected_guid: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Verifies via the OS adapter that `usb_root` is an authorized physical removable USB device
        (never an internal or system disk) and matches `expected_serial`/`expected_guid` if already bound.
        """
        try:
            telemetry, _ = self._adapter.validate_authorized_usb(
                usb_root,
                self._authorized_devices,
                required_free_bytes=0,
            )
        except Exception as exc:
            raise CleanupGateBlockedError(f"Physical USB authorization failed: {exc}") from exc

        if expected_serial is not None and telemetry.serial_number.upper() != expected_serial.upper():
            raise CleanupGateBlockedError(
                f"CRITICAL: Physical USB serial changed mid-cleanup ({expected_serial} -> {telemetry.serial_number})!"
            )
        if expected_guid is not None and telemetry.volume_guid.upper() != expected_guid.upper():
            raise CleanupGateBlockedError(
                f"CRITICAL: Physical USB volume GUID changed mid-cleanup ({expected_guid} -> {telemetry.volume_guid})!"
            )
        return telemetry.serial_number, telemetry.volume_guid

    def execute_authorized_cleanup(
        self,
        *,
        usb_mount_root: Union[str, Path],
        transfer_id: str,
        attempt_id: str,
    ) -> CleanupExecutionReport:
        """
        Performs controlled deletion of exact verified payload chunks for `(transfer_id, attempt_id)`
        and diagnostic probe files on `usb_mount_root`.
        Never accepts file path lists or wildcards from callers.
        """
        if not transfer_id or not attempt_id or any(c in transfer_id + attempt_id for c in ("*", "?", "/", "\\", "..")):
            raise CleanupGateBlockedError("Invalid or wildcard transfer_id/attempt_id rejected by cleanup gate.")

        usb_root = Path(os.path.abspath(str(usb_mount_root)))
        if not usb_root.exists() or not usb_root.is_dir() or is_reparse_point_or_symlink(usb_root):
            raise CleanupGateBlockedError(f"Invalid or symlinked USB root: {usb_root}")

        # Gate 1: Bind and verify physical USB identity
        bound_serial, bound_guid = self._verify_bound_usb_identity(usb_root)

        # Gate 2: Load signed outer manifest from USB and verify sender signature
        rel_manifest = Path("Transfers") / transfer_id / attempt_id / "manifest.signed.json"
        try:
            with safe_readonly_open(usb_root, rel_manifest) as mfh:
                manifest_raw = mfh.read()
            outer_manifest = parse_strict_json(manifest_raw)
            verify_outer_manifest_envelope(outer_manifest, self._trusted_sender_keys)
        except Exception as exc:
            raise CleanupGateBlockedError(
                f"Cannot verify signed outer manifest on USB at '{rel_manifest}': {exc}"
            ) from exc

        if outer_manifest.get("transferId") != transfer_id or outer_manifest.get("attemptId") != attempt_id:
            raise CleanupGateBlockedError("Outer manifest transferId/attemptId mismatch with cleanup target.")

        expected_sender_id = str(outer_manifest["senderId"])
        manifest_sha256 = sha256_hex(canonical_json_bytes(outer_manifest))

        # Gate 3: Load and verify signed COMMITTED receipt persisted on the SAME USB
        rel_receipt = Path("Receipts") / f"{transfer_id}.receipt.json"
        try:
            with safe_readonly_open(usb_root, rel_receipt) as rfh:
                receipt_raw = rfh.read()
            receipt_doc = parse_strict_json(receipt_raw)
            verified_receipt = verify_server_receipt_document(
                receipt_doc,
                self._trusted_server_keys,
                expected_transfer_id=transfer_id,
                expected_sender_id=expected_sender_id,
                expected_manifest_hash=manifest_sha256,
                require_committed_status=True,
            )
        except Exception as exc:
            raise CleanupGateBlockedError(
                f"USB cleanup blocked: Persisted server receipt verification failed: {exc}"
            ) from exc

        if verified_receipt.status != "COMMITTED":
            raise CleanupGateBlockedError(
                f"USB cleanup blocked: Receipt status is '{verified_receipt.status}', not 'COMMITTED'."
            )

        # Gate 4: Verify exact payload inventory on USB matches manifest before deleting anything
        attempt_dir_rel = Path("Transfers") / transfer_id / attempt_id
        attempt_dir_abs = validate_confined_path(usb_root, attempt_dir_rel, must_exist=True)

        expected_chunks: Dict[str, Tuple[int, str]] = {}
        for ch in outer_manifest["chunks"]:
            cid = str(ch["opaqueChunkId"])
            if "/" in cid or "\\" in cid or not cid.startswith("CHK-") or not cid.endswith(".bin"):
                raise CleanupGateBlockedError(f"Non-conforming chunk filename in manifest: '{cid}'")
            expected_chunks[cid] = (int(ch["cipherSize"]), str(ch["cipherSHA256"]))

        # Check for any unknown/extra files inside the transfer attempt directory
        actual_items = sorted(attempt_dir_abs.iterdir(), key=lambda p: p.name)
        for item in actual_items:
            if item.name == "manifest.signed.json":
                continue
            if item.name not in expected_chunks:
                raise CleanupGateBlockedError(
                    f"USB cleanup blocked: Unknown file '{item.name}' found in '{attempt_dir_rel}'. Refusing deletion."
                )
            if not item.is_file() or is_reparse_point_or_symlink(item) or has_multiple_hardlinks(item):
                raise CleanupGateBlockedError(
                    f"USB cleanup blocked: Irregular, symlinked, or hardlinked chunk file '{item.name}'."
                )
            exp_sz, exp_sha = expected_chunks[item.name]
            with safe_readonly_open(usb_root, attempt_dir_rel / item.name) as cfh:
                act_sha, act_sz = sha256_stream(cfh)
            if act_sz != exp_sz or act_sha != exp_sha:
                raise CleanupGateBlockedError(
                    f"USB cleanup blocked: Chunk '{item.name}' on USB does not match committed manifest hash."
                )

        # Gate 5: Collect eligible diagnostic probe files (`USB:\Diagnostics\PROBE-*.bin`)
        eligible_probes: List[Path] = []
        diag_dir_rel = Path("Diagnostics")
        diag_dir_abs = usb_root / diag_dir_rel
        if diag_dir_abs.exists():
            validate_confined_path(usb_root, diag_dir_rel, must_exist=True)
            for p_item in sorted(diag_dir_abs.iterdir(), key=lambda p: p.name):
                if (
                    p_item.is_file()
                    and p_item.name.startswith("PROBE-")
                    and p_item.name.endswith(".bin")
                    and not is_reparse_point_or_symlink(p_item)
                    and not has_multiple_hardlinks(p_item)
                ):
                    eligible_probes.append(diag_dir_rel / p_item.name)
                else:
                    raise CleanupGateBlockedError(
                        f"USB cleanup blocked: Unexpected file '{p_item.name}' inside Diagnostics directory."
                    )

        # Gate 6 & 7: Delete exact allowlisted payload chunks + manifest + probes, revalidating USB identity before each unlink
        deleted_payloads: List[str] = []
        for cid in sorted(expected_chunks.keys()):
            rel_target = attempt_dir_rel / cid
            if not (usb_root / rel_target).exists():
                continue
            self._verify_bound_usb_identity(usb_root, bound_serial, bound_guid)
            self._safe_confined_unlink(usb_root, rel_target)
            deleted_payloads.append(rel_target.as_posix())

        # Unlink the attempt's outer manifest after all its chunks are removed (receipt in USB:\Receipts\ is retained!)
        self._verify_bound_usb_identity(usb_root, bound_serial, bound_guid)
        self._safe_confined_unlink(usb_root, rel_manifest)
        deleted_payloads.append(rel_manifest.as_posix())

        deleted_probes: List[str] = []
        for rel_probe in eligible_probes:
            self._verify_bound_usb_identity(usb_root, bound_serial, bound_guid)
            self._safe_confined_unlink(usb_root, rel_probe)
            deleted_probes.append(rel_probe.as_posix())

        # Final post-condition check: confirm receipt in USB:\Receipts\ is still intact and valid
        with safe_readonly_open(usb_root, rel_receipt) as rfh:
            post_receipt_doc = parse_strict_json(rfh.read())
        verify_server_receipt_document(
            post_receipt_doc,
            self._trusted_server_keys,
            expected_transfer_id=transfer_id,
            expected_sender_id=expected_sender_id,
            expected_manifest_hash=manifest_sha256,
            require_committed_status=True,
        )

        return CleanupExecutionReport(
            transfer_id=transfer_id,
            attempt_id=attempt_id,
            usb_serial_number=bound_serial,
            usb_volume_guid=bound_guid,
            deleted_payload_files=tuple(deleted_payloads),
            deleted_probe_files=tuple(deleted_probes),
            retained_receipt_path=rel_receipt.as_posix(),
        )

    @staticmethod
    def _safe_confined_unlink(usb_root: Path, rel_path: Path) -> None:
        """
        Unlinks a single confined regular file on `usb_root`, enforcing that it does not
        reside in any protected directory (`Application`, `Configuration`, `Certificates`, `Receipts`, `Logs`).
        """
        top_folder = rel_path.parts[0].lower() if rel_path.parts else ""
        if top_folder in PROTECTED_TOP_LEVEL_PREFIXES:
            raise CleanupGateBlockedError(
                f"CRITICAL SAFETY BLOCK: Attempted to delete file inside protected USB folder '{rel_path}'!"
            )
        if top_folder not in ("transfers", "diagnostics"):
            raise CleanupGateBlockedError(
                f"CRITICAL SAFETY BLOCK: Cleanup target '{rel_path}' is outside Transfers/Diagnostics!"
            )

        target_abs = validate_confined_path(
            usb_root,
            rel_path,
            must_exist=True,
            reject_hardlinks=True,
        )
        if not target_abs.is_file() or is_reparse_point_or_symlink(target_abs):
            raise CleanupGateBlockedError(f"Target '{target_abs}' is not a regular file or is a symlink.")

        os.unlink(target_abs)
