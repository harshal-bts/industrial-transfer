"""
transports/usb_transport.py
Single-USB Export & Import Transport + Quick Non-Destructive Health Probe
(Section 11, Section 12, USB-01..USB-04):
- Enforces standard USB directory hierarchy:
    USB:\\
      Application\\     (protected; never touched by cleanup)
      Configuration\\   (protected; never touched by cleanup)
      Certificates\\    (protected; never touched by cleanup)
      Transfers\\<transferId>\\<attemptId>\\
      Diagnostics\\
      Receipts\\
      Logs\\
- Export preflight (Part A ONLY):
  * Verifies physical USB device serial, volume GUID, removable bus, filesystem, dirty bit, and capacity.
  * Strict-mode custody cycle: if `require_prior_receipt=True` and previous unacknowledged transfers exist on USB,
    verifies a matching signed `COMMITTED` receipt is present in `USB:\\Receipts\\` before unlocking the next export.
  * Performs a 32-64 MiB random diagnostic write/flush/read-back hash probe in `USB:\\Diagnostics\\` (never locally!).
- Import preflight (Part B ONLY):
  * Strictly read-only checks on USB payload and outer manifest signature before streaming chunks to SMB.
  * Persists the verified signed `COMMITTED` server receipt to `USB:\\Receipts\\<transferId>.receipt.json` via create-only write.
- CRITICAL (SAF-03): This transport module contains ZERO file deletion or cleanup functions.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import ed25519

from industrial_secure_transfer.adapters.base import BaseOSAdapter, USBDeviceTelemetry
from industrial_secure_transfer.core.config import AuthorizedUSBDevice
from industrial_secure_transfer.core.crypto import (
    IntegrityVerificationError,
    canonical_json_bytes,
    compute_manifest_digest,
    parse_strict_json,
    sha256_hex,
    sha256_stream,
)
from industrial_secure_transfer.core.packaging import (
    EncryptedChunkItem,
    verify_outer_manifest_envelope,
)
from industrial_secure_transfer.core.safety import (
    create_only_write_bytes,
    ensure_confined_directory_tree,
    generate_immutable_attempt_id,
    safe_readonly_open,
    validate_confined_path,
)
from industrial_secure_transfer.transports.smb_transport import (
    VerifiedServerReceipt,
    verify_server_receipt_document,
)

DEFAULT_PROBE_SIZE_BYTES = 32 * 1024 * 1024  # 32 MiB (configurable 32-64 MiB)
MIN_PROBE_SIZE_BYTES = 32 * 1024 * 1024
MAX_PROBE_SIZE_BYTES = 64 * 1024 * 1024

PROTECTED_USB_DIRECTORIES = ("Application", "Configuration", "Certificates", "Receipts", "Logs")
UNEXPECTED_EXECUTABLE_EXTENSIONS = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".scr", ".com", ".dll", ".sh"}


class USBTransportError(Exception):
    """Raised when a USB health probe, media content check, or read-back verification fails."""


@dataclass(frozen=True)
class USBHealthProbeResult:
    probe_relative_path: str
    probe_size_bytes: int
    probe_sha256: str
    elapsed_seconds: float


@dataclass(frozen=True)
class USBPreflightReport:
    telemetry: USBDeviceTelemetry
    authorized_device: AuthorizedUSBDevice
    probe_result: Optional[USBHealthProbeResult]
    prior_receipts_verified: Tuple[str, ...]


class USBTransport:
    """
    Non-destructive single-USB transport for Part A (export) and Part B (read-only import + receipt write).
    Contains NO deletion methods (SAF-03).
    """

    def __init__(
        self,
        adapter: BaseOSAdapter,
        usb_mount_root: Union[str, Path],
        authorized_devices: Tuple[AuthorizedUSBDevice, ...],
        *,
        trusted_sender_keys: Optional[Dict[str, ed25519.Ed25519PublicKey]] = None,
        trusted_server_keys: Optional[Dict[str, ed25519.Ed25519PublicKey]] = None,
    ) -> None:
        self._adapter = adapter
        self._root = Path(usb_mount_root)
        self._authorized_devices = authorized_devices
        self._trusted_sender_keys = dict(trusted_sender_keys or {})
        self._trusted_server_keys = dict(trusted_server_keys or {})

    @property
    def root(self) -> Path:
        return self._root

    def _scan_for_unexpected_root_executables(self) -> None:
        """
        Section 11 Media content gate: blocks transfer if unexpected files or executables exist
        outside the approved directory layout on the USB.
        """
        allowed_top_dirs = {
            "Application",
            "Configuration",
            "Certificates",
            "Transfers",
            "Diagnostics",
            "Receipts",
            "Logs",
            "System Volume Information",
        }
        for item in self._root.iterdir():
            if item.name in allowed_top_dirs:
                continue
            raise USBTransportError(
                f"USB-01 Media Content Violation: Unexpected file or folder '{item.name}' in USB root."
            )

        # Ensure no unexpected executables were dropped inside Transfers, Diagnostics, Receipts, or Logs
        for data_subdir in ("Transfers", "Diagnostics", "Receipts", "Logs"):
            sub_p = self._root / data_subdir
            if not sub_p.exists():
                continue
            for dirpath, _, filenames in os.walk(sub_p, followlinks=False):
                for fn in filenames:
                    ext = Path(fn).suffix.lower()
                    if ext in UNEXPECTED_EXECUTABLE_EXTENSIONS:
                        raise USBTransportError(
                            f"USB-01 Media Content Violation: Executable/script '{fn}' detected in '{data_subdir}'."
                        )

    def verify_returned_receipts_on_usb(self, expected_sender_id: str) -> Tuple[str, ...]:
        """
        Verifies that:
        1. Every existing transfer package still remaining in `USB:\\Transfers\\<transferId>\\<attemptId>\\`
           has a corresponding cryptographically signed `COMMITTED` receipt in `USB:\\Receipts\\<transferId>.receipt.json`.
        2. Every signed receipt in `USB:\\Receipts\\*.receipt.json` (including transfers whose payload chunks
           were already removed by Part B's post-receipt cleanup gate) carries a valid server Ed25519 signature,
           `status == "COMMITTED"`, and `senderId == expected_sender_id`
           (Section 11 & Section 12 single-USB custody cycle).
        """
        transfers_dir = self._root / "Transfers"
        receipts_dir = self._root / "Receipts"
        verified_ids: List[str] = []

        # 1. Verify any remaining transfer attempt directories have matching receipts
        if transfers_dir.exists():
            for t_dir in sorted(transfers_dir.iterdir()):
                if not t_dir.is_dir():
                    continue
                transfer_id = t_dir.name
                for att_dir in sorted(t_dir.iterdir()):
                    if not att_dir.is_dir():
                        continue
                    manifest_rel = Path("Transfers") / transfer_id / att_dir.name / "manifest.signed.json"
                    manifest_abs = self._root / manifest_rel
                    if not manifest_abs.exists():
                        continue
                    with safe_readonly_open(self._root, manifest_rel) as fh:
                        manifest_doc = parse_strict_json(fh.read())
                    manifest_hash = compute_manifest_digest(manifest_doc)

                    receipt_rel = Path("Receipts") / f"{transfer_id}.receipt.json"
                    if not (self._root / receipt_rel).exists():
                        raise USBTransportError(
                            f"Strict single-USB custody gate: Previous transfer '{transfer_id}' on USB has no signed server receipt."
                        )
                    with safe_readonly_open(self._root, receipt_rel) as rfh:
                        receipt_doc = parse_strict_json(rfh.read())

                    verify_server_receipt_document(
                        receipt_doc,
                        self._trusted_server_keys,
                        expected_transfer_id=transfer_id,
                        expected_sender_id=expected_sender_id,
                        expected_manifest_hash=manifest_hash,
                        require_committed_status=True,
                    )
                    if transfer_id not in verified_ids:
                        verified_ids.append(transfer_id)

        # 2. Verify all persisted receipts in USB:\Receipts\ (for cleaned USB packages returning to Part A)
        if receipts_dir.exists():
            for r_file in sorted(receipts_dir.iterdir()):
                if not r_file.is_file() or not r_file.name.endswith(".receipt.json"):
                    continue
                rel_r = Path("Receipts") / r_file.name
                with safe_readonly_open(self._root, rel_r) as rfh:
                    receipt_doc = parse_strict_json(rfh.read())
                t_id = str(receipt_doc.get("transferId", ""))
                m_hash = str(receipt_doc.get("manifestHash", ""))
                verify_server_receipt_document(
                    receipt_doc,
                    self._trusted_server_keys,
                    expected_transfer_id=t_id,
                    expected_sender_id=expected_sender_id,
                    expected_manifest_hash=m_hash,
                    require_committed_status=True,
                )
                if t_id not in verified_ids:
                    verified_ids.append(t_id)

        return tuple(verified_ids)

    def run_export_health_probe(
        self,
        *,
        probe_size_bytes: int = DEFAULT_PROBE_SIZE_BYTES,
        timeout_seconds: float = 20.0,
        enforce_32_64_mib_bounds: bool = True,
        clock: Callable[[], float] = time.monotonic,
    ) -> USBHealthProbeResult:
        """
        Export-only Write/Flush/Read-Back Health Probe (Section 11, USB-01, USB-02, USB-04):
        - Creates a 32-64 MiB random diagnostic file ONLY on the authorized USB (`USB:\\Diagnostics\\PROBE-<id>.bin`),
          NEVER on local storage.
        - Flushes, fsyncs, closes, re-opens, reads back, and compares SHA-256 and timing against `timeout_seconds`.
        - Retains the probe artifact in `USB:\\Diagnostics\\` for Part B's post-receipt cleanup inventory.
        """
        if enforce_32_64_mib_bounds and not (MIN_PROBE_SIZE_BYTES <= probe_size_bytes <= MAX_PROBE_SIZE_BYTES):
            raise ValueError(
                f"USB export health probe size ({probe_size_bytes}) must be between 32 MiB and 64 MiB."
            )
        if probe_size_bytes <= 0:
            raise ValueError("probe_size_bytes must be positive.")

        t0 = clock()
        probe_id = generate_immutable_attempt_id("PROBE")
        rel_probe = Path("Diagnostics") / f"{probe_id}.bin"

        # Generate random payload and compute expected SHA-256 in memory
        random_payload = os.urandom(probe_size_bytes)
        expected_sha256 = sha256_hex(random_payload)

        try:
            create_only_write_bytes(
                self._root,
                rel_probe,
                random_payload,
                create_parents=True,
                fsync=True,
            )
            with safe_readonly_open(self._root, rel_probe) as fh:
                read_sha256, read_size = sha256_stream(fh)
        except Exception as exc:
            raise USBTransportError(f"USB-02 Health Probe I/O failure on '{rel_probe}': {exc}") from exc

        elapsed = clock() - t0
        if read_size != probe_size_bytes or read_sha256 != expected_sha256:
            raise USBTransportError(
                f"USB-02 Health Probe hash mismatch on '{rel_probe}' "
                f"(expected {expected_sha256}, got {read_sha256})."
            )
        if elapsed > timeout_seconds:
            raise USBTransportError(
                f"USB-02 Health Probe timeout: took {elapsed:.2f}s (max allowed {timeout_seconds:.2f}s)."
            )

        return USBHealthProbeResult(
            probe_relative_path=rel_probe.as_posix(),
            probe_size_bytes=probe_size_bytes,
            probe_sha256=expected_sha256,
            elapsed_seconds=elapsed,
        )

    def run_export_preflight(
        self,
        *,
        expected_dataset_bytes: int,
        expected_sender_id: str,
        require_prior_receipt: bool = True,
        probe_size_bytes: int = DEFAULT_PROBE_SIZE_BYTES,
        enforce_32_64_mib_probe: bool = True,
        probe_timeout_seconds: float = 20.0,
    ) -> USBPreflightReport:
        """
        Executes all mandatory Part A USB export preflight gates (Section 11, USB-01..USB-04):
        1. Physical device identity, volume GUID, removable USB bus, filesystem, dirty bit, and SMART check.
        2. Worst-case uncompressed payload + crypto/manifest overhead + probe + 10% retry reserve capacity check.
        3. Media content check (reject unexpected root files or unauthorized executables).
        4. Prior server receipt verification (if previous transfers remain on the USB).
        5. Write/flush/read-back diagnostic probe on the USB volume.
        """
        overhead_and_reserve = int(expected_dataset_bytes * 1.15) + probe_size_bytes + (64 * 1024 * 1024)
        telemetry, auth_dev = self._adapter.validate_authorized_usb(
            self._root,
            self._authorized_devices,
            required_free_bytes=overhead_and_reserve,
        )

        # Ensure standard non-destructive folder hierarchy exists
        for folder in ("Application", "Configuration", "Certificates", "Transfers", "Diagnostics", "Receipts", "Logs"):
            ensure_confined_directory_tree(self._root, folder)

        self._scan_for_unexpected_root_executables()

        prior_verified: Tuple[str, ...] = ()
        if require_prior_receipt:
            prior_verified = self.verify_returned_receipts_on_usb(expected_sender_id)

        probe_res = self.run_export_health_probe(
            probe_size_bytes=probe_size_bytes,
            timeout_seconds=probe_timeout_seconds,
            enforce_32_64_mib_bounds=enforce_32_64_mib_probe,
        )

        return USBPreflightReport(
            telemetry=telemetry,
            authorized_device=auth_dev,
            probe_result=probe_res,
            prior_receipts_verified=prior_verified,
        )

    def run_import_preflight(self) -> USBPreflightReport:
        """
        Executes strictly read-only Part B USB import preflight gates (Section 11 & Section 12):
        - Physical USB device authorization, filesystem, and dirty-bit check.
        - Media content verification (no unexpected executables).
        - Zero writes or diagnostic probes on the USB during import preflight!
        """
        telemetry, auth_dev = self._adapter.validate_authorized_usb(
            self._root,
            self._authorized_devices,
            required_free_bytes=0,
        )
        self._scan_for_unexpected_root_executables()
        return USBPreflightReport(
            telemetry=telemetry,
            authorized_device=auth_dev,
            probe_result=None,
            prior_receipts_verified=(),
        )

    def check_existing_chunk_on_usb(
        self,
        *,
        transfer_id: str,
        attempt_id: str,
        opaque_chunk_id: str,
        expected_cipher_size: int,
        expected_cipher_sha256: str,
    ) -> bool:
        """
        Used during checkpoint recovery (Section 14, RES-01): checks whether an intact,
        hash-verified encrypted chunk already exists on the USB volume for `(transfer_id, attempt_id)`.
        """
        rel_chunk = Path("Transfers") / transfer_id / attempt_id / opaque_chunk_id
        try:
            target = validate_confined_path(self._root, rel_chunk, must_exist=True)
            if not target.is_file():
                return False
            with safe_readonly_open(self._root, rel_chunk) as fh:
                digest, size = sha256_stream(fh)
            return size == expected_cipher_size and digest == expected_cipher_sha256
        except Exception:
            return False

    def write_and_verify_chunk_on_usb(
        self,
        *,
        transfer_id: str,
        attempt_id: str,
        chunk: EncryptedChunkItem,
    ) -> Path:
        """
        Writes an encrypted chunk to `USB:\\Transfers\\<transferId>\\<attemptId>\\<opaqueChunkId>`
        using exclusive create-only (`xb`), flushes/fsyncs, and immediately re-opens and reads back
        to verify its SHA-256 and byte length on the physical USB media (Section 11).
        """
        rel_chunk = Path("Transfers") / transfer_id / attempt_id / chunk.opaque_chunk_id
        written_path = create_only_write_bytes(
            self._root,
            rel_chunk,
            chunk.cipher_bytes,
            create_parents=True,
            fsync=True,
        )

        with safe_readonly_open(self._root, rel_chunk) as fh:
            usb_sha256, usb_size = sha256_stream(fh)

        if usb_size != chunk.cipher_size or usb_sha256 != chunk.cipher_sha256:
            raise IntegrityVerificationError(
                f"USB read-back verification failed for chunk '{chunk.opaque_chunk_id}' "
                f"(expected {chunk.cipher_sha256}, got {usb_sha256})."
            )
        return written_path

    def publish_final_manifest_on_usb(
        self,
        *,
        transfer_id: str,
        attempt_id: str,
        signed_outer_manifest: Dict[str, Any],
    ) -> Tuple[Path, str]:
        """
        Writes `manifest.signed.json` LAST to `USB:\\Transfers\\<transferId>\\<attemptId>\\manifest.signed.json`
        and verifies its read-back SHA-256 digest.
        """
        manifest_bytes = canonical_json_bytes(signed_outer_manifest)
        expected_hash = sha256_hex(manifest_bytes)
        rel_manifest = Path("Transfers") / transfer_id / attempt_id / "manifest.signed.json"

        written_path = create_only_write_bytes(
            self._root,
            rel_manifest,
            manifest_bytes,
            create_parents=True,
            fsync=True,
        )

        with safe_readonly_open(self._root, rel_manifest) as fh:
            usb_sha256, usb_size = sha256_stream(fh)

        if usb_size != len(manifest_bytes) or usb_sha256 != expected_hash:
            raise IntegrityVerificationError("USB read-back verification failed for outer manifest.")
        return written_path, expected_hash

    def read_and_validate_usb_package(
        self,
        *,
        transfer_id: str,
        attempt_id: str,
    ) -> Tuple[Dict[str, Any], str]:
        """
        Used by Part B in read-only mode:
        1. Reads `USB:\\Transfers\\<transferId>\\<attemptId>\\manifest.signed.json`.
        2. Verifies the sender's Ed25519 signature over the outer manifest.
        3. Verifies every listed encrypted chunk exists on the USB and matches its `cipherSize` and `cipherSHA256`.
        Returns `(outer_manifest_dict, manifest_sha256)`.
        """
        rel_manifest = Path("Transfers") / transfer_id / attempt_id / "manifest.signed.json"
        with safe_readonly_open(self._root, rel_manifest) as fh:
            raw_bytes = fh.read()

        outer_manifest = parse_strict_json(raw_bytes)
        if outer_manifest.get("transferId") != transfer_id or outer_manifest.get("attemptId") != attempt_id:
            raise USBTransportError("Outer manifest transferId/attemptId does not match USB directory path.")

        verify_outer_manifest_envelope(outer_manifest, self._trusted_sender_keys)
        manifest_hash = sha256_hex(canonical_json_bytes(outer_manifest))

        for ch_meta in outer_manifest["chunks"]:
            cid = str(ch_meta["opaqueChunkId"])
            expected_sz = int(ch_meta["cipherSize"])
            expected_sha = str(ch_meta["cipherSHA256"])
            rel_chunk = Path("Transfers") / transfer_id / attempt_id / cid
            with safe_readonly_open(self._root, rel_chunk) as cfh:
                actual_sha, actual_sz = sha256_stream(cfh)
            if actual_sz != expected_sz or actual_sha != expected_sha:
                raise IntegrityVerificationError(
                    f"USB chunk integrity failure on '{rel_chunk}': expected sha256={expected_sha} ({expected_sz}B), "
                    f"got {actual_sha} ({actual_sz}B)."
                )

        return outer_manifest, manifest_hash

    def persist_verified_receipt_to_usb(
        self,
        receipt: VerifiedServerReceipt,
    ) -> Path:
        """
        Persists a cryptographically verified `COMMITTED` server receipt to
        `USB:\\Receipts\\<transferId>.receipt.json` using exclusive create-only semantics (`xb`)
        and verifies it via read-back hash before returning.
        """
        if receipt.status != "COMMITTED":
            raise USBTransportError("Refusing to persist non-COMMITTED receipt as a completion record on USB.")

        rel_receipt = Path("Receipts") / f"{receipt.transfer_id}.receipt.json"
        target = validate_confined_path(self._root, rel_receipt, must_exist=False)
        receipt_bytes = canonical_json_bytes(receipt.raw_document)
        expected_sha = sha256_hex(receipt_bytes)

        if target.exists():
            # If identical receipt already persisted, verify and return
            with safe_readonly_open(self._root, rel_receipt) as fh:
                existing_sha, _ = sha256_stream(fh)
            if existing_sha == expected_sha:
                return target
            raise USBTransportError(f"Conflicting receipt file already exists on USB at '{rel_receipt}'.")

        written = create_only_write_bytes(
            self._root,
            rel_receipt,
            receipt_bytes,
            create_parents=True,
            fsync=True,
        )
        with safe_readonly_open(self._root, rel_receipt) as fh:
            read_sha, read_sz = sha256_stream(fh)
        if read_sz != len(receipt_bytes) or read_sha != expected_sha:
            raise IntegrityVerificationError("Failed read-back verification of receipt persisted on USB.")
        return written
