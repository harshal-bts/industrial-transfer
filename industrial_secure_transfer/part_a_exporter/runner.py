"""
part_a_exporter/runner.py
Part A — Exporter Orchestrator (Windows 10 Industrial PC):
- CRITICAL (SAF-03): Never imports or invokes `cleanup_gate` or any deletion routine,
  and never holds the server's private decryption key.
- Authenticates operator via `LocalAuthenticator` before any discovery or preflight (AUTH-01).
- Verifies signed machine configuration (DEP-01) and reserves minimum operational local disk space.
- Discovers and freezes the daily dataset in read-only mode (DAT-01).
- Executes mandatory SMB 3.1.1 or single-USB preflight gates (including the 32-64 MiB USB probe
  and verification of any returned USB receipt to unlock the next strict-mode USB export).
- Streams bounded-memory compressed + AES-256-GCM encrypted chunks to SMB or USB using create-only writes ('xb')
  with immediate read-back hash verification and append-only checkpointing.
- Supports Pause, Resume (with full preflight re-verification), and Stop Safely at verified chunk boundaries.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set, Tuple, Union

_REPO_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
import industrial_secure_transfer  # noqa: E402,F401

from cryptography.hazmat.primitives.asymmetric import ed25519

from industrial_secure_transfer.adapters.base import BaseOSAdapter
from industrial_secure_transfer.core.auth import LocalAuthenticator, OperatorSession
from industrial_secure_transfer.core.config import JobConfig, MachineConfig
from industrial_secure_transfer.core.crypto import (
    load_ed25519_public_key_pem,
    load_rsa_public_key_pem,
)
from industrial_secure_transfer.core.discovery import (
    FrozenDatasetInventory,
    discover_and_freeze_dataset,
)
from industrial_secure_transfer.core.eta import ETASnapshot, RollingETACalculator
from industrial_secure_transfer.core.packaging import StreamingPackager
from industrial_secure_transfer.core.safety import (
    FileCollisionError,
    SafetyViolationError,
    ensure_confined_directory_tree,
    generate_immutable_attempt_id,
)
from industrial_secure_transfer.core.state import (
    AppendOnlyJournal,
    ChunkCheckpoint,
    TransferState,
    TransferStateMachine,
    utc_now_iso,
)
from industrial_secure_transfer.transports.smb_transport import (
    SMBTransport,
    VerifiedServerReceipt,
)
from industrial_secure_transfer.transports.usb_transport import (
    DEFAULT_PROBE_SIZE_BYTES,
    USBTransport,
)


def _assert_no_cleanup_module_loaded() -> None:
    """
    SAF-03 Hard Runtime Assertion: Part A must never bundle or import `cleanup_gate`.
    Checks both the Part A module global namespace and, when running as a frozen PyInstaller
    Part A deliverable, `sys.modules`.
    """
    for sym_name in globals():
        if "cleanup_gate" in sym_name.lower() or "restrictedusbcleanupgate" in sym_name.lower():
            raise SafetyViolationError(
                "SAF-03 CRITICAL VIOLATION: USB cleanup symbol present in Part A Exporter module!"
            )
    if getattr(sys, "frozen", False):
        for mod_name in list(sys.modules.keys()):
            if "cleanup_gate" in mod_name:
                raise SafetyViolationError(
                    "SAF-03 CRITICAL VIOLATION: USB cleanup module is loaded in frozen Part A Exporter binary!"
                )


@dataclass(frozen=True)
class PartAExportOutcome:
    transfer_id: str
    attempt_id: str
    final_state: TransferState
    inventory: FrozenDatasetInventory
    signed_outer_manifest: Optional[Dict[str, Any]]
    manifest_sha256: Optional[str]
    verified_chunks_count: int
    verified_bytes: int
    server_receipt: Optional[VerifiedServerReceipt] = None


class PartAExporterRunner:
    """
    Orchestrates Part A export workflows (Option 1: Direct SMB, Option 2A: Single USB Export,
    plus returned USB receipt acknowledgment).
    """

    def __init__(
        self,
        *,
        config: MachineConfig,
        adapter: BaseOSAdapter,
        authenticator: LocalAuthenticator,
        sender_signing_private_key: ed25519.Ed25519PrivateKey,
        usb_mount_root: Optional[Union[str, Path]] = None,
        probe_size_bytes: int = DEFAULT_PROBE_SIZE_BYTES,
        enforce_32_64_mib_probe: bool = True,
    ) -> None:
        _assert_no_cleanup_module_loaded()
        if config.role != "PART_A_EXPORTER":
            raise SafetyViolationError(f"PartAExporterRunner requires role 'PART_A_EXPORTER', got '{config.role}'.")

        self._config = config
        self._adapter = adapter
        self._auth = authenticator
        self._sender_signing_key = sender_signing_private_key
        self._recipient_rsa_pub = load_rsa_public_key_pem(config.recipient_rsa_public_key_pem)
        self._trusted_server_keys = {
            k: load_ed25519_public_key_pem(v)
            for k, v in config.trusted_server_signing_keys_pem.items()
        }
        self._trusted_sender_keys = {
            k: load_ed25519_public_key_pem(v)
            for k, v in config.trusted_sender_public_keys_pem.items()
        }

        journal_base = Path(config.state_journal_dir)
        journal_base.parent.mkdir(parents=True, exist_ok=True)
        ensure_confined_directory_tree(journal_base.parent, journal_base.name)
        self._journal = AppendOnlyJournal(journal_base, config.machine_id)

        self._usb_mount_root = Path(usb_mount_root) if usb_mount_root is not None else None
        self._probe_size_bytes = probe_size_bytes
        self._enforce_32_64_mib_probe = enforce_32_64_mib_probe

        self._pause_requested = False
        self._stop_requested = False

    @property
    def journal(self) -> AppendOnlyJournal:
        return self._journal

    def request_pause(self) -> None:
        """Signals the runner to pause at the next verified chunk boundary (UI-05)."""
        self._pause_requested = True

    def request_stop_safely(self) -> None:
        """Signals the runner to stop safely at the next verified chunk boundary, retaining all files (UI-05)."""
        self._stop_requested = True

    def run_ui_preflight(self, job: JobConfig) -> list[Any]:
        """
        Executes real backend preflight checks (dataset discovery, disk space, SMB 3.1.1 / USB)
        and returns `PreflightCheckItem` records for the Desktop UI (`SCR-03` / `SCR-07`).
        """
        from industrial_secure_transfer.ui.desktop_app import PreflightCheckItem, PreflightItemStatus

        items: list[PreflightCheckItem] = []
        # 1. Source dataset discovery check
        try:
            ack_hashes = self._journal.get_acknowledged_file_hashes(self._config.machine_id)
            inv = discover_and_freeze_dataset(
                job.source_root,
                dataset_id=f"DS-{job.job_id}",
                discovery_mode=job.discovery_mode,
                require_completion_marker=job.require_completion_marker,
                completion_marker_filename=job.completion_marker_filename,
                stability_window_seconds=job.stability_window_seconds,
                acknowledged_hashes=ack_hashes,
            )
            items.append(
                PreflightCheckItem(
                    "SRC",
                    "Dataset / prior status",
                    PreflightItemStatus.PASSED,
                    True,
                    f"{inv.file_count} files ready ({inv.total_bytes} B) • {len(inv.deferred_files)} deferred",
                )
            )
            needed_bytes = int(inv.total_bytes * 1.15) + 64 * 1024 * 1024
        except Exception as exc:
            items.append(PreflightCheckItem("SRC", "Dataset / prior status", PreflightItemStatus.FAILED, True, str(exc)))
            needed_bytes = 64 * 1024 * 1024

        # 2. Local operational disk reserve check
        try:
            self._check_local_operational_disk_space()
            items.append(PreflightCheckItem("DISK", "Local operational reserve", PreflightItemStatus.PASSED, True, "Minimum free space verified"))
        except Exception as exc:
            items.append(PreflightCheckItem("DISK", "Local operational reserve", PreflightItemStatus.FAILED, True, str(exc)))

        # 3. Destination transport preflight (SMB or USB)
        if job.transfer_method.upper() == "SMB":
            try:
                if self._config.smb_endpoint is None:
                    raise SafetyViolationError("smb_endpoint missing in configuration")
                smb_tx = SMBTransport(self._adapter, self._config.smb_endpoint, self._trusted_server_keys)
                tel = smb_tx.run_preflight(required_free_bytes=needed_bytes)
                items.append(PreflightCheckItem("SMB", "Authentication / SMB", PreflightItemStatus.PASSED, True, f"SMB {tel.dialect} • encrypted={tel.encrypted}"))
            except Exception as exc:
                items.append(PreflightCheckItem("SMB", "Authentication / SMB", PreflightItemStatus.FAILED, True, str(exc)))
        elif job.transfer_method.upper() == "USB":
            try:
                if self._usb_mount_root is None:
                    raise SafetyViolationError("USB mount root not provided")
                usb_tx = USBTransport(
                    self._adapter,
                    self._usb_mount_root,
                    self._config.authorized_usb_devices,
                    trusted_sender_keys=self._trusted_sender_keys,
                    trusted_server_keys=self._trusted_server_keys,
                )
                rep = usb_tx.run_export_preflight(
                    expected_dataset_bytes=needed_bytes,
                    expected_sender_id=self._config.machine_id,
                    require_prior_receipt=job.require_prior_receipt_for_usb,
                    probe_size_bytes=self._probe_size_bytes,
                    enforce_32_64_mib_probe=self._enforce_32_64_mib_probe,
                )
                items.append(
                    PreflightCheckItem(
                        "USB_ID",
                        "Device / filesystem",
                        PreflightItemStatus.PASSED,
                        True,
                        f"{rep.telemetry.serial_number} • {rep.telemetry.filesystem} • dirty={rep.telemetry.is_dirty}",
                    )
                )
                smart_st = (
                    PreflightItemStatus.PASSED
                    if rep.telemetry.smart_health_status == "PASSED"
                    else PreflightItemStatus.UNAVAILABLE
                )
                items.append(PreflightCheckItem("SMART", "Hardware health", smart_st, False, rep.telemetry.smart_health_status))
                if rep.probe_result:
                    items.append(
                        PreflightCheckItem(
                            "PROBE",
                            "USB sample write/read-back",
                            PreflightItemStatus.PASSED,
                            True,
                            f"SHA-256 verified ({rep.probe_result.elapsed_seconds:.2f}s)",
                        )
                    )
            except Exception as exc:
                items.append(PreflightCheckItem("USB", "Authorized USB check", PreflightItemStatus.FAILED, True, str(exc)))

        return items

    def _check_local_operational_disk_space(self) -> None:
        free_b, _ = self._adapter.get_free_space_bytes(self._journal.root)
        if free_b < self._config.min_free_space_bytes:
            raise SafetyViolationError(
                f"PERF-01/SAF-01: Local operational disk free space ({free_b} bytes) is below "
                f"OEM minimum reserve ({self._config.min_free_space_bytes} bytes). Blocking export."
            )

    def acknowledge_returned_usb_receipts(self, session_id: str) -> Tuple[str, ...]:
        """
        When the single authorized USB returns from Part B with a signed `COMMITTED` receipt,
        Part A verifies the receipt on the USB and records `ACKNOWLEDGED` in its local journal,
        unlocking the next strict-mode USB export (Section 12 & Section 22.8).
        """
        _assert_no_cleanup_module_loaded()
        session = self._auth.validate_session(session_id)
        if self._usb_mount_root is None:
            raise SafetyViolationError("USB mount root is not configured for receipt acknowledgment.")

        usb_tx = USBTransport(
            self._adapter,
            self._usb_mount_root,
            self._config.authorized_usb_devices,
            trusted_sender_keys=self._trusted_sender_keys,
            trusted_server_keys=self._trusted_server_keys,
        )
        verified_ids = usb_tx.verify_returned_receipts_on_usb(self._config.machine_id)
        for tid in verified_ids:
            self._journal.append_record(
                "AUDIT_EVENT",
                transfer_id=tid,
                attempt_id="ACK-RECEIPT",
                operator=session.username,
                payload={"event": "USB_RECEIPT_ACKNOWLEDGED", "status": "ACKNOWLEDGED"},
            )
        return verified_ids

    def execute_export(
        self,
        session_id: str,
        job: JobConfig,
        *,
        transfer_id: Optional[str] = None,
        attempt_id: Optional[str] = None,
        resume_dek: Optional[bytes] = None,
        resume_nonce_prefix: Optional[bytes] = None,
        poll_for_smb_receipt: bool = True,
        receipt_timeout_seconds: float = 30.0,
        progress_callback: Optional[Callable[[ETASnapshot, str], None]] = None,
    ) -> PartAExportOutcome:
        """
        Executes a full or resumed Part A export job for `job`.
        """
        _assert_no_cleanup_module_loaded()
        session: OperatorSession = self._auth.validate_session(session_id)
        self._check_local_operational_disk_space()

        self._pause_requested = False
        self._stop_requested = False

        t_id = transfer_id or generate_immutable_attempt_id("TR")
        att_id = attempt_id or generate_immutable_attempt_id("ATT")

        sm = TransferStateMachine(
            self._journal,
            transfer_id=t_id,
            attempt_id=att_id,
            operator=session.username,
            initial_state=TransferState.READY,
        )
        sm.transition_to(TransferState.PREFLIGHT, reason=f"Starting preflight for job {job.job_id}")

        # 1. Discover and freeze dataset
        ack_hashes = self._journal.get_acknowledged_file_hashes(self._config.machine_id)
        inventory = discover_and_freeze_dataset(
            job.source_root,
            dataset_id=f"DS-{job.job_id}",
            discovery_mode=job.discovery_mode,
            require_completion_marker=job.require_completion_marker,
            completion_marker_filename=job.completion_marker_filename,
            stability_window_seconds=job.stability_window_seconds,
            acknowledged_hashes=ack_hashes,
        )

        self._journal.append_record(
            "AUDIT_EVENT",
            transfer_id=t_id,
            attempt_id=att_id,
            operator=session.username,
            payload={
                "deferred_count": len(inventory.deferred_files),
                "eligible_count": inventory.file_count,
                "event": "DATASET_FROZEN",
                "skipped_unchanged_count": len(inventory.skipped_unchanged_files),
                "total_bytes": inventory.total_bytes,
            },
        )

        # 2. Transport preflight (SMB or USB)
        smb_tx: Optional[SMBTransport] = None
        usb_tx: Optional[USBTransport] = None
        method = job.transfer_method.upper()

        if method == "SMB":
            if self._config.smb_endpoint is None:
                raise SafetyViolationError("SMB job selected, but smb_endpoint is missing in configuration.")
            smb_tx = SMBTransport(self._adapter, self._config.smb_endpoint, self._trusted_server_keys)
            smb_tx.run_preflight(required_free_bytes=int(inventory.total_bytes * 1.15) + 64 * 1024 * 1024)
        elif method == "USB":
            if self._usb_mount_root is None:
                raise SafetyViolationError("USB job selected, but usb_mount_root was not provided.")
            usb_tx = USBTransport(
                self._adapter,
                self._usb_mount_root,
                self._config.authorized_usb_devices,
                trusted_sender_keys=self._trusted_sender_keys,
                trusted_server_keys=self._trusted_server_keys,
            )
            usb_report = usb_tx.run_export_preflight(
                expected_dataset_bytes=inventory.total_bytes,
                expected_sender_id=self._config.machine_id,
                require_prior_receipt=job.require_prior_receipt_for_usb,
                probe_size_bytes=self._probe_size_bytes,
                enforce_32_64_mib_probe=self._enforce_32_64_mib_probe,
            )
            for ack_tid in usb_report.prior_receipts_verified:
                self._journal.append_record(
                    "AUDIT_EVENT",
                    transfer_id=ack_tid,
                    attempt_id=att_id,
                    operator=session.username,
                    payload={"event": "PRIOR_USB_RECEIPT_VERIFIED", "status": "ACKNOWLEDGED"},
                )
        else:
            raise SafetyViolationError(f"Unsupported transfer method: {method}")

        # 3. Reconcile any previously verified checkpoints for this transfer/attempt
        prior_checkpoints = self._journal.get_verified_chunks(t_id, att_id)
        skip_indices: Set[int] = set()
        existing_meta: Dict[int, Dict[str, Any]] = {}
        already_verified_bytes = 0

        for idx, cp in prior_checkpoints.items():
            # Confirm destination still holds the intact chunk before skipping (AWS DataSync-style delta resume)
            if method == "SMB" and smb_tx is not None:
                intact = smb_tx.check_existing_chunk_on_destination(
                    transfer_id=t_id,
                    attempt_id=att_id,
                    opaque_chunk_id=cp.opaque_chunk_id,
                    expected_cipher_size=cp.cipher_size,
                    expected_cipher_sha256=cp.cipher_sha256,
                )
            elif method == "USB" and usb_tx is not None:
                intact = usb_tx.check_existing_chunk_on_usb(
                    transfer_id=t_id,
                    attempt_id=att_id,
                    opaque_chunk_id=cp.opaque_chunk_id,
                    expected_cipher_size=cp.cipher_size,
                    expected_cipher_sha256=cp.cipher_sha256,
                )
            else:
                intact = False
            if intact:
                skip_indices.add(idx)
                existing_meta[idx] = {
                    "cipher_sha256": cp.cipher_sha256,
                    "cipher_size": cp.cipher_size,
                }
                already_verified_bytes += cp.plain_size

        # 4. Stream, compress, encrypt, write create-only, verify read-back, and checkpoint
        sm.transition_to(TransferState.TRANSFERRING, reason="Preflight passed; streaming encrypted chunks")
        eta_calc = RollingETACalculator(inventory.total_bytes)
        eta_calc.start()
        if already_verified_bytes > 0:
            eta_calc.record_verified_bytes(already_verified_bytes)

        packager = StreamingPackager(
            transfer_id=t_id,
            attempt_id=att_id,
            sender_id=self._config.machine_id,
            sender_signing_key_id=self._config.sender_signing_key_id,
            sender_signing_private_key=self._sender_signing_key,
            recipient_key_id=self._config.recipient_encryption_key_id,
            recipient_rsa_public_key=self._recipient_rsa_pub,
            inventory=inventory,
            chunk_size_bytes=job.chunk_size_bytes,
            dek=resume_dek,
            nonce_prefix=resume_nonce_prefix,
        )

        verified_chunks_count = len(skip_indices)
        verified_uncompressed_bytes = already_verified_bytes

        for file_entry, chunk in packager.stream_encrypted_chunks(
            skip_chunk_indices=skip_indices,
            existing_chunk_meta=existing_meta,
        ):
            self._auth.validate_session(session_id)

            try:
                if method == "SMB" and smb_tx is not None:
                    def _on_smb_drop(retry_num: int, err: Exception) -> None:
                        eta_calc.set_disconnected(True)
                        self._journal.append_record(
                            "AUDIT_EVENT",
                            transfer_id=t_id,
                            attempt_id=att_id,
                            operator=session.username,
                            payload={
                                "chunk_index": chunk.chunk_index,
                                "error": str(err),
                                "event": "SMB_TRANSIENT_DISCONNECT_RETRY",
                                "retry_attempt": retry_num,
                            },
                        )

                    smb_tx.write_and_verify_chunk_resilient(
                        transfer_id=t_id,
                        attempt_id=att_id,
                        chunk=chunk,
                        on_disconnect_callback=_on_smb_drop,
                    )
                    eta_calc.set_disconnected(False)
                elif method == "USB" and usb_tx is not None:
                    usb_tx.write_and_verify_chunk_on_usb(transfer_id=t_id, attempt_id=att_id, chunk=chunk)
            except FileCollisionError:
                # Never overwrite on collision: allocate a new immutable attempt ID and fail closed for retry
                sm.transition_to(
                    TransferState.INTERRUPTED,
                    reason=f"Create-only collision on chunk {chunk.opaque_chunk_id}; new attempt required.",
                )
                raise

            # Durable checkpoint ONLY after destination read-back verification succeeded
            cp = ChunkCheckpoint(
                transfer_id=t_id,
                attempt_id=att_id,
                package_id=chunk.package_id,
                chunk_index=chunk.chunk_index,
                opaque_chunk_id=chunk.opaque_chunk_id,
                cipher_size=chunk.cipher_size,
                cipher_sha256=chunk.cipher_sha256,
                plain_size=chunk.uncompressed_size,
                plain_sha256=chunk.plain_sha256,
                verified_at_utc=utc_now_iso(),
                operator=session.username,
            )
            self._journal.record_chunk_checkpoint(cp)
            verified_chunks_count += 1
            verified_uncompressed_bytes += chunk.uncompressed_size
            eta_calc.record_verified_bytes(chunk.uncompressed_size)

            if progress_callback is not None:
                progress_callback(eta_calc.snapshot(stage_completed=False), f"Verified {chunk.opaque_chunk_id}")

            # Check safe boundary pause/stop requests (UI-05)
            if self._stop_requested:
                sm.transition_to(TransferState.STOP_REQUESTED, reason="Operator requested Stop Safely")
                sm.transition_to(TransferState.STOPPED, reason="Stopped at verified chunk boundary; files retained")
                eta_calc.set_paused(True)
                return PartAExportOutcome(
                    transfer_id=t_id,
                    attempt_id=att_id,
                    final_state=sm.state,
                    inventory=inventory,
                    signed_outer_manifest=None,
                    manifest_sha256=None,
                    verified_chunks_count=verified_chunks_count,
                    verified_bytes=verified_uncompressed_bytes,
                )

            if self._pause_requested:
                sm.transition_to(TransferState.PAUSE_REQUESTED, reason="Operator requested Pause")
                sm.transition_to(TransferState.PAUSED, reason="Paused at verified chunk boundary")
                eta_calc.set_paused(True)
                return PartAExportOutcome(
                    transfer_id=t_id,
                    attempt_id=att_id,
                    final_state=sm.state,
                    inventory=inventory,
                    signed_outer_manifest=None,
                    manifest_sha256=None,
                    verified_chunks_count=verified_chunks_count,
                    verified_bytes=verified_uncompressed_bytes,
                )

        # 5. Build and publish signed outer manifest LAST
        signed_manifest = packager.build_signed_outer_manifest()

        if method == "USB" and usb_tx is not None:
            _, manifest_sha = usb_tx.publish_final_manifest_on_usb(
                transfer_id=t_id,
                attempt_id=att_id,
                signed_outer_manifest=signed_manifest,
            )
            sm.transition_to(
                TransferState.EXPORTED_TO_USB,
                reason="Encrypted payload and signed manifest verified on USB; awaiting server receipt",
            )
            if progress_callback is not None:
                progress_callback(eta_calc.snapshot(stage_completed=True), "EXPORTED_TO_USB")
            return PartAExportOutcome(
                transfer_id=t_id,
                attempt_id=att_id,
                final_state=sm.state,
                inventory=inventory,
                signed_outer_manifest=signed_manifest,
                manifest_sha256=manifest_sha,
                verified_chunks_count=verified_chunks_count,
                verified_bytes=verified_uncompressed_bytes,
            )

        # Direct SMB path
        assert smb_tx is not None
        _, manifest_sha = smb_tx.publish_final_manifest(
            transfer_id=t_id,
            attempt_id=att_id,
            signed_outer_manifest=signed_manifest,
        )

        receipt: Optional[VerifiedServerReceipt] = None
        if poll_for_smb_receipt:
            receipt = smb_tx.poll_for_receipt(
                transfer_id=t_id,
                sender_id=self._config.machine_id,
                expected_manifest_hash=manifest_sha,
                timeout_seconds=receipt_timeout_seconds,
                require_committed_status=True,
            )
            sm.transition_to(TransferState.COMMITTED, reason=f"Verified server receipt commitId={receipt.commit_id}")
            sm.transition_to(TransferState.ACKNOWLEDGED, reason="Source acknowledged signed COMMITTED receipt")
            self._journal.record_acknowledged_files(
                transfer_id=t_id,
                attempt_id=att_id,
                operator=session.username,
                device_id=self._config.machine_id,
                files_map={f.relative_path: f.sha256 for f in inventory.eligible_files},
            )
            if progress_callback is not None:
                progress_callback(eta_calc.snapshot(stage_completed=True), "COMMITTED")

        return PartAExportOutcome(
            transfer_id=t_id,
            attempt_id=att_id,
            final_state=sm.state,
            inventory=inventory,
            signed_outer_manifest=signed_manifest,
            manifest_sha256=manifest_sha,
            verified_chunks_count=verified_chunks_count,
            verified_bytes=verified_uncompressed_bytes,
            server_receipt=receipt,
        )


def main(argv: Optional[list[str]] = None) -> int:
    """
    Production CLI / Desktop UI Entrypoint for Part A — Exporter (Windows 10 Industrial PC).
    - DEP-02: Never triggered by USB Autorun; always launched manually by the operator.
    - DEP-01: Verifies the Ed25519 signature on `machine_config.signed.json` before opening the UI.
    - UI-01..UI-03: Launches the Tkinter Operator Login Screen (`SCR-01`). If exactly 1 job is configured,
      valid login automatically triggers preflight and starts the export once all mandatory checks pass.
    """
    import argparse
    from industrial_secure_transfer.adapters.base import get_current_os_adapter
    from industrial_secure_transfer.core.auth import AccountRecord, LocalAuthenticator
    from industrial_secure_transfer.core.config import load_signed_config_file
    from industrial_secure_transfer.core.crypto import (
        load_ed25519_private_key_pem,
        parse_strict_json,
    )
    from industrial_secure_transfer.core.safety import safe_readonly_open
    from industrial_secure_transfer.ui.desktop_app import (
        IndustrialTransferDesktopApp,
        OperatorUIController,
    )

    _assert_no_cleanup_module_loaded()

    parser = argparse.ArgumentParser(
        prog="IST_PartA_Exporter",
        description="Industrial Secure Data Transfer — Part A Exporter (Windows 10 Industrial PC)",
    )
    parser.add_argument("--config-dir", required=True, help="Directory holding signed configuration & key files")
    parser.add_argument("--config-file", default="machine_config.signed.json", help="Signed machine config filename")
    parser.add_argument("--provisioning-pubkey", default="provisioning_pub.pem", help="Provisioning Ed25519 public key")
    parser.add_argument("--sender-privkey", default="sender_signing_priv.pem", help="Sender Ed25519 signing private key")
    parser.add_argument("--accounts-file", default="accounts.json", help="Salted Argon2id operator accounts file")
    parser.add_argument("--usb-root", default=None, help="Authorized USB mount root (e.g. E:\\) for Option 2A")
    args = parser.parse_args(argv)

    cfg_dir = Path(args.config_dir).resolve()
    with safe_readonly_open(cfg_dir, args.provisioning_pubkey) as fh:
        prov_pub_pem = fh.read().decode("utf-8")
    with safe_readonly_open(cfg_dir, args.sender_privkey) as fh:
        sender_priv = load_ed25519_private_key_pem(fh.read().decode("utf-8"))
    with safe_readonly_open(cfg_dir, args.accounts_file) as fh:
        acc_raw = parse_strict_json(fh.read())

    config = load_signed_config_file(
        cfg_dir,
        args.config_file,
        prov_pub_pem,
        expected_role="PART_A_EXPORTER",
    )
    accounts = {
        u: AccountRecord(
            username=u,
            password_hash=str(info["password_hash"]),
            role=str(info.get("role", "OPERATOR")),
        )
        for u, info in acc_raw.get("accounts", {}).items()
    }
    auth = LocalAuthenticator(accounts)
    adapter = get_current_os_adapter()

    runner = PartAExporterRunner(
        config=config,
        adapter=adapter,
        authenticator=auth,
        sender_signing_private_key=sender_priv,
        usb_mount_root=args.usb_root,
    )

    def _preflight_fn(job: JobConfig) -> list[Any]:
        return runner.run_ui_preflight(job)

    def _worker_fn(session_id: str, job: JobConfig, ctrl: OperatorUIController) -> PartAExportOutcome:
        from industrial_secure_transfer.core.state import TransferState
        is_resuming = ctrl.vm.transfer_state in (TransferState.PAUSED, TransferState.STOPPED)
        t_id = ctrl.vm.transfer_id if (is_resuming and ctrl.vm.transfer_id) else generate_immutable_attempt_id("TR")
        att_id = ctrl.vm.attempt_id if (is_resuming and ctrl.vm.attempt_id) else generate_immutable_attempt_id("ATT")
        ctrl.post_worker_event("JOB_META", {"transfer_id": t_id, "attempt_id": att_id})
        return runner.execute_export(
            session_id,
            job,
            transfer_id=t_id,
            attempt_id=att_id,
            progress_callback=ctrl.post_progress_snapshot,
        )

    controller = OperatorUIController(
        config=config,
        authenticator=auth,
        journal=runner.journal,
        preflight_runner=_preflight_fn,
        transfer_worker_fn=_worker_fn,
        pause_fn=runner.request_pause,
        stop_fn=runner.request_stop_safely,
    )
    app = IndustrialTransferDesktopApp(controller)
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

