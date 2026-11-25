"""
part_b_workstation/runner.py
Part B — Facility Transfer Workstation Orchestrator (Windows / Linux) (Section 12):
- Authenticates operator before any USB or SMB access (AUTH-01).
- Runs strictly read-only USB import preflight + SMB 3.1.1 session preflight.
- Reads and validates the source Ed25519 signature on `manifest.signed.json` and verifies all
  encrypted chunk SHA-256 digests on the authorized USB.
- Streams encrypted chunks directly from the USB to `IndustrialIncoming/<transferId>/<attemptId>/`
  over SMB using create-only writes ('xb') and immediate destination read-back hash verification
  (ZERO local payload staging, ZERO decryption private key).
- Publishes `manifest.signed.json` last to `IndustrialIncoming`.
- Polls `IndustrialReceipts` for the server's signed `COMMITTED` receipt, persists the receipt
  to `USB:\\Receipts\\<transferId>.receipt.json`, and invokes `RestrictedUSBCleanupGate` to
  remove only the acknowledged encrypted payload chunks and diagnostic probes from the USB.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set, Union

_REPO_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
import industrial_secure_transfer  # noqa: E402,F401

from industrial_secure_transfer.adapters.base import BaseOSAdapter
from industrial_secure_transfer.core.auth import LocalAuthenticator, OperatorSession
from industrial_secure_transfer.core.config import MachineConfig
from industrial_secure_transfer.core.crypto import load_ed25519_public_key_pem
from industrial_secure_transfer.core.eta import ETASnapshot, RollingETACalculator
from industrial_secure_transfer.core.packaging import EncryptedChunkItem
from industrial_secure_transfer.core.safety import (
    SafetyViolationError,
    ensure_confined_directory_tree,
    safe_readonly_open,
)
from industrial_secure_transfer.core.state import (
    AppendOnlyJournal,
    ChunkCheckpoint,
    TransferState,
    TransferStateMachine,
    utc_now_iso,
)
from industrial_secure_transfer.part_b_workstation.cleanup_gate import (
    CleanupExecutionReport,
    RestrictedUSBCleanupGate,
)
from industrial_secure_transfer.transports.smb_transport import (
    SMBTransport,
    VerifiedServerReceipt,
)
from industrial_secure_transfer.transports.usb_transport import USBTransport


@dataclass(frozen=True)
class PartBForwardOutcome:
    transfer_id: str
    attempt_id: str
    final_state: TransferState
    manifest_sha256: str
    forwarded_chunks_count: int
    forwarded_cipher_bytes: int
    server_receipt: Optional[VerifiedServerReceipt]
    usb_receipt_path: Optional[str]
    cleanup_report: Optional[CleanupExecutionReport]


class PartBWorkstationRunner:
    """
    Orchestrates Part B USB -> SMB forwarding, receipt persistence to USB,
    and controlled post-receipt USB cleanup.
    """

    def __init__(
        self,
        *,
        config: MachineConfig,
        adapter: BaseOSAdapter,
        authenticator: LocalAuthenticator,
        usb_mount_root: Union[str, Path],
    ) -> None:
        if config.role != "PART_B_WORKSTATION":
            raise SafetyViolationError(
                f"PartBWorkstationRunner requires role 'PART_B_WORKSTATION', got '{config.role}'."
            )
        if config.smb_endpoint is None:
            raise SafetyViolationError("Part B configuration requires an smb_endpoint.")

        self._config = config
        self._adapter = adapter
        self._auth = authenticator
        self._usb_root = Path(usb_mount_root)

        self._trusted_sender_keys = {
            k: load_ed25519_public_key_pem(v)
            for k, v in config.trusted_sender_public_keys_pem.items()
        }
        self._trusted_server_keys = {
            k: load_ed25519_public_key_pem(v)
            for k, v in config.trusted_server_signing_keys_pem.items()
        }

        journal_base = Path(config.state_journal_dir)
        journal_base.parent.mkdir(parents=True, exist_ok=True)
        ensure_confined_directory_tree(journal_base.parent, journal_base.name)
        self._journal = AppendOnlyJournal(journal_base, config.machine_id)

        self._usb_tx = USBTransport(
            self._adapter,
            self._usb_root,
            self._config.authorized_usb_devices,
            trusted_sender_keys=self._trusted_sender_keys,
            trusted_server_keys=self._trusted_server_keys,
        )
        self._smb_tx = SMBTransport(
            self._adapter,
            self._config.smb_endpoint,
            self._trusted_server_keys,
        )
        self._cleanup_gate = RestrictedUSBCleanupGate(
            adapter=self._adapter,
            authorized_usb_devices=self._config.authorized_usb_devices,
            trusted_sender_keys=self._trusted_sender_keys,
            trusted_server_keys=self._trusted_server_keys,
        )

        self._pause_requested = False
        self._stop_requested = False

    @property
    def journal(self) -> AppendOnlyJournal:
        return self._journal

    def discover_pending_usb_transfers(self) -> list[tuple[str, str]]:
        """Scans `USB:\\Transfers\\<transferId>\\<attemptId>\\manifest.signed.json` for pending packages."""
        found: list[tuple[str, str]] = []
        transfers_dir = self._usb_root / "Transfers"
        if not transfers_dir.exists():
            return found
        for t_dir in sorted(transfers_dir.iterdir()):
            if not t_dir.is_dir():
                continue
            for att_dir in sorted(t_dir.iterdir()):
                if att_dir.is_dir() and (att_dir / "manifest.signed.json").is_file():
                    found.append((t_dir.name, att_dir.name))
        return found

    def run_ui_preflight(self) -> list[Any]:
        """Executes Part B read-only USB + SMB 3.1.1 preflight checks for `SCR-10`."""
        from industrial_secure_transfer.ui.desktop_app import PreflightCheckItem, PreflightItemStatus

        items: list[PreflightCheckItem] = []
        try:
            rep = self._usb_tx.run_import_preflight()
            items.append(
                PreflightCheckItem(
                    "USB_RO",
                    "Physical USB / filesystem",
                    PreflightItemStatus.PASSED,
                    True,
                    f"{rep.telemetry.serial_number} • read-only check passed",
                )
            )
        except Exception as exc:
            items.append(PreflightCheckItem("USB_RO", "Physical USB / filesystem", PreflightItemStatus.FAILED, True, str(exc)))

        pending = self.discover_pending_usb_transfers()
        if pending:
            t_id, a_id = pending[0]
            try:
                manifest, _ = self._usb_tx.read_and_validate_usb_package(transfer_id=t_id, attempt_id=a_id)
                items.append(
                    PreflightCheckItem(
                        "SIG",
                        "Signed package inventory",
                        PreflightItemStatus.PASSED,
                        True,
                        f"{t_id} ({len(manifest.get('chunks', []))} chunks) • Ed25519 valid",
                    )
                )
            except Exception as exc:
                items.append(PreflightCheckItem("SIG", "Signed package inventory", PreflightItemStatus.FAILED, True, str(exc)))
        else:
            items.append(PreflightCheckItem("SIG", "Signed package inventory", PreflightItemStatus.FAILED, True, "No signed package found on USB"))

        try:
            tel = self._smb_tx.run_preflight()
            items.append(PreflightCheckItem("SMB", "Server / network", PreflightItemStatus.PASSED, True, f"SMB {tel.dialect} • encrypted={tel.encrypted}"))
        except Exception as exc:
            items.append(PreflightCheckItem("SMB", "Server / network", PreflightItemStatus.FAILED, True, str(exc)))

        return items

    def request_pause(self) -> None:
        self._pause_requested = True

    def request_stop_safely(self) -> None:
        self._stop_requested = True

    def execute_usb_to_smb_transfer(
        self,
        session_id: str,
        *,
        transfer_id: str,
        attempt_id: str,
        run_cleanup_after_receipt: bool = True,
        receipt_timeout_seconds: float = 30.0,
        progress_callback: Optional[Callable[[ETASnapshot, str], None]] = None,
    ) -> PartBForwardOutcome:
        """
        Executes Option 2B workflow:
        Authenticate -> Read-Only USB Preflight + SMB Preflight -> Validate Signed USB Envelope
        -> Direct USB-to-SMB Encrypted Chunk Stream + Read-Back Verification -> Publish Manifest Last
        -> Poll Signed COMMITTED Receipt -> Persist Receipt on USB -> Controlled USB Cleanup Gate.
        """
        session: OperatorSession = self._auth.validate_session(session_id)
        self._pause_requested = False
        self._stop_requested = False

        sm = TransferStateMachine(
            self._journal,
            transfer_id=transfer_id,
            attempt_id=attempt_id,
            operator=session.username,
            initial_state=TransferState.READY,
        )
        sm.transition_to(TransferState.PREFLIGHT, reason="Running Part B read-only USB and SMB preflight")

        # 1. Read-only USB preflight
        self._usb_tx.run_import_preflight()

        # 2. Read and cryptographically validate outer manifest and encrypted chunks on USB
        outer_manifest, manifest_sha256 = self._usb_tx.read_and_validate_usb_package(
            transfer_id=transfer_id,
            attempt_id=attempt_id,
        )
        sender_id = str(outer_manifest["senderId"])
        chunks_meta = outer_manifest["chunks"]
        total_cipher_bytes = sum(int(c["cipherSize"]) for c in chunks_meta)

        # 3. SMB preflight
        self._smb_tx.run_preflight(required_free_bytes=int(total_cipher_bytes * 1.1) + 32 * 1024 * 1024)

        # 4. Reconcile any chunks already forwarded and verified on SMB
        prior_cps = self._journal.get_verified_chunks(transfer_id, attempt_id)
        skip_indices: Set[int] = set()
        already_forwarded_bytes = 0

        for idx, cp in prior_cps.items():
            if self._smb_tx.check_existing_chunk_on_destination(
                transfer_id=transfer_id,
                attempt_id=attempt_id,
                opaque_chunk_id=cp.opaque_chunk_id,
                expected_cipher_size=cp.cipher_size,
                expected_cipher_sha256=cp.cipher_sha256,
            ):
                skip_indices.add(idx)
                already_forwarded_bytes += cp.cipher_size

        sm.transition_to(TransferState.TRANSFERRING, reason="Streaming encrypted chunks directly from USB to SMB")
        eta_calc = RollingETACalculator(total_cipher_bytes)
        eta_calc.start()
        if already_forwarded_bytes > 0:
            eta_calc.record_verified_bytes(already_forwarded_bytes)

        forwarded_count = len(skip_indices)
        forwarded_bytes = already_forwarded_bytes

        for ch_meta in chunks_meta:
            self._auth.validate_session(session_id)
            c_idx = int(ch_meta["chunkIndex"])
            if c_idx in skip_indices:
                continue

            cid = str(ch_meta["opaqueChunkId"])
            c_size = int(ch_meta["cipherSize"])
            c_sha = str(ch_meta["cipherSHA256"])
            pkg_id = str(ch_meta["packageId"])

            # Read encrypted chunk directly from USB into bounded memory (never staged to local disk!)
            rel_usb_chunk = Path("Transfers") / transfer_id / attempt_id / cid
            with safe_readonly_open(self._usb_root, rel_usb_chunk) as ufh:
                cipher_bytes = ufh.read()

            chunk_item = EncryptedChunkItem(
                package_id=pkg_id,
                chunk_index=c_idx,
                opaque_chunk_id=cid,
                codec="encrypted",
                uncompressed_size=c_size,
                plain_size=c_size,
                plain_sha256=c_sha,
                cipher_bytes=cipher_bytes,
                cipher_size=c_size,
                cipher_sha256=c_sha,
            )

            def _on_smb_drop(retry_num: int, err: Exception) -> None:
                eta_calc.set_disconnected(True)
                self._journal.append_record(
                    "AUDIT_EVENT",
                    transfer_id=transfer_id,
                    attempt_id=attempt_id,
                    operator=session.username,
                    payload={
                        "chunk_index": c_idx,
                        "error": str(err),
                        "event": "PART_B_SMB_DISCONNECT_RETRY",
                        "retry_attempt": retry_num,
                    },
                )

            self._smb_tx.write_and_verify_chunk_resilient(
                transfer_id=transfer_id,
                attempt_id=attempt_id,
                chunk=chunk_item,
                on_disconnect_callback=_on_smb_drop,
            )
            eta_calc.set_disconnected(False)

            cp = ChunkCheckpoint(
                transfer_id=transfer_id,
                attempt_id=attempt_id,
                package_id=pkg_id,
                chunk_index=c_idx,
                opaque_chunk_id=cid,
                cipher_size=c_size,
                cipher_sha256=c_sha,
                plain_size=c_size,
                plain_sha256=c_sha,
                verified_at_utc=utc_now_iso(),
                operator=session.username,
            )
            self._journal.record_chunk_checkpoint(cp)
            forwarded_count += 1
            forwarded_bytes += c_size
            eta_calc.record_verified_bytes(c_size)

            if progress_callback is not None:
                progress_callback(eta_calc.snapshot(stage_completed=False), f"Forwarded {cid} to SMB")

            if self._stop_requested:
                sm.transition_to(TransferState.STOP_REQUESTED, reason="Operator requested Stop Safely")
                sm.transition_to(TransferState.STOPPED, reason="Stopped at verified chunk boundary")
                eta_calc.set_paused(True)
                return PartBForwardOutcome(
                    transfer_id=transfer_id,
                    attempt_id=attempt_id,
                    final_state=sm.state,
                    manifest_sha256=manifest_sha256,
                    forwarded_chunks_count=forwarded_count,
                    forwarded_cipher_bytes=forwarded_bytes,
                    server_receipt=None,
                    usb_receipt_path=None,
                    cleanup_report=None,
                )

            if self._pause_requested:
                sm.transition_to(TransferState.PAUSE_REQUESTED, reason="Operator requested Pause")
                sm.transition_to(TransferState.PAUSED, reason="Paused at verified chunk boundary")
                eta_calc.set_paused(True)
                return PartBForwardOutcome(
                    transfer_id=transfer_id,
                    attempt_id=attempt_id,
                    final_state=sm.state,
                    manifest_sha256=manifest_sha256,
                    forwarded_chunks_count=forwarded_count,
                    forwarded_cipher_bytes=forwarded_bytes,
                    server_receipt=None,
                    usb_receipt_path=None,
                    cleanup_report=None,
                )

        # 5. Publish signed outer manifest LAST to SMB
        self._smb_tx.publish_final_manifest(
            transfer_id=transfer_id,
            attempt_id=attempt_id,
            signed_outer_manifest=outer_manifest,
        )

        # 6. Poll read-only receipt share for signed COMMITTED receipt
        receipt = self._smb_tx.poll_for_receipt(
            transfer_id=transfer_id,
            sender_id=sender_id,
            expected_manifest_hash=manifest_sha256,
            timeout_seconds=receipt_timeout_seconds,
            require_committed_status=True,
        )
        sm.transition_to(TransferState.COMMITTED, reason=f"Verified server COMMITTED receipt {receipt.commit_id}")

        # 7. Persist signed COMMITTED receipt to the same USB
        usb_receipt_file = self._usb_tx.persist_verified_receipt_to_usb(receipt)
        self._journal.append_record(
            "AUDIT_EVENT",
            transfer_id=transfer_id,
            attempt_id=attempt_id,
            operator=session.username,
            payload={
                "commit_id": receipt.commit_id,
                "event": "RECEIPT_PERSISTED_TO_USB",
                "usb_receipt_path": usb_receipt_file.name,
            },
        )

        # 8. Run isolated USB cleanup gate if requested
        cleanup_rep: Optional[CleanupExecutionReport] = None
        if run_cleanup_after_receipt:
            cleanup_rep = self._cleanup_gate.execute_authorized_cleanup(
                usb_mount_root=self._usb_root,
                transfer_id=transfer_id,
                attempt_id=attempt_id,
            )
            sm.transition_to(
                TransferState.USB_CLEANED,
                reason=(
                    f"Cleaned {len(cleanup_rep.deleted_payload_files)} payload files and "
                    f"{len(cleanup_rep.deleted_probe_files)} probe files on USB {cleanup_rep.usb_serial_number}"
                ),
            )

        if progress_callback is not None:
            progress_callback(eta_calc.snapshot(stage_completed=True), sm.state.value)

        return PartBForwardOutcome(
            transfer_id=transfer_id,
            attempt_id=attempt_id,
            final_state=sm.state,
            manifest_sha256=manifest_sha256,
            forwarded_chunks_count=forwarded_count,
            forwarded_cipher_bytes=forwarded_bytes,
            server_receipt=receipt,
            usb_receipt_path=str(usb_receipt_file),
            cleanup_report=cleanup_rep,
        )


def main(argv: Optional[list[str]] = None) -> int:
    """
    Production CLI / Desktop UI Entrypoint for Part B — Facility Transfer Workstation (Windows / Linux).
    - Always launched from the locally installed protected directory (never executed off the USB).
    - Verifies signed machine config (`DEP-01`), opens the Operator Login UI (`SCR-01`),
      and forwards encrypted USB packages to SMB -> polls COMMITTED receipt -> persists receipt to USB
      -> executes the isolated `RestrictedUSBCleanupGate`.
    """
    import argparse
    from industrial_secure_transfer.adapters.base import get_current_os_adapter
    from industrial_secure_transfer.core.auth import AccountRecord, LocalAuthenticator
    from industrial_secure_transfer.core.config import JobConfig, load_signed_config_file
    from industrial_secure_transfer.core.crypto import parse_strict_json
    from industrial_secure_transfer.core.safety import safe_readonly_open
    from industrial_secure_transfer.ui.desktop_app import (
        IndustrialTransferDesktopApp,
        OperatorUIController,
    )

    parser = argparse.ArgumentParser(
        prog="IST_PartB_Workstation",
        description="Industrial Secure Data Transfer — Part B Transfer Workstation (USB -> SMB -> Receipt -> Cleanup)",
    )
    parser.add_argument("--config-dir", required=True, help="Directory holding signed configuration & key files")
    parser.add_argument("--config-file", default="machine_config.signed.json", help="Signed machine config filename")
    parser.add_argument("--provisioning-pubkey", default="provisioning_pub.pem", help="Provisioning Ed25519 public key")
    parser.add_argument("--accounts-file", default="accounts.json", help="Salted Argon2id operator accounts file")
    parser.add_argument("--usb-root", required=True, help="Authorized USB mount root (e.g. E:\\ or /mnt/usb003)")
    parser.add_argument("--transfer-id", default=None, help="Specific transferId on USB to forward")
    parser.add_argument("--attempt-id", default=None, help="Specific attemptId on USB to forward")
    args = parser.parse_args(argv)

    cfg_dir = Path(args.config_dir).resolve()
    with safe_readonly_open(cfg_dir, args.provisioning_pubkey) as fh:
        prov_pub_pem = fh.read().decode("utf-8")
    with safe_readonly_open(cfg_dir, args.accounts_file) as fh:
        acc_raw = parse_strict_json(fh.read())

    config = load_signed_config_file(
        cfg_dir,
        args.config_file,
        prov_pub_pem,
        expected_role="PART_B_WORKSTATION",
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

    runner = PartBWorkstationRunner(
        config=config,
        adapter=adapter,
        authenticator=auth,
        usb_mount_root=args.usb_root,
    )

    def _preflight_fn(_job: JobConfig) -> list[Any]:
        return runner.run_ui_preflight()

    def _worker_fn(session_id: str, _job: JobConfig, ctrl: OperatorUIController) -> PartBForwardOutcome:
        pending = runner.discover_pending_usb_transfers()
        t_id = args.transfer_id or (pending[0][0] if pending else "TR-AUTO")
        a_id = args.attempt_id or (pending[0][1] if pending else "ATT-0001")
        ctrl.post_worker_event("JOB_META", {"transfer_id": t_id, "attempt_id": a_id})
        return runner.execute_usb_to_smb_transfer(
            session_id,
            transfer_id=t_id,
            attempt_id=a_id,
            run_cleanup_after_receipt=True,
            progress_callback=ctrl.post_progress_snapshot,
        )

    def _cleanup_fn(transfer_id: str, attempt_id: str) -> CleanupExecutionReport:
        return runner._cleanup_gate.execute_authorized_cleanup(
            usb_mount_root=args.usb_root,
            transfer_id=transfer_id,
            attempt_id=attempt_id,
        )

    controller = OperatorUIController(
        config=config,
        authenticator=auth,
        journal=runner.journal,
        preflight_runner=_preflight_fn,
        transfer_worker_fn=_worker_fn,
        pause_fn=runner.request_pause,
        stop_fn=runner.request_stop_safely,
        cleanup_fn=_cleanup_fn,
    )
    app = IndustrialTransferDesktopApp(controller)
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

