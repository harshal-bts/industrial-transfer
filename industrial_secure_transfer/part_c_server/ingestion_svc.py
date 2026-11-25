"""
part_c_server/ingestion_svc.py
Part C — Restricted Ingestion Server Service (Windows / Linux)
(Section 13, SRV-01, SRV-02, SRV-03):
- Watches `IndustrialIncoming` for final signed manifests (`manifest.signed.json`) and performs
  periodic reconciliation across all `<transferId>/<attemptId>/` directories (ignores partial uploads
  without a final manifest).
- Enforces server idempotency & deduplication (`senderId + transferId + manifestHash`):
  * Duplicate upload with identical manifestHash returns the exact same verified commit receipt (SRV-03).
  * Conflicting manifest with same transferId is quarantined.
- Validates sender Ed25519 signature over outer manifest BEFORE allocating decryption resources.
- Validates every chunk's existence, byte size, and ciphertext SHA-256, and rejects unknown extra files
  in the incoming attempt directory.
- Unwraps the per-transfer DEK using the server-only RSA-OAEP-SHA256 private key and decrypts ONLY inside
  an isolated quarantine directory (`quarantine_dir/<transferId>/<attemptId>/`) (SRV-01).
- Enforces bounded decompression quotas (`max_decompressed_package_bytes`, `max_compression_ratio`) to block
  decompression bombs.
- Reconstructs original files in quarantine using create-only writes ('xb'), verifies full-file SHA-256
  and geospatial shapefile companion completeness (`.shp/.shx/.dbf/.prj`), and invokes the pluggable
  Malware Scan Hook on the quarantined plaintext before any commit.
- Performs a durable, create-only immutable commit into `committed_repository_dir/<senderId>/<datasetId>/<commitId>/`
  and verifies every committed file's read-back SHA-256 before recording `COMMITTED` in the server journal.
- Signs and publishes the `COMMITTED` receipt to `IndustrialReceipts/<transferId>.receipt.json` ONLY after
  durable commit succeeds (SRV-02).
"""

from __future__ import annotations

import hashlib
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

_REPO_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
import industrial_secure_transfer  # noqa: E402,F401

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from industrial_secure_transfer.core.config import MachineConfig
from industrial_secure_transfer.core.crypto import (
    ChunkAAD,
    CryptoError,
    IntegrityVerificationError,
    canonical_json_bytes,
    compute_manifest_digest,
    decrypt_chunk_aes_gcm,
    load_ed25519_public_key_pem,
    parse_strict_json,
    sha256_hex,
    sha256_stream,
    sign_canonical_document,
    unwrap_dek_rsa_oaep,
)
from industrial_secure_transfer.core.discovery import (
    SHAPEFILE_REQUIRED_EXTENSIONS,
    _extract_shapefile_stem,
)
from industrial_secure_transfer.core.packaging import (
    DecompressionBombError,
    PackagingError,
    decompress_slice_bounded,
    decrypt_inner_manifest,
    verify_outer_manifest_envelope,
)
from industrial_secure_transfer.core.safety import (
    SafetyViolationError,
    create_only_open,
    create_only_write_bytes,
    detect_case_collisions,
    ensure_confined_directory_tree,
    safe_readonly_open,
    validate_confined_path,
    validate_relative_path,
)
from industrial_secure_transfer.core.state import (
    AppendOnlyJournal,
    TransferState,
    TransferStateMachine,
    utc_now_iso,
)
from industrial_secure_transfer.transports.smb_transport import RECEIPT_DOMAIN_SEPARATOR


class IngestionError(Exception):
    """Base exception when a transfer package fails server ingestion validation and is quarantined."""


@dataclass(frozen=True)
class MalwareScanResult:
    clean: bool
    scanner_name: str
    details: str = ""


# Type alias for pluggable malware scanner hook taking the isolated quarantine directory path
MalwareScanHook = Callable[[Path], MalwareScanResult]


def default_clean_malware_scan_hook(quarantine_attempt_dir: Path) -> MalwareScanResult:
    """
    Default built-in heuristic malware scan hook for lab/reference execution.
    Scans quarantined files for standard EICAR test signatures (assembled dynamically so
    host AV does not block the Python source file). Production deployments bind
    this hook to the enterprise EDR/AV CLI scanner.
    """
    import os
    eicar_marker = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}" + b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    ist_test_marker = b"IST-MALWARE-SIMULATION-PAYLOAD-V1"
    for dirpath, _, files in os.walk(quarantine_attempt_dir, followlinks=False):
        root = Path(dirpath)
        for fname in files:
            fpath = root / fname
            with open(fpath, "rb") as fh:
                content = fh.read(64 * 1024)
                if eicar_marker in content or ist_test_marker in content:
                    return MalwareScanResult(
                        clean=False,
                        scanner_name="IST-Quarantine-Scanner",
                        details=f"Malware signature detected in quarantined file '{fname}'",
                    )
    return MalwareScanResult(clean=True, scanner_name="IST-Quarantine-Scanner", details="No threats detected")


@dataclass(frozen=True)
class IngestionOutcome:
    transfer_id: str
    attempt_id: str
    sender_id: str
    manifest_hash: str
    status: str  # "COMMITTED" or "QUARANTINED"
    commit_id: Optional[str]
    files_verified: int
    total_bytes: int
    receipt_document: Optional[Dict[str, Any]]
    receipt_path: Optional[Path]
    failure_reason: Optional[str] = None


class IngestionServerService:
    """
    Part C Ingestion Server Service implementing manifest reconciliation, isolated quarantine
    decryption, decompression-bomb enforcement, malware scan hook, durable immutable commit,
    and Ed25519 receipt signing.
    """

    def __init__(
        self,
        *,
        config: MachineConfig,
        recipient_rsa_private_key: rsa.RSAPrivateKey,
        server_signing_private_key: ed25519.Ed25519PrivateKey,
        server_signing_key_id: str,
        malware_scan_hook: MalwareScanHook = default_clean_malware_scan_hook,
    ) -> None:
        if config.role != "PART_C_SERVER":
            raise SafetyViolationError(
                f"IngestionServerService requires role 'PART_C_SERVER', got '{config.role}'."
            )
        if not config.smb_endpoint or not config.quarantine_dir or not config.committed_repository_dir:
            raise SafetyViolationError(
                "Part C configuration requires smb_endpoint, quarantine_dir, and committed_repository_dir."
            )

        self._config = config
        self._rsa_priv_key = recipient_rsa_private_key
        self._server_signing_key = server_signing_private_key
        self._server_key_id = server_signing_key_id
        self._malware_hook = malware_scan_hook

        self._incoming_root = Path(config.smb_endpoint.incoming_share_path).resolve()
        self._receipt_root = Path(config.smb_endpoint.receipt_share_path).resolve()
        self._quarantine_root = Path(config.quarantine_dir).resolve()
        self._repository_root = Path(config.committed_repository_dir).resolve()

        # Verify quarantine and final repository are strictly distinct directories (SRV-01)
        if self._quarantine_root == self._repository_root:
            raise SafetyViolationError("SRV-01 Violation: quarantine_dir and committed_repository_dir must be isolated.")

        for d in (self._incoming_root, self._receipt_root, self._quarantine_root, self._repository_root):
            d.mkdir(parents=True, exist_ok=True)

        journal_base = Path(config.state_journal_dir)
        journal_base.parent.mkdir(parents=True, exist_ok=True)
        ensure_confined_directory_tree(journal_base.parent, journal_base.name)
        self._journal = AppendOnlyJournal(journal_base, config.machine_id)

        self._trusted_sender_keys = {
            k: load_ed25519_public_key_pem(v)
            for k, v in config.trusted_sender_public_keys_pem.items()
        }

        # Deduplication index loaded from journal: transferId -> (senderId, manifestHash, receipt_doc)
        self._committed_dedup: Dict[str, Tuple[str, str, Dict[str, Any]]] = {}
        self._quarantined_transfers: Set[str] = set()
        self._rebuild_dedup_index()

    @property
    def journal(self) -> AppendOnlyJournal:
        return self._journal

    def _rebuild_dedup_index(self) -> None:
        for rec in self._journal.records:
            if rec.record_type == "AUDIT_EVENT":
                ev = rec.payload.get("event")
                if ev == "SERVER_COMMIT_DURABLE":
                    t_id = rec.transfer_id
                    s_id = str(rec.payload["sender_id"])
                    m_hash = str(rec.payload["manifest_hash"])
                    r_doc = dict(rec.payload["receipt_document"])
                    self._committed_dedup[t_id] = (s_id, m_hash, r_doc)
                elif ev == "SERVER_TRANSFER_QUARANTINED":
                    self._quarantined_transfers.add(rec.transfer_id)

    def scan_and_reconcile_incoming(self) -> List[IngestionOutcome]:
        """
        Scans `IndustrialIncoming` for `<transferId>/<attemptId>/manifest.signed.json`.
        Ignores partial upload directories that do not yet have `manifest.signed.json` (Section 13 & 14).
        Processes every ready transfer package and returns outcomes.
        """
        outcomes: List[IngestionOutcome] = []
        if not self._incoming_root.exists():
            return outcomes

        for t_dir in sorted(self._incoming_root.iterdir(), key=lambda p: p.name):
            if not t_dir.is_dir():
                continue
            transfer_id = t_dir.name
            for att_dir in sorted(t_dir.iterdir(), key=lambda p: p.name):
                if not att_dir.is_dir():
                    continue
                attempt_id = att_dir.name
                manifest_file = att_dir / "manifest.signed.json"
                if not manifest_file.exists() or not manifest_file.is_file():
                    # Partial upload in progress; ignore until final signed manifest arrives
                    continue
                outcome = self.process_transfer_attempt(transfer_id=transfer_id, attempt_id=attempt_id)
                outcomes.append(outcome)
        return outcomes

    def process_transfer_attempt(self, *, transfer_id: str, attempt_id: str) -> IngestionOutcome:
        """
        Processes a single `<transferId>/<attemptId>` directory containing `manifest.signed.json`.
        Enforces SRV-01 (quarantine vs commit separation), SRV-02 (no receipt before durable commit),
        and SRV-03 (idempotent duplicate handling).
        """
        rel_attempt_dir = Path(transfer_id) / attempt_id
        rel_manifest = rel_attempt_dir / "manifest.signed.json"

        try:
            with safe_readonly_open(self._incoming_root, rel_manifest) as fh:
                manifest_raw = fh.read()
            outer_manifest = parse_strict_json(manifest_raw)
        except Exception as exc:
            return self._quarantine_transfer(
                transfer_id=transfer_id,
                attempt_id=attempt_id,
                sender_id="UNKNOWN",
                manifest_hash="INVALID",
                reason=f"Malformed outer manifest JSON: {exc}",
            )

        sender_id = str(outer_manifest.get("senderId", "UNKNOWN"))
        manifest_hash = compute_manifest_digest(outer_manifest)

        # SRV-03 Idempotency / Deduplication check
        if transfer_id in self._committed_dedup:
            prev_sender, prev_hash, prev_receipt = self._committed_dedup[transfer_id]
            if prev_sender == sender_id and prev_hash == manifest_hash:
                # Duplicate upload of identical committed transfer: return existing verified receipt (SRV-03)
                receipt_path = self._ensure_receipt_published(transfer_id, prev_receipt)
                return IngestionOutcome(
                    transfer_id=transfer_id,
                    attempt_id=attempt_id,
                    sender_id=sender_id,
                    manifest_hash=manifest_hash,
                    status="COMMITTED",
                    commit_id=str(prev_receipt["commitId"]),
                    files_verified=int(prev_receipt["filesVerified"]),
                    total_bytes=int(prev_receipt["totalBytes"]),
                    receipt_document=prev_receipt,
                    receipt_path=receipt_path,
                )
            else:
                # Conflicting manifest with existing committed transferId -> quarantine!
                return self._quarantine_transfer(
                    transfer_id=transfer_id,
                    attempt_id=attempt_id,
                    sender_id=sender_id,
                    manifest_hash=manifest_hash,
                    reason=f"Conflicting manifest hash for already-committed transferId '{transfer_id}'.",
                )

        sm = TransferStateMachine(
            self._journal,
            transfer_id=transfer_id,
            attempt_id=attempt_id,
            operator="PART_C_SERVICE",
            initial_state=TransferState.RECEIVED,
        )
        sm.transition_to(TransferState.VALIDATING, reason="Validating outer signature, chunks, and quarantine payload")

        try:
            # 1. Verify outer manifest schema and sender Ed25519 signature BEFORE trusting fields
            if outer_manifest.get("transferId") != transfer_id or outer_manifest.get("attemptId") != attempt_id:
                raise IngestionError("Outer manifest transferId/attemptId does not match incoming directory path.")
            verify_outer_manifest_envelope(outer_manifest, self._trusted_sender_keys)

            # 2. Validate every chunk in incoming attempt directory and reject unknown extra files
            attempt_abs = validate_confined_path(self._incoming_root, rel_attempt_dir, must_exist=True)
            expected_chunks_map: Dict[str, Dict[str, Any]] = {
                str(ch["opaqueChunkId"]): ch for ch in outer_manifest["chunks"]
            }

            actual_files = {p.name for p in attempt_abs.iterdir() if p.name != "manifest.signed.json"}
            expected_files = set(expected_chunks_map.keys())
            extra_files = actual_files - expected_files
            missing_files = expected_files - actual_files
            if extra_files:
                raise IngestionError(f"Unknown extra files in incoming directory rejected: {sorted(extra_files)}")
            if missing_files:
                raise IngestionError(f"Missing expected chunk files in incoming directory: {sorted(missing_files)}")

            # Verify ciphertext size and SHA-256 of every chunk before decryption
            chunk_blobs: Dict[int, bytes] = {}
            for cid, ch_meta in expected_chunks_map.items():
                c_idx = int(ch_meta["chunkIndex"])
                exp_sz = int(ch_meta["cipherSize"])
                exp_sha = str(ch_meta["cipherSHA256"])
                with safe_readonly_open(self._incoming_root, rel_attempt_dir / cid) as cfh:
                    blob = cfh.read()
                if len(blob) != exp_sz or sha256_hex(blob) != exp_sha:
                    raise IntegrityVerificationError(
                        f"Incoming chunk '{cid}' failed ciphertext hash or size verification."
                    )
                chunk_blobs[c_idx] = blob

            # 3. Unwrap per-transfer DEK with server RSA-OAEP-SHA256 private key and decrypt inner manifest
            dek = unwrap_dek_rsa_oaep(str(outer_manifest["wrappedKey"]), self._rsa_priv_key)
            inner_manifest = decrypt_inner_manifest(outer_manifest, dek)

            dataset_id = str(inner_manifest["datasetId"])
            expected_file_count = int(inner_manifest["fileCount"])
            expected_total_bytes = int(inner_manifest["totalBytes"])
            files_list = inner_manifest["files"]
            if not isinstance(files_list, list) or len(files_list) != expected_file_count:
                raise IngestionError("Inner manifest fileCount does not match files list length.")

            if expected_total_bytes > self._config.max_decompressed_package_bytes:
                raise DecompressionBombError(
                    f"Declared dataset totalBytes ({expected_total_bytes}) exceeds server quota "
                    f"({self._config.max_decompressed_package_bytes})."
                )

            # Validate all relative paths and check for case collisions before writing to quarantine
            all_rel_paths = [str(f["relativePath"]) for f in files_list]
            for rp in all_rel_paths:
                validate_relative_path(rp)
            detect_case_collisions(iter(all_rel_paths))

            # Verify geospatial shapefile companion completeness in inner manifest
            shp_groups: Dict[str, Set[str]] = {}
            for rp in all_rel_paths:
                stem, ext = _extract_shapefile_stem(rp)
                if stem is not None and ext is not None:
                    shp_groups.setdefault(stem, set()).add(ext)
            for stem, exts in shp_groups.items():
                missing_shp = SHAPEFILE_REQUIRED_EXTENSIONS - exts
                if missing_shp:
                    raise IngestionError(
                        f"Incomplete geospatial shapefile group '{stem}' in manifest (missing {sorted(missing_shp)})."
                    )

            # 4. Decrypt and decompress ONLY inside isolated quarantine directory (SRV-01)
            quarantine_attempt_rel = Path(transfer_id) / attempt_id
            quarantine_attempt_dir = ensure_confined_directory_tree(self._quarantine_root, quarantine_attempt_rel)

            cumulative_decompressed_bytes = 0
            reconstructed_files: List[Tuple[str, int, str]] = []  # (rel_path, size, sha256)

            for file_meta in files_list:
                rel_p = str(file_meta["relativePath"])
                exp_f_size = int(file_meta["size"])
                exp_f_sha = str(file_meta["sha256"])
                slices = file_meta["chunks"]

                file_hasher = hashlib.sha256()
                written_f_bytes = 0

                with create_only_open(quarantine_attempt_dir, rel_p, create_parents=True) as qfh:
                    for sl in slices:
                        c_idx = int(sl["index"])
                        pkg_id = str(sl["packageId"])
                        codec = str(sl["codec"])
                        plain_sz = int(sl["plainSize"])
                        uncomp_sz = int(sl["uncompressedSize"])
                        exp_slice_sha = str(sl["plainSHA256"])

                        if c_idx not in chunk_blobs:
                            raise IngestionError(f"Inner manifest references missing chunk index {c_idx}.")

                        cumulative_decompressed_bytes += uncomp_sz
                        if cumulative_decompressed_bytes > self._config.max_decompressed_package_bytes:
                            raise DecompressionBombError(
                                "Cumulative decompressed bytes exceeded server max_decompressed_package_bytes quota."
                            )

                        aad = ChunkAAD(
                            version=1,
                            transfer_id=transfer_id,
                            attempt_id=attempt_id,
                            package_id=pkg_id,
                            chunk_index=c_idx,
                            codec=codec,
                            plain_size=plain_sz,
                            uncompressed_size=uncomp_sz,
                        )
                        decrypted_payload = decrypt_chunk_aes_gcm(dek, chunk_blobs[c_idx], aad)
                        if len(decrypted_payload) != plain_sz:
                            raise IntegrityVerificationError(f"Decrypted payload size mismatch on chunk {c_idx}.")

                        raw_slice = decompress_slice_bounded(
                            decrypted_payload,
                            codec,
                            expected_uncompressed_size=uncomp_sz,
                            max_ratio=self._config.max_compression_ratio,
                        )
                        if sha256_hex(raw_slice) != exp_slice_sha:
                            raise IntegrityVerificationError(f"Plaintext slice SHA-256 mismatch on chunk {c_idx}.")

                        qfh.write(raw_slice)
                        file_hasher.update(raw_slice)
                        written_f_bytes += len(raw_slice)

                    qfh.flush()

                if written_f_bytes != exp_f_size or file_hasher.hexdigest() != exp_f_sha:
                    raise IntegrityVerificationError(
                        f"Quarantined file '{rel_p}' failed full-file SHA-256 or byte length verification."
                    )
                reconstructed_files.append((rel_p, exp_f_size, exp_f_sha))

            if cumulative_decompressed_bytes != expected_total_bytes:
                raise IngestionError(
                    f"Dataset totalBytes mismatch: expected {expected_total_bytes}, reconstructed {cumulative_decompressed_bytes}."
                )

            # 5. Invoke Malware Scan Hook on isolated quarantine directory BEFORE committing (Section 13)
            scan_res = self._malware_hook(quarantine_attempt_dir)
            if not scan_res.clean:
                raise IngestionError(
                    f"Malware scan blocked package ({scan_res.scanner_name}): {scan_res.details}"
                )

            # 6. Durable Immutable Commit to final repository (SRV-01, SRV-02)
            commit_id = f"CMT-{uuid.uuid4().hex[:16].upper()}"
            commit_base_rel = Path(sender_id) / dataset_id / commit_id
            commit_dir = ensure_confined_directory_tree(self._repository_root, commit_base_rel)

            for rel_p, exp_f_size, exp_f_sha in reconstructed_files:
                with safe_readonly_open(quarantine_attempt_dir, rel_p) as q_src:
                    data_bytes = q_src.read()
                create_only_write_bytes(commit_dir, rel_p, data_bytes, create_parents=True, fsync=True)

                # Read-back verification of committed file in final repository
                with safe_readonly_open(commit_dir, rel_p) as c_ver:
                    c_sha, c_sz = sha256_stream(c_ver)
                if c_sz != exp_f_size or c_sha != exp_f_sha:
                    raise IntegrityVerificationError(f"Durable commit verification failed for '{rel_p}'.")

            committed_at_utc = utc_now_iso()
            receipt_doc: Dict[str, Any] = {
                "attemptId": attempt_id,
                "commitId": commit_id,
                "committedAtUtc": committed_at_utc,
                "filesVerified": len(reconstructed_files),
                "manifestHash": manifest_hash,
                "senderId": sender_id,
                "serverKeyId": self._server_key_id,
                "status": "COMMITTED",
                "totalBytes": cumulative_decompressed_bytes,
                "transferId": transfer_id,
                "version": 1,
            }
            receipt_doc["signature"] = sign_canonical_document(
                receipt_doc,
                self._server_signing_key,
                domain_separator=RECEIPT_DOMAIN_SEPARATOR,
            )

            # Record durable commit in server journal BEFORE publishing receipt (SRV-02)
            sm.transition_to(TransferState.COMMITTED, reason=f"Durable commit completed: {commit_id}")
            self._journal.append_record(
                "AUDIT_EVENT",
                transfer_id=transfer_id,
                attempt_id=attempt_id,
                operator="PART_C_SERVICE",
                payload={
                    "commit_id": commit_id,
                    "event": "SERVER_COMMIT_DURABLE",
                    "files_verified": len(reconstructed_files),
                    "manifest_hash": manifest_hash,
                    "receipt_document": receipt_doc,
                    "sender_id": sender_id,
                    "total_bytes": cumulative_decompressed_bytes,
                },
            )
            self._committed_dedup[transfer_id] = (sender_id, manifest_hash, receipt_doc)

            # 7. Publish signed COMMITTED receipt to read-only receipt share
            receipt_path = self._ensure_receipt_published(transfer_id, receipt_doc)

            return IngestionOutcome(
                transfer_id=transfer_id,
                attempt_id=attempt_id,
                sender_id=sender_id,
                manifest_hash=manifest_hash,
                status="COMMITTED",
                commit_id=commit_id,
                files_verified=len(reconstructed_files),
                total_bytes=cumulative_decompressed_bytes,
                receipt_document=receipt_doc,
                receipt_path=receipt_path,
            )

        except (
            IngestionError,
            PackagingError,
            CryptoError,
            SafetyViolationError,
        ) as exc:
            return self._quarantine_transfer(
                transfer_id=transfer_id,
                attempt_id=attempt_id,
                sender_id=sender_id,
                manifest_hash=manifest_hash,
                reason=str(exc),
                state_machine=sm,
            )

    def _ensure_receipt_published(self, transfer_id: str, receipt_doc: Dict[str, Any]) -> Path:
        """
        Publishes `<transferId>.receipt.json` to `IndustrialReceipts` via create-only write ('xb'),
        or returns the existing receipt path if already published during an earlier run.
        """
        rel_receipt = Path(f"{transfer_id}.receipt.json")
        target = validate_confined_path(self._receipt_root, rel_receipt, must_exist=False)
        receipt_bytes = canonical_json_bytes(receipt_doc)
        expected_sha = sha256_hex(receipt_bytes)

        if target.exists():
            with safe_readonly_open(self._receipt_root, rel_receipt) as fh:
                existing_sha, _ = sha256_stream(fh)
            if existing_sha == expected_sha:
                return target
            raise SafetyViolationError(f"Conflicting receipt file already exists at '{target}'.")

        written = create_only_write_bytes(
            self._receipt_root,
            rel_receipt,
            receipt_bytes,
            create_parents=False,
            fsync=True,
        )
        return written

    def _quarantine_transfer(
        self,
        *,
        transfer_id: str,
        attempt_id: str,
        sender_id: str,
        manifest_hash: str,
        reason: str,
        state_machine: Optional[TransferStateMachine] = None,
    ) -> IngestionOutcome:
        """
        Transitions the transfer to `QUARANTINED`, logs the forensic reason in the append-only
        server journal, and NEVER issues a `COMMITTED` receipt (SRV-02).
        """
        if state_machine is not None and state_machine.state != TransferState.QUARANTINED:
            state_machine.transition_to(TransferState.QUARANTINED, reason=reason)
        else:
            self._journal.append_record(
                "STATE_TRANSITION",
                transfer_id=transfer_id,
                attempt_id=attempt_id,
                operator="PART_C_SERVICE",
                payload={"from_state": "RECEIVED", "reason": reason, "to_state": "QUARANTINED"},
            )

        self._journal.append_record(
            "AUDIT_EVENT",
            transfer_id=transfer_id,
            attempt_id=attempt_id,
            operator="PART_C_SERVICE",
            payload={
                "event": "SERVER_TRANSFER_QUARANTINED",
                "manifest_hash": manifest_hash,
                "reason": reason,
                "sender_id": sender_id,
            },
        )
        self._quarantined_transfers.add(transfer_id)

        return IngestionOutcome(
            transfer_id=transfer_id,
            attempt_id=attempt_id,
            sender_id=sender_id,
            manifest_hash=manifest_hash,
            status="QUARANTINED",
            commit_id=None,
            files_verified=0,
            total_bytes=0,
            receipt_document=None,
            receipt_path=None,
            failure_reason=reason,
        )

    def run_daemon_loop(
        self,
        *,
        poll_interval_seconds: float = 2.0,
        max_cycles: Optional[int] = None,
    ) -> None:
        """
        Continuous background service loop for Part C (Windows Service / Linux systemd daemon).
        Watches and reconciles `IndustrialIncoming` every `poll_interval_seconds` for completed
        `manifest.signed.json` envelopes.
        """
        import time
        cycles = 0
        while True:
            self.scan_and_reconcile_incoming()
            cycles += 1
            if max_cycles is not None and cycles >= max_cycles:
                break
            time.sleep(poll_interval_seconds)


def main(argv: Optional[List[str]] = None) -> int:
    """
    Production Daemon Entrypoint for Part C — Restricted Ingestion Server Service (Windows / Linux).
    Triggered automatically at server boot by Windows Service Control Manager (SCM) or Linux `systemd`.
    """
    import argparse
    from industrial_secure_transfer.core.config import load_signed_config_file
    from industrial_secure_transfer.core.crypto import (
        load_ed25519_private_key_pem,
        load_rsa_private_key_pem,
    )
    from industrial_secure_transfer.core.safety import safe_readonly_open

    parser = argparse.ArgumentParser(
        prog="IST_PartC_IngestionService",
        description="Industrial Secure Data Transfer — Part C Restricted Ingestion Server Service",
    )
    parser.add_argument("--config-dir", required=True, help="Directory holding signed configuration & server keys")
    parser.add_argument("--config-file", default="machine_config.signed.json", help="Signed machine config filename")
    parser.add_argument("--provisioning-pubkey", default="provisioning_pub.pem", help="Provisioning Ed25519 public key")
    parser.add_argument("--server-rsa-privkey", default="server_rsa_priv.pem", help="Server RSA-OAEP decryption private key")
    parser.add_argument("--server-signing-privkey", default="server_signing_priv.pem", help="Server Ed25519 receipt signing key")
    parser.add_argument("--server-signing-key-id", default="ING-SRV-SIGN-01", help="Server signing key ID")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Reconciliation interval in seconds")
    parser.add_argument("--once", action="store_true", help="Run a single reconciliation pass and exit")
    args = parser.parse_args(argv)

    cfg_dir = Path(args.config_dir).resolve()
    with safe_readonly_open(cfg_dir, args.provisioning_pubkey) as fh:
        prov_pub_pem = fh.read().decode("utf-8")
    with safe_readonly_open(cfg_dir, args.server_rsa_privkey) as fh:
        rsa_priv = load_rsa_private_key_pem(fh.read().decode("utf-8"))
    with safe_readonly_open(cfg_dir, args.server_signing_privkey) as fh:
        sign_priv = load_ed25519_private_key_pem(fh.read().decode("utf-8"))

    config = load_signed_config_file(
        cfg_dir,
        args.config_file,
        prov_pub_pem,
        expected_role="PART_C_SERVER",
    )

    service = IngestionServerService(
        config=config,
        recipient_rsa_private_key=rsa_priv,
        server_signing_private_key=sign_priv,
        server_signing_key_id=args.server_signing_key_id,
    )
    service.run_daemon_loop(
        poll_interval_seconds=args.poll_interval,
        max_cycles=1 if args.once else None,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

