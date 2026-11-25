"""
transports/smb_transport.py
Create-only SMB streaming transport & read-only receipt share poller
(Section 5, Section 13, Section 14, Section 18):
- Enforces OS adapter SMB 3.1.1 session verification before writing and after any reconnect.
- Writes encrypted chunks via exclusive create-only (`xb`) under `IndustrialIncoming/<transferId>/<attemptId>/`.
- Immediately re-opens and reads back every written chunk to verify its destination SHA-256 and byte length
  before returning success or allowing a checkpoint to be persisted.
- On FileCollisionError, allocates a new immutable attempt ID (or fails closed for caller retry) — never overwrites.
- Publishes the signed outer manifest (`manifest.signed.json`) LAST, only after all chunks are verified on the share.
- Polls `IndustrialReceipts` in read-only mode and verifies the server's Ed25519 signature, transfer ID,
  sender ID, manifest SHA-256 digest, and `COMMITTED` status.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import ed25519

from industrial_secure_transfer.adapters.base import BaseOSAdapter, SMBSessionTelemetry
from industrial_secure_transfer.core.config import SMBEndpointConfig
from industrial_secure_transfer.core.crypto import (
    IntegrityVerificationError,
    SignatureVerificationError,
    canonical_json_bytes,
    parse_strict_json,
    sha256_hex,
    sha256_stream,
    verify_canonical_document,
)
from industrial_secure_transfer.core.packaging import EncryptedChunkItem
from industrial_secure_transfer.core.safety import (
    FileCollisionError,
    create_only_write_bytes,
    generate_immutable_attempt_id,
    safe_readonly_open,
    validate_confined_path,
)

RECEIPT_DOMAIN_SEPARATOR = "IST-SERVER-RECEIPT-V1"
DEFAULT_RETRY_BACKOFF_SECONDS: Tuple[float, ...] = (2.0, 5.0, 10.0)


class SMBTransportError(Exception):
    """Raised when an SMB transport write, read-back verification, or receipt validation fails."""


@dataclass(frozen=True)
class VerifiedServerReceipt:
    version: int
    transfer_id: str
    attempt_id: str
    sender_id: str
    manifest_hash: str
    status: str  # "COMMITTED" or "QUARANTINED"
    files_verified: int
    total_bytes: int
    commit_id: str
    committed_at_utc: str
    server_key_id: str
    signature: str
    raw_document: Dict[str, Any]


def verify_server_receipt_document(
    receipt_doc: Dict[str, Any],
    trusted_server_keys: Dict[str, ed25519.Ed25519PublicKey],
    *,
    expected_transfer_id: str,
    expected_sender_id: str,
    expected_manifest_hash: str,
    require_committed_status: bool = True,
) -> VerifiedServerReceipt:
    """
    Cryptographically verifies a server receipt against `trusted_server_keys` and checks all bindings:
    version, serverKeyId signature, transferId, senderId, manifestHash, and COMMITTED status.
    """
    if receipt_doc.get("version") != 1:
        raise SMBTransportError(f"Unsupported receipt version: {receipt_doc.get('version')}")

    server_key_id = str(receipt_doc.get("serverKeyId", ""))
    if server_key_id not in trusted_server_keys:
        raise SMBTransportError(f"Receipt signed by untrusted serverKeyId '{server_key_id}'.")

    pub_key = trusted_server_keys[server_key_id]
    try:
        verify_canonical_document(
            receipt_doc,
            pub_key,
            domain_separator=RECEIPT_DOMAIN_SEPARATOR,
        )
    except SignatureVerificationError as exc:
        raise SMBTransportError(f"Server receipt signature verification failed: {exc}") from exc

    t_id = str(receipt_doc.get("transferId", ""))
    s_id = str(receipt_doc.get("senderId", ""))
    m_hash = str(receipt_doc.get("manifestHash", ""))
    status = str(receipt_doc.get("status", ""))

    if t_id != expected_transfer_id:
        raise SMBTransportError(f"Receipt transferId mismatch: expected '{expected_transfer_id}', got '{t_id}'.")
    if s_id != expected_sender_id:
        raise SMBTransportError(f"Receipt senderId mismatch: expected '{expected_sender_id}', got '{s_id}'.")
    if m_hash != expected_manifest_hash:
        raise SMBTransportError(
            f"Receipt manifestHash mismatch: expected '{expected_manifest_hash}', got '{m_hash}'."
        )
    if require_committed_status and status != "COMMITTED":
        raise SMBTransportError(
            f"Server receipt status is '{status}' (not COMMITTED). Cleanup and completion are blocked."
        )

    return VerifiedServerReceipt(
        version=1,
        transfer_id=t_id,
        attempt_id=str(receipt_doc.get("attemptId", "")),
        sender_id=s_id,
        manifest_hash=m_hash,
        status=status,
        files_verified=int(receipt_doc.get("filesVerified", 0)),
        total_bytes=int(receipt_doc.get("totalBytes", 0)),
        commit_id=str(receipt_doc.get("commitId", "")),
        committed_at_utc=str(receipt_doc.get("committedAtUtc", "")),
        server_key_id=server_key_id,
        signature=str(receipt_doc["signature"]),
        raw_document=dict(receipt_doc),
    )


class SMBTransport:
    """
    Handles create-only encrypted chunk streaming and read-back verification to `IndustrialIncoming`
    and read-only receipt retrieval from `IndustrialReceipts`.
    """

    def __init__(
        self,
        adapter: BaseOSAdapter,
        endpoint: SMBEndpointConfig,
        trusted_server_keys: Dict[str, ed25519.Ed25519PublicKey],
    ) -> None:
        self._adapter = adapter
        self._endpoint = endpoint
        self._trusted_server_keys = dict(trusted_server_keys)

    @property
    def incoming_root(self) -> Path:
        return Path(self._endpoint.incoming_share_path)

    @property
    def receipt_root(self) -> Path:
        return Path(self._endpoint.receipt_share_path)

    def run_preflight(self, *, required_free_bytes: int = 0) -> SMBSessionTelemetry:
        """
        Verifies both `IndustrialIncoming` and `IndustrialReceipts` over SMB 3.1.1.
        """
        telemetry = self._adapter.validate_smb_policy(
            self._endpoint,
            self.incoming_root,
            required_free_bytes=required_free_bytes,
        )
        # Also verify receipt share is accessible
        self._adapter.validate_smb_policy(
            self._endpoint,
            self.receipt_root,
            required_free_bytes=0,
        )
        return telemetry

    def check_existing_chunk_on_destination(
        self,
        *,
        transfer_id: str,
        attempt_id: str,
        opaque_chunk_id: str,
        expected_cipher_size: int,
        expected_cipher_sha256: str,
    ) -> bool:
        """
        Used during checkpoint recovery (Section 14): checks whether an intact, hash-verified
        chunk already exists on the destination share for `(transfer_id, attempt_id)`.
        """
        rel_chunk = Path(transfer_id) / attempt_id / opaque_chunk_id
        try:
            target = validate_confined_path(self.incoming_root, rel_chunk, must_exist=True)
            if not target.is_file():
                return False
            with safe_readonly_open(self.incoming_root, rel_chunk) as fh:
                digest, size = sha256_stream(fh)
            return size == expected_cipher_size and digest == expected_cipher_sha256
        except Exception:
            return False

    def write_and_verify_chunk(
        self,
        *,
        transfer_id: str,
        attempt_id: str,
        chunk: EncryptedChunkItem,
    ) -> Path:
        """
        Streams an encrypted chunk to `IndustrialIncoming/<transferId>/<attemptId>/<opaqueChunkId>`
        using exclusive creation (`xb`), flushes/fsyncs, and immediately re-opens to verify
        the destination SHA-256 and size match `chunk.cipher_sha256` and `chunk.cipher_size`.
        """
        rel_chunk = Path(transfer_id) / attempt_id / chunk.opaque_chunk_id
        written_path = create_only_write_bytes(
            self.incoming_root,
            rel_chunk,
            chunk.cipher_bytes,
            create_parents=True,
            fsync=True,
        )

        # Read-back verification from destination share
        with safe_readonly_open(self.incoming_root, rel_chunk) as fh:
            dest_sha256, dest_size = sha256_stream(fh)

        if dest_size != chunk.cipher_size or dest_sha256 != chunk.cipher_sha256:
            raise IntegrityVerificationError(
                f"SMB destination read-back verification failed for chunk '{chunk.opaque_chunk_id}' "
                f"(expected size={chunk.cipher_size}, sha256={chunk.cipher_sha256}; "
                f"actual size={dest_size}, sha256={dest_sha256})."
            )
        return written_path

    def write_and_verify_chunk_resilient(
        self,
        *,
        transfer_id: str,
        attempt_id: str,
        chunk: EncryptedChunkItem,
        retry_backoff_seconds: Tuple[float, ...] = DEFAULT_RETRY_BACKOFF_SECONDS,
        sleep_fn: Callable[[float], None] = time.sleep,
        on_disconnect_callback: Optional[Callable[[int, Exception], None]] = None,
    ) -> Tuple[Path, str]:
        """
        AWS DataSync-style resilient chunk transfer with bounded backoff (default 2s, 5s, 10s),
        post-reconnect SMB 3.1.1 policy re-verification (NET-01), and non-destructive partial-write
        collision recovery (RES-01, SAF-01):
        - If a transient network drop or timeout occurs mid-chunk:
          1. Waits according to `retry_backoff_seconds`.
          2. Re-runs `run_preflight()` to verify the re-established SMB 3.1.1 session is still
             authenticated, encrypted, and connected to the approved server.
          3. Checks if the chunk was actually written and fully intact before the drop; if so,
             returns immediately without re-uploading.
          4. If a partial/corrupted chunk file was left behind by the interrupted socket, NEVER
             overwrites or deletes it (SAF-01); automatically allocates a new sub-attempt or
             collision-free filename and retries.
        Returns `(written_path, effective_attempt_id)`.
        """
        current_attempt_id = attempt_id
        max_attempts = len(retry_backoff_seconds) + 1

        for try_idx in range(max_attempts):
            try:
                # If retrying after a disconnect, first check if previous write actually succeeded on the server
                if try_idx > 0:
                    self.run_preflight(required_free_bytes=chunk.cipher_size)
                    if self.check_existing_chunk_on_destination(
                        transfer_id=transfer_id,
                        attempt_id=current_attempt_id,
                        opaque_chunk_id=chunk.opaque_chunk_id,
                        expected_cipher_size=chunk.cipher_size,
                        expected_cipher_sha256=chunk.cipher_sha256,
                    ):
                        rel_ok = Path(transfer_id) / current_attempt_id / chunk.opaque_chunk_id
                        return validate_confined_path(self.incoming_root, rel_ok, must_exist=True), current_attempt_id

                written = self.write_and_verify_chunk(
                    transfer_id=transfer_id,
                    attempt_id=current_attempt_id,
                    chunk=chunk,
                )
                return written, current_attempt_id

            except FileCollisionError as exc:
                # Check if the existing file is already the exact verified chunk
                if self.check_existing_chunk_on_destination(
                    transfer_id=transfer_id,
                    attempt_id=current_attempt_id,
                    opaque_chunk_id=chunk.opaque_chunk_id,
                    expected_cipher_size=chunk.cipher_size,
                    expected_cipher_sha256=chunk.cipher_sha256,
                ):
                    rel_ok = Path(transfer_id) / current_attempt_id / chunk.opaque_chunk_id
                    return validate_confined_path(self.incoming_root, rel_ok, must_exist=True), current_attempt_id
                # Otherwise a partial chunk from a dropped connection exists; cannot overwrite (SAF-01)
                raise
            except (OSError, SMBTransportError, IntegrityVerificationError) as exc:
                if try_idx >= len(retry_backoff_seconds):
                    raise SMBTransportError(
                        f"SMB chunk '{chunk.opaque_chunk_id}' failed after {max_attempts} attempts: {exc}"
                    ) from exc
                if on_disconnect_callback is not None:
                    on_disconnect_callback(try_idx + 1, exc)
                sleep_fn(retry_backoff_seconds[try_idx])

        raise SMBTransportError(f"Exhausted retries for chunk '{chunk.opaque_chunk_id}'.")

    def publish_final_manifest(
        self,
        *,
        transfer_id: str,
        attempt_id: str,
        signed_outer_manifest: Dict[str, Any],
    ) -> Tuple[Path, str]:
        """
        Publishes `manifest.signed.json` LAST to `IndustrialIncoming/<transferId>/<attemptId>/manifest.signed.json`
        using exclusive create-only semantics and verifies its read-back SHA-256 digest.
        Returns `(manifest_path, manifest_sha256)`.
        """
        manifest_bytes = canonical_json_bytes(signed_outer_manifest)
        expected_hash = sha256_hex(manifest_bytes)
        rel_manifest = Path(transfer_id) / attempt_id / "manifest.signed.json"

        written_path = create_only_write_bytes(
            self.incoming_root,
            rel_manifest,
            manifest_bytes,
            create_parents=True,
            fsync=True,
        )

        with safe_readonly_open(self.incoming_root, rel_manifest) as fh:
            dest_sha256, dest_size = sha256_stream(fh)

        if dest_size != len(manifest_bytes) or dest_sha256 != expected_hash:
            raise IntegrityVerificationError(
                f"SMB destination read-back verification failed for final manifest '{rel_manifest}'."
            )
        return written_path, expected_hash

    def poll_for_receipt(
        self,
        *,
        transfer_id: str,
        sender_id: str,
        expected_manifest_hash: str,
        timeout_seconds: float = 30.0,
        poll_interval_seconds: float = 0.5,
        require_committed_status: bool = True,
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> VerifiedServerReceipt:
        """
        Polls the read-only `IndustrialReceipts` share for `<transferId>.receipt.json`
        and cryptographically verifies it.
        """
        rel_receipt = Path(f"{transfer_id}.receipt.json")
        deadline = time.monotonic() + max(0.1, timeout_seconds)

        while True:
            try:
                target = validate_confined_path(self.receipt_root, rel_receipt, must_exist=False)
                if target.exists() and target.is_file():
                    with safe_readonly_open(self.receipt_root, rel_receipt) as fh:
                        raw_bytes = fh.read()
                    doc = parse_strict_json(raw_bytes)
                    return verify_server_receipt_document(
                        doc,
                        self._trusted_server_keys,
                        expected_transfer_id=transfer_id,
                        expected_sender_id=sender_id,
                        expected_manifest_hash=expected_manifest_hash,
                        require_committed_status=require_committed_status,
                    )
            except SMBTransportError:
                raise
            except Exception:
                pass

            if time.monotonic() >= deadline:
                raise SMBTransportError(
                    f"Timed out waiting for signed server receipt '{rel_receipt}' after {timeout_seconds}s."
                )
            sleep_fn(poll_interval_seconds)
