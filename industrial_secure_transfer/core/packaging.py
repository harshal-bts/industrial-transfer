"""
core/packaging.py
Bounded-memory streaming packager, lossless per-chunk compression (zlib/none),
AES-256-GCM chunk encryption, and authenticated inner/outer manifest builder
(Section 9 & Section 10).
- Default 32 MiB chunk slicing (configurable up to 64 MiB).
- Skips re-compression for pre-compressed formats (JPEG, JPG, PNG, LAZ, ZIP, MP4, GZ, BZ2, XZ, 7Z, ZST).
- For compressible formats, retains zlib-compressed payload ONLY if strictly smaller than raw plaintext.
- Encrypts the inner manifest (which holds file relative paths, sizes, timestamps, SHA-256 hashes,
  and chunk mappings) with AES-256-GCM so Part B and network observers see only opaque chunk IDs.
- Signs the outer manifest with the sender's Ed25519 private key.
"""

from __future__ import annotations

import base64
import hashlib
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from industrial_secure_transfer.core.crypto import (
    ChunkAAD,
    NonceGenerator,
    canonical_json_bytes,
    decrypt_chunk_aes_gcm,
    encrypt_chunk_aes_gcm,
    generate_dek,
    parse_strict_json,
    sha256_hex,
    sign_canonical_document,
    verify_canonical_document,
    wrap_dek_rsa_oaep,
)
from industrial_secure_transfer.core.discovery import (
    FrozenDatasetInventory,
    FrozenFileEntry,
    LiveFileMutationError,
    verify_frozen_file_unchanged,
)
from industrial_secure_transfer.core.safety import safe_readonly_open

MANIFEST_DOMAIN_SEPARATOR = "IST-OUTER-MANIFEST-V1"
INNER_MANIFEST_AAD_PREFIX = b"IST-INNER-MANIFEST-AAD-V1:"
DEFAULT_CHUNK_SIZE_BYTES = 32 * 1024 * 1024  # 32 MiB

# Extensions that are already compressed and must bypass zlib compression (Section 9)
PRE_COMPRESSED_EXTENSIONS: Set[str] = {
    ".jpg", ".jpeg", ".png", ".laz", ".zip", ".mp4",
    ".gz", ".tgz", ".bz2", ".xz", ".7z", ".zst", ".webp",
}


class PackagingError(Exception):
    """Raised when streaming packaging or decompression encounters an integrity or quota error."""


class DecompressionBombError(PackagingError):
    """Raised when a chunk or package exceeds configured decompression size or ratio limits."""


@dataclass(frozen=True)
class EncryptedChunkItem:
    package_id: str
    chunk_index: int
    opaque_chunk_id: str
    codec: str  # "zlib" or "none"
    uncompressed_size: int
    plain_size: int  # size of payload passed to AES-GCM (after optional zlib)
    plain_sha256: str  # SHA-256 of uncompressed slice bytes
    cipher_bytes: bytes
    cipher_size: int
    cipher_sha256: str


@dataclass(frozen=True)
class InnerFileSliceMeta:
    chunk_index: int
    opaque_chunk_id: str
    package_id: str
    codec: str
    uncompressed_size: int
    plain_size: int
    plain_sha256: str


def should_skip_compression(relative_path: str) -> bool:
    """Returns True if the file extension indicates a pre-compressed format."""
    ext = Path(relative_path).suffix.lower()
    return ext in PRE_COMPRESSED_EXTENSIONS


def compress_slice_lossless(
    raw_bytes: bytes,
    *,
    skip_compression: bool,
    zlib_level: int = 3,
    min_savings_ratio: float = 0.98,
) -> Tuple[bytes, str]:
    """
    Applies bounded lossless zlib compression to a single memory slice unless `skip_compression`
    is True or compressed output is not smaller than `min_savings_ratio * len(raw_bytes)`.
    Returns (payload_to_encrypt, codec_name).
    """
    if skip_compression or len(raw_bytes) == 0:
        return raw_bytes, "none"
    compressed = zlib.compress(raw_bytes, level=zlib_level)
    if len(compressed) < int(len(raw_bytes) * min_savings_ratio):
        return compressed, "zlib"
    return raw_bytes, "none"


def decompress_slice_bounded(
    payload: bytes,
    codec: str,
    *,
    expected_uncompressed_size: int,
    max_chunk_bytes: int = 64 * 1024 * 1024,
    max_ratio: float = 100.0,
) -> bytes:
    """
    Safely decompresses a single decrypted chunk slice enforcing strict maximum output size
    and expansion ratio quotas to prevent decompression bomb attacks (Section 13).
    """
    if expected_uncompressed_size < 0 or expected_uncompressed_size > max_chunk_bytes:
        raise DecompressionBombError(
            f"Expected uncompressed chunk size ({expected_uncompressed_size}) exceeds limit ({max_chunk_bytes})."
        )

    if codec == "none":
        if len(payload) != expected_uncompressed_size:
            raise PackagingError(
                f"Uncompressed chunk size mismatch: expected {expected_uncompressed_size}, got {len(payload)}"
            )
        return payload

    if codec != "zlib":
        raise PackagingError(f"Unsupported chunk compression codec: '{codec}'")

    if expected_uncompressed_size > 1024 * 1024 and len(payload) > 0 and (expected_uncompressed_size / len(payload)) > max_ratio:
        raise DecompressionBombError(
            f"Chunk compression ratio ({expected_uncompressed_size / len(payload):.1f}x) exceeds max_ratio ({max_ratio}x)."
        )

    decomp = zlib.decompressobj()
    try:
        # Decompress at most max_chunk_bytes + 1 to detect overflow without exhausting RAM
        limit = min(max_chunk_bytes, max(expected_uncompressed_size, 1)) + 1
        out = decomp.decompress(payload, limit)
        if decomp.unconsumed_tail or decomp.flush(16):
            raise DecompressionBombError("Decompressed stream exceeds expected chunk size limit.")
    except zlib.error as exc:
        raise PackagingError(f"Zlib decompression error: {exc}") from exc

    if len(out) > 1024 * 1024 and len(payload) > 0 and (len(out) / len(payload)) > max_ratio:
        raise DecompressionBombError(
            f"Actual decompressed ratio ({len(out) / len(payload):.1f}x) exceeds max_ratio ({max_ratio}x)."
        )

    if len(out) != expected_uncompressed_size:
        raise PackagingError(
            f"Decompressed byte length ({len(out)}) does not match expected ({expected_uncompressed_size})."
        )
    return out


class StreamingPackager:
    """
    Streams frozen source files in bounded memory (32 MiB default chunks),
    yields encrypted `EncryptedChunkItem` objects one by one, and builds the
    signed outer manifest with an AES-256-GCM encrypted inner manifest.
    Never creates any local temporary ZIP or staging file.
    """

    def __init__(
        self,
        *,
        transfer_id: str,
        attempt_id: str,
        sender_id: str,
        sender_signing_key_id: str,
        sender_signing_private_key: ed25519.Ed25519PrivateKey,
        recipient_key_id: str,
        recipient_rsa_public_key: rsa.RSAPublicKey,
        inventory: FrozenDatasetInventory,
        chunk_size_bytes: int = DEFAULT_CHUNK_SIZE_BYTES,
        dek: Optional[bytes] = None,
        nonce_prefix: Optional[bytes] = None,
    ) -> None:
        if chunk_size_bytes <= 0 or chunk_size_bytes > 64 * 1024 * 1024:
            raise ValueError("chunk_size_bytes must be in (0, 64 MiB].")
        self._transfer_id = transfer_id
        self._attempt_id = attempt_id
        self._sender_id = sender_id
        self._sender_signing_key_id = sender_signing_key_id
        self._sender_signing_key = sender_signing_private_key
        self._recipient_key_id = recipient_key_id
        self._recipient_pub_key = recipient_rsa_public_key
        self._inventory = inventory
        self._chunk_size = chunk_size_bytes

        self._dek = dek if dek is not None else generate_dek()
        self._nonce_gen = NonceGenerator(prefix_4b=nonce_prefix)

        self._outer_chunks_meta: List[Dict[str, Any]] = []
        self._inner_files_meta: List[Dict[str, Any]] = []
        self._finished_streaming = False

    def stream_encrypted_chunks(
        self,
        *,
        skip_chunk_indices: Optional[Set[int]] = None,
        existing_chunk_meta: Optional[Dict[int, Dict[str, Any]]] = None,
    ) -> Iterator[Tuple[FrozenFileEntry, EncryptedChunkItem]]:
        """
        Reads each file in `self._inventory.eligible_files` in bounded `self._chunk_size` slices,
        verifies no live source mutation occurred before/during/after reading,
        compresses, encrypts with AES-256-GCM + AAD, and yields `(file_entry, encrypted_chunk)`.
        """
        skip_set = skip_chunk_indices or set()
        existing_meta = existing_chunk_meta or {}

        global_chunk_index = 0
        package_index = 1
        files_in_current_pkg = 0
        bytes_in_current_pkg = 0

        self._outer_chunks_meta.clear()
        self._inner_files_meta.clear()

        for file_entry in self._inventory.eligible_files:
            # Group up to 500 files or ~1 GiB uncompressed per logical package ID (Section 9)
            if files_in_current_pkg >= 500 or bytes_in_current_pkg >= 1024 * 1024 * 1024:
                package_index += 1
                files_in_current_pkg = 0
                bytes_in_current_pkg = 0

            package_id = f"PKG-{package_index:04d}"
            files_in_current_pkg += 1
            bytes_in_current_pkg += file_entry.size

            verify_frozen_file_unchanged(self._inventory.source_root, file_entry)
            skip_comp = should_skip_compression(file_entry.relative_path)

            file_hasher = hashlib.sha256()
            file_bytes_read = 0
            file_slices_meta: List[Dict[str, Any]] = []

            with safe_readonly_open(self._inventory.source_root, file_entry.relative_path) as fh:
                while True:
                    raw_slice = fh.read(self._chunk_size)
                    if not raw_slice and file_bytes_read > 0:
                        break

                    file_hasher.update(raw_slice)
                    file_bytes_read += len(raw_slice)

                    uncompressed_sz = len(raw_slice)
                    slice_plain_sha256 = sha256_hex(raw_slice)
                    payload_to_encrypt, codec = compress_slice_lossless(
                        raw_slice,
                        skip_compression=skip_comp,
                    )
                    plain_sz = len(payload_to_encrypt)
                    opaque_id = f"CHK-{global_chunk_index:06d}.bin"

                    aad = ChunkAAD(
                        version=1,
                        transfer_id=self._transfer_id,
                        attempt_id=self._attempt_id,
                        package_id=package_id,
                        chunk_index=global_chunk_index,
                        codec=codec,
                        plain_size=plain_sz,
                        uncompressed_size=uncompressed_sz,
                    )
                    nonce = self._nonce_gen.next_nonce(explicit_index=global_chunk_index)

                    if global_chunk_index in skip_set and global_chunk_index in existing_meta:
                        prev_m = existing_meta[global_chunk_index]
                        cipher_sz = int(prev_m["cipher_size"])
                        cipher_digest = str(prev_m["cipher_sha256"])
                        cipher_blob = b""
                    else:
                        cipher_blob = encrypt_chunk_aes_gcm(self._dek, nonce, payload_to_encrypt, aad)
                        cipher_sz = len(cipher_blob)
                        cipher_digest = sha256_hex(cipher_blob)

                        item = EncryptedChunkItem(
                            package_id=package_id,
                            chunk_index=global_chunk_index,
                            opaque_chunk_id=opaque_id,
                            codec=codec,
                            uncompressed_size=uncompressed_sz,
                            plain_size=plain_sz,
                            plain_sha256=slice_plain_sha256,
                            cipher_bytes=cipher_blob,
                            cipher_size=cipher_sz,
                            cipher_sha256=cipher_digest,
                        )
                        yield file_entry, item

                    self._outer_chunks_meta.append({
                        "chunkIndex": global_chunk_index,
                        "cipherSHA256": cipher_digest,
                        "cipherSize": cipher_sz,
                        "opaqueChunkId": opaque_id,
                        "packageId": package_id,
                    })
                    file_slices_meta.append({
                        "codec": codec,
                        "index": global_chunk_index,
                        "opaqueChunkId": opaque_id,
                        "packageId": package_id,
                        "plainSHA256": slice_plain_sha256,
                        "plainSize": plain_sz,
                        "uncompressedSize": uncompressed_sz,
                    })
                    global_chunk_index += 1

                    if file_entry.size == 0:
                        # Zero-byte file produces exactly one empty authenticated chunk
                        break

            # Verify full-file SHA-256 and metadata stability after streaming
            verify_frozen_file_unchanged(self._inventory.source_root, file_entry)
            actual_sha256 = file_hasher.hexdigest()
            if file_bytes_read != file_entry.size or actual_sha256 != file_entry.sha256:
                raise LiveFileMutationError(
                    f"DAT-01 Violation: File '{file_entry.relative_path}' content changed while streaming."
                )

            self._inner_files_meta.append({
                "chunks": file_slices_meta,
                "groupId": file_entry.group_id,
                "mtimeUtc": file_entry.mtime_utc_iso,
                "mtimeUtcNs": file_entry.mtime_utc_ns,
                "relativePath": file_entry.relative_path,
                "sha256": file_entry.sha256,
                "size": file_entry.size,
            })

        self._finished_streaming = True

    def build_signed_outer_manifest(self) -> Dict[str, Any]:
        """
        Constructs the encrypted inner manifest, wraps the per-transfer DEK with the
        server's RSA-OAEP-SHA256 public key, and signs the outer manifest with Ed25519
        (Section 10 schema).
        """
        if not self._finished_streaming:
            raise PackagingError("Cannot build outer manifest before streaming all chunks.")

        inner_manifest = {
            "attemptId": self._attempt_id,
            "cutoffUtc": self._inventory.cutoff_utc_iso,
            "datasetId": self._inventory.dataset_id,
            "discoveryMode": self._inventory.discovery_mode,
            "fileCount": self._inventory.file_count,
            "files": self._inner_files_meta,
            "totalBytes": self._inventory.total_bytes,
            "transferId": self._transfer_id,
            "version": 1,
        }
        inner_bytes = canonical_json_bytes(inner_manifest)
        # Use a dedicated high counter index for the inner manifest encryption nonce
        manifest_nonce = self._nonce_gen.next_nonce(explicit_index=(1 << 63) - 1)
        inner_aad = INNER_MANIFEST_AAD_PREFIX + f"{self._transfer_id}:{self._attempt_id}".encode("utf-8")
        encrypted_inner_blob = encrypt_chunk_aes_gcm(self._dek, manifest_nonce, inner_bytes, inner_aad)
        encrypted_inner_b64 = base64.b64encode(encrypted_inner_blob).decode("ascii")

        wrapped_key_b64 = wrap_dek_rsa_oaep(self._dek, self._recipient_pub_key)

        outer_doc: Dict[str, Any] = {
            "attemptId": self._attempt_id,
            "chunks": self._outer_chunks_meta,
            "encryptedManifest": encrypted_inner_b64,
            "recipientKeyId": self._recipient_key_id,
            "senderId": self._sender_id,
            "signingKeyId": self._sender_signing_key_id,
            "transferId": self._transfer_id,
            "version": 1,
            "wrappedKey": wrapped_key_b64,
        }
        outer_doc["signature"] = sign_canonical_document(
            outer_doc,
            self._sender_signing_key,
            domain_separator=MANIFEST_DOMAIN_SEPARATOR,
        )
        return outer_doc


def verify_outer_manifest_envelope(
    outer_manifest: Dict[str, Any],
    trusted_sender_keys: Dict[str, ed25519.Ed25519PublicKey],
) -> None:
    """
    Verifies the outer manifest schema and Ed25519 signature against the trusted sender key registry
    BEFORE allocating resources or trusting chunk lists (Section 10).
    """
    if outer_manifest.get("version") != 1:
        raise PackagingError(f"Unsupported outer manifest version: {outer_manifest.get('version')}")

    sender_id = str(outer_manifest.get("senderId", ""))
    signing_key_id = str(outer_manifest.get("signingKeyId", ""))
    lookup_key = signing_key_id if signing_key_id in trusted_sender_keys else sender_id
    if lookup_key not in trusted_sender_keys:
        raise PackagingError(f"Untrusted senderId/signingKeyId: '{sender_id}' / '{signing_key_id}'")

    pub_key = trusted_sender_keys[lookup_key]
    verify_canonical_document(
        outer_manifest,
        pub_key,
        domain_separator=MANIFEST_DOMAIN_SEPARATOR,
    )

    chunks = outer_manifest.get("chunks")
    if not isinstance(chunks, list):
        raise PackagingError("Outer manifest 'chunks' must be a list.")

    seen_ids: Set[str] = set()
    seen_indices: Set[int] = set()
    for ch in chunks:
        if not isinstance(ch, dict):
            raise PackagingError("Malformed chunk metadata entry in outer manifest.")
        cid = str(ch.get("opaqueChunkId", ""))
        cidx = int(ch.get("chunkIndex", -1))
        if not cid or cidx < 0:
            raise PackagingError("Invalid opaqueChunkId or chunkIndex in outer manifest.")
        if cid in seen_ids or cidx in seen_indices:
            raise PackagingError(f"Duplicate chunk ID ({cid}) or index ({cidx}) in outer manifest.")
        seen_ids.add(cid)
        seen_indices.add(cidx)


def decrypt_inner_manifest(
    outer_manifest: Dict[str, Any],
    dek: bytes,
) -> Dict[str, Any]:
    """
    Decrypts and parses the authenticated inner manifest using the unwrapped DEK.
    (Used ONLY on Part C Ingestion Server).
    """
    transfer_id = str(outer_manifest["transferId"])
    attempt_id = str(outer_manifest["attemptId"])
    enc_b64 = str(outer_manifest["encryptedManifest"])
    blob = base64.b64decode(enc_b64.encode("ascii"), validate=True)
    inner_aad = INNER_MANIFEST_AAD_PREFIX + f"{transfer_id}:{attempt_id}".encode("utf-8")
    plain_bytes = decrypt_chunk_aes_gcm(dek, blob, inner_aad)
    inner = parse_strict_json(plain_bytes)
    if inner.get("transferId") != transfer_id or inner.get("attemptId") != attempt_id:
        raise PackagingError("Inner manifest transferId/attemptId mismatch with outer manifest.")
    return inner
