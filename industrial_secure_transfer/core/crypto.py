"""
core/crypto.py
Defense-in-depth cryptography module (SEC-01):
- AES-256-GCM per chunk with unique 96-bit deterministic/counter-bound nonces + structured AAD
  (authenticating version, transferId, packageId, chunkIndex, codec, plainSize).
- RSA-OAEP (SHA-256, 3072/4096-bit) wrapping of per-transfer 256-bit Data Encryption Keys (DEK).
- Ed25519 signing & verification over canonical deterministic JSON manifests, configs, and server receipts.
- SHA-256 streaming & buffer digest computation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Dict, Tuple, Union

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoError(Exception):
    """Base exception for cryptographic verification, decryption, or signature failures."""


class SignatureVerificationError(CryptoError):
    """Raised when an Ed25519 signature check fails."""


class IntegrityVerificationError(CryptoError):
    """Raised when a SHA-256 digest or AES-GCM authentication tag fails verification."""


class SchemaValidationError(CryptoError):
    """Raised when canonical JSON parsing detects duplicate keys or malformed structures."""


def canonical_json_bytes(obj: Any) -> bytes:
    """
    Serializes a JSON-compatible object into deterministic, canonical UTF-8 bytes
    (sorted keys, no extra whitespace, strict ASCII/UTF-8 representation).
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def parse_strict_json(raw_bytes: bytes, max_size_bytes: int = 16 * 1024 * 1024) -> Dict[str, Any]:
    """
    Parses JSON strictly, rejecting duplicate object keys, NaN/Infinity constants,
    and oversize payloads before trusting fields.
    """
    if len(raw_bytes) > max_size_bytes:
        raise SchemaValidationError(f"JSON payload exceeds max allowed size ({max_size_bytes} bytes)")

    def _reject_duplicate_keys(pairs: list[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for k, v in pairs:
            if k in result:
                raise SchemaValidationError(f"Duplicate JSON key rejected: '{k}'")
            result[k] = v
        return result

    def _reject_bad_constants(val: str) -> Any:
        raise SchemaValidationError(f"Invalid numeric constant in JSON: {val}")

    try:
        parsed = json.loads(
            raw_bytes.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_bad_constants,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SchemaValidationError(f"Malformed JSON document: {exc}") from exc

    if not isinstance(parsed, dict):
        raise SchemaValidationError("Top-level JSON document must be an object.")
    return parsed


def sha256_hex(data: bytes) -> str:
    """Returns lowercase hex SHA-256 digest of in-memory bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_stream(stream: BinaryIO, chunk_size: int = 1024 * 1024) -> Tuple[str, int]:
    """
    Computes SHA-256 hex digest and total byte count from a binary stream in bounded memory.
    """
    hasher = hashlib.sha256()
    total = 0
    while True:
        block = stream.read(chunk_size)
        if not block:
            break
        hasher.update(block)
        total += len(block)
    return hasher.hexdigest(), total


def sha256_file(path: Union[str, Path], chunk_size: int = 1024 * 1024) -> Tuple[str, int]:
    """Computes SHA-256 hex digest and byte length of a file on disk."""
    with open(path, "rb") as fh:
        return sha256_stream(fh, chunk_size=chunk_size)


@dataclass(frozen=True)
class ChunkAAD:
    """
    Structured Additional Authenticated Data (AAD) bound to each AES-256-GCM chunk.
    Prevents chunk reordering, cross-transfer splicing, codec downgrade, or length tampering.
    """
    version: int
    transfer_id: str
    attempt_id: str
    package_id: str
    chunk_index: int
    codec: str
    plain_size: int
    uncompressed_size: int

    def to_bytes(self) -> bytes:
        return canonical_json_bytes({
            "attemptId": self.attempt_id,
            "chunkIndex": self.chunk_index,
            "codec": self.codec,
            "packageId": self.package_id,
            "plainSize": self.plain_size,
            "transferId": self.transfer_id,
            "uncompressedSize": self.uncompressed_size,
            "version": self.version,
        })


class NonceGenerator:
    """
    Guarantees unique 96-bit (12-byte) AES-GCM nonces per transfer key without collision.
    Combines a 32-bit random salt prefix (generated with the transfer DEK) and a strictly
    monotonic 64-bit big-endian counter.
    """

    def __init__(self, prefix_4b: Optional[bytes] = None, start_counter: int = 0) -> None:
        if prefix_4b is not None:
            if len(prefix_4b) != 4:
                raise CryptoError("Nonce prefix must be exactly 4 bytes.")
            self._prefix = prefix_4b
        else:
            self._prefix = os.urandom(4)
        self._counter = start_counter
        self._seen_nonces: set[bytes] = set()

    @property
    def prefix(self) -> bytes:
        return self._prefix

    def next_nonce(self, explicit_index: Optional[int] = None) -> bytes:
        """
        Produces a unique 12-byte nonce. Never reuses a nonce within the same instance.
        """
        idx = explicit_index if explicit_index is not None else self._counter
        if idx < 0 or idx >= (1 << 64):
            raise CryptoError("Nonce counter out of 64-bit bounds.")
        if explicit_index is None:
            self._counter += 1
        else:
            self._counter = max(self._counter, idx + 1)

        nonce = self._prefix + struct.pack(">Q", idx)
        if nonce in self._seen_nonces:
            raise CryptoError("CRITICAL: Nonce reuse detected and blocked.")
        self._seen_nonces.add(nonce)
        return nonce


def generate_dek() -> bytes:
    """Generates a cryptographically strong 256-bit (32-byte) AES-GCM Data Encryption Key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_chunk_aes_gcm(
    dek: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: Union[ChunkAAD, bytes],
) -> bytes:
    """
    Encrypts a chunk with AES-256-GCM.
    Wire format returned: [12-byte nonce][ciphertext + 16-byte GCM tag].
    """
    if len(dek) != 32:
        raise CryptoError("AES-256-GCM requires a 32-byte key.")
    if len(nonce) != 12:
        raise CryptoError("AES-256-GCM requires a 96-bit (12-byte) nonce.")
    aad_bytes = aad.to_bytes() if isinstance(aad, ChunkAAD) else aad
    aesgcm = AESGCM(dek)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad_bytes)
    return nonce + ciphertext_with_tag


def decrypt_chunk_aes_gcm(
    dek: bytes,
    blob: bytes,
    aad: Union[ChunkAAD, bytes],
) -> bytes:
    """
    Verifies the 16-byte AES-256-GCM authentication tag against `aad` and decrypts `blob`
    ([12-byte nonce][ciphertext + 16-byte tag]). Fails closed before emitting any plaintext.
    """
    if len(dek) != 32:
        raise CryptoError("AES-256-GCM requires a 32-byte key.")
    if len(blob) < 12 + 16:
        raise IntegrityVerificationError("Encrypted chunk blob is smaller than nonce + GCM tag.")
    nonce = blob[:12]
    ciphertext_with_tag = blob[12:]
    aad_bytes = aad.to_bytes() if isinstance(aad, ChunkAAD) else aad
    aesgcm = AESGCM(dek)
    try:
        return aesgcm.decrypt(nonce, ciphertext_with_tag, aad_bytes)
    except InvalidTag as exc:
        raise IntegrityVerificationError(
            "AES-256-GCM authentication tag verification failed (tampered ciphertext or AAD)."
        ) from exc


# --- RSA-OAEP Key Wrapping (Server Public Key wraps DEK; Server Private Key unwraps) ---

def generate_rsa_keypair(key_size: int = 3072) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generates an RSA keypair (minimum 3072-bit) for RSA-OAEP SHA-256 DEK wrapping."""
    if key_size < 3072:
        raise CryptoError("RSA key size must be at least 3072 bits.")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return priv, priv.public_key()


def wrap_dek_rsa_oaep(dek: bytes, public_key: rsa.RSAPublicKey) -> str:
    """
    Wraps a 32-byte DEK using the Ingestion Server's RSA public key with OAEP-SHA256.
    Returns base64-encoded wrapped key string.
    """
    if len(dek) != 32:
        raise CryptoError("DEK must be 32 bytes.")
    wrapped = public_key.encrypt(
        dek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=b"INDUSTRIAL-SECURE-TRANSFER-DEK-V1",
        ),
    )
    return base64.b64encode(wrapped).decode("ascii")


def unwrap_dek_rsa_oaep(wrapped_b64: str, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Unwraps a base64-encoded RSA-OAEP-SHA256 wrapped DEK using the server's private key.
    (Used ONLY on Part C Ingestion Server).
    """
    try:
        wrapped = base64.b64decode(wrapped_b64.encode("ascii"), validate=True)
        dek = private_key.decrypt(
            wrapped,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=b"INDUSTRIAL-SECURE-TRANSFER-DEK-V1",
            ),
        )
    except Exception as exc:
        raise CryptoError("RSA-OAEP key unwrapping failed.") from exc
    if len(dek) != 32:
        raise CryptoError("Unwrapped DEK has invalid length.")
    return dek


# --- Ed25519 Digital Signatures (Manifests, Receipts, Signed Configs) ---

def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generates an Ed25519 signing keypair."""
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def sign_canonical_document(
    document: Dict[str, Any],
    signing_key: ed25519.Ed25519PrivateKey,
    *,
    domain_separator: str = "IST-DOC-V1",
) -> str:
    """
    Signs a dictionary document (excluding any existing 'signature' key) using Ed25519
    over domain-separated canonical JSON bytes. Returns base64 signature.
    """
    payload_copy = {k: v for k, v in document.items() if k != "signature"}
    canonical = canonical_json_bytes(payload_copy)
    message = f"{domain_separator}:".encode("utf-8") + canonical
    sig = signing_key.sign(message)
    return base64.b64encode(sig).decode("ascii")


def verify_canonical_document(
    document: Dict[str, Any],
    public_key: ed25519.Ed25519PublicKey,
    *,
    domain_separator: str = "IST-DOC-V1",
) -> None:
    """
    Verifies an Ed25519 'signature' field on a dictionary document against `public_key`.
    Raises SignatureVerificationError on any mismatch or missing signature.
    """
    sig_b64 = document.get("signature")
    if not isinstance(sig_b64, str) or not sig_b64:
        raise SignatureVerificationError("Document is missing 'signature' string field.")
    try:
        sig = base64.b64decode(sig_b64.encode("ascii"), validate=True)
    except Exception as exc:
        raise SignatureVerificationError("Malformed base64 signature.") from exc

    payload_copy = {k: v for k, v in document.items() if k != "signature"}
    canonical = canonical_json_bytes(payload_copy)
    message = f"{domain_separator}:".encode("utf-8") + canonical
    try:
        public_key.verify(sig, message)
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            f"Ed25519 signature verification failed for domain '{domain_separator}'."
        ) from exc


def compute_manifest_digest(manifest: Dict[str, Any]) -> str:
    """
    Computes the deterministic SHA-256 hex digest of an outer manifest
    (including its signature) for receipt binding.
    """
    return sha256_hex(canonical_json_bytes(manifest))


# --- PEM Serialization Helpers ---

def serialize_public_key_pem(pub_key: Union[ed25519.Ed25519PublicKey, rsa.RSAPublicKey]) -> str:
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def serialize_private_key_pem(priv_key: Union[ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey]) -> str:
    return priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def load_ed25519_public_key_pem(pem_str: str) -> ed25519.Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem_str.encode("utf-8"))
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise CryptoError("Loaded public key is not an Ed25519PublicKey.")
    return key


def load_ed25519_private_key_pem(pem_str: str) -> ed25519.Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem_str.encode("utf-8"), password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise CryptoError("Loaded private key is not an Ed25519PrivateKey.")
    return key


def load_rsa_public_key_pem(pem_str: str) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem_str.encode("utf-8"))
    if not isinstance(key, rsa.RSAPublicKey):
        raise CryptoError("Loaded public key is not an RSAPublicKey.")
    return key


def load_rsa_private_key_pem(pem_str: str) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem_str.encode("utf-8"), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CryptoError("Loaded private key is not an RSAPrivateKey.")
    return key
