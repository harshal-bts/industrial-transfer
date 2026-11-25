"""
core/config.py
Signed machine configuration loader and strict schema validation (DEP-01, SAF-02).
- Verifies Ed25519 provisioning signature over configuration before any job discovery or execution.
- Rejects any override flags or weakened security parameters (no encryption toggle, no preflight bypass).
- Ensures Part A and Part B configs never hold server private decryption keys.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import ed25519

from industrial_secure_transfer.core.crypto import (
    SchemaValidationError,
    SignatureVerificationError,
    load_ed25519_public_key_pem,
    parse_strict_json,
    sign_canonical_document,
    verify_canonical_document,
)
from industrial_secure_transfer.core.safety import SafetyViolationError, safe_readonly_open

CONFIG_DOMAIN_SEPARATOR = "IST-CONFIG-V1"

VALID_ROLES = {"PART_A_EXPORTER", "PART_B_WORKSTATION", "PART_C_SERVER"}
VALID_MODES = {"INCREMENTAL", "FULL_DAILY", "DATE_RANGE", "RETRY"}
VALID_TRANSPORTS = {"SMB", "USB"}

# Any presence of override keys in configuration is immediately rejected (SAF-02)
FORBIDDEN_OVERRIDE_KEYS = {
    "allow_unencrypted",
    "bypass_auth",
    "bypass_preflight",
    "skip_signature_verification",
    "allow_overwrite",
    "disable_path_confinement",
    "force_cleanup",
    "allow_arbitrary_usb",
    "ignore_dirty_bit",
}


class ConfigurationError(Exception):
    """Raised when configuration fails signature verification or schema validation."""


@dataclass(frozen=True)
class AuthorizedUSBDevice:
    serial_number: str
    volume_guid: str
    expected_filesystem: str = "NTFS"  # "NTFS" or "EXFAT"
    label: str = "IST_SECURE_USB"


@dataclass(frozen=True)
class SMBEndpointConfig:
    server_name: str
    incoming_share_path: str
    receipt_share_path: str
    require_smb311: bool = True
    require_encryption: bool = True
    allow_signed_unencrypted_vlan_exception: bool = False


@dataclass(frozen=True)
class JobConfig:
    job_id: str
    name: str
    source_root: str
    transfer_method: str  # "SMB" or "USB"
    discovery_mode: str = "INCREMENTAL"
    timezone_name: str = "UTC"
    require_completion_marker: bool = True
    completion_marker_filename: str = "_DATASET_READY.marker"
    stability_window_seconds: float = 5.0
    chunk_size_bytes: int = 32 * 1024 * 1024  # 32 MiB default
    require_prior_receipt_for_usb: bool = True


@dataclass(frozen=True)
class MachineConfig:
    version: int
    machine_id: str
    role: str  # "PART_A_EXPORTER", "PART_B_WORKSTATION", "PART_C_SERVER"
    provisioning_key_id: str
    sender_signing_key_id: str
    recipient_encryption_key_id: str
    recipient_rsa_public_key_pem: str
    trusted_sender_public_keys_pem: Dict[str, str]
    trusted_server_signing_keys_pem: Dict[str, str]
    state_journal_dir: str
    min_free_space_bytes: int = 512 * 1024 * 1024
    authorized_usb_devices: Tuple[AuthorizedUSBDevice, ...] = field(default_factory=tuple)
    smb_endpoint: Optional[SMBEndpointConfig] = None
    jobs: Tuple[JobConfig, ...] = field(default_factory=tuple)
    # Part C specific directories
    quarantine_dir: Optional[str] = None
    committed_repository_dir: Optional[str] = None
    max_decompressed_package_bytes: int = 32 * 1024 * 1024 * 1024  # 32 GiB
    max_compression_ratio: float = 100.0


def _check_no_forbidden_keys_recursive(obj: Any) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in FORBIDDEN_OVERRIDE_KEYS:
                raise SafetyViolationError(
                    f"SAF-02 Violation: Forbidden security override key '{k}' present in configuration."
                )
            _check_no_forbidden_keys_recursive(v)
    elif isinstance(obj, list):
        for item in obj:
            _check_no_forbidden_keys_recursive(item)


def validate_and_parse_config(
    raw_dict: Dict[str, Any],
    provisioning_public_key: ed25519.Ed25519PublicKey,
    *,
    expected_role: Optional[str] = None,
) -> MachineConfig:
    """
    Verifies the Ed25519 provisioning signature on `raw_dict` and validates all schema invariants.
    Fails closed on any missing field, invalid role, or forbidden override parameter.
    """
    # 1. Verify signature BEFORE trusting any fields
    try:
        verify_canonical_document(
            raw_dict,
            provisioning_public_key,
            domain_separator=CONFIG_DOMAIN_SEPARATOR,
        )
    except SignatureVerificationError as exc:
        raise ConfigurationError(f"DEP-01: Configuration signature verification failed: {exc}") from exc

    # 2. Check for forbidden override keys anywhere in the tree
    _check_no_forbidden_keys_recursive(raw_dict)

    version = raw_dict.get("version")
    if version != 1:
        raise ConfigurationError(f"Unsupported configuration version: {version}")

    role = raw_dict.get("role")
    if role not in VALID_ROLES:
        raise ConfigurationError(f"Invalid machine role '{role}'. Must be one of {sorted(VALID_ROLES)}")

    if expected_role is not None and role != expected_role:
        raise ConfigurationError(f"Role mismatch: expected '{expected_role}', got '{role}'")

    # Trust boundary check: Part A and Part B must NEVER hold server private decryption keys in config
    if role in ("PART_A_EXPORTER", "PART_B_WORKSTATION"):
        for forbidden_secret in ("recipient_rsa_private_key_pem", "server_signing_private_key_pem", "private_key"):
            if forbidden_secret in raw_dict:
                raise SafetyViolationError(
                    f"Trust boundary violation: {role} configuration contains forbidden server private key '{forbidden_secret}'."
                )

    machine_id = str(raw_dict.get("machine_id", "")).strip()
    if not machine_id:
        raise ConfigurationError("Missing or empty 'machine_id'")

    provisioning_key_id = str(raw_dict.get("provisioning_key_id", "")).strip()
    sender_signing_key_id = str(raw_dict.get("sender_signing_key_id", "")).strip()
    recipient_encryption_key_id = str(raw_dict.get("recipient_encryption_key_id", "")).strip()
    recipient_rsa_public_key_pem = str(raw_dict.get("recipient_rsa_public_key_pem", "")).strip()
    state_journal_dir = str(raw_dict.get("state_journal_dir", "")).strip()

    if not all([provisioning_key_id, recipient_encryption_key_id, recipient_rsa_public_key_pem, state_journal_dir]):
        raise ConfigurationError("Missing required cryptographic or journal fields in configuration.")

    trusted_senders = raw_dict.get("trusted_sender_public_keys_pem", {})
    trusted_servers = raw_dict.get("trusted_server_signing_keys_pem", {})
    if not isinstance(trusted_senders, dict) or not isinstance(trusted_servers, dict):
        raise ConfigurationError("Trusted public key registries must be dictionaries.")

    # Parse USB devices
    usb_list: List[AuthorizedUSBDevice] = []
    for u in raw_dict.get("authorized_usb_devices", []):
        fs = str(u.get("expected_filesystem", "NTFS")).upper()
        if fs not in ("NTFS", "EXFAT"):
            raise ConfigurationError(f"Unsupported USB filesystem '{fs}'. Only NTFS and EXFAT are allowed.")
        serial = str(u.get("serial_number", "")).strip()
        vguid = str(u.get("volume_guid", "")).strip()
        if not serial or not vguid:
            raise ConfigurationError("Authorized USB device requires non-empty 'serial_number' and 'volume_guid'.")
        usb_list.append(
            AuthorizedUSBDevice(
                serial_number=serial,
                volume_guid=vguid,
                expected_filesystem=fs,
                label=str(u.get("label", "IST_SECURE_USB")),
            )
        )

    # Parse SMB endpoint
    smb_cfg: Optional[SMBEndpointConfig] = None
    if "smb_endpoint" in raw_dict and raw_dict["smb_endpoint"] is not None:
        s = raw_dict["smb_endpoint"]
        req_enc = bool(s.get("require_encryption", True))
        allow_vlan_exc = bool(s.get("allow_signed_unencrypted_vlan_exception", False))
        if not req_enc and not allow_vlan_exc:
            raise ConfigurationError(
                "NET-01: Unencrypted SMB is prohibited unless 'allow_signed_unencrypted_vlan_exception' is explicitly signed in config."
            )
        smb_cfg = SMBEndpointConfig(
            server_name=str(s["server_name"]).strip(),
            incoming_share_path=str(s["incoming_share_path"]).strip(),
            receipt_share_path=str(s["receipt_share_path"]).strip(),
            require_smb311=bool(s.get("require_smb311", True)),
            require_encryption=req_enc,
            allow_signed_unencrypted_vlan_exception=allow_vlan_exc,
        )

    # Parse jobs
    job_list: List[JobConfig] = []
    for j in raw_dict.get("jobs", []):
        method = str(j.get("transfer_method", "")).upper()
        if method not in VALID_TRANSPORTS:
            raise ConfigurationError(f"Invalid job transfer_method '{method}'.")
        mode = str(j.get("discovery_mode", "INCREMENTAL")).upper()
        if mode not in VALID_MODES:
            raise ConfigurationError(f"Invalid job discovery_mode '{mode}'.")
        chunk_sz = int(j.get("chunk_size_bytes", 32 * 1024 * 1024))
        if chunk_sz < 64 * 1024 or chunk_sz > 64 * 1024 * 1024:
            raise ConfigurationError(f"chunk_size_bytes ({chunk_sz}) out of allowed range [64 KiB, 64 MiB].")
        job_list.append(
            JobConfig(
                job_id=str(j["job_id"]).strip(),
                name=str(j["name"]).strip(),
                source_root=str(j["source_root"]).strip(),
                transfer_method=method,
                discovery_mode=mode,
                timezone_name=str(j.get("timezone_name", "UTC")),
                require_completion_marker=bool(j.get("require_completion_marker", True)),
                completion_marker_filename=str(j.get("completion_marker_filename", "_DATASET_READY.marker")),
                stability_window_seconds=float(j.get("stability_window_seconds", 5.0)),
                chunk_size_bytes=chunk_sz,
                require_prior_receipt_for_usb=bool(j.get("require_prior_receipt_for_usb", True)),
            )
        )

    return MachineConfig(
        version=version,
        machine_id=machine_id,
        role=role,
        provisioning_key_id=provisioning_key_id,
        sender_signing_key_id=sender_signing_key_id,
        recipient_encryption_key_id=recipient_encryption_key_id,
        recipient_rsa_public_key_pem=recipient_rsa_public_key_pem,
        trusted_sender_public_keys_pem=dict(trusted_senders),
        trusted_server_signing_keys_pem=dict(trusted_servers),
        state_journal_dir=state_journal_dir,
        min_free_space_bytes=int(raw_dict.get("min_free_space_bytes", 512 * 1024 * 1024)),
        authorized_usb_devices=tuple(usb_list),
        smb_endpoint=smb_cfg,
        jobs=tuple(job_list),
        quarantine_dir=raw_dict.get("quarantine_dir"),
        committed_repository_dir=raw_dict.get("committed_repository_dir"),
        max_decompressed_package_bytes=int(raw_dict.get("max_decompressed_package_bytes", 32 * 1024 * 1024 * 1024)),
        max_compression_ratio=float(raw_dict.get("max_compression_ratio", 100.0)),
    )


def load_signed_config_file(
    config_dir: Union[str, Path],
    config_filename: str,
    provisioning_public_key_pem: str,
    *,
    expected_role: Optional[str] = None,
) -> MachineConfig:
    """
    Loads a signed JSON configuration file from a confined directory and validates its signature & schema.
    """
    pub_key = load_ed25519_public_key_pem(provisioning_public_key_pem)
    with safe_readonly_open(config_dir, config_filename) as fh:
        raw_bytes = fh.read()
    try:
        raw_dict = parse_strict_json(raw_bytes)
    except SchemaValidationError as exc:
        raise ConfigurationError(f"Configuration JSON parse error: {exc}") from exc
    return validate_and_parse_config(raw_dict, pub_key, expected_role=expected_role)


def create_signed_config_dict(
    unsigned_config: Dict[str, Any],
    provisioning_private_key: ed25519.Ed25519PrivateKey,
) -> Dict[str, Any]:
    """Helper for provisioning tools and tests to produce a validly signed config dictionary."""
    doc = dict(unsigned_config)
    doc["signature"] = sign_canonical_document(
        doc,
        provisioning_private_key,
        domain_separator=CONFIG_DOMAIN_SEPARATOR,
    )
    return doc
