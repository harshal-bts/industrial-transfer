"""
adapters/base.py
Abstract OS adapter interface defining platform-independent contracts for:
- Physical USB device identification (hardware serial, volume GUID, removable bus verification, non-OS disk check)
- Filesystem & dirty-bit health check (USB-01, USB-02, USB-03)
- SMB 3.1.1 session verification (dialect, encryption, signing, remote mount validation) (NET-01, NET-02)
- Free space and read-only/ACL verification
"""

from __future__ import annotations

import abc
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, Union

from industrial_secure_transfer.core.config import AuthorizedUSBDevice, SMBEndpointConfig


class AdapterValidationError(Exception):
    """Raised when an OS-level hardware, filesystem, or SMB session check fails (fail closed)."""


@dataclass(frozen=True)
class USBDeviceTelemetry:
    mount_root: str
    serial_number: str
    volume_guid: str
    filesystem: str  # "NTFS", "EXFAT", etc.
    is_removable_usb_bus: bool
    is_system_or_internal_disk: bool
    is_dirty: Optional[bool]  # True = dirty (blocks transfer), False = clean, None = telemetry unavailable
    smart_health_status: str  # "PASSED", "FAILED", or "UNAVAILABLE"
    free_bytes: int
    total_bytes: int


@dataclass(frozen=True)
class SMBSessionTelemetry:
    server_name: str
    share_path: str
    dialect: str  # e.g., "3.1.1", "3.0.2", "3.0"
    encrypted: bool
    signed: bool
    is_remote_mount: bool
    free_bytes: int


class BaseOSAdapter(abc.ABC):
    """Abstract base class for platform-specific OS operations."""

    @abc.abstractmethod
    def get_usb_telemetry(self, mount_root: Union[str, Path]) -> USBDeviceTelemetry:
        """
        Queries native OS volume/bus identity, filesystem type, dirty bit, and SMART telemetry
        for `mount_root`.
        """

    @abc.abstractmethod
    def verify_smb_session(
        self,
        endpoint: SMBEndpointConfig,
        target_share_path: Union[str, Path],
    ) -> SMBSessionTelemetry:
        """
        Verifies active SMB connection dialect (SMB 3.1.1 preferred, SMB 1 prohibited),
        transport encryption/signing, and confirms the share is a real remote SMB session.
        """

    @abc.abstractmethod
    def verify_directory_permissions(self, path: Union[str, Path], *, require_readonly: bool = False) -> bool:
        """
        Checks OS filesystem ACL / POSIX permissions for least-privilege compliance.
        """

    def get_free_space_bytes(self, path: Union[str, Path]) -> Tuple[int, int]:
        """Returns (free_bytes, total_bytes) for the volume hosting `path`."""
        usage = shutil.disk_usage(str(path))
        return usage.free, usage.total

    def validate_authorized_usb(
        self,
        mount_root: Union[str, Path],
        authorized_devices: Tuple[AuthorizedUSBDevice, ...],
        *,
        required_free_bytes: int = 0,
    ) -> Tuple[USBDeviceTelemetry, AuthorizedUSBDevice]:
        """
        Enforces mandatory USB preflight gates (USB-01, USB-02, USB-03):
        - Rejects internal/OS disks or non-USB buses.
        - Matches physical serial number + volume GUID + filesystem against signed allowlist.
        - Blocks if dirty bit is set or SMART health reports failure.
        - Logs/tolerates unavailable optional hardware telemetry (`UNAVAILABLE`) while enforcing mandatory gates.
        """
        telemetry = self.get_usb_telemetry(mount_root)

        if telemetry.is_system_or_internal_disk or not telemetry.is_removable_usb_bus:
            raise AdapterValidationError(
                f"USB-01 Violation: Target '{mount_root}' is an internal/system disk or not on a verified USB bus."
            )

        matched_cfg: Optional[AuthorizedUSBDevice] = None
        for dev in authorized_devices:
            if (
                dev.serial_number.upper() == telemetry.serial_number.upper()
                and dev.volume_guid.upper() == telemetry.volume_guid.upper()
            ):
                matched_cfg = dev
                break

        if matched_cfg is None:
            raise AdapterValidationError(
                f"USB-01 Violation: USB device (serial='{telemetry.serial_number}', guid='{telemetry.volume_guid}') "
                "is not in the signed authorized device registry."
            )

        if telemetry.filesystem.upper() != matched_cfg.expected_filesystem.upper():
            raise AdapterValidationError(
                f"USB-01 Violation: Filesystem mismatch on authorized USB. Expected '{matched_cfg.expected_filesystem}', "
                f"got '{telemetry.filesystem}'."
            )

        if telemetry.is_dirty is True:
            raise AdapterValidationError(
                f"USB-02 Violation: Volume '{mount_root}' has the filesystem dirty bit set. "
                "Transfer blocked; do not run automatic repair."
            )

        if telemetry.smart_health_status.upper() == "FAILED":
            raise AdapterValidationError(
                f"USB-02 Violation: Hardware health telemetry reported FAILED for '{mount_root}'."
            )

        if telemetry.free_bytes < required_free_bytes:
            raise AdapterValidationError(
                f"USB-02 Violation: Insufficient USB free space ({telemetry.free_bytes} bytes available, "
                f"{required_free_bytes} bytes required including reserve)."
            )

        return telemetry, matched_cfg

    def validate_smb_policy(
        self,
        endpoint: SMBEndpointConfig,
        target_share_path: Union[str, Path],
        *,
        required_free_bytes: int = 0,
    ) -> SMBSessionTelemetry:
        """
        Enforces mandatory SMB policy gates (NET-01, NET-02):
        - Must be an active remote mount/UNC session matching `endpoint.server_name`.
        - Dialect must be SMB 3.1.1 (or 3.0.x if `require_smb311=False`); SMB 1/2 prohibited.
        - Must be transport-encrypted (or signed if `allow_signed_unencrypted_vlan_exception=True`).
        """
        telemetry = self.verify_smb_session(endpoint, target_share_path)

        if not telemetry.is_remote_mount:
            raise AdapterValidationError(
                f"NET-01 Violation: Target share '{target_share_path}' is not an active remote SMB mount/UNC session."
            )

        if telemetry.server_name.lower() != endpoint.server_name.lower():
            raise AdapterValidationError(
                f"NET-01 Violation: SMB server identity mismatch (expected '{endpoint.server_name}', got '{telemetry.server_name}')."
            )

        dialect = telemetry.dialect.strip()
        if dialect.startswith(("1", "2", "SMB1", "SMB2", "NT1")):
            raise AdapterValidationError(
                f"NET-02 Violation: Prohibited legacy SMB dialect '{dialect}' detected."
            )

        if endpoint.require_smb311 and dialect not in ("3.1.1", "3.11", "SMB3_11"):
            raise AdapterValidationError(
                f"NET-01 Violation: SMB 3.1.1 is required by policy, but session negotiated '{dialect}'."
            )
        elif not endpoint.require_smb311 and not dialect.startswith(("3.", "SMB3")):
            raise AdapterValidationError(
                f"NET-01 Violation: Minimum SMB 3.0 required, got '{dialect}'."
            )

        if endpoint.require_encryption and not telemetry.encrypted:
            raise AdapterValidationError(
                "NET-01 Violation: SMB session transport encryption is required by policy but inactive."
            )

        if not telemetry.encrypted:
            if not (endpoint.allow_signed_unencrypted_vlan_exception and telemetry.signed):
                raise AdapterValidationError(
                    "NET-01 Violation: Unencrypted SMB session must be explicitly permitted and cryptographically signed."
                )

        if telemetry.free_bytes < required_free_bytes:
            raise AdapterValidationError(
                f"NET-01 Violation: Insufficient SMB share capacity ({telemetry.free_bytes} available, {required_free_bytes} required)."
            )

        return telemetry


def get_current_os_adapter() -> BaseOSAdapter:
    """Factory returning the appropriate OS adapter for the running platform."""
    if sys.platform == "win32":
        from industrial_secure_transfer.adapters.windows import WindowsOSAdapter
        return WindowsOSAdapter()
    from industrial_secure_transfer.adapters.linux import LinuxOSAdapter
    return LinuxOSAdapter()
