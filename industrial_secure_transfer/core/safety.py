"""
core/safety.py
Mandatory non-destructive safety invariants (SAF-01, SAF-02, SAF-03):
- Zero Local Modification: never delete, format, move, rename, truncate, or overwrite existing local/server files.
- Create-Only Writes: exclusive file creation ("xb" / CREATE_NEW). Collisions raise FileCollisionError.
- Path Confinement: strict canonicalization, rejecting path traversal (..), symlinks, junctions,
  reparse points, Alternate Data Streams (ADS), device paths, hardlinks, reserved names, and case collisions.
"""

from __future__ import annotations

import ctypes
import os
import re
import stat
import sys
import unicodedata
import uuid
from pathlib import Path
from typing import BinaryIO, Iterator, Optional, Set, Union


class SafetyViolationError(Exception):
    """Base exception for any non-destructive safety invariant failure (fail closed)."""


class PathConfinementError(SafetyViolationError):
    """Raised when a path fails canonical confinement, traversal, symlink, ADS, or hardlink validation."""


class FileCollisionError(SafetyViolationError):
    """Raised when an exclusive create-only operation detects an existing target file or directory."""


class DestructiveOperationForbiddenError(SafetyViolationError):
    """Raised if any code path attempts a forbidden destructive operation."""


# Windows reserved device names (case-insensitive, with or without extension)
WINDOWS_RESERVED_NAMES: Set[str] = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    "CONIN$", "CONOUT$", "CLOCK$",
}

# File attribute flag on Windows for reparse points / junctions / symlinks
FILE_ATTRIBUTE_REPARSE_POINT = 0x0400
MAX_SAFE_PATH_LENGTH = 240
MAX_COMPONENT_LENGTH = 128

# Disallowed control or shell/device characters in relative paths
INVALID_COMPONENT_CHARS_RE = re.compile(r'[\x00-\x1f<>:"|?*]')


def generate_immutable_attempt_id(prefix: str = "ATT") -> str:
    """Generates a unique, collision-resistant immutable attempt ID."""
    return f"{prefix}-{uuid.uuid4().hex[:12].upper()}"


def validate_no_ads_or_device_prefix(raw_path: Union[str, Path]) -> str:
    """
    Validates that a path string contains no Windows Alternate Data Streams (ADS),
    device namespace prefixes (\\\\.\\, \\\\?\\), or null bytes.
    """
    s = str(raw_path)
    if "\x00" in s:
        raise PathConfinementError("Null byte detected in path.")

    normalized_s = unicodedata.normalize("NFC", s)
    if normalized_s != s:
        raise PathConfinementError("Non-NFC Unicode normalization detected in path.")

    # Reject Windows device paths or NT namespace prefixes
    if s.startswith(("\\\\.\\", "\\\\?\\", "//./", "//?/")):
        raise PathConfinementError(f"Device namespace prefix forbidden: {s}")

    # Check for Alternate Data Streams (colon anywhere except a drive letter at index 1 like "C:\")
    colon_positions = [i for i, ch in enumerate(s) if ch == ":"]
    for pos in colon_positions:
        if not (pos == 1 and len(s) >= 2 and s[0].isalpha()):
            raise PathConfinementError(f"Alternate Data Stream (ADS) or illegal colon in path: {s}")

    return s


def is_reparse_point_or_symlink(path: Path) -> bool:
    """
    Checks if a path is a symlink, junction, or Windows reparse point without following the link.
    """
    try:
        if path.is_symlink():
            return True
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            return True
        # Check Windows file attributes for FILE_ATTRIBUTE_REPARSE_POINT (junctions, mount points, symlinks)
        file_attrs = getattr(st, "st_file_attributes", 0)
        if file_attrs & FILE_ATTRIBUTE_REPARSE_POINT:
            return True
        if sys.platform == "win32":
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            if attrs != -1 and (attrs & FILE_ATTRIBUTE_REPARSE_POINT):
                return True
    except OSError:
        # If the path exists and lstat failed unexpectedly, fail closed if it appears to exist
        if os.path.lexists(path):
            return True
    return False


def has_multiple_hardlinks(path: Path) -> bool:
    """Returns True if an existing regular file has link count > 1 (hardlink risk)."""
    try:
        if not os.path.lexists(path):
            return False
        st = os.lstat(path)
        if stat.S_ISREG(st.st_mode) and st.st_nlink > 1:
            return True
    except OSError:
        return True
    return False


def validate_relative_path(rel_path: Union[str, Path]) -> Path:
    """
    Validates a relative path for manifests/packages:
    - Must be relative (no leading slash, backslash, or drive letter)
    - No '..', '.', empty segments, ADS, reserved Windows device names, trailing dots/spaces
    - Normalized NFC Unicode
    """
    s = validate_no_ads_or_device_prefix(rel_path)
    if not s or not s.strip():
        raise PathConfinementError("Empty relative path is forbidden.")

    if s.startswith(("/", "\\")) or (len(s) >= 2 and s[1] == ":"):
        raise PathConfinementError(f"Relative path must not be absolute or drive-qualified: {s}")

    # Split on both forward and backward slashes
    raw_parts = re.split(r"[\\/]", s)
    clean_parts = []
    for part in raw_parts:
        if part in ("", ".", ".."):
            raise PathConfinementError(f"Path traversal or empty component forbidden in relative path: {s}")
        if len(part) > MAX_COMPONENT_LENGTH:
            raise PathConfinementError(f"Path component exceeds {MAX_COMPONENT_LENGTH} chars: {part}")
        if INVALID_COMPONENT_CHARS_RE.search(part):
            raise PathConfinementError(f"Illegal character in path component: {part}")
        if part.endswith((" ", ".")):
            raise PathConfinementError(f"Trailing dot or space forbidden in component: {part}")
        stem = part.split(".")[0].upper()
        if stem in WINDOWS_RESERVED_NAMES:
            raise PathConfinementError(f"Reserved Windows device name forbidden: {part}")
        clean_parts.append(part)

    result = Path(*clean_parts)
    if len(str(result)) > MAX_SAFE_PATH_LENGTH:
        raise PathConfinementError(f"Relative path exceeds maximum safe length ({MAX_SAFE_PATH_LENGTH}): {s}")
    return result


def validate_confined_path(
    base_dir: Union[str, Path],
    target_rel_or_abs: Union[str, Path],
    *,
    must_exist: bool = False,
    reject_hardlinks: bool = True,
) -> Path:
    """
    Strictly confines `target_rel_or_abs` within `base_dir`.
    - Validates `base_dir` exists and is not a symlink/reparse point.
    - Rejects traversal (`..`), symlinks, junctions, reparse points at every ancestor and target.
    - Rejects ADS, device paths, reserved device names, and hardlinks.
    """
    validate_no_ads_or_device_prefix(base_dir)
    validate_no_ads_or_device_prefix(target_rel_or_abs)

    base_path = Path(os.path.abspath(str(base_dir)))
    if not base_path.exists() or not base_path.is_dir():
        raise PathConfinementError(f"Confinement base directory does not exist: {base_path}")
    if is_reparse_point_or_symlink(base_path):
        raise PathConfinementError(f"Confinement base directory is a symlink or reparse point: {base_path}")

    resolved_base = base_path.resolve(strict=True)
    if resolved_base != base_path:
        # Check if any parent of base_path had a symlink redirection
        if is_reparse_point_or_symlink(base_path):
            raise PathConfinementError(f"Base path resolution mismatch: {base_path} -> {resolved_base}")

    target_in = Path(str(target_rel_or_abs))
    if target_in.is_absolute():
        # Must structurally reside under base_path without '..'
        raw_parts = re.split(r"[\\/]", str(target_rel_or_abs))
        if ".." in raw_parts:
            raise PathConfinementError(f"Traversal '..' forbidden in path: {target_rel_or_abs}")
        candidate = Path(os.path.abspath(str(target_in)))
        try:
            rel_to_base = candidate.relative_to(base_path)
        except ValueError as exc:
            raise PathConfinementError(
                f"Target path {candidate} escapes confinement root {base_path}"
            ) from exc
        if str(rel_to_base) in ("", "."):
            return base_path
        rel_path = validate_relative_path(rel_to_base)
    else:
        rel_path = validate_relative_path(target_in)

    # Walk step-by-step from base_path down through each component of rel_path
    current = base_path
    for part in rel_path.parts:
        current = current / part
        if os.path.lexists(current):
            if is_reparse_point_or_symlink(current):
                raise PathConfinementError(
                    f"Symlink, junction, or reparse point rejected inside confined tree: {current}"
                )

    # Final canonical resolution check
    resolved_target = current.resolve(strict=False)
    try:
        resolved_target.relative_to(resolved_base)
    except ValueError as exc:
        raise PathConfinementError(
            f"Canonical target {resolved_target} escapes canonical base {resolved_base}"
        ) from exc

    if must_exist and not current.exists():
        raise PathConfinementError(f"Expected confined target does not exist: {current}")

    if reject_hardlinks and current.exists() and current.is_file():
        if has_multiple_hardlinks(current):
            raise PathConfinementError(f"Multiple hardlinks detected on confined file: {current}")

    return current


def detect_case_collisions(relative_paths: Iterator[Union[str, Path]]) -> None:
    """
    Ensures a collection of relative paths contains no case-insensitive collisions
    (critical for cross-platform Windows/Linux and NTFS/exFAT safety).
    """
    seen_lower: dict[str, str] = {}
    for p in relative_paths:
        rel = str(validate_relative_path(p)).replace("\\", "/")
        folded = rel.casefold()
        if folded in seen_lower and seen_lower[folded] != rel:
            raise PathConfinementError(
                f"Case-insensitive path collision detected between '{seen_lower[folded]}' and '{rel}'"
            )
        seen_lower[folded] = rel


def ensure_confined_directory_tree(base_dir: Union[str, Path], rel_dir: Union[str, Path]) -> Path:
    """
    Safely creates new subdirectories under `base_dir` without modifying existing files
    and verifying no symlinks or reparse points exist along the branch.
    """
    target_dir = validate_confined_path(base_dir, rel_dir, must_exist=False)
    base_path = Path(os.path.abspath(str(base_dir)))
    rel_parts = target_dir.relative_to(base_path).parts

    current = base_path
    for part in rel_parts:
        current = current / part
        if os.path.lexists(current):
            if is_reparse_point_or_symlink(current):
                raise PathConfinementError(f"Refusing to traverse symlink/reparse directory: {current}")
            if not current.is_dir():
                raise FileCollisionError(f"Cannot create directory; file already exists at: {current}")
        else:
            os.mkdir(current)
    return current


def create_only_open(
    base_dir: Union[str, Path],
    rel_path: Union[str, Path],
    *,
    create_parents: bool = True,
) -> BinaryIO:
    """
    Opens a binary file for writing using strict exclusive creation ('xb' / O_CREAT | O_EXCL).
    - Validates path confinement before parent creation and again before file creation.
    - Never overwrites or truncates existing files; raises FileCollisionError on collision.
    """
    target_path = validate_confined_path(base_dir, rel_path, must_exist=False)
    base_path = Path(os.path.abspath(str(base_dir)))
    rel_validated = target_path.relative_to(base_path)

    if create_parents and len(rel_validated.parts) > 1:
        parent_rel = Path(*rel_validated.parts[:-1])
        ensure_confined_directory_tree(base_path, parent_rel)

    # Re-validate target path right before exclusive open
    target_path = validate_confined_path(base_path, rel_validated, must_exist=False)
    if os.path.lexists(target_path):
        raise FileCollisionError(f"Create-only violation: target already exists at {target_path}")

    try:
        return open(target_path, "xb")
    except FileExistsError as exc:
        raise FileCollisionError(f"Create-only collision: {target_path} already exists") from exc


def create_only_write_bytes(
    base_dir: Union[str, Path],
    rel_path: Union[str, Path],
    data: bytes,
    *,
    create_parents: bool = True,
    fsync: bool = True,
) -> Path:
    """
    Writes `data` to `base_dir / rel_path` using exclusive create-only semantics ('xb'),
    flushing and fsyncing before closing.
    """
    with create_only_open(base_dir, rel_path, create_parents=create_parents) as fh:
        fh.write(data)
        fh.flush()
        if fsync:
            os.fsync(fh.fileno())
        written_path = Path(fh.name)
    return written_path


def safe_readonly_open(
    base_dir: Union[str, Path],
    rel_or_abs_path: Union[str, Path],
    *,
    reject_hardlinks: bool = True,
) -> BinaryIO:
    """
    Opens an existing confined file strictly in binary read-only mode ('rb')
    after verifying it is not a symlink, reparse point, ADS, or hardlinked file.
    """
    target = validate_confined_path(
        base_dir,
        rel_or_abs_path,
        must_exist=True,
        reject_hardlinks=reject_hardlinks,
    )
    if not target.is_file():
        raise PathConfinementError(f"Target is not a regular file: {target}")
    if is_reparse_point_or_symlink(target):
        raise PathConfinementError(f"Target became a symlink/reparse point before open: {target}")
    return open(target, "rb")
