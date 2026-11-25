"""
core/discovery.py
Daily Dataset Discovery & Frozen Inventory (DAT-01, DAT-02):
- Never traverses outside the approved source root.
- Supports discovery modes: INCREMENTAL (default), FULL_DAILY, DATE_RANGE, RETRY.
- Companion file grouping for geospatial datasets (.shp/.shx/.dbf/.prj, plus optional .cpg/.qpj/.sbn/.sbx):
  defers the entire group if any required shapefile companion is missing or actively being written.
- Active-write deferral: defers files modified within `stability_window_seconds` or failing read-open checks.
- Freezes inventory before transfer (dataset ID, relative path, size, mtime UTC, SHA-256, companion group ID)
  and verifies post-read metadata/identity to detect live file mutation during packaging.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

from industrial_secure_transfer.core.crypto import sha256_stream
from industrial_secure_transfer.core.safety import (
    PathConfinementError,
    detect_case_collisions,
    has_multiple_hardlinks,
    is_reparse_point_or_symlink,
    safe_readonly_open,
    validate_confined_path,
    validate_relative_path,
)


class DatasetDiscoveryError(Exception):
    """Raised when dataset discovery fails a mandatory readiness or safety gate."""


class LiveFileMutationError(DatasetDiscoveryError):
    """Raised when a frozen file changes size, mtime, or SHA-256 during reading (DAT-01)."""


# Required companions whenever ANY shapefile member (.shp, .shx, .dbf, .prj) is present
SHAPEFILE_REQUIRED_EXTENSIONS: Set[str] = {".shp", ".shx", ".dbf", ".prj"}
SHAPEFILE_ALL_EXTENSIONS: Set[str] = {
    ".shp", ".shx", ".dbf", ".prj", ".cpg", ".qpj", ".sbn", ".sbx", ".shp.xml"
}


@dataclass(frozen=True)
class FrozenFileEntry:
    relative_path: str
    size: int
    mtime_utc_ns: int
    mtime_utc_iso: str
    sha256: str
    group_id: str


@dataclass(frozen=True)
class DeferredFileEntry:
    relative_path: str
    reason: str


@dataclass(frozen=True)
class FrozenDatasetInventory:
    dataset_id: str
    source_root: str
    discovery_mode: str
    cutoff_utc_iso: str
    eligible_files: Tuple[FrozenFileEntry, ...]
    deferred_files: Tuple[DeferredFileEntry, ...]
    skipped_unchanged_files: Tuple[str, ...]
    total_bytes: int

    @property
    def file_count(self) -> int:
        return len(self.eligible_files)


def _format_ns_utc(ns: int) -> str:
    dt = datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _extract_shapefile_stem(rel_path_posix: str) -> Tuple[Optional[str], Optional[str]]:
    """
    If `rel_path_posix` is part of a shapefile companion family, returns (group_stem_posix, lower_ext).
    Otherwise returns (None, None).
    """
    lower = rel_path_posix.lower()
    if lower.endswith(".shp.xml"):
        stem = rel_path_posix[:-8]
        return stem, ".shp.xml"
    ext = Path(rel_path_posix).suffix.lower()
    if ext in SHAPEFILE_ALL_EXTENSIONS:
        stem = rel_path_posix[: -len(ext)]
        return stem, ext
    return None, None


def discover_and_freeze_dataset(
    source_root: Union[str, Path],
    *,
    dataset_id: str,
    discovery_mode: str = "INCREMENTAL",
    require_completion_marker: bool = True,
    completion_marker_filename: str = "_DATASET_READY.marker",
    stability_window_seconds: float = 5.0,
    acknowledged_hashes: Optional[Dict[str, str]] = None,
    date_range_bounds: Optional[Tuple[date, date]] = None,
    clock: Callable[[], float] = time.time,
) -> FrozenDatasetInventory:
    """
    Scans `source_root` in read-only mode, applies completion marker, stability window,
    shapefile companion grouping, and mode filtering, and returns a frozen inventory.
    Never silently skips files: every non-transferred file is recorded in `deferred_files`
    or `skipped_unchanged_files` (DAT-01).
    """
    mode = discovery_mode.upper()
    if mode not in {"INCREMENTAL", "FULL_DAILY", "DATE_RANGE", "RETRY"}:
        raise DatasetDiscoveryError(f"Unsupported discovery mode: {discovery_mode}")

    root_path = validate_confined_path(source_root, source_root, must_exist=True)
    now_sec = clock()
    cutoff_ns = int(now_sec * 1e9)
    stability_cutoff_ns = int((now_sec - max(0.0, stability_window_seconds)) * 1e9)
    cutoff_iso = _format_ns_utc(cutoff_ns)

    if require_completion_marker:
        marker_path = root_path / completion_marker_filename
        if not marker_path.exists() or not marker_path.is_file() or is_reparse_point_or_symlink(marker_path):
            raise DatasetDiscoveryError(
                f"Dataset readiness gate failed: missing completion marker '{completion_marker_filename}' in {root_path}"
            )

    ack_map = acknowledged_hashes or {}
    deferred: List[DeferredFileEntry] = []
    skipped_unchanged: List[str] = []

    # Candidate map: rel_posix -> (abs_path, stat_result)
    candidates: Dict[str, Tuple[Path, os.stat_result]] = {}

    # Walk directory tree deterministically without following symlinks
    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True, followlinks=False):
        dirnames.sort()
        filenames.sort()
        curr_dir = Path(dirpath)

        # Reject symlinked subdirectories without traversing them
        safe_subdirs: List[str] = []
        for dname in dirnames:
            sub_p = curr_dir / dname
            rel_sub = sub_p.relative_to(root_path).as_posix()
            if is_reparse_point_or_symlink(sub_p):
                deferred.append(DeferredFileEntry(rel_sub, "Symlink or reparse point directory rejected"))
            else:
                safe_subdirs.append(dname)
        dirnames[:] = safe_subdirs

        for fname in filenames:
            if fname == completion_marker_filename:
                continue
            abs_p = curr_dir / fname
            raw_rel = abs_p.relative_to(root_path).as_posix()

            # Validate path safety
            try:
                validate_relative_path(raw_rel)
            except PathConfinementError as exc:
                deferred.append(DeferredFileEntry(raw_rel, f"Invalid path name: {exc}"))
                continue

            if is_reparse_point_or_symlink(abs_p):
                deferred.append(DeferredFileEntry(raw_rel, "Symlink or reparse point file rejected"))
                continue

            if has_multiple_hardlinks(abs_p):
                deferred.append(DeferredFileEntry(raw_rel, "Multiple hardlinks rejected"))
                continue

            try:
                st = os.lstat(abs_p)
            except OSError as exc:
                deferred.append(DeferredFileEntry(raw_rel, f"Stat error: {exc}"))
                continue

            # Date-range filtering if DATE_RANGE mode is active
            if mode == "DATE_RANGE" and date_range_bounds is not None:
                start_d, end_d = date_range_bounds
                file_date = datetime.fromtimestamp(st.st_mtime_ns / 1e9, tz=timezone.utc).date()
                if not (start_d <= file_date <= end_d):
                    deferred.append(
                        DeferredFileEntry(raw_rel, f"File date {file_date.isoformat()} outside range [{start_d}, {end_d}]")
                    )
                    continue

            # Active-write stability window check
            if st.st_mtime_ns > stability_cutoff_ns:
                deferred.append(
                    DeferredFileEntry(raw_rel, "Active write detected (modified within stability window)")
                )
                continue

            candidates[raw_rel] = (abs_p, st)

    # Check case collisions across all discovered candidate paths
    detect_case_collisions(iter(candidates.keys()))

    # Group shapefile companions (.shp/.shx/.dbf/.prj) and verify completeness
    shapefile_groups: Dict[str, Dict[str, str]] = {}  # stem -> {ext: rel_posix}
    for rel_posix in list(candidates.keys()):
        stem, ext = _extract_shapefile_stem(rel_posix)
        if stem is not None and ext is not None:
            shapefile_groups.setdefault(stem, {})[ext] = rel_posix

    for stem, ext_map in shapefile_groups.items():
        present_exts = set(ext_map.keys())
        missing_required = SHAPEFILE_REQUIRED_EXTENSIONS - present_exts
        if missing_required:
            missing_str = ", ".join(sorted(missing_required))
            for _, member_rel in sorted(ext_map.items()):
                candidates.pop(member_rel, None)
                deferred.append(
                    DeferredFileEntry(
                        member_rel,
                        f"Incomplete geospatial shapefile companion group '{stem}' (missing: {missing_str})",
                    )
                )

    # Hash and freeze remaining candidates, verifying metadata before and after reading
    eligible: List[FrozenFileEntry] = []
    total_bytes = 0

    for rel_posix in sorted(candidates.keys()):
        abs_p, st_before = candidates[rel_posix]
        try:
            with safe_readonly_open(root_path, rel_posix) as fh:
                digest, read_size = sha256_stream(fh)
            st_after = os.lstat(abs_p)
        except (OSError, PathConfinementError) as exc:
            deferred.append(DeferredFileEntry(rel_posix, f"Read/open failure during freeze: {exc}"))
            continue

        if (
            read_size != st_before.st_size
            or st_after.st_size != st_before.st_size
            or st_after.st_mtime_ns != st_before.st_mtime_ns
        ):
            deferred.append(
                DeferredFileEntry(rel_posix, "File mutated during inventory freeze scan")
            )
            continue

        # Incremental filter: skip if exact relative path + SHA-256 already acknowledged by server receipt
        if mode == "INCREMENTAL" and ack_map.get(rel_posix) == digest:
            skipped_unchanged.append(rel_posix)
            continue

        stem, _ = _extract_shapefile_stem(rel_posix)
        group_id = f"SHP:{stem}" if stem is not None else f"FILE:{rel_posix}"

        entry = FrozenFileEntry(
            relative_path=rel_posix,
            size=read_size,
            mtime_utc_ns=st_before.st_mtime_ns,
            mtime_utc_iso=_format_ns_utc(st_before.st_mtime_ns),
            sha256=digest,
            group_id=group_id,
        )
        eligible.append(entry)
        total_bytes += read_size

    return FrozenDatasetInventory(
        dataset_id=dataset_id,
        source_root=str(root_path),
        discovery_mode=mode,
        cutoff_utc_iso=cutoff_iso,
        eligible_files=tuple(eligible),
        deferred_files=tuple(deferred),
        skipped_unchanged_files=tuple(skipped_unchanged),
        total_bytes=total_bytes,
    )


def verify_frozen_file_unchanged(source_root: Union[str, Path], entry: FrozenFileEntry) -> None:
    """
    Verifies that a file in the frozen inventory has not changed size or mtime on disk.
    Raises LiveFileMutationError if mutated (DAT-01).
    """
    abs_p = validate_confined_path(source_root, entry.relative_path, must_exist=True)
    st = os.lstat(abs_p)
    if st.st_size != entry.size or st.st_mtime_ns != entry.mtime_utc_ns:
        raise LiveFileMutationError(
            f"DAT-01 Violation: Frozen source file '{entry.relative_path}' mutated during transfer "
            f"(expected size={entry.size}, mtime_ns={entry.mtime_utc_ns}; "
            f"actual size={st.st_size}, mtime_ns={st.st_mtime_ns})."
        )
