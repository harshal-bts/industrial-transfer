"""
core/state.py
Append-only immutable checkpoint and hash-chained audit journal + Transfer State Machine
(RES-01, AUD-01, SAF-01).
- Never deletes, truncates, or overwrites journal files (avoids SQLite WAL deletion).
- Creates a new immutable segment file (`SEG-000001-<uuid>.json`) via exclusive create (`xb`)
  for each event or checkpoint record.
- Enforces strict state machine transitions:
  READY -> PREFLIGHT -> PACKAGING -> TRANSFERRING -> PAUSE_REQUESTED -> PAUSED
        -> STOP_REQUESTED -> STOPPED -> INTERRUPTED -> EXPORTED_TO_USB
        -> RECEIVED -> VALIDATING -> QUARANTINED -> COMMITTED -> ACKNOWLEDGED -> USB_CLEANED
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from industrial_secure_transfer.core.crypto import (
    canonical_json_bytes,
    parse_strict_json,
    sha256_hex,
)
from industrial_secure_transfer.core.safety import (
    create_only_write_bytes,
    ensure_confined_directory_tree,
    generate_immutable_attempt_id,
    safe_readonly_open,
    validate_confined_path,
)


class StateTransitionError(Exception):
    """Raised when an invalid state transition is attempted."""


class JournalIntegrityError(Exception):
    """Raised when the hash-chained audit/checkpoint journal fails tamper verification."""


class TransferState(str, Enum):
    READY = "READY"
    PREFLIGHT = "PREFLIGHT"
    PACKAGING = "PACKAGING"
    TRANSFERRING = "TRANSFERRING"
    PAUSE_REQUESTED = "PAUSE_REQUESTED"
    PAUSED = "PAUSED"
    STOP_REQUESTED = "STOP_REQUESTED"
    STOPPED = "STOPPED"
    INTERRUPTED = "INTERRUPTED"
    EXPORTED_TO_USB = "EXPORTED_TO_USB"
    RECEIVED = "RECEIVED"
    VALIDATING = "VALIDATING"
    QUARANTINED = "QUARANTINED"
    COMMITTED = "COMMITTED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    USB_CLEANED = "USB_CLEANED"


ALLOWED_TRANSITIONS: Dict[TransferState, Set[TransferState]] = {
    TransferState.READY: {TransferState.PREFLIGHT, TransferState.STOPPED},
    TransferState.PREFLIGHT: {
        TransferState.PACKAGING,
        TransferState.TRANSFERRING,
        TransferState.STOPPED,
        TransferState.INTERRUPTED,
    },
    TransferState.PACKAGING: {
        TransferState.TRANSFERRING,
        TransferState.PAUSE_REQUESTED,
        TransferState.PAUSED,
        TransferState.STOP_REQUESTED,
        TransferState.STOPPED,
        TransferState.INTERRUPTED,
    },
    TransferState.TRANSFERRING: {
        TransferState.PAUSE_REQUESTED,
        TransferState.PAUSED,
        TransferState.STOP_REQUESTED,
        TransferState.STOPPED,
        TransferState.INTERRUPTED,
        TransferState.EXPORTED_TO_USB,
        TransferState.RECEIVED,
        TransferState.COMMITTED,
    },
    TransferState.PAUSE_REQUESTED: {
        TransferState.PAUSED,
        TransferState.STOP_REQUESTED,
        TransferState.STOPPED,
        TransferState.INTERRUPTED,
    },
    TransferState.PAUSED: {
        TransferState.PREFLIGHT,
        TransferState.TRANSFERRING,
        TransferState.STOP_REQUESTED,
        TransferState.STOPPED,
    },
    TransferState.STOP_REQUESTED: {
        TransferState.STOPPED,
        TransferState.INTERRUPTED,
    },
    TransferState.STOPPED: {
        TransferState.PREFLIGHT,
        TransferState.TRANSFERRING,
    },
    TransferState.INTERRUPTED: {
        TransferState.PREFLIGHT,
        TransferState.STOPPED,
    },
    TransferState.EXPORTED_TO_USB: {
        TransferState.TRANSFERRING,
        TransferState.RECEIVED,
        TransferState.COMMITTED,
        TransferState.ACKNOWLEDGED,
    },
    TransferState.RECEIVED: {
        TransferState.VALIDATING,
        TransferState.QUARANTINED,
    },
    TransferState.VALIDATING: {
        TransferState.COMMITTED,
        TransferState.QUARANTINED,
    },
    TransferState.QUARANTINED: set(),  # Terminal blocked state; no cleanup or commit permitted
    TransferState.COMMITTED: {
        TransferState.ACKNOWLEDGED,
        TransferState.USB_CLEANED,
    },
    TransferState.ACKNOWLEDGED: {
        TransferState.USB_CLEANED,
        TransferState.READY,
    },
    TransferState.USB_CLEANED: {
        TransferState.ACKNOWLEDGED,
        TransferState.READY,
    },
}


# Sensitive field names that must NEVER be written into audit records (AUD-01)
FORBIDDEN_AUDIT_SECRET_KEYS = {
    "password",
    "dek",
    "private_key",
    "secret",
    "raw_key",
    "plaintext",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass(frozen=True)
class ChunkCheckpoint:
    transfer_id: str
    attempt_id: str
    package_id: str
    chunk_index: int
    opaque_chunk_id: str
    cipher_size: int
    cipher_sha256: str
    plain_size: int
    plain_sha256: str
    verified_at_utc: str
    operator: str


@dataclass(frozen=True)
class JournalRecord:
    seq: int
    record_type: str  # "STATE_TRANSITION", "CHUNK_CHECKPOINT", "AUDIT_EVENT", "FILE_ACKNOWLEDGED"
    timestamp_utc: str
    transfer_id: str
    attempt_id: str
    operator: str
    machine_id: str
    payload: Dict[str, Any]
    prev_record_hash: str
    record_hash: str


class AppendOnlyJournal:
    """
    Immutable, create-only segment journal on disk.
    Each record is written as its own exclusive file `SEG-<seq:08d>-<nonce>.json`
    chained via SHA-256 `prev_record_hash` -> `record_hash` to satisfy strict no-modification
    and no-WAL-deletion rules (Section 4 & Section 14).
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, journal_root: Union[str, Path], machine_id: str) -> None:
        self._root = Path(journal_root).resolve()
        self._machine_id = machine_id
        self._records: List[JournalRecord] = []
        self._load_and_verify_existing()

    @property
    def root(self) -> Path:
        return self._root

    @property
    def records(self) -> Tuple[JournalRecord, ...]:
        return tuple(self._records)

    def _load_and_verify_existing(self) -> None:
        if not self._root.exists():
            return
        seg_files = sorted(
            [p for p in self._root.iterdir() if p.is_file() and p.name.startswith("SEG-") and p.name.endswith(".json")],
            key=lambda x: x.name,
        )
        prev_hash = self.GENESIS_HASH
        loaded: List[JournalRecord] = []
        for idx, seg_path in enumerate(seg_files, start=1):
            with safe_readonly_open(self._root, seg_path.name) as fh:
                doc = parse_strict_json(fh.read())
            rec_hash = str(doc.get("record_hash", ""))
            body = {k: v for k, v in doc.items() if k != "record_hash"}
            expected_hash = sha256_hex(canonical_json_bytes(body))
            if rec_hash != expected_hash:
                raise JournalIntegrityError(
                    f"Journal tamper detected in {seg_path.name}: hash mismatch."
                )
            if doc.get("prev_record_hash") != prev_hash:
                raise JournalIntegrityError(
                    f"Journal chain broken at {seg_path.name}: expected prev {prev_hash}, got {doc.get('prev_record_hash')}"
                )
            if int(doc.get("seq", -1)) != idx:
                raise JournalIntegrityError(
                    f"Journal sequence gap at {seg_path.name}: expected seq {idx}, got {doc.get('seq')}"
                )
            loaded.append(
                JournalRecord(
                    seq=idx,
                    record_type=str(doc["record_type"]),
                    timestamp_utc=str(doc["timestamp_utc"]),
                    transfer_id=str(doc["transfer_id"]),
                    attempt_id=str(doc["attempt_id"]),
                    operator=str(doc["operator"]),
                    machine_id=str(doc["machine_id"]),
                    payload=dict(doc["payload"]),
                    prev_record_hash=prev_hash,
                    record_hash=rec_hash,
                )
            )
            prev_hash = rec_hash
        self._records = loaded

    def append_record(
        self,
        record_type: str,
        *,
        transfer_id: str,
        attempt_id: str,
        operator: str,
        payload: Dict[str, Any],
    ) -> JournalRecord:
        """
        Appends a new immutable hash-chained record using create-only file operations ('xb').
        Ensures no secret keys exist in `payload` (AUD-01).
        """
        for k in payload:
            if k.lower() in FORBIDDEN_AUDIT_SECRET_KEYS:
                raise ValueError(f"AUD-01 Violation: Refusing to log sensitive key '{k}' in journal.")

        seq = len(self._records) + 1
        prev_hash = self._records[-1].record_hash if self._records else self.GENESIS_HASH
        ts = utc_now_iso()

        body = {
            "attempt_id": attempt_id,
            "machine_id": self._machine_id,
            "operator": operator,
            "payload": payload,
            "prev_record_hash": prev_hash,
            "record_type": record_type,
            "seq": seq,
            "timestamp_utc": ts,
            "transfer_id": transfer_id,
        }
        rec_hash = sha256_hex(canonical_json_bytes(body))
        full_doc = dict(body)
        full_doc["record_hash"] = rec_hash

        seg_id = generate_immutable_attempt_id("SEG")
        filename = f"SEG-{seq:08d}-{seg_id}.json"
        create_only_write_bytes(
            self._root,
            filename,
            canonical_json_bytes(full_doc),
            create_parents=False,
            fsync=True,
        )

        record = JournalRecord(
            seq=seq,
            record_type=record_type,
            timestamp_utc=ts,
            transfer_id=transfer_id,
            attempt_id=attempt_id,
            operator=operator,
            machine_id=self._machine_id,
            payload=payload,
            prev_record_hash=prev_hash,
            record_hash=rec_hash,
        )
        self._records.append(record)
        return record

    def record_chunk_checkpoint(self, checkpoint: ChunkCheckpoint) -> JournalRecord:
        """Persists a durable chunk checkpoint ONLY after destination read-back verification."""
        return self.append_record(
            "CHUNK_CHECKPOINT",
            transfer_id=checkpoint.transfer_id,
            attempt_id=checkpoint.attempt_id,
            operator=checkpoint.operator,
            payload={
                "chunk_index": checkpoint.chunk_index,
                "cipher_sha256": checkpoint.cipher_sha256,
                "cipher_size": checkpoint.cipher_size,
                "opaque_chunk_id": checkpoint.opaque_chunk_id,
                "package_id": checkpoint.package_id,
                "plain_sha256": checkpoint.plain_sha256,
                "plain_size": checkpoint.plain_size,
                "verified_at_utc": checkpoint.verified_at_utc,
            },
        )

    def get_verified_chunks(self, transfer_id: str, attempt_id: Optional[str] = None) -> Dict[int, ChunkCheckpoint]:
        """
        Returns all durably checkpointed chunks for `transfer_id` (and optional `attempt_id`),
        keyed by `chunk_index`.
        """
        verified: Dict[int, ChunkCheckpoint] = {}
        for rec in self._records:
            if rec.record_type == "CHUNK_CHECKPOINT" and rec.transfer_id == transfer_id:
                if attempt_id is not None and rec.attempt_id != attempt_id:
                    continue
                p = rec.payload
                idx = int(p["chunk_index"])
                verified[idx] = ChunkCheckpoint(
                    transfer_id=rec.transfer_id,
                    attempt_id=rec.attempt_id,
                    package_id=str(p["package_id"]),
                    chunk_index=idx,
                    opaque_chunk_id=str(p["opaque_chunk_id"]),
                    cipher_size=int(p["cipher_size"]),
                    cipher_sha256=str(p["cipher_sha256"]),
                    plain_size=int(p["plain_size"]),
                    plain_sha256=str(p["plain_sha256"]),
                    verified_at_utc=str(p["verified_at_utc"]),
                    operator=rec.operator,
                )
        return verified

    def record_acknowledged_files(
        self,
        *,
        transfer_id: str,
        attempt_id: str,
        operator: str,
        device_id: str,
        files_map: Dict[str, str],  # relative_path -> sha256
    ) -> JournalRecord:
        """
        Records files acknowledged by a verified server COMMITTED receipt so incremental
        discovery can skip unchanged file versions on subsequent runs.
        """
        return self.append_record(
            "FILE_ACKNOWLEDGED",
            transfer_id=transfer_id,
            attempt_id=attempt_id,
            operator=operator,
            payload={
                "device_id": device_id,
                "files": files_map,
            },
        )

    def get_acknowledged_file_hashes(self, device_id: str) -> Dict[str, str]:
        """Returns mapping of relative_path -> latest acknowledged sha256 for `device_id`."""
        ack: Dict[str, str] = {}
        for rec in self._records:
            if rec.record_type == "FILE_ACKNOWLEDGED" and rec.payload.get("device_id") == device_id:
                files = rec.payload.get("files", {})
                if isinstance(files, dict):
                    for rel_p, digest in files.items():
                        ack[str(rel_p)] = str(digest)
        return ack

    def get_transfer_history(self) -> List[Dict[str, Any]]:
        """
        Aggregates an immutable read-only summary of all transfers recorded in the journal
        for the UI History view (Section 16).
        """
        transfers: Dict[str, Dict[str, Any]] = {}
        for rec in self._records:
            if not rec.transfer_id or rec.transfer_id == "SYSTEM":
                continue
            entry = transfers.setdefault(
                rec.transfer_id,
                {
                    "transfer_id": rec.transfer_id,
                    "operator": rec.operator,
                    "attempts": set(),
                    "started_at_utc": rec.timestamp_utc,
                    "updated_at_utc": rec.timestamp_utc,
                    "current_state": "READY",
                    "verified_chunks": 0,
                    "verified_bytes": 0,
                    "receipt_status": "PENDING",
                    "last_error": None,
                },
            )
            entry["attempts"].add(rec.attempt_id)
            entry["updated_at_utc"] = rec.timestamp_utc
            if rec.record_type == "STATE_TRANSITION":
                to_st = rec.payload.get("to_state", entry["current_state"])
                entry["current_state"] = to_st
                if to_st in ("COMMITTED", "ACKNOWLEDGED", "USB_CLEANED"):
                    entry["receipt_status"] = to_st
                if rec.payload.get("reason") and to_st in ("INTERRUPTED", "QUARANTINED", "STOPPED"):
                    entry["last_error"] = rec.payload.get("reason")
            elif rec.record_type == "CHUNK_CHECKPOINT":
                entry["verified_chunks"] += 1
                entry["verified_bytes"] += int(rec.payload.get("plain_size", 0))

        result = []
        for t_id, info in transfers.items():
            info_copy = dict(info)
            info_copy["attempts"] = sorted(info["attempts"])
            result.append(info_copy)
        return result


class TransferStateMachine:
    """
    Enforces valid transfer lifecycle transitions and logs every transition
    into the append-only journal.
    """

    def __init__(
        self,
        journal: AppendOnlyJournal,
        *,
        transfer_id: str,
        attempt_id: str,
        operator: str,
        initial_state: TransferState = TransferState.READY,
    ) -> None:
        self._journal = journal
        self._transfer_id = transfer_id
        self._attempt_id = attempt_id
        self._operator = operator
        self._state = initial_state

    @property
    def state(self) -> TransferState:
        return self._state

    @property
    def transfer_id(self) -> str:
        return self._transfer_id

    @property
    def attempt_id(self) -> str:
        return self._attempt_id

    def transition_to(self, next_state: TransferState, *, reason: str = "") -> JournalRecord:
        allowed = ALLOWED_TRANSITIONS.get(self._state, set())
        if next_state not in allowed:
            raise StateTransitionError(
                f"Illegal state transition for {self._transfer_id}: {self._state.value} -> {next_state.value}"
            )
        prev_state = self._state
        self._state = next_state
        return self._journal.append_record(
            "STATE_TRANSITION",
            transfer_id=self._transfer_id,
            attempt_id=self._attempt_id,
            operator=self._operator,
            payload={
                "from_state": prev_state.value,
                "reason": reason,
                "to_state": next_state.value,
            },
        )
