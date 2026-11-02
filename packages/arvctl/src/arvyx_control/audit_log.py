from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .filesystem import durable_mkdir, fsync_directory
from .locks import exclusive_lock
from .operation_journal import (
    claim_audit_receipt,
    journal_path,
    mark_audit_receipt_written,
    migrate_legacy_audit_operations,
    pending_operation_count,
)


GENESIS = "0" * 64
_TAIL_BYTES = 8192
_READINESS_TAIL_BYTES = 4 * 1024 * 1024


class AuditCorruptionError(OSError):
    """Raised when appending would extend a malformed or torn audit chain."""


@dataclass(frozen=True)
class AuditVerifyResult:
    ok: bool
    events: int
    first_break_line: int | None

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "events": self.events, "first_break_line": self.first_break_line}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def _persist_audit(path: Path, record: dict[str, Any] | None = None) -> None:
    """Persist new bytes (or a recovered record), then their directory entry.

    Callers hold the audit lock. Recovery must repeat both barriers before
    acknowledging a receipt, even when the record is already visible.
    """
    from .replica_authority import assert_bound_authority
    assert_bound_authority()
    durable_mkdir(path.parent)
    with path.open("a" if record is not None else "r+", encoding="utf-8") as handle:
        if record is not None:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    fsync_directory(path.parent)


def _append_locked(path: Path, event: dict[str, Any]) -> dict[str, Any]:
    record = {**event, "ts": event.get("ts") or _now()}
    prev_hash = _last_hash(path)
    record["prev_hash"] = prev_hash
    record["hash"] = _chain_hash(prev_hash, record)
    _persist_audit(path, record)
    return record


def append_audit(path: Path, event: dict[str, Any]) -> dict[str, Any]:
    """Append a hash-chained record with file and namespace durability."""
    from .replica_authority import assert_bound_authority
    assert_bound_authority()
    durable_mkdir(path.parent)
    with exclusive_lock(path.with_suffix(path.suffix + ".lock")):
        return _append_locked(path, event)


def append_audit_once(path: Path, event: dict[str, Any]) -> dict[str, Any]:
    """Deduplicate event IDs against receipts and the retained audit log.

    This is not an exactly-once guarantee across independent log/sidecar
    deletion or rollback. A written receipt without its record fails closed.
    """
    from .replica_authority import assert_bound_authority
    assert_bound_authority()
    event_id = event.get("event_id")
    if not isinstance(event_id, str) or not event_id:
        raise ValueError("append_audit_once requires event_id")
    durable_mkdir(path.parent)
    receipt_path = journal_path(path)
    with exclusive_lock(path.with_suffix(path.suffix + ".lock")):
        receipt_state = claim_audit_receipt(receipt_path, event_id)
        if receipt_state in ("written", "pending"):
            existing = _find_event(path, event_id)
            if existing is not None:
                _persist_audit(path)
                if receipt_state != "written":
                    mark_audit_receipt_written(receipt_path, event_id)
                return existing
            if receipt_state == "written":
                raise AuditCorruptionError("written audit receipt has no audit record")
        record = _append_locked(path, event)
        mark_audit_receipt_written(receipt_path, event_id)
        return record


def _find_event(path: Path, event_id: str) -> dict[str, Any] | None:
    if not path.exists():
        return None
    found = None
    prev_hash = GENESIS
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.endswith("\n"):
                raise AuditCorruptionError("audit log has a torn final record")
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditCorruptionError("audit log contains malformed JSON") from exc
            if (not isinstance(record, dict) or record.get("prev_hash") != prev_hash
                    or _chain_hash(prev_hash, record) != record.get("hash")):
                raise AuditCorruptionError("audit log contains an invalid chain")
            prev_hash = record["hash"]
            if record.get("event_id") == event_id:
                found = record
    return found


def verify_chain(path: Path) -> AuditVerifyResult:
    if not path.exists():
        return AuditVerifyResult(ok=True, events=0, first_break_line=None)
    payload = path.read_bytes()
    return _verify_snapshot(payload)


def _verify_snapshot(payload: bytes) -> AuditVerifyResult:
    if payload and not payload.endswith(b"\n"):
        return AuditVerifyResult(ok=False, events=0, first_break_line=1)
    try:
        return _verify_lines(payload.decode("utf-8").splitlines())
    except UnicodeDecodeError:
        return AuditVerifyResult(ok=False, events=0, first_break_line=1)


def verify_chain_tail(path: Path, max_bytes: int = _READINESS_TAIL_BYTES) -> AuditVerifyResult:
    """Verify a bounded audit tail for frequent container health checks.

    Full-history verification remains the release/audit gate. This function
    validates the final records and their links without rereading an unbounded
    log every 30 seconds.
    """
    if not path.exists():
        return AuditVerifyResult(ok=True, events=0, first_break_line=None)
    size = path.stat().st_size
    offset = max(0, size - max_bytes)
    with path.open("rb") as handle:
        handle.seek(offset)
        payload = handle.read(max_bytes + 1)
    if payload and not payload.endswith(b"\n"):
        return AuditVerifyResult(ok=False, events=0, first_break_line=1)
    if len(payload) > max_bytes:
        return AuditVerifyResult(ok=False, events=0, first_break_line=1)
    if offset:
        newline = payload.find(b"\n")
        if newline < 0:
            return AuditVerifyResult(ok=False, events=0, first_break_line=1)
        payload = payload[newline + 1 :]
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return AuditVerifyResult(ok=False, events=0, first_break_line=1)
    nonempty = [line for line in lines if line.strip()]
    if not nonempty:
        return AuditVerifyResult(ok=not bool(offset), events=0, first_break_line=1 if offset else None)
    try:
        first = json.loads(nonempty[0])
    except json.JSONDecodeError:
        return AuditVerifyResult(ok=False, events=0, first_break_line=1)
    if not isinstance(first, dict):
        return AuditVerifyResult(ok=False, events=0, first_break_line=1)
    initial_prev = str(first.get("prev_hash", "")) if offset else GENESIS
    return _verify_lines_from(nonempty, initial_prev)


def pending_operations(path: Path) -> int:
    """Count pending operations through the indexed durable sidecar.

    When an audit log is present, the operation journal is migrated/stamped
    first so schema-only or partially written sidecars cannot hide unresolved
    intent/outcome pairs. Real pending rows remain visible after migration.
    """
    sidecar = journal_path(path)
    if path.exists():
        sidecar = migrate_legacy_audit_operations(path)
    elif not sidecar.exists():
        return 0
    return pending_operation_count(sidecar)


def _verify_lines(lines: list[str]) -> AuditVerifyResult:
    return _verify_lines_from(lines, GENESIS)


def _verify_lines_from(lines: list[str], initial_prev: str) -> AuditVerifyResult:
    prev_hash = initial_prev
    events = 0
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return AuditVerifyResult(ok=False, events=events, first_break_line=line_number)
        if not isinstance(record, dict):
            return AuditVerifyResult(ok=False, events=events, first_break_line=line_number)
        stored_hash = record.get("hash")
        if record.get("prev_hash") != prev_hash or _chain_hash(prev_hash, record) != stored_hash:
            return AuditVerifyResult(ok=False, events=events, first_break_line=line_number)
        prev_hash = str(stored_hash)
        events += 1
    return AuditVerifyResult(ok=True, events=events, first_break_line=None)


@dataclass(frozen=True)
class AuditBrowseResult:
    events: list[dict[str, Any]]
    total: int
    chain: AuditVerifyResult

    def to_dict(self) -> dict[str, Any]:
        return {"events": self.events, "total": self.total, "chain": self.chain.to_dict()}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def recent_events(path: Path, limit: int = 50) -> AuditBrowseResult:
    """Return the tail of the audit log plus its tamper-evidence status.

    The chain hashes themselves are dropped from the browse projection: the
    operator wants who/what/decision, and verify status is reported once.
    """
    payload = path.read_bytes() if path.exists() else b""
    chain = _verify_snapshot(payload)
    # Projection and verification share the same bytes, including the final
    # delimiter. Replacement decoding keeps damaged evidence browsable.
    lines = payload.decode("utf-8", errors="replace").splitlines()
    records: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append({key: value for key, value in record.items() if key not in ("prev_hash", "hash")})
    tail = records[-limit:] if limit > 0 else records
    return AuditBrowseResult(events=tail, total=len(records), chain=chain)


def default_audit_log(state: Path) -> Path:
    return state.parent / "audit-log.jsonl"


def _chain_hash(prev_hash: str, record: dict[str, Any]) -> str:
    body = {key: value for key, value in record.items() if key != "hash"}
    canonical = json.dumps(body, sort_keys=True)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def _last_hash(path: Path) -> str:
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return GENESIS
    if size == 0:
        return GENESIS
    with path.open("rb") as handle:
        handle.seek(-1, os.SEEK_END)
        if handle.read(1) != b"\n":
            raise AuditCorruptionError("audit log has a torn final record")
    # Grow the tail window until the complete final record is available.
    window = _TAIL_BYTES
    while True:
        with path.open("rb") as handle:
            handle.seek(max(0, size - window))
            lines = [line for line in handle.read().splitlines() if line.strip()]
        if lines:
            try:
                record = json.loads(lines[-1].decode("utf-8"))
                if not isinstance(record, dict):
                    raise AuditCorruptionError("audit final record must be a JSON object")
                digest = record.get("hash")
                if not isinstance(digest, str) or len(digest) != 64:
                    raise AuditCorruptionError("audit final record has no valid hash")
                int(digest, 16)
                return digest
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
            except ValueError as exc:
                raise AuditCorruptionError("audit final record has an invalid hash") from exc
        if window >= size:
            raise AuditCorruptionError("audit final record is malformed")
        window = min(window * 2, size)


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")
