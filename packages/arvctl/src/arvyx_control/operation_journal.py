from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import uuid


KEY_MIN_LENGTH = 16
KEY_MAX_LENGTH = 256
KEY_PATTERN = r"^[!-~]+$"
KEY_RE = re.compile(rf"[!-~]{{{KEY_MIN_LENGTH},{KEY_MAX_LENGTH}}}")


def idempotency_key_schema(domain_max: int = KEY_MAX_LENGTH) -> dict[str, object]:
    return {"type": "string", "minLength": KEY_MIN_LENGTH,
            "maxLength": min(domain_max, KEY_MAX_LENGTH), "pattern": KEY_PATTERN}
LEGACY_MIGRATION_KEY = "legacy_audit_migration"
LEGACY_MIGRATION_VALUE = "v2"


class JournalStateError(RuntimeError):
    """The durable journal cannot establish the requested operation state."""


class JournalNamespaceError(JournalStateError):
    """A claim cannot inherit another authority's operation history."""


def validate_mutation_key(value: str) -> None:
    if not isinstance(value, str) or not KEY_RE.fullmatch(value):
        raise ValueError("idempotency key must be 16-256 printable ASCII characters")
    from .security import contains_literal_secret
    if contains_literal_secret(value):
        raise ValueError("idempotency key contains a secret-shaped string")


def _namespace_identity(vault: Path, state: Path | None) -> str:
    return json.dumps({"schema": "operation-authority/v1", "vault": str(vault.resolve()),
                       "state": str(state.resolve()) if state is not None else None},
                      sort_keys=True, separators=(",", ":"))


def _bind_namespace(connection: sqlite3.Connection, vault: Path, state: Path | None) -> None:
    # The trusted entry context can retain a more specific state than a
    # vault-only library caller. Never downgrade that binding to vault-only.
    from .replica_authority import _authority
    bound = _authority.get()
    exact_state = state if state is not None else (bound[1] if bound is not None else None)
    namespace = _namespace_identity(vault, exact_state)
    row = connection.execute("SELECT value FROM journal_meta WHERE key='authority_namespace'").fetchone()
    if row is not None:
        if row[0] != namespace:
            raise JournalNamespaceError("operation journal namespace mismatch; use the original authority")
        return
    if connection.execute("SELECT 1 FROM operations LIMIT 1").fetchone() is not None:
        # Neither a completed row nor a resumable intent proves which vault or
        # state produced it. Inspection/reconciliation remains available; an
        # ordinary request is never an operator-confirmed migration ceremony.
        raise JournalNamespaceError("legacy operation journal namespace is unbound; reconciliation required")
    connection.execute("INSERT INTO journal_meta(key,value) VALUES('authority_namespace',?)", (namespace,))


_SCHEMA = """
CREATE TABLE IF NOT EXISTS operations (
    operation_id TEXT PRIMARY KEY,
    principal_scope TEXT NOT NULL,
    action TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    dispatch_owner TEXT,
    safe_outcome_json TEXT,
    http_status INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(principal_scope, action, key_hash)
);
CREATE INDEX IF NOT EXISTS operations_pending_idx
ON operations(state, updated_at)
WHERE state NOT IN ('completed', 'rejected');
CREATE TABLE IF NOT EXISTS audit_receipts (
    event_id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK(state IN ('pending', 'written')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS journal_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class OperationClaim:
    operation_id: str
    state: str
    created: bool
    conflict: bool = False
    safe_outcome: dict[str, object] | None = None


@dataclass(frozen=True)
class OperationRecord:
    operation_id: str
    principal_scope: str
    action: str
    state: str
    safe_outcome: dict[str, object] | None
    http_status: int | None
    created_at: str
    updated_at: str


def journal_path(audit_log: Path) -> Path:
    return audit_log.with_name(f"{audit_log.name}.operations.sqlite3")


def migrate_legacy_audit_operations(audit_log: Path) -> Path:
    """Bootstrap the durable operation sidecar from a pre-journal audit log.

    Large legacy deployments must not look permanently unhealthy merely because
    the sidecar is absent. Scan the full audit under lock, materialize any
    unresolved intent/outcome pairs, and stamp migration completion only after
    that work commits. File existence alone is not treated as success, so a
    schema-only/partial journal cannot hide orphan intents.
    """
    sidecar = journal_path(audit_log)
    # Hot path: stamped journals skip the audit flock so readiness probes do not
    # serialize behind writers every few seconds.
    if _legacy_migration_complete(sidecar):
        return sidecar
    lock_path = audit_log.with_suffix(audit_log.suffix + ".lock")
    from .locks import exclusive_lock

    with exclusive_lock(lock_path):
        if _legacy_migration_complete(sidecar):
            return sidecar
        pending_ids = _legacy_pending_operation_ids(audit_log)
        with _connection(sidecar) as connection:
            connection.execute("BEGIN IMMEDIATE")
            for operation_id in sorted(pending_ids):
                digest = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()
                connection.execute(
                    "INSERT OR IGNORE INTO operations("
                    "operation_id, principal_scope, action, key_hash, request_hash, state, dispatch_owner"
                    ") VALUES(?, ?, ?, ?, ?, 'dispatching', 'legacy-audit-migration')",
                    (
                        operation_id,
                        "legacy-audit-migration",
                        "legacy:pending-outcome",
                        digest,
                        digest,
                    ),
                )
            # A legacy intent cannot prove whether its effect ran. Upgrade only
            # the synthetic v1 migration rows; ordinary resumable intents retain
            # their existing admission semantics. No domain dispatch occurs.
            connection.execute(
                "UPDATE operations SET state='dispatching', dispatch_owner='legacy-audit-migration', "
                "updated_at=CURRENT_TIMESTAMP WHERE principal_scope='legacy-audit-migration' "
                "AND action='legacy:pending-outcome' AND state='intent_durable' "
                "AND dispatch_owner IS NULL AND safe_outcome_json IS NULL"
            )
            connection.execute(
                "INSERT OR REPLACE INTO journal_meta(key, value) VALUES(?, ?)",
                (LEGACY_MIGRATION_KEY, LEGACY_MIGRATION_VALUE),
            )
            connection.commit()
    return sidecar


def _legacy_migration_complete(path: Path) -> bool:
    if not path.exists():
        return False
    try:
        with _connection(path) as connection:
            row = connection.execute(
                "SELECT value FROM journal_meta WHERE key=?",
                (LEGACY_MIGRATION_KEY,),
            ).fetchone()
    except sqlite3.Error:
        return False
    return row is not None and str(row[0]) == LEGACY_MIGRATION_VALUE


def _legacy_pending_operation_ids(audit_log: Path) -> set[str]:
    if not audit_log.exists():
        return set()
    intents: set[str] = set()
    outcomes: set[str] = set()
    with audit_log.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError("audit log contains malformed JSON during journal migration") from exc
            operation_id = record.get("operation_id")
            if not isinstance(operation_id, str) or not operation_id:
                continue
            phase = record.get("phase")
            if phase == "intent":
                intents.add(operation_id)
            elif phase == "outcome":
                outcomes.add(operation_id)
    return intents - outcomes


def request_digest(body: dict[str, object]) -> str:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


from .replica_authority import bound_entry

@bound_entry
def claim_operation(
    path: Path,
    *,
    vault: Path,
    state: Path | None = None,
    principal_scope: str,
    action: str,
    idempotency_key: str,
    request_hash: str,
    legacy_action: str | None = None,
    legacy_request_hash: str | None = None,
) -> OperationClaim:
    # Require the actual vault explicitly: journal storage can be external to
    # the vault, so deriving its role from the SQLite path is not safe.
    from .replica_authority import assert_mutation_authority
    assert_mutation_authority(vault)
    validate_mutation_key(idempotency_key)
    key_hash = hashlib.sha256(idempotency_key.encode("ascii")).hexdigest()
    operation_id = uuid.uuid4().hex
    with _connection(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _bind_namespace(connection, vault, state)
        # Compatibility is an exact, lookup-only alias, never an INSERT value.
        # Keep lookup and fresh claim in one transaction to avoid upgrade races.
        rows = connection.execute(
            "SELECT operation_id, request_hash, state, safe_outcome_json "
            "FROM operations WHERE principal_scope=? AND action IN (?, ?) AND key_hash=?",
            (principal_scope, action, legacy_action or action, key_hash),
        ).fetchall()
        if len(rows) > 1:
            # Both spellings already exist: do not choose an outcome or dispatch.
            connection.commit()
            return OperationClaim(operation_id=str(rows[0][0]), state=str(rows[0][2]),
                                  created=False, conflict=True)
        row = rows[0] if rows else None
        if row is None:
            connection.execute(
                "INSERT INTO operations(operation_id, principal_scope, action, key_hash, request_hash, state) "
                "VALUES(?, ?, ?, ?, ?, 'claimed')",
                (operation_id, principal_scope, action, key_hash, request_hash),
            )
            connection.commit()
            return OperationClaim(operation_id=operation_id, state="claimed", created=True)
        stored_id, stored_hash, state, safe_json = row
        # Upgrade only an exact old-envelope match within the same principal,
        # action/alias and key lookup. A changed old correlation ID fails closed:
        # its semantic content cannot be reconstructed from a digest alone.
        if legacy_request_hash is not None and stored_hash == legacy_request_hash:
            connection.execute(
                "UPDATE operations SET request_hash=? WHERE operation_id=?",
                (request_hash, stored_id),
            )
            stored_hash = request_hash
        connection.commit()
    safe = json.loads(safe_json) if safe_json else None
    return OperationClaim(
        operation_id=str(stored_id),
        state=str(state),
        created=False,
        conflict=str(stored_hash) != request_hash,
        safe_outcome=safe if isinstance(safe, dict) else None,
    )


def set_operation_state(
    path: Path,
    operation_id: str,
    state: str,
    *,
    safe_outcome: dict[str, object] | None = None,
    http_status: int | None = None,
) -> None:
    safe_json = json.dumps(safe_outcome, sort_keys=True) if safe_outcome is not None else None
    with _connection(path) as connection:
        cursor = connection.execute(
            "UPDATE operations SET state=?, safe_outcome_json=COALESCE(?, safe_outcome_json), "
            "http_status=COALESCE(?, http_status), updated_at=CURRENT_TIMESTAMP WHERE operation_id=?",
            (state, safe_json, http_status, operation_id),
        )
        if cursor.rowcount != 1:
            raise JournalStateError("operation journal row is missing")
        connection.commit()


def transition_operation_state(
    path: Path,
    operation_id: str,
    *,
    expected_state: str,
    new_state: str,
) -> bool:
    """Advance one operation only when its current state still matches."""
    with _connection(path) as connection:
        cursor = connection.execute(
            "UPDATE operations SET state=?, updated_at=CURRENT_TIMESTAMP "
            "WHERE operation_id=? AND state=?",
            (new_state, operation_id, expected_state),
        )
        connection.commit()
    return cursor.rowcount == 1


def try_begin_dispatch(path: Path, operation_id: str, owner: str) -> bool:
    if not owner or len(owner) > 128:
        raise ValueError("dispatch owner must be 1-128 characters")
    with _connection(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            "UPDATE operations SET state='dispatching', dispatch_owner=?, updated_at=CURRENT_TIMESTAMP "
            "WHERE operation_id=? AND state='intent_durable' AND dispatch_owner IS NULL",
            (owner, operation_id),
        )
        connection.commit()
    return cursor.rowcount == 1


def pending_operation_count(path: Path) -> int:
    if not path.exists():
        return 0
    with _connection(path) as connection:
        row = connection.execute(
            "SELECT COUNT(*) FROM operations WHERE state NOT IN ('completed', 'rejected')"
        ).fetchone()
    return int(row[0]) if row else 0


def pending_operation_records(path: Path, *, limit: int = 100) -> list[OperationRecord]:
    if not path.exists():
        return []
    if not 1 <= limit <= 1000:
        raise ValueError("operation list limit must be 1-1000")
    with _connection(path) as connection:
        rows = connection.execute(
            "SELECT operation_id, principal_scope, action, state, safe_outcome_json, "
            "http_status, created_at, updated_at FROM operations "
            "WHERE state NOT IN ('completed', 'rejected') ORDER BY updated_at, operation_id LIMIT ?",
            (limit,),
        ).fetchall()
    return [_record_from_row(row) for row in rows]


def operation_record(path: Path, operation_id: str) -> OperationRecord | None:
    if not path.exists():
        return None
    with _connection(path) as connection:
        row = connection.execute(
            "SELECT operation_id, principal_scope, action, state, safe_outcome_json, "
            "http_status, created_at, updated_at FROM operations WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
    return _record_from_row(row) if row is not None else None


def reject_unknown_dispatch(path: Path, operation_id: str) -> bool:
    """Resolve an operator-inspected ambiguous dispatch without redispatching it."""
    with _connection(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            "UPDATE operations SET state='rejected', dispatch_owner=NULL, updated_at=CURRENT_TIMESTAMP "
            "WHERE operation_id=? AND state='dispatching'",
            (operation_id,),
        )
        connection.commit()
    return cursor.rowcount == 1


def _record_from_row(row: tuple[object, ...]) -> OperationRecord:
    safe = json.loads(str(row[4])) if row[4] else None
    return OperationRecord(
        operation_id=str(row[0]),
        principal_scope=str(row[1]),
        action=str(row[2]),
        state=str(row[3]),
        safe_outcome=safe if isinstance(safe, dict) else None,
        http_status=int(row[5]) if row[5] is not None else None,
        created_at=str(row[6]),
        updated_at=str(row[7]),
    )


def claim_audit_receipt(path: Path, event_id: str) -> str:
    if not event_id or len(event_id) > 512:
        raise ValueError("audit event_id must be 1-512 characters")
    with _connection(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT state FROM audit_receipts WHERE event_id=?", (event_id,)
        ).fetchone()
        if row is None:
            connection.execute(
                "INSERT INTO audit_receipts(event_id, state) VALUES(?, 'pending')",
                (event_id,),
            )
            connection.commit()
            return "new"
        connection.commit()
    return str(row[0])


def mark_audit_receipt_written(path: Path, event_id: str) -> None:
    with _connection(path) as connection:
        cursor = connection.execute(
            "UPDATE audit_receipts SET state='written', updated_at=CURRENT_TIMESTAMP WHERE event_id=?",
            (event_id,),
        )
        if cursor.rowcount != 1:
            raise JournalStateError("audit receipt row is missing")
        connection.commit()


def _connect(path: Path) -> sqlite3.Connection:
    from .replica_authority import assert_bound_authority
    assert_bound_authority()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5.0)
    try:
        # Claim admission is not the only journal entry point: recovery, audit
        # receipts, inspection and reject-unknown must not cross an already
        # established authority either. Check before schema/PRAGMA writes.
        from .replica_authority import _authority
        binding = _authority.get()
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='journal_meta'"
        ).fetchone() is not None:
            row = connection.execute(
                "SELECT value FROM journal_meta WHERE key='authority_namespace'"
            ).fetchone()
            if row is not None and (binding is None or row[0] != _namespace_identity(*binding)):
                raise JournalNamespaceError("operation journal namespace mismatch; use the original authority")
        # An unbound legacy journal remains inspectable/reconcilable without
        # silently adopting it. Only _bind_namespace may establish ownership.
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.executescript(_SCHEMA)
        columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(operations)")}
        if "dispatch_owner" not in columns:
            connection.execute("ALTER TABLE operations ADD COLUMN dispatch_owner TEXT")
            connection.commit()
    except BaseException:
        connection.close()
        raise
    return connection


@contextmanager
def _connection(path: Path):
    connection = _connect(path)
    try:
        yield connection
    finally:
        connection.close()
