from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3

from .control import parse_event_lines, read_events
from .outbox import OUTBOX_EVENT_TYPES


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  owner TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  command_hash TEXT NOT NULL,
  requester TEXT NOT NULL,
  approver TEXT,
  status TEXT NOT NULL,
  reason TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS handoffs (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  from_agent TEXT NOT NULL,
  to_agent TEXT NOT NULL,
  status TEXT NOT NULL,
  summary TEXT NOT NULL,
  reviewer TEXT NOT NULL DEFAULT '',
  review_decision TEXT NOT NULL DEFAULT '',
  review_notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bus_messages (
  id TEXT PRIMARY KEY,
  channel TEXT NOT NULL,
  actor TEXT NOT NULL,
  severity TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threads (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL,
  actor TEXT NOT NULL,
  target TEXT NOT NULL,
  channel TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL,
  pending INTEGER NOT NULL,
  unread INTEGER NOT NULL,
  acked_by TEXT NOT NULL DEFAULT '',
  done_by TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  latest_at TEXT NOT NULL,
  acked_at TEXT NOT NULL DEFAULT '',
  done_at TEXT NOT NULL DEFAULT '',
  read_at TEXT NOT NULL DEFAULT '',
  completion_artifact TEXT NOT NULL DEFAULT '',
  completion_anchor TEXT NOT NULL DEFAULT '',
  evidence_artifact TEXT NOT NULL DEFAULT '',
  evidence_anchor TEXT NOT NULL DEFAULT '',
  evidence_method TEXT NOT NULL DEFAULT '',
  retirement_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS outbox (
  id TEXT PRIMARY KEY,
  subject_id TEXT NOT NULL,
  target TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  epoch INTEGER NOT NULL,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  next_attempt_at TEXT NOT NULL,
  lease_owner TEXT NOT NULL,
  lease_expires_at TEXT NOT NULL,
  failures INTEGER NOT NULL,
  failure_detail TEXT NOT NULL,
  delivered_at TEXT NOT NULL,
  receipt_status TEXT NOT NULL,
  receipt_by TEXT NOT NULL,
  receipt_at TEXT NOT NULL,
  receipt_detail TEXT NOT NULL,
  retirement_json TEXT NOT NULL DEFAULT '{}'
);
"""


@dataclass(frozen=True)
class StoreSyncResult:
    db: str
    events: int
    source_events: int
    tasks: int
    approvals: int
    handoffs: int
    bus_messages: int
    threads: int
    outbox: int
    retention: str

    def to_dict(self) -> dict[str, object]:
        return {
            "db": self.db,
            "events": self.events,
            "source_events": self.source_events,
            "tasks": self.tasks,
            "approvals": self.approvals,
            "handoffs": self.handoffs,
            "bus_messages": self.bus_messages,
            "threads": self.threads,
            "outbox": self.outbox,
            "retention": self.retention,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class StoreManifestResult:
    state: str
    events: int
    sha256: str
    first_timestamp: str | None
    last_timestamp: str | None
    event_types: dict[str, int]
    retention: str

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "events": self.events,
            "sha256": self.sha256,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "event_types": self.event_types,
            "retention": self.retention,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def sync_sqlite(state: Path, db: Path, retain_events: int | None = None) -> StoreSyncResult:
    if retain_events is not None and retain_events < 1:
        raise ValueError("--retain-events must be greater than zero")
    db.parent.mkdir(parents=True, exist_ok=True)
    events = read_events(state)
    retained_events = events[-retain_events:] if retain_events is not None else events
    from .control import _project_handoffs
    handoffs = _project_handoffs(state, events)
    with closing(sqlite3.connect(db)) as conn, conn:
        conn.executescript(SCHEMA)
        outbox_columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(outbox)")}
        if outbox_columns and "failures" not in outbox_columns:
            conn.execute("ALTER TABLE outbox ADD COLUMN failures INTEGER NOT NULL DEFAULT 0")
        if "retirement_json" not in outbox_columns:
            conn.execute("ALTER TABLE outbox ADD COLUMN retirement_json TEXT NOT NULL DEFAULT '{}'")
        thread_columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(threads)")}
        if "retirement_json" not in thread_columns:
            conn.execute("ALTER TABLE threads ADD COLUMN retirement_json TEXT NOT NULL DEFAULT '{}'")
        for column in (
            "completion_artifact", "completion_anchor", "evidence_artifact",
            "evidence_anchor", "evidence_method",
        ):
            if column not in thread_columns:
                conn.execute(f"ALTER TABLE threads ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
        for table in ("tasks", "handoffs"):
            columns = {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}
            if "retirement_json" not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN retirement_json TEXT NOT NULL DEFAULT '{{}}'")
        handoff_columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(handoffs)")}
        if "accepted_by" not in handoff_columns:
            conn.execute("ALTER TABLE handoffs ADD COLUMN accepted_by TEXT NOT NULL DEFAULT ''")
        conn.execute("PRAGMA user_version = 2")
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM tasks")
        conn.execute("DELETE FROM approvals")
        conn.execute("DELETE FROM handoffs")
        conn.execute("DELETE FROM bus_messages")
        conn.execute("DELETE FROM threads")
        conn.execute("DELETE FROM outbox")
        for event in retained_events:
            payload_json = json.dumps(event.payload, sort_keys=True)
            conn.execute(
                # OR REPLACE (like the projection tables) so a duplicated or
                # re-applied event id cannot abort the whole sync with an
                # IntegrityError and leave no database at all
                """
                INSERT OR REPLACE INTO events (id, type, subject_id, timestamp, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event.id, event.type, event.task_id, event.timestamp, payload_json),
            )
        for event in events:
            if event.type in {"task.created", "task.completed", "task.operator_archived"}:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO tasks (id, title, owner, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.payload["id"],
                        event.payload["title"],
                        event.payload["owner"],
                        event.payload["status"],
                        event.payload["created_at"],
                        event.payload["updated_at"],
                    ),
                )
            if event.type in {"task.created", "task.completed", "task.operator_archived"}:
                conn.execute("UPDATE tasks SET retirement_json = ? WHERE id = ?",
                             (json.dumps(event.payload.get("retirement", {}), sort_keys=True), event.task_id))
            if event.type in {"approval.requested", "approval.approved", "approval.consumed"}:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO approvals
                      (id, command_hash, requester, approver, status, reason, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.payload["id"],
                        event.payload["command_hash"],
                        event.payload["requester"],
                        event.payload.get("approver"),
                        event.payload["status"],
                        event.payload["reason"],
                        event.payload["created_at"],
                        event.payload["updated_at"],
                    ),
                )
            if event.type in {"handoff.created", "handoff.accepted", "handoff.reviewed", "handoff.completed", "handoff.operator_archived"}:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO handoffs
                      (id, title, from_agent, to_agent, status, summary,
                       reviewer, review_decision, review_notes, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.payload["id"],
                        event.payload["title"],
                        event.payload["from_agent"],
                        event.payload["to_agent"],
                        event.payload["status"],
                        event.payload["summary"],
                        event.payload.get("reviewer", ""),
                        event.payload.get("review_decision", ""),
                        event.payload.get("review_notes", ""),
                        event.payload["created_at"],
                        event.payload["updated_at"],
                    ),
                )
            if event.type in {"handoff.created", "handoff.accepted", "handoff.reviewed", "handoff.completed", "handoff.operator_archived"}:
                conn.execute("UPDATE handoffs SET retirement_json = ?, accepted_by = ? WHERE id = ?",
                             (json.dumps(event.payload.get("retirement", {}), sort_keys=True), handoffs[event.task_id].accepted_by, event.task_id))
            if event.type == "bus.message":
                conn.execute(
                    """
                    INSERT OR REPLACE INTO bus_messages
                      (id, channel, actor, severity, message, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.payload["id"],
                        event.payload["channel"],
                        event.payload["actor"],
                        event.payload["severity"],
                        event.payload["message"],
                        event.payload["created_at"],
                    ),
                )
            if event.type in {
                "thread.created",
                "thread.message.posted",
                "thread.acknowledged",
                "thread.done",
                "thread.read",
                "thread.retired",
                "thread.operator_archived",
            }:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO threads
                      (id, type, actor, target, channel, severity, title, body, status,
                       pending, unread, acked_by, done_by,
                       created_at, latest_at, acked_at, done_at, read_at,
                       completion_artifact, completion_anchor, evidence_artifact,
                       evidence_anchor, evidence_method, retirement_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.payload["id"],
                        event.payload["type"],
                        event.payload["actor"],
                        event.payload["target"],
                        event.payload["channel"],
                        event.payload["severity"],
                        event.payload["title"],
                        event.payload["body"],
                        event.payload["status"],
                        int(bool(event.payload.get("pending"))),
                        int(bool(event.payload.get("unread"))),
                        event.payload.get("acked_by", ""),
                        event.payload.get("done_by", ""),
                        event.payload["created_at"],
                        event.payload["latest_at"],
                        event.payload.get("acked_at", ""),
                        event.payload.get("done_at", ""),
                        event.payload.get("read_at", ""),
                        event.payload.get("completion_artifact", ""),
                        event.payload.get("completion_anchor", ""),
                        event.payload.get("evidence_artifact", ""),
                        event.payload.get("evidence_anchor", ""),
                        event.payload.get("evidence_method", ""),
                        json.dumps(event.payload.get("retirement", {}), sort_keys=True),
                    ),
                )
            if event.type in OUTBOX_EVENT_TYPES:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO outbox
                      (id, subject_id, target, payload_json, payload_hash, epoch, status,
                       attempts, created_at, updated_at, next_attempt_at, lease_owner,
                       lease_expires_at, failures, failure_detail, delivered_at, receipt_status,
                       receipt_by, receipt_at, receipt_detail, retirement_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.payload["id"], event.payload["subject_id"], event.payload["target"],
                        json.dumps(event.payload["payload"], sort_keys=True), event.payload["payload_hash"],
                        event.payload["epoch"], event.payload["status"], event.payload["attempts"],
                        event.payload["created_at"], event.payload["updated_at"], event.payload["next_attempt_at"],
                        event.payload.get("lease_owner", ""), event.payload.get("lease_expires_at", ""),
                        event.payload.get("failures", 0), event.payload.get("failure_detail", ""),
                        event.payload.get("delivered_at", ""),
                        event.payload.get("receipt_status", ""), event.payload.get("receipt_by", ""),
                        event.payload.get("receipt_at", ""), event.payload.get("receipt_detail", ""),
                        json.dumps(event.payload.get("retirement", {}), sort_keys=True),
                    ),
                )
        conn.commit()
        event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        task_count = conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        approval_count = conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0]
        handoff_count = conn.execute("SELECT COUNT(*) FROM handoffs").fetchone()[0]
        bus_count = conn.execute("SELECT COUNT(*) FROM bus_messages").fetchone()[0]
        thread_count = conn.execute("SELECT COUNT(*) FROM threads").fetchone()[0]
        outbox_count = conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
    return StoreSyncResult(
        db=str(db),
        events=int(event_count),
        source_events=len(events),
        tasks=int(task_count),
        approvals=int(approval_count),
        handoffs=int(handoff_count),
        bus_messages=int(bus_count),
        threads=int(thread_count),
        outbox=int(outbox_count),
        retention=f"sqlite-events:last-{retain_events}" if retain_events is not None else "sqlite-events:all",
    )


def manifest_state(state: Path) -> StoreManifestResult:
    raw = state.read_bytes() if state.exists() else b""
    # Digest and metadata must describe the same immutable byte snapshot even
    # when a normal producer appends while this receipt is being computed.
    events = parse_event_lines(raw.decode("utf-8"))
    event_types: dict[str, int] = {}
    for event in events:
        event_types[event.type] = event_types.get(event.type, 0) + 1
    timestamps = [event.timestamp for event in events]
    return StoreManifestResult(
        state=str(state),
        events=len(events),
        sha256=hashlib.sha256(raw).hexdigest(),
        first_timestamp=min(timestamps) if timestamps else None,
        last_timestamp=max(timestamps) if timestamps else None,
        event_types=dict(sorted(event_types.items())),
        retention="append-only-jsonl",
    )
