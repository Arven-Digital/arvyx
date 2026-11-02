"""Task-scoped, explicitly submitted external progress/results.

Integration interface (no dependency on the grant implementation): construct
ExternalWork(path, authorize=callback). On EVERY operation callback receives the
trusted authenticated actor, exact task ID and 'read' or 'submit', and returns a
fresh WorkAuthorization or None. The adapter must resolve current resource AND
operation authority, expiry, revocation and explicit observer membership from the
server-side authority, not request-body claims. Never cache the callback result
across requests. A snapshot is valid only for this synchronous operation; callers
must serialize grant mutation with this call if strict revocation linearization
is required. Pass the boundary-authenticated actor, never a claimed actor field.

Records are append-only and grant-bound. Observers can read, never submit on a
recipient's behalf. Audit metadata and successful submissions commit together;
audit contains no submitted content. This is an independent local primitive, not
HTTP/MCP wiring, a grant issuer, a transcript collector or a reasoning collector.
Only intentional public progress/result text is accepted, not arbitrary telemetry.
The host must protect the database and route audit export through its own scoped
operator authorization; there is deliberately no global listing/audit API here.
"""
from dataclasses import dataclass
import hashlib
import math
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from typing import NoReturn


@dataclass(frozen=True)
class WorkAuthorization:
    task_id: str
    grant_id: str
    recipient: str
    observers: frozenset[str]
    operations: frozenset[str]
    expires_at: float
    revoked: bool
    provenance: str
    observer_operations: frozenset[str] = frozenset()


def _text(value, maximum):
    if not isinstance(value, str) or not value.strip() or '\x00' in value:
        raise ValueError('bounded nonempty text required')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeError as exc:
        raise ValueError('valid UTF-8 required') from exc
    if size > maximum:
        raise ValueError('text exceeds byte bound')
    return value


def validate_submission(kind, text, source):
    if kind not in ('progress', 'result'):
        raise ValueError('only intentional progress/result submissions allowed')
    _text(text, 16384)
    _text(source, 512)


def validate_submission_id(value):
    """Identifiers are durable retry metadata, never a credential container."""
    from .security import contains_literal_secret
    _text(value, 256)
    if contains_literal_secret(value):
        raise ValueError('secret-shaped submission identifier refused')
    return value


class ExternalWork:
    def __init__(self, path, *, authorize: Callable[[str, str, str], WorkAuthorization | None],
                 clock: Callable[[], float] = time.time):
        if not callable(authorize) or not callable(clock):
            raise TypeError('authorization and clock callbacks required')
        self._authorize = authorize
        self._clock = clock
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript('''
            CREATE TABLE IF NOT EXISTS external_work (
                id TEXT PRIMARY KEY, task_id TEXT NOT NULL, grant_id TEXT NOT NULL,
                actor TEXT NOT NULL, kind TEXT NOT NULL, text TEXT NOT NULL,
                source TEXT NOT NULL, provenance TEXT NOT NULL,
                sha256 TEXT NOT NULL, created_at REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS external_work_scope
                ON external_work(task_id, grant_id);
            CREATE TABLE IF NOT EXISTS external_work_audit (
                id TEXT PRIMARY KEY, task_id TEXT NOT NULL, actor TEXT NOT NULL,
                action TEXT NOT NULL, decision TEXT NOT NULL, grant_id TEXT,
                record_id TEXT, created_at REAL NOT NULL);
        ''')

    def close(self):
        with self._lock:
            self._db.close()

    def _audit(self, task, actor, action, decision, grant=None, record=None):
        self._db.execute('INSERT INTO external_work_audit VALUES (?,?,?,?,?,?,?,?)',
                         (uuid.uuid4().hex, task, actor, action, decision,
                          grant, record, self._clock()))

    def _deny(self, task, actor, action) -> NoReturn:
        self._audit(task, actor, action, 'deny')
        self._db.commit()
        raise PermissionError('work unavailable')

    def _access(self, task, actor, action):
        _text(task, 256)
        _text(actor, 256)
        operation = 'submit' if action == 'submit' else 'read'
        grant = self._authorize(actor, task, operation)
        now = self._clock()
        valid = (
            isinstance(grant, WorkAuthorization)
            and grant.task_id == task and grant.revoked is False
            and isinstance(grant.expires_at, (int, float))
            and not isinstance(grant.expires_at, bool)
            and math.isfinite(grant.expires_at) and now < grant.expires_at
            and isinstance(grant.observers, frozenset)
            and isinstance(grant.operations, frozenset)
            and isinstance(grant.observer_operations, frozenset)
            and ((actor == grant.recipient and operation in grant.operations) or
                 (operation == 'read' and actor in grant.observers
                  and operation in (grant.operations | grant.observer_operations)))
        )
        if not valid or not isinstance(grant, WorkAuthorization):
            self._deny(task, actor, action)
        try:
            _text(grant.grant_id, 256)
            _text(grant.recipient, 256)
            _text(grant.provenance, 2048)
        except ValueError:
            self._deny(task, actor, action)
        return grant

    def submit(self, task_id, *, actor, kind, text, source, record_id=None):
        """Append or explicitly retry a trusted composition's durable attempt ID.

        Replays reauthorize first and must match every bound scope/content field.
        Standalone callers omitting record_id retain append-only UUID behavior.
        """
        if record_id is not None:
            validate_submission_id(record_id)
        with self._lock:
            grant = self._access(task_id, actor, 'submit')
            try:
                validate_submission(kind, text, source)
                if record_id is not None:
                    _text(record_id, 256)
            except ValueError:
                with self._db:
                    self._audit(task_id, actor, 'submit', 'reject', grant.grant_id)
                raise
            row = dict(id=record_id or uuid.uuid4().hex, task_id=task_id,
                       grant_id=grant.grant_id, actor=actor, kind=kind,
                       text=text, source=source, provenance=grant.provenance,
                       sha256=hashlib.sha256(text.encode('utf-8')).hexdigest(),
                       created_at=self._clock())
            with self._db:
                # Acquire the writer reservation before the final freshness
                # check, so the first INSERT cannot wait for another writer.
                if not self._db.in_transaction:
                    self._db.execute('BEGIN IMMEDIATE')
                existing = self._db.execute('SELECT * FROM external_work WHERE id=?', (row['id'],)).fetchone()
                # Preparation/SELECT can wait on another database writer.
                # Reauthorize the append AND explicit replay at admission.
                current = self._access(task_id, actor, 'submit')
                if current != grant:
                    raise ValueError('work authorization changed before append')
                from .public_onboarding_api import assert_request_active
                assert_request_active()
                if existing is not None:
                    if any(existing[key] != row[key] for key in
                           ('task_id', 'grant_id', 'actor', 'kind', 'text', 'source', 'provenance', 'sha256')):
                        raise ValueError('work attempt already bound to other content or scope')
                    row = dict(existing)
                else:
                    self._db.execute('INSERT INTO external_work VALUES (?,?,?,?,?,?,?,?,?,?)', tuple(row.values()))
                self._audit(task_id, actor, 'submit', 'allow', grant.grant_id, row['id'])
            return row

    def list_page(self, task_id, *, actor, limit=100, cursor=None):
        """Append-order keyset page; cursor is an existing record in this grant.

        Reauthorize every page. Concurrent appends do not shift earlier positions;
        new records may appear on subsequent pages, not a frozen snapshot.
        """
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('limit must be 1..100')
        with self._lock:
            grant = self._access(task_id, actor, 'list')
            after = 0
            if cursor is not None:
                _text(cursor, 256)
                anchor = self._db.execute('''SELECT rowid FROM external_work
                    WHERE task_id=? AND grant_id=? AND actor=? AND id=?''',
                    (task_id, grant.grant_id, grant.recipient, cursor)).fetchone()
                if anchor is None:
                    raise ValueError('cursor unavailable in this grant')
                after = anchor['rowid']
            rows = self._db.execute('''SELECT * FROM external_work
                WHERE task_id=? AND grant_id=? AND actor=? AND rowid>?
                ORDER BY rowid LIMIT ?''',
                (task_id, grant.grant_id, grant.recipient, after, limit + 1)).fetchall()
            has_more = len(rows) > limit
            items = [dict(row) for row in rows[:limit]]
            with self._db:
                self._audit(task_id, actor, 'list', 'allow', grant.grant_id)
            return dict(items=items, has_more=has_more,
                        next_cursor=items[-1]['id'] if has_more else None)

    def list(self, task_id, *, actor, limit=100):
        # Compatibility for existing local/API consumers of a plain list.
        return self.list_page(task_id, actor=actor, limit=limit)['items']

    def get(self, task_id, record_id, *, actor):
        with self._lock:
            grant = self._access(task_id, actor, 'get')
            _text(record_id, 256)
            row = self._db.execute('''SELECT * FROM external_work
                WHERE task_id=? AND grant_id=? AND actor=? AND id=?''',
                (task_id, grant.grant_id, grant.recipient, record_id)).fetchone()
            if row is None:
                self._deny(task_id, actor, 'get')
            with self._db:
                self._audit(task_id, actor, 'get', 'allow', grant.grant_id, record_id)
            return dict(row)
