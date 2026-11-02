"""Persistent, default-deny external delegation policy (no transport integration).

Only trusted local provisioning code may call set_authority/set_excluded, get or
 audit. Request boundaries must supply authenticated principals, never claimed
actors. Resource identifiers are exact opaque manifest IDs, not filesystem paths;
workspace expansion, exclusion classification and safe byte export belong to the
export boundary. No links, descendants or adjacent resources are inferred here.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import sqlite3
import threading
import uuid


def _text(value):
    if not isinstance(value, str) or not value.strip() or '*' in value or '\x00' in value:
        raise ValueError('explicit nonempty identifier required; no wildcard')
    return value


def _scope(values):
    if isinstance(values, (str, bytes)):
        raise ValueError('scope must be a collection of explicit identifiers')
    try:
        result = frozenset(_text(value) for value in values)
    except TypeError as exc:
        raise ValueError('invalid scope') from exc
    if not result:
        raise ValueError('empty scope')
    return result


def _utc(value):
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError('timezone-aware datetime required')
    return value.astimezone(timezone.utc)


def validate_resource_operations(resources, operations):
    """Submission has one supported consumer: an explicitly granted task."""
    if 'submit' in operations and not any(
            key.startswith('task:') and len(key) > len('task:') for key in resources):
        raise ValueError('result submission requires an explicitly selected task')


@dataclass(frozen=True)
class Grant:
    id: str
    issuer: str
    recipient: str
    resources: frozenset[str]
    operations: frozenset[str]
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    provenance: str
    parent_id: str | None


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: str


class ExternalGrantStore:
    """SQLite authority and audit store. Provisioning methods are administrative.

    Each mutation/decision uses BEGIN IMMEDIATE so independent store instances
    serialize authority checks and writes. A grant ID alone is never a credential.
    Operations are exact application-defined names; 'delegate' is additionally
    required on a parent for onward grants. All issuer authority is rechecked.
    """

    def __init__(self, path, *, clock=None):
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS external_authorities (
                principal TEXT PRIMARY KEY, resources TEXT NOT NULL,
                operations TEXT NOT NULL, can_issue INTEGER NOT NULL, can_export INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS external_exclusions (resource TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS external_grants (
                id TEXT PRIMARY KEY, issuer TEXT NOT NULL, recipient TEXT NOT NULL,
                resources TEXT NOT NULL, operations TEXT NOT NULL, created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL, revoked_at TEXT, provenance TEXT NOT NULL, parent_id TEXT);
            CREATE TABLE IF NOT EXISTS external_grant_audit (
                sequence INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, event TEXT NOT NULL, details TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS external_grant_audit_scope (
                sequence INTEGER PRIMARY KEY, grant_id TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS external_grant_audit_scope_page
                ON external_grant_audit_scope(grant_id, sequence);
            CREATE TABLE IF NOT EXISTS external_grant_manifests (
                grant_id TEXT NOT NULL, resource TEXT NOT NULL, fingerprint TEXT NOT NULL,
                PRIMARY KEY(grant_id, resource));
            CREATE TABLE IF NOT EXISTS external_submission_attempts (
                id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, principal TEXT NOT NULL,
                task_id TEXT NOT NULL, submission_id TEXT NOT NULL, fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','confirmed')),
                UNIQUE(grant_id, principal, task_id, submission_id));
        ''')

    def close(self):
        self.db.close()

    def _record(self, event, now, **details):
        row = self.db.execute('INSERT INTO external_grant_audit(timestamp,event,details) VALUES (?,?,?)',
                              (now.isoformat(), event, json.dumps(details, sort_keys=True)))
        # Index ownership in the SAME authority transaction. Do not infer legacy
        # ownership by searching JSON text or backfill it on an observer request.
        if isinstance(details.get('grant_id'), str):
            self.db.execute('INSERT INTO external_grant_audit_scope VALUES (?,?)',
                            (row.lastrowid, details['grant_id']))

    def audit_page(self, grant_id, *, after=0, through=None, limit=50):
        """Trusted composition only: bounded metadata for one exact grant.

        The authenticated API authorizes inside serialized(). Administrative
        audit() retains old rows; this feed promises scope-indexed events only,
        never complete pre-migration history.
        """
        _text(grant_id)
        if type(after) is not int or not 0 <= after < 2**63:
            raise ValueError('invalid audit cursor')
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('audit page limit must be between 1 and 100')
        if through is not None and (type(through) is not int or not after <= through < 2**63):
            raise ValueError('invalid audit snapshot boundary')
        fields = {'grant_id', 'principal', 'resource', 'operation', 'allowed',
                  'issuer', 'recipient', 'actor', 'task_id', 'attempt_id'}
        with self.lock:
            if through is None:
                through = self.db.execute('''SELECT COALESCE(MAX(sequence),0)
                    FROM external_grant_audit_scope WHERE grant_id=?''', (grant_id,)).fetchone()[0]
            rows = self.db.execute('''SELECT a.sequence,a.timestamp,a.event,
                CASE WHEN length(CAST(a.details AS BLOB)) <= 65536 THEN a.details END AS details
                FROM external_grant_audit_scope AS s
                JOIN external_grant_audit AS a ON a.sequence=s.sequence
                WHERE s.grant_id=? AND s.sequence>? AND s.sequence<=?
                ORDER BY s.sequence LIMIT ?''', (grant_id, after, through, limit + 1)).fetchall()
            result = []
            for row in rows[:limit]:
                if row['details'] is None:
                    raise ValueError('audit metadata exceeds page budget')
                details = json.loads(row['details'])
                if type(details) is not dict or details.get('grant_id') != grant_id:
                    raise ValueError('audit scope index mismatch')
                projected = {key: value for key, value in details.items() if key in fields}
                if any(not (type(value) is bool or isinstance(value, str) and len(value) <= 512)
                       for value in projected.values()):
                    raise ValueError('invalid bounded audit metadata')
                result.append(dict(sequence=row['sequence'], timestamp=row['timestamp'],
                                   event=row['event'], details=projected))
            return dict(items=result, has_more=len(rows) > limit,
                        next_after=result[-1]['sequence'] if len(rows) > limit else None,
                        through=through,
                        coverage='scope-indexed-events-only')

    def _transaction(self, action):
        from .replica_authority import assert_bound_authority
        assert_bound_authority()
        with self.lock:
            if self.db.in_transaction:
                return action()
            self.db.execute('BEGIN IMMEDIATE')
            try:
                result = action()
                self.db.commit()
                return result
            except BaseException:
                self.db.rollback()
                raise

    def serialized(self, action):
        """Trusted synchronous composition: serialize grant use with all mutations.

        Nested decisions share the outer BEGIN IMMEDIATE transaction. The caller
        must not return protected bytes or commit effects after this callback.
        Policy denials are returned to preserve their durable access audit; other
        exceptions roll back the authority transaction and fail closed.
        """
        def run():
            try:
                return action()
            except PermissionError as error:
                return error
        result = self._transaction(run)
        if isinstance(result, PermissionError):
            raise result
        return result

    def set_authority(self, principal, *, resources, operations, can_issue=False, can_export=False):
        """Trusted provisioning only; ordinary read permission is insufficient."""
        principal, resources, operations = _text(principal), _scope(resources), _scope(operations)
        if type(can_issue) is not bool or type(can_export) is not bool:
            raise ValueError('authority flags must be booleans')
        def action():
            self.db.execute('INSERT OR REPLACE INTO external_authorities VALUES (?,?,?,?,?)',
                            (principal, json.dumps(sorted(resources)), json.dumps(sorted(operations)), can_issue, can_export))
        self._transaction(action)

    def prepare_submission(self, *, grant_id, principal, task_id, submission_id, fingerprint):
        """Durable pre-effect intent and decision, without retaining submitted text.

        Must commit independently BEFORE the work database is touched. Pending
        means the work ID may or may not exist; only explicit authenticated retry
        or trusted reconciliation may resolve it. Never automatically replay it.
        """
        for value in (grant_id, principal, task_id, fingerprint):
            _text(value)
        identifier = uuid.uuid4().hex
        from .external_work import validate_submission_id
        submission_id = identifier if submission_id is None else validate_submission_id(submission_id)
        def action():
            if not self.decide(grant_id, principal=principal,
                    resource='task:' + task_id, operation='submit').allowed:
                raise PermissionError('work unavailable')
            row = self.db.execute('''SELECT * FROM external_submission_attempts
                WHERE grant_id=? AND principal=? AND task_id=? AND submission_id=?''',
                (grant_id, principal, task_id, submission_id)).fetchone()
            if row is not None:
                if row['fingerprint'] != fingerprint:
                    raise ValueError('submission identifier already bound to other content')
                return dict(row)
            self.db.execute('INSERT INTO external_submission_attempts VALUES (?,?,?,?,?,?,?,?)',
                (identifier, grant_id, principal, task_id, submission_id, fingerprint,
                 _utc(self.clock()).isoformat(), 'pending'))
            self._record('submission_prepared', _utc(self.clock()), attempt_id=identifier,
                         grant_id=grant_id, principal=principal, task_id=task_id)
            return dict(self.db.execute('SELECT * FROM external_submission_attempts WHERE id=?',
                                        (identifier,)).fetchone())
        with self.lock:
            if self.db.in_transaction:
                raise ValueError('submission intent requires an independent commit')
            return self.serialized(action)

    def confirm_submission(self, attempt_id):
        """Trusted composition only, after the matching work ID commits."""
        _text(attempt_id)
        self._transaction(lambda: self.db.execute(
            "UPDATE external_submission_attempts SET state='confirmed' WHERE id=?", (attempt_id,)))

    def set_excluded(self, resource, excluded=True):
        """Trusted classifier: exclusions override even previously issued grants."""
        resource = _text(resource)
        if type(excluded) is not bool:
            raise ValueError('excluded must be boolean')
        def action():
            if excluded:
                self.db.execute('INSERT OR IGNORE INTO external_exclusions VALUES (?)', (resource,))
            else:
                self.db.execute('DELETE FROM external_exclusions WHERE resource=?', (resource,))
        self._transaction(action)

    def get(self, grant_id):
        """Administrative lookup, not an externally accessible enumeration API."""
        with self.lock:
            row = self.db.execute('SELECT * FROM external_grants WHERE id=?', (grant_id,)).fetchone()
        if row is None:
            return None
        return Grant(row['id'], row['issuer'], row['recipient'], frozenset(json.loads(row['resources'])),
                     frozenset(json.loads(row['operations'])), datetime.fromisoformat(row['created_at']),
                     datetime.fromisoformat(row['expires_at']),
                     datetime.fromisoformat(row['revoked_at']) if row['revoked_at'] else None,
                     row['provenance'], row['parent_id'])

    def _authority(self, issuer, resources, operations):
        row = self.db.execute('SELECT * FROM external_authorities WHERE principal=?', (issuer,)).fetchone()
        return bool(row and row['can_issue'] and row['can_export']
                    and resources <= set(json.loads(row['resources']))
                    and operations <= set(json.loads(row['operations'])))

    def _active(self, grant, now):
        seen = set()
        while grant is not None:
            if grant.id in seen or grant.revoked_at is not None or not grant.created_at <= now < grant.expires_at:
                return False
            seen.add(grant.id)
            if not self._authority(grant.issuer, grant.resources, grant.operations):
                return False
            if any(self.db.execute('SELECT 1 FROM external_exclusions WHERE resource=?', (resource,)).fetchone()
                   for resource in grant.resources):
                return False
            if grant.parent_id is None:
                return True
            parent = self.get(grant.parent_id)
            if not (parent and grant.issuer == parent.recipient and 'delegate' in parent.operations
                    and grant.resources <= parent.resources and grant.operations <= parent.operations
                    and grant.expires_at <= parent.expires_at):
                return False
            grant = parent
        return False

    def manifest_bindings(self, grant_id):
        """Trusted lookup; absence is unbound legacy authority, never current consent."""
        with self.lock:
            return dict(self.db.execute('SELECT resource,fingerprint FROM external_grant_manifests WHERE grant_id=?',
                                        (grant_id,)).fetchall())

    def issue(self, *, issuer, recipient, resources, operations, expires_at, provenance, parent_id=None,
              manifest_bindings=None):
        issuer, recipient, provenance = _text(issuer), _text(recipient), _text(provenance)
        resources, operations, expires_at = _scope(resources), _scope(operations), _utc(expires_at)
        validate_resource_operations(resources, operations)
        bindings = dict(manifest_bindings or {})
        if (not set(bindings) <= resources or any(not isinstance(value, str) or len(value) != 64
                or any(c not in '0123456789abcdef' for c in value) for value in bindings.values())):
            raise ValueError('exact resource manifest fingerprints required')
        if parent_id is not None:
            _text(parent_id)
        def action():
            now = _utc(self.clock())
            if expires_at <= now:
                raise ValueError('expiry must be in the future')
            if not self._authority(issuer, resources, operations):
                raise PermissionError('issuer lacks resource or export authority')
            if any(self.db.execute('SELECT 1 FROM external_exclusions WHERE resource=?', (resource,)).fetchone()
                   for resource in resources):
                raise PermissionError('excluded resource; review coverage is incomplete')
            if parent_id is not None:
                parent = self.get(parent_id)
                if not (parent and self._active(parent, now) and parent.recipient == issuer
                        and 'delegate' in parent.operations and resources <= parent.resources
                        and operations <= parent.operations and expires_at <= parent.expires_at):
                    raise PermissionError('delegation must not expand parent authority')
                parent_bindings = self.manifest_bindings(parent_id)
                if any(bindings.get(key) != parent_bindings.get(key) for key in resources):
                    raise PermissionError('delegation must retain parent manifest identity')
            identifier = uuid.uuid4().hex
            self.db.execute('INSERT INTO external_grants VALUES (?,?,?,?,?,?,?,?,?,?)',
                            (identifier, issuer, recipient, json.dumps(sorted(resources)), json.dumps(sorted(operations)),
                             now.isoformat(), expires_at.isoformat(), None, provenance, parent_id))
            self.db.executemany('INSERT INTO external_grant_manifests VALUES (?,?,?)',
                                ((identifier, key, value) for key, value in bindings.items()))
            self._record('created', now, grant_id=identifier, issuer=issuer, recipient=recipient)
            return self.get(identifier)
        return self._transaction(action)

    def revoke(self, grant_id, *, actor):
        """Authenticated original issuer or bound recipient may stop future access."""
        _text(actor)
        def action():
            grant = self.get(grant_id)
            if grant is None or actor not in (grant.issuer, grant.recipient):
                raise PermissionError('not permitted to revoke')
            if grant.revoked_at is None:
                now = _utc(self.clock())
                self.db.execute('UPDATE external_grants SET revoked_at=? WHERE id=?', (now.isoformat(), grant_id))
                self._record('revoked', now, grant_id=grant_id, actor=actor)
        self._transaction(action)

    def decide(self, grant_id, *, principal, resource, operation):
        """Check and persist each access decision, including unknown grants."""
        for value in (grant_id, principal, resource, operation):
            _text(value)
        def action():
            now = _utc(self.clock())
            grant = self.get(grant_id)
            allowed = bool(grant and principal == grant.recipient and resource in grant.resources
                           and operation in grant.operations and self._active(grant, now))
            decision = AccessDecision(allowed, 'allowed' if allowed else 'denied')
            self._record('access', now, grant_id=grant_id, principal=principal,
                         resource=resource, operation=operation, allowed=allowed)
            return decision
        return self._transaction(action)

    def decide_observer(self, grant_id, *, principal, resource):
        """Trusted configured observers only; no recipient operation is added.

        The authenticated composition checks observer membership. Scope, issuer
        authority and the complete parent lifecycle remain live store decisions.
        """
        for value in (grant_id, principal, resource):
            _text(value)
        def action():
            now = _utc(self.clock())
            grant = self.get(grant_id)
            allowed = bool(grant and resource in grant.resources and self._active(grant, now))
            self._record('observer_access', now, grant_id=grant_id, principal=principal,
                         resource=resource, operation='read', allowed=allowed)
            return AccessDecision(allowed, 'allowed' if allowed else 'denied')
        return self._transaction(action)

    def audit(self):
        """Trusted observer API; records never include private model reasoning."""
        with self.lock:
            return [dict(row, details=json.loads(row['details'])) for row in
                    self.db.execute('SELECT * FROM external_grant_audit ORDER BY sequence')]
