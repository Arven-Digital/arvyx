"""Persistent MAIN pairing authority.

MAIN issue -> REMOTE proof-backed claim -> separate MAIN decide by fingerprint.
Legacy request/confirm methods are local compatibility APIs, never transported.
Only trusted local main-side code may hold this store or call confirm/revoke.
Actor is audit attribution, NOT authentication. A future transport must verify
possession of the remote Ed25519 private key before calling check(identity).
Public identity or a successful check is NOT a bearer credential or permission
for root, secrets, workspace access, task execution, or onward delegation.
LAN addresses and Tailscale membership confer no authority. No network is used.
The caller must provision a private database directory and protect its integrity.
"""
import base64
from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import math
import secrets
import sqlite3
import threading
import time


@dataclass(frozen=True)
class MachineIdentity:
    """Public Ed25519 key (canonical base64, 32 bytes), plus display-only name."""
    name: str
    public_key: str

    def __post_init__(self):
        if not isinstance(self.name, str) or not 1 <= len(self.name) <= 100 or any(ord(c) < 32 for c in self.name):
            raise ValueError('invalid machine name')
        try:
            raw = base64.b64decode(self.public_key, validate=True)
            if len(raw) != 32 or base64.b64encode(raw).decode() != self.public_key:
                raise ValueError
        except (ValueError, TypeError) as exc:
            raise ValueError('canonical public Ed25519 key required') from exc

    @property
    def fingerprint(self):
        return hashlib.sha256(base64.b64decode(self.public_key)).hexdigest()


@dataclass(frozen=True)
class PairingTicket:
    code: str = field(repr=False)
    fingerprint: str
    expires_at: float


@dataclass(frozen=True)
class PairingDecision:
    allowed: bool
    reason: str


class PairingStore:
    """Atomic SQLite state machine: pending -> approved/expired/revoked.

    Codes have 128 bits of entropy, are returned only at issuance, and are stored
    only as hashes. Both issuance and all confirmation attempts have persistent,
    global fixed-window limits (not caller-controlled source/IP buckets).
    Re-requesting an identity invalidates its earlier pending codes but does not
    revoke an approved identity; revoke invalidates every pending code as well.
    Audit and authority mutations commit together; failures roll back both.
    """

    def __init__(self, path, *, clock=time.time, limit=5, window=60):
        if type(limit) is not int or limit < 1 or not isinstance(window, (int, float)) or not math.isfinite(window) or window <= 0:
            raise ValueError('invalid rate policy')
        self.clock, self.limit, self.window = clock, limit, window
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS machine_pairing_codes (
                digest TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
                name TEXT NOT NULL, public_key TEXT NOT NULL,
                expires REAL NOT NULL, state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS paired_machines (
                fingerprint TEXT PRIMARY KEY, name TEXT NOT NULL,
                public_key TEXT NOT NULL, state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS machine_pairing_limits (
                action TEXT PRIMARY KEY, started REAL NOT NULL, count INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS machine_pairing_audit (
                sequence INTEGER PRIMARY KEY, timestamp REAL NOT NULL,
                action TEXT NOT NULL, actor TEXT NOT NULL,
                fingerprint TEXT, allowed INTEGER NOT NULL, reason TEXT NOT NULL);
        ''')
        # IDs identify claims independently of their key or invitation secret.
        # Retained claims receive stable IDs without changing their authority.
        with self._transaction():
            columns = {row['name'] for row in self.db.execute('PRAGMA table_info(machine_pairing_codes)')}
            if 'claim_id' not in columns:
                self.db.execute('ALTER TABLE machine_pairing_codes ADD COLUMN claim_id TEXT')
            for row in self.db.execute('SELECT digest FROM machine_pairing_codes WHERE claim_id IS NULL').fetchall():
                self.db.execute('UPDATE machine_pairing_codes SET claim_id=? WHERE digest=?',
                                (secrets.token_hex(16), row['digest']))
            self.db.execute('CREATE UNIQUE INDEX IF NOT EXISTS machine_pairing_claim_id ON machine_pairing_codes(claim_id)')

    def close(self):
        with self.lock:
            self.db.close()

    @contextmanager
    def _transaction(self, *, reviewed=False, consent_expires_at=None):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                yield
                if reviewed:
                    self._publication_guard(consent_expires_at)
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK')
                raise

    @staticmethod
    def _publication_guard(expires):
        from .public_onboarding_api import assert_request_active
        from .reviewed_actions import assert_consent_active
        assert_request_active()
        assert_consent_active(expires)

    def _now(self):
        now = self.clock()
        if not isinstance(now, (int, float)) or not math.isfinite(now):
            raise ValueError('invalid clock')
        return now

    def _audit(self, now, action, actor, fingerprint, allowed, reason):
        self.db.execute('INSERT INTO machine_pairing_audit VALUES (NULL,?,?,?,?,?,?)',
                        (now, action, actor, fingerprint, int(allowed), reason))
        return PairingDecision(allowed, reason)

    def _limited(self, action, now):
        row = self.db.execute('SELECT * FROM machine_pairing_limits WHERE action=?', (action,)).fetchone()
        # A backwards clock never resets a rate bucket.
        if row is None or now >= row['started'] + self.window:
            self.db.execute('INSERT OR REPLACE INTO machine_pairing_limits VALUES (?,?,1)', (action, now))
            return False
        if row['count'] >= self.limit:
            return True
        self.db.execute('UPDATE machine_pairing_limits SET count=count+1 WHERE action=?', (action,))
        return False

    @staticmethod
    def _actor(actor):
        if not isinstance(actor, str) or not 1 <= len(actor) <= 100 or any(ord(c) < 32 for c in actor):
            raise ValueError('explicit main-side actor required')

    def request(self, identity: MachineIdentity, *, ttl=300):
        if not isinstance(identity, MachineIdentity):
            raise ValueError('public machine identity required')
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not math.isfinite(ttl) or not 0 < ttl <= 600:
            raise ValueError('ttl must be positive and at most 600 seconds')
        ticket = None
        with self._transaction():
            now = self._now()
            if self._limited('request', now):
                self._audit(now, 'request', 'remote', identity.fingerprint, False, 'rate_limited')
            else:
                code = secrets.token_hex(16).upper()
                self.db.execute("UPDATE machine_pairing_codes SET state='revoked' WHERE fingerprint COLLATE BINARY=? AND state IN ('pending', 'claimed')", (identity.fingerprint,))
                self.db.execute('INSERT INTO machine_pairing_codes(digest,fingerprint,name,public_key,expires,state,claim_id) VALUES (?,?,?,?,?,?,?)',
                                (hashlib.sha256(code.encode()).hexdigest(), identity.fingerprint,
                                 identity.name, identity.public_key, now + ttl, 'pending', secrets.token_hex(16)))
                self._audit(now, 'request', 'remote', identity.fingerprint, True, 'pending')
                ticket = PairingTicket(code, identity.fingerprint, now + ttl)
        if ticket is None:
            raise ValueError('rate_limited')
        return ticket

    def confirm(self, code, *, actor, approved=False):
        """Trusted main-side explicit approval only; false leaves the code pending."""
        self._actor(actor)
        with self._transaction():
            now = self._now()
            if self._limited('confirm', now):
                return self._audit(now, 'confirm', actor, None, False, 'rate_limited')
            if not isinstance(code, str) or len(code) != 32 or any(c not in '0123456789ABCDEF' for c in code):
                row = None
            else:
                row = self.db.execute('SELECT * FROM machine_pairing_codes WHERE digest=?',
                                      (hashlib.sha256(code.encode()).hexdigest(),)).fetchone()
            fingerprint = row['fingerprint'] if row else None
            reason = 'invalid_code'
            if row:
                reason = row['state'] if row['state'] != 'pending' else 'approval_required'
                if row['state'] == 'pending' and now >= row['expires']:
                    self.db.execute("UPDATE machine_pairing_codes SET state='expired' WHERE digest=?", (row['digest'],))
                    reason = 'expired'
                elif row['state'] == 'pending' and approved is True:
                    self.db.execute("UPDATE machine_pairing_codes SET state='approved' WHERE digest=?", (row['digest'],))
                    self.db.execute('INSERT OR REPLACE INTO paired_machines VALUES (?,?,?,?)',
                                    (fingerprint, row['name'], row['public_key'], 'approved'))
                    return self._audit(now, 'confirm', actor, fingerprint, True, 'approved')
            return self._audit(now, 'confirm', actor, fingerprint, False, reason)

    def issue(self, *, actor, ttl=300, consent_expires_at=None):
        """MAIN creates an unbound single-use invitation; never enrollment."""
        self._actor(actor)
        if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not math.isfinite(ttl) or not 0 < ttl <= 600:
            raise ValueError('invalid invitation ttl')
        with self._transaction(reviewed=True, consent_expires_at=consent_expires_at):
            now = self._now()
            if self._limited('issue', now):
                raise ValueError('rate_limited')
            from .public_onboarding_api import assert_request_active
            assert_request_active()
            code = secrets.token_hex(16).upper()
            self._publication_guard(consent_expires_at)
            self.db.execute('INSERT INTO machine_pairing_codes(digest,fingerprint,name,public_key,expires,state,claim_id) VALUES (?,?,?,?,?,?,?)',
                            (hashlib.sha256(code.encode()).hexdigest(), '', '', '', now + ttl, 'issued', secrets.token_hex(16)))
            self._audit(now, 'issue', actor, None, True, 'issued')
        return PairingTicket(code, '', now + ttl)

    def claim(self, code, identity):
        """REMOTE proof verified by transport; consume code, await MAIN approval."""
        if not isinstance(identity, MachineIdentity):
            raise ValueError('identity required')
        with self._transaction():
            now = self._now()
            if self._limited('claim', now):
                return self._audit(now, 'claim', 'remote', identity.fingerprint, False, 'rate_limited')
            valid = isinstance(code, str) and len(code) == 32 and all(c in '0123456789ABCDEF' for c in code)
            row = self.db.execute('SELECT * FROM machine_pairing_codes WHERE digest=?',
                                  (hashlib.sha256(code.encode()).hexdigest(),)).fetchone() if valid else None
            reason = 'invalid_or_used_code'
            if row and row['state'] == 'issued':
                if now >= row['expires']:
                    self.db.execute("UPDATE machine_pairing_codes SET state='expired' WHERE digest=?", (row['digest'],))
                    reason = 'expired'
                else:
                    self.db.execute("UPDATE machine_pairing_codes SET state='claimed',fingerprint=?,name=?,public_key=? WHERE digest=?",
                                    (identity.fingerprint, identity.name, identity.public_key, row['digest']))
                    return self._audit(now, 'claim', 'remote', identity.fingerprint, True, 'pending_main_approval')
            return self._audit(now, 'claim', 'remote', identity.fingerprint, False, reason)

    @staticmethod
    def _claim_record(row):
        return {key: row[key] for key in ('claim_id', 'fingerprint', 'name', 'public_key', 'expires', 'state')}

    def claim_snapshot(self, fingerprint, claim_id=None):
        """Capture one current enrollment for review; never infer among claims."""
        with self.lock:
            rows = self.db.execute("SELECT * FROM machine_pairing_codes WHERE fingerprint COLLATE BINARY=? AND state='claimed' AND expires>?" +
                (' AND claim_id COLLATE BINARY=?' if claim_id is not None else ''),
                (fingerprint, self._now(), claim_id) if claim_id is not None else (fingerprint, self._now())).fetchall()
            if len(rows) != 1 or not rows[0]['claim_id']:
                raise ValueError('one exact current claimed enrollment required')
            return self._claim_record(rows[0])

    def decide(self, fingerprint, *, actor, approved=False, deny=False, claim_id=None, review_snapshot=None, consent_expires_at=None):
        """Consume only the exact claim, comparing reviewed bytes in this transaction."""
        self._actor(actor)
        with self._transaction(reviewed=True, consent_expires_at=consent_expires_at):
            now = self._now()
            rows = self.db.execute("SELECT * FROM machine_pairing_codes WHERE fingerprint COLLATE BINARY=? AND state='claimed'" +
                (' AND claim_id COLLATE BINARY=?' if claim_id is not None else ''),
                (fingerprint, claim_id) if claim_id is not None else (fingerprint,)).fetchall()
            reason = 'no_pending_claim'
            if len(rows) > 1:
                return self._audit(now, 'decide', actor, fingerprint, False, 'ambiguous_claim')
            if len(rows) == 1:
                row = rows[0]
                if review_snapshot is not None and (claim_id is None or review_snapshot != self._claim_record(row)):
                    return self._audit(now, 'decide', actor, fingerprint, False, 'reviewed_claim_changed')
                if now >= row['expires']:
                    self.db.execute("UPDATE machine_pairing_codes SET state='expired' WHERE claim_id COLLATE BINARY=?", (row['claim_id'],))
                    reason = 'expired'
                elif approved is True or deny is True:
                    from .public_onboarding_api import assert_request_active
                    assert_request_active()
                    state = 'denied' if deny else 'approved'
                    self._publication_guard(consent_expires_at)
                    if self._now() >= row['expires']:
                        raise ValueError('claim expired before publication')
                    self.db.execute("UPDATE machine_pairing_codes SET state=? WHERE claim_id COLLATE BINARY=?", (state, row['claim_id']))
                    # Denying one pending claim is not fingerprint-wide revocation.
                    if not deny:
                        self.db.execute('INSERT OR REPLACE INTO paired_machines VALUES (?,?,?,?)',
                                        (fingerprint, row['name'], row['public_key'], state))
                    return self._audit(now, 'decide', actor, fingerprint, True, state)
                else:
                    reason = 'approval_required'
            return self._audit(now, 'decide', actor, fingerprint, False, reason)

    def check(self, identity: MachineIdentity):
        """Check enrollment only; caller must independently authenticate the key."""
        if not isinstance(identity, MachineIdentity):
            raise ValueError('public machine identity required')
        with self._transaction():
            row = self.db.execute('SELECT state FROM paired_machines WHERE fingerprint COLLATE BINARY=?', (identity.fingerprint,)).fetchone()
            allowed = row is not None and row['state'] == 'approved'
            return self._audit(self._now(), 'check', 'remote', identity.fingerprint, allowed,
                               'approved' if allowed else 'not_paired')

    def revoke(self, identity: MachineIdentity, *, actor):
        self._actor(actor)
        if not isinstance(identity, MachineIdentity):
            raise ValueError('public machine identity required')
        with self._transaction():
            self.db.execute("UPDATE machine_pairing_codes SET state='revoked' WHERE fingerprint COLLATE BINARY=? AND state IN ('pending', 'claimed')", (identity.fingerprint,))
            self.db.execute('INSERT OR REPLACE INTO paired_machines VALUES (?,?,?,?)',
                            (identity.fingerprint, identity.name, identity.public_key, 'revoked'))
            return self._audit(self._now(), 'revoke', actor, identity.fingerprint, True, 'revoked')

    def audit(self):
        """Trusted local audit read; never contains pairing codes or private keys."""
        with self.lock:
            return [dict(row) for row in self.db.execute('SELECT * FROM machine_pairing_audit ORDER BY sequence')]
