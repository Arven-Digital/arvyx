"""Pairing service contract: no transport or CLI integration."""
import base64
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import tempfile
import unittest
from pathlib import Path

from arvyx_control.machine_pairing import MachineIdentity, PairingStore


class MachinePairingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'pairing.db'
        self.now = 1000.0
        self.identity = MachineIdentity('remote', base64.b64encode(b'x' * 32).decode())
        self.store = self.open()

    def open(self, **kwargs):
        store = PairingStore(self.path, clock=lambda: self.now, **kwargs)
        self.addCleanup(store.close)
        return store

    def test_pending_explicit_approval_and_revoke_persist(self):
        ticket = self.store.request(self.identity)
        self.assertNotIn(ticket.code, repr(ticket))
        self.assertFalse(self.store.check(self.identity).allowed)
        self.assertFalse(self.store.confirm(ticket.code, actor='main', approved=False).allowed)
        reopened = self.open()
        self.assertTrue(reopened.confirm(ticket.code, actor='main', approved=True).allowed)
        self.assertTrue(self.store.check(self.identity).allowed)
        self.assertFalse(self.store.confirm(ticket.code, actor='main', approved=True).allowed)
        self.assertTrue(reopened.revoke(self.identity, actor='main').allowed)
        self.assertFalse(self.store.check(self.identity).allowed)
        self.assertFalse(self.store.confirm(ticket.code, actor='main', approved=True).allowed)

    def test_expiry_exact_boundary_is_terminal(self):
        ticket = self.store.request(self.identity, ttl=10)
        self.now += 10
        self.assertEqual(self.store.confirm(ticket.code, actor='main', approved=True).reason, 'expired')
        self.now -= 1
        self.assertFalse(self.store.confirm(ticket.code, actor='main', approved=True).allowed)

    def test_rate_limits_survive_reopen_and_identity_rotation(self):
        limited = self.open(limit=2)
        for _ in range(2):
            self.assertFalse(limited.confirm('invalid', actor='main', approved=True).allowed)
        self.assertEqual(self.open(limit=2).confirm('invalid', actor='other', approved=True).reason, 'rate_limited')
        self.now += 61
        self.assertEqual(limited.confirm('invalid', actor='main', approved=True).reason, 'invalid_code')
        limited.request(self.identity)
        limited.request(MachineIdentity('another', base64.b64encode(b'y' * 32).decode()))
        with self.assertRaisesRegex(ValueError, 'rate_limited'):
            self.open(limit=2).request(self.identity)

    def test_public_identity_is_exact_and_no_ambient_trust(self):
        ticket = self.store.request(self.identity)
        self.store.confirm(ticket.code, actor='main', approved=True)
        other = MachineIdentity('remote', base64.b64encode(b'z' * 32).decode())
        self.assertFalse(self.store.check(other).allowed)
        self.assertFalse(self.store.check(MachineIdentity('tailscale', other.public_key)).allowed)
        with self.assertRaises(ValueError):
            MachineIdentity('remote', 'PRIVATE KEY')
        with self.assertRaises(TypeError):
            self.store.request(self.identity, workspace='/root')
        with self.assertRaises(ValueError):
            self.store.confirm(ticket.code, actor='', approved=True)

    def test_audit_and_database_do_not_store_codes(self):
        ticket = self.store.request(self.identity)
        self.store.confirm(ticket.code, actor='main', approved=True)
        self.store.check(self.identity)
        self.store.revoke(self.identity, actor='main')
        audit = self.store.audit()
        self.assertEqual([a['action'] for a in audit], ['request', 'confirm', 'check', 'revoke'])
        self.assertNotIn(ticket.code, str(audit))
        with sqlite3.connect(self.path) as db:
            self.assertNotIn(ticket.code, str(list(db.iterdump())))

    def test_single_use_across_connections(self):
        ticket = self.store.request(self.identity)
        other = self.open()
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda s: s.confirm(ticket.code, actor='main', approved=True), [self.store, other]))
        self.assertEqual(sum(r.allowed for r in results), 1)

    def test_new_request_invalidates_old_code(self):
        old = self.store.request(self.identity)
        new = self.store.request(self.identity)
        self.assertFalse(self.store.confirm(old.code, actor='main', approved=True).allowed)
        self.assertTrue(self.store.confirm(new.code, actor='main', approved=True).allowed)

    def test_audit_failure_rolls_back_approval(self):
        ticket = self.store.request(self.identity)
        self.store.db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON machine_pairing_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.confirm(ticket.code, actor='main', approved=True)
        self.store.db.execute('DROP TRIGGER fail_audit')
        self.assertFalse(self.store.check(self.identity).allowed)
        self.assertTrue(self.store.confirm(ticket.code, actor='main', approved=True).allowed)

    def test_invalid_ttl_and_nonboolean_approval_fail_closed(self):
        for ttl in (0, -1, 601, float('nan'), float('inf'), True):
            with self.assertRaises(ValueError):
                self.store.request(self.identity, ttl=ttl)
        ticket = self.store.request(self.identity)
        self.assertFalse(self.store.confirm(ticket.code, actor='main', approved='yes').allowed)
        self.assertTrue(self.store.confirm(ticket.code, actor='main', approved=True).allowed)

    def test_revoke_pending_prevents_later_confirmation(self):
        ticket = self.store.request(self.identity)
        self.store.revoke(self.identity, actor='main')
        self.assertFalse(self.store.confirm(ticket.code, actor='main', approved=True).allowed)


if __name__ == '__main__':
    unittest.main()
