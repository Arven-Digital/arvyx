"""Isolated contract tests: no router, grant-core or provider dependencies."""
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from arvyx_control.external_work import ExternalWork, WorkAuthorization


class ExternalWorkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'work.sqlite'
        self.now = 100.0
        self.grants = {
            task: WorkAuthorization(task_id=task, grant_id='grant-' + task,
                recipient='grok-cloud', observers=frozenset({'squad-reader'}),
                operations=frozenset({'read', 'submit'}), expires_at=200,
                revoked=False, provenance='issuer:owner')
            for task in ('a', 'b')
        }
        self.calls = []
        def authorize(actor, task, operation):
            self.calls.append((actor, task, operation))
            return self.grants.get(task)
        self.authorize = authorize
        self.work = ExternalWork(self.path, authorize=authorize, clock=lambda: self.now)
        self.addCleanup(self.work.close)

    def submit(self, task='a', **kwargs):
        return self.work.submit(task, actor='grok-cloud', kind='progress',
                                text='Review started', source='grok-cloud/session-1', **kwargs)

    def test_recipient_observer_and_durable_provenance(self):
        row = self.submit()
        self.assertEqual(row['actor'], 'grok-cloud')
        self.assertEqual(row['grant_id'], 'grant-a')
        self.assertEqual(row['provenance'], 'issuer:owner')
        self.assertEqual(self.work.list('a', actor='squad-reader'), [row])
        self.assertEqual(self.work.get('a', row['id'], actor='grok-cloud'), row)
        other = ExternalWork(self.path, authorize=self.authorize, clock=lambda: self.now)
        self.addCleanup(other.close)
        self.assertEqual(other.get('a', row['id'], actor='squad-reader'), row)
        with sqlite3.connect(self.path) as db:
            events = db.execute('SELECT action, decision FROM external_work_audit').fetchall()
        self.assertIn(('submit', 'allow'), events)
        self.assertIn(('get', 'allow'), events)

    def test_no_cross_task_or_identity_lookup_leakage(self):
        row = self.submit()
        self.assertEqual(self.work.list('b', actor='grok-cloud'), [])
        for task, identifier, actor in [('b', row['id'], 'grok-cloud'),
                ('a', row['id'], 'grok-local'), ('a', 'missing', 'grok-local')]:
            with self.assertRaisesRegex(PermissionError, '^work unavailable$'):
                self.work.get(task, identifier, actor=actor)
        with self.assertRaises(PermissionError):
            self.work.list('a', actor='unrelated-squad-member')
        with self.assertRaises(PermissionError):
            self.work.submit('a', actor='squad-reader', kind='result', text='forged', source='x')

    def test_rechecks_expiry_revocation_and_observer_removal(self):
        row = self.submit()
        original = self.grants['a']
        for grant in [replace(original, revoked=True), replace(original, expires_at=100),
                      replace(original, observers=frozenset()),
                      replace(original, task_id='b'), replace(original, operations=frozenset())]:
            self.grants['a'] = grant
            with self.assertRaises(PermissionError):
                self.work.get('a', row['id'], actor='squad-reader')
        self.grants['a'] = replace(original, revoked=True)
        with self.assertRaises(PermissionError):
            self.submit()
        self.grants['a'] = replace(original, grant_id='replacement')
        self.assertEqual(self.work.list('a', actor='grok-cloud'), [])
        with self.assertRaises(PermissionError):
            self.work.get('a', row['id'], actor='grok-cloud')

    def test_bounded_closed_submission_surface(self):
        for text in ['', ' ', 'x' * 16385, 'é' * 8193, 'x\x00y']:
            with self.assertRaises(ValueError):
                self.work.submit('a', actor='grok-cloud', kind='result', text=text, source='s')
        for kind in ['reasoning', 'transcript', 'personal-activity', 'thoughts']:
            with self.assertRaises(ValueError):
                self.work.submit('a', actor='grok-cloud', kind=kind, text='x', source='s')
        with self.assertRaises(TypeError):
            self.submit(reasoning='not collected')
        self.assertEqual(self.work.list('a', actor='grok-cloud'), [])
        result = self.work.submit('a', actor='grok-cloud', kind='result', text='Done', source='s')
        self.assertEqual(result['kind'], 'result')

    def test_audit_denials_do_not_store_payload_or_foreign_id(self):
        with self.assertRaises(PermissionError):
            self.work.submit('a', actor='grok-local', kind='result', text='private payload', source='s')
        with sqlite3.connect(self.path) as db:
            events = db.execute('SELECT * FROM external_work_audit').fetchall()
        self.assertTrue(events)
        self.assertNotIn('private payload', repr(events))
        self.assertIn('deny', repr(events))

    def test_invalid_submission_is_audited_and_audit_failure_rolls_back(self):
        with self.assertRaises(ValueError):
            self.work.submit('a', actor='grok-cloud', kind='reasoning', text='private', source='s')
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT decision FROM external_work_audit WHERE action='submit'").fetchall(), [('reject',)])
            db.execute("CREATE TRIGGER reject_audit BEFORE INSERT ON external_work_audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.submit()
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM external_work').fetchone()[0], 0)

    def test_invalid_auth_and_unbounded_reads_fail_closed(self):
        self.grants['a'] = None
        with self.assertRaises(PermissionError):
            self.work.list('a', actor='grok-cloud')
        for limit in [0, 101, True, '10']:
            with self.assertRaises(ValueError):
                self.work.list('a', actor='grok-cloud', limit=limit)
        self.assertNotIn(('grok-cloud', 'b', 'read'), self.calls)


if __name__ == '__main__':
    unittest.main()
