"""Lane 08 only: disposable stores, direct dispatch, no listener or providers."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
import hashlib
from pathlib import Path
import sqlite3
from contextlib import closing
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.external_api import ExternalAPI, Principal
from arvyx_control.external_grants import ExternalGrantStore
from arvyx_control.external_workspace import manifest_fingerprint, snapshot_workspace
from arvyx_control.replica_authority import authority_context


class Interrupted(BaseException):
    pass


class CommitFault:
    """Fail only the grant commit following a real durable work append."""
    def __init__(self, db, work_path, error):
        self.db, self.work_path, self.error = db, work_path, error
        self.fired = False

    def __getattr__(self, name):
        return getattr(self.db, name)

    def commit(self):
        with closing(sqlite3.connect(self.work_path)) as db, db:
            committed = db.execute('SELECT count(*) FROM external_work').fetchone()[0]
        if committed and not self.fired:
            self.fired = True
            raise self.error
        self.db.commit()


class Deep10Fix08Tests(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(tmp)
        self.vault, self.state = self.root / 'vault', self.root / 'events.jsonl'
        self.vault.mkdir()
        self.enterContext(authority_context(self.vault, self.state))
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.grant_path, self.work_path = self.root / 'grants.db', self.root / 'work.db'
        selected = self.root / 'selected'
        selected.mkdir()
        (selected / 'one.txt').write_text('safe one')
        (selected / 'two.txt').write_text('safe two')
        self.snapshots = {'selection': snapshot_workspace(selected, ['one.txt']),
                          'workspace': snapshot_workspace(selected)}
        self.credentials = {hashlib.sha256(k.encode()).hexdigest(): Principal(*v)
                            for k, v in {'recipient': ('cloud', 'external'),
                                         'other': ('other', 'external'),
                                         'observer': ('reader', 'observer')}.items()}
        self.open_stores()
        self.addCleanup(self.close_stores)
        self.resources = ['task:A', 'workspace:selection', 'workspace:workspace']
        self.store.set_authority('issuer', resources=self.resources,
            operations=['read', 'list', 'submit'], can_issue=True, can_export=True)
        self.grant = self.store.issue(issuer='issuer', recipient='cloud',
            resources=self.resources, operations=['read', 'list', 'submit'],
            expires_at=self.now + timedelta(hours=24), provenance='synthetic lane 08',
            # External workspace access requires the issuer-reviewed manifest
            # fingerprint bound at issuance (ExternalAPI._snapshot granted=True).
            manifest_bindings={'workspace:' + name: manifest_fingerprint(snapshot)
                               for name, snapshot in self.snapshots.items()})
        self.route = '/external/grants/' + self.grant.id + '/tasks/A/results'
        self.body = dict(kind='result', text='intentional synthetic result', source='fixture')

    def open_stores(self):
        self.store = ExternalGrantStore(self.grant_path, clock=lambda: self.now)
        self.api = ExternalAPI(self.store, self.work_path, credentials=self.credentials,
            tasks={'A'}, workspaces=self.snapshots, observers={'reader'},
            vault=self.vault, state=self.state)

    def close_stores(self):
        self.api.close()
        self.store.close()

    def reopen(self):
        self.close_stores()
        self.open_stores()

    def post(self, body=None, token='recipient'):
        return self.api.dispatch('POST', self.route, 'Bearer ' + token,
                                 self.body if body is None else body)

    def rows(self):
        with closing(sqlite3.connect(self.work_path)) as db, db:
            return db.execute('SELECT id FROM external_work').fetchall()

    def pending(self):
        return self.store.db.execute("SELECT * FROM external_submission_attempts WHERE state='pending'").fetchall()

    def test_08_01_commit_failure_is_uncertain_and_durably_reconcilable(self):
        proxy = CommitFault(self.store.db, self.work_path, sqlite3.OperationalError('synthetic commit fault'))
        self.store.db = proxy
        status, result = self.post()
        self.assertTrue(proxy.fired)
        self.assertEqual(status, 503, result)
        self.assertEqual(result['error'], 'submission outcome uncertain')
        self.reopen()
        self.assertEqual(len(self.rows()), 1)
        attempts = self.pending()
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0]['id'], self.rows()[0][0])
        self.assertEqual(result['submission_id'], attempts[0]['submission_id'])
        decisions = [e['details'] for e in self.store.audit() if e['event'] == 'access']
        self.assertTrue(any(d['allowed'] and d['operation'] == 'submit' for d in decisions))
        status, row = self.post(dict(self.body, submission_id=result['submission_id']))
        self.assertEqual(status, 201, row)
        self.assertEqual(row['id'], attempts[0]['id'])
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.pending(), [])

    def test_08_01_interruption_after_work_commit_retains_attempt(self):
        proxy = CommitFault(self.store.db, self.work_path, Interrupted())
        self.store.db = proxy
        with self.assertRaises(Interrupted):
            self.post()
        self.reopen()
        attempts = self.pending()
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0]['id'], self.rows()[0][0])
        status, row = self.post(dict(self.body, submission_id=attempts[0]['submission_id']))
        self.assertEqual(status, 201, row)
        self.assertEqual(len(self.rows()), 1)

    def test_08_01_retry_same_identifier_is_single_record_after_reopen(self):
        body = dict(self.body, submission_id='retry-08')
        status, first = self.post(body)
        self.assertEqual(status, 201, first)
        self.reopen()
        self.assertEqual(self.post(body), (201, first))
        self.assertEqual(self.rows(), [(first['id'],)])
        self.assertEqual(self.pending(), [])
        status, listed = self.api.dispatch('GET', self.route, 'Bearer observer', {})
        self.assertEqual((status, listed), (200, [first]))

    def test_08_01_retry_identifier_cannot_change_content(self):
        body = dict(self.body, submission_id='retry-08')
        status, first = self.post(body)
        self.assertEqual(status, 201, first)
        for key, value in [('text', 'changed'), ('kind', 'progress'), ('source', 'elsewhere')]:
            with self.subTest(key=key):
                self.assertEqual(self.post(dict(body, **{key: value}))[0], 400)
        self.assertEqual(self.rows(), [(first['id'],)])

    def test_08_01_retry_rechecks_revocation_and_identity(self):
        body = dict(self.body, submission_id='retry-08')
        status, first = self.post(body)
        self.assertEqual(status, 201, first)
        self.assertEqual(self.post(body, token='other')[0], 403)
        self.assertEqual(self.post(body, token='observer')[0], 403)
        self.store.revoke(self.grant.id, actor='issuer')
        self.assertEqual(self.post(body)[0], 403)
        self.assertEqual(self.rows(), [(first['id'],)])

    def test_08_01_revoke_between_intent_and_work_blocks_append(self):
        prepare = self.store.prepare_submission
        other = ExternalGrantStore(self.grant_path, clock=lambda: self.now)
        self.addCleanup(other.close)
        def prepare_then_revoke(**kwargs):
            attempt = prepare(**kwargs)
            other.revoke(self.grant.id, actor='issuer')
            return attempt
        with patch.object(self.store, 'prepare_submission', side_effect=prepare_then_revoke):
            # A durable pending intent exists: effect-phase failures are uncertain,
            # not a claim that the requested submission could not have committed.
            status, result = self.post()
            self.assertEqual(status, 503, result)
            self.assertEqual(result['error'], 'submission outcome uncertain')
        self.assertEqual(self.rows(), [])
        self.assertEqual(len(self.pending()), 1)

    def test_08_01_work_audit_failure_keeps_pending_intent_without_append(self):
        with closing(sqlite3.connect(self.work_path)) as db, db:
            db.execute("CREATE TRIGGER reject_work_audit BEFORE INSERT ON external_work_audit BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END")
        status, result = self.post()
        self.assertEqual(status, 503, result)
        self.reopen()
        self.assertEqual(self.rows(), [])
        self.assertEqual(len(self.pending()), 1)
        with closing(sqlite3.connect(self.work_path)) as db, db:
            db.execute('DROP TRIGGER reject_work_audit')
        self.assertEqual(self.post(dict(self.body, submission_id=result['submission_id']))[0], 201)
        self.assertEqual(len(self.rows()), 1)

    def test_08_01_authority_fence_after_work_commit_is_uncertain(self):
        submit = self.api.work.submit
        def submit_then_fence(*args, **kwargs):
            row = submit(*args, **kwargs)
            (self.vault / '.arvyx-replica').write_text('synthetic failover fence')
            return row
        with patch.object(self.api.work, 'submit', side_effect=submit_then_fence):
            status, result = self.post()
        self.assertEqual(status, 503, result)
        self.assertEqual(result['error'], 'submission outcome uncertain')
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(len(self.pending()), 1)

    def test_08_01_all_postcommit_errors_remain_uncertain(self):
        submit = self.api.work.submit
        for number, error in enumerate([PermissionError('fence'), ValueError('adapter'),
                                        RuntimeError('adapter')]):
            body = dict(self.body, submission_id=f'postcommit-{number}')
            def commit_then_error(*args, **kwargs):
                submit(*args, **kwargs)
                raise error
            with patch.object(self.api.work, 'submit', side_effect=commit_then_error):
                status, result = self.post(body)
            self.assertEqual(status, 503, result)
            self.assertEqual(result['submission_id'], body['submission_id'])
            self.reopen()
            submit = self.api.work.submit
            self.assertEqual(len(self.rows()), number + 1)
            self.assertEqual(self.post(body)[0], 201)
            self.assertEqual(len(self.rows()), number + 1)

    def test_08_01_intent_audit_failure_prevents_work(self):
        self.store.db.execute("CREATE TRIGGER reject_grant_audit BEFORE INSERT ON external_grant_audit WHEN NEW.event='access' BEGIN SELECT RAISE(ABORT,'fixture grant audit failure'); END")
        self.assertNotEqual(self.post()[0], 201)
        self.assertEqual(self.rows(), [])

    def test_08_01_legacy_identical_submissions_remain_distinct(self):
        a, first = self.post()
        b, second = self.post()
        self.assertEqual((a, b), (201, 201))
        self.assertNotEqual(first['id'], second['id'])

    def test_08_01_invalid_retry_identifiers_fail_closed(self):
        for identifier in ['', ' ', 'x' * 257, 'x\x00y', True, {}, '\ud800']:
            with self.subTest(identifier=repr(identifier)):
                self.assertEqual(self.post(dict(self.body, submission_id=identifier))[0], 400)
        self.assertEqual(self.rows(), [])

    def test_08_01_null_retry_identifier_is_invalid(self):
        self.assertEqual(self.post(dict(self.body, submission_id=None))[0], 400)
        self.assertEqual(self.rows(), [])

    def test_08_01_concurrent_connections_retry_single_record(self):
        other_store = ExternalGrantStore(self.grant_path, clock=lambda: self.now)
        self.addCleanup(other_store.close)
        other_api = ExternalAPI(other_store, self.work_path, credentials=self.credentials,
            tasks={'A'}, workspaces=self.snapshots, vault=self.vault, state=self.state)
        self.addCleanup(other_api.close)
        body = dict(self.body, submission_id='parallel-08')
        def send(api):
            return api.dispatch('POST', self.route, 'Bearer recipient', body)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(send, [self.api, other_api]))
        self.assertEqual(results[0][0], 201, results)
        self.assertEqual(results[0], results[1])
        self.assertEqual(len(self.rows()), 1)

    def test_08_01_retry_keys_are_scoped_to_grant_and_task(self):
        body = dict(self.body, submission_id='scoped-08')
        status, first = self.post(body)
        self.assertEqual(status, 201, first)
        self.api.tasks = frozenset({'A', 'B'})
        self.store.set_authority('issuer', resources=self.resources + ['task:B'],
            operations=['read', 'list', 'submit'], can_issue=True, can_export=True)
        grant = self.store.issue(issuer='issuer', recipient='cloud', resources=['task:A', 'task:B'],
            operations=['read', 'submit'], expires_at=self.now + timedelta(hours=24), provenance='second')
        self.route = '/external/grants/' + grant.id + '/tasks/A/results'
        status, second = self.post(body)
        self.assertEqual(status, 201, second)
        self.route = '/external/grants/' + grant.id + '/tasks/B/results'
        status, third = self.post(body)
        self.assertEqual(status, 201, third)
        self.assertEqual(len({first['id'], second['id'], third['id']}), 3)

    def test_08_01_retry_rechecks_expiry_exclusions_and_issuer_authority(self):
        body = dict(self.body, submission_id='policy-08')
        self.assertEqual(self.post(body)[0], 201)
        self.now += timedelta(hours=24)
        self.assertEqual(self.post(body)[0], 403)
        self.now -= timedelta(hours=24)
        self.store.set_excluded('task:A')
        self.assertEqual(self.post(body)[0], 403)
        self.store.set_excluded('task:A', False)
        self.store.set_authority('issuer', resources=self.resources,
            operations=['read', 'list', 'submit'], can_issue=True, can_export=False)
        self.assertEqual(self.post(body)[0], 403)
        self.assertEqual(len(self.rows()), 1)

    def test_08_02_direct_export_preserves_scoped_completeness(self):
        for scope, expected_files in [('selection', ['one.txt']), ('workspace', ['one.txt', 'two.txt'])]:
            with self.subTest(scope=scope):
                route = '/external/grants/' + self.grant.id + '/resources/workspace/' + scope
                status, result = self.api.dispatch('GET', route, 'Bearer recipient', {})
                self.assertEqual(status, 200, result)
                self.assertEqual(result.get('coverage'), scope)
                self.assertTrue(result['complete'])
                self.assertEqual(result['excluded_count'], 0)
                self.assertEqual([f['path'] for f in result['files']], expected_files)

    def test_08_02_discovery_preserves_coverage(self):
        route = '/external/grants/' + self.grant.id + '/resources'
        status, result = self.api.dispatch('GET', route, 'Bearer recipient', {})
        self.assertEqual(status, 200, result)
        self.assertEqual({r['id']: r.get('coverage') for r in result if r['kind'] == 'workspace'},
                         {'selection': 'selection', 'workspace': 'workspace'})

    def test_08_02_discovery_without_reviewed_manifest_binding_is_denied(self):
        unbound = self.store.issue(issuer='issuer', recipient='cloud',
            resources=self.resources, operations=['read', 'list', 'submit'],
            expires_at=self.now + timedelta(hours=24), provenance='synthetic unbound')
        status, result = self.api.dispatch(
            'GET', '/external/grants/' + unbound.id + '/resources', 'Bearer recipient', {})
        self.assertEqual((status, result), (403, {'error': 'access denied'}))


if __name__ == '__main__':
    unittest.main()
