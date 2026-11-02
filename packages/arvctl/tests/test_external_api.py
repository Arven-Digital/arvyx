"""Real loopback transport with disposable synthetic authority, no providers."""
import base64
import hashlib
import json
from datetime import datetime, UTC, timedelta
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from arvyx_control.external_api import ExternalAPI, Principal, make_server
from arvyx_control.external_grants import ExternalGrantStore
from arvyx_control.external_workspace import snapshot_workspace
from arvyx_control.replica_authority import authority_context


class ExternalAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.vault, self.state = root / 'vault', root / 'events.jsonl'
        self.vault.mkdir()
        self.enterContext(authority_context(self.vault, self.state))
        (root / 'safe.txt').write_text('selected review bytes')
        self.now = datetime(2026, 1, 1, tzinfo=UTC)
        self.store = ExternalGrantStore(root / 'grant.db', clock=lambda: self.now)
        self.addCleanup(self.store.close)
        self.resources = ['workspace:review', 'task:A']
        self.ops = ['read', 'lookup', 'list', 'search', 'submit']
        self.store.set_authority('marlow', resources=self.resources, operations=self.ops,
                                 can_issue=True, can_export=True)
        credentials = {hashlib.sha256(k.encode()).hexdigest(): Principal(*v) for k,v in {
            'issuer-token': ('marlow', 'issuer'), 'cloud-token': ('grok-cloud', 'external'),
            'local-token': ('grok-local', 'external'), 'observer-token': ('reader', 'observer'),
            'reader-token': ('ordinary-reader', 'issuer')}.items()}
        self.api = ExternalAPI(self.store, root / 'work.db', credentials=credentials,
            workspaces={'review': snapshot_workspace(root, ['safe.txt', '.env'])},
            tasks={'A'}, observers={'reader'}, vault=self.vault, state=self.state)
        self.addCleanup(self.api.close)
        self.server = make_server(self.api)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.base = 'http://127.0.0.1:' + str(self.server.server_port)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, path, token='cloud-token', body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = Request(self.base + path, data=data, headers={'Authorization': 'Bearer ' + token})
        try:
            with urlopen(req, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as exc:
            return exc.code, json.load(exc)

    def issue(self, **changes):
        body = dict(recipient='grok-cloud', resources=self.resources,
                    operations=self.ops, provenance='explicit synthetic review')
        body.update(changes)
        status, result = self.request('/external/grants', 'issuer-token', body)
        self.assertEqual(status, 201, result)
        return result['id']

    def test_paginated_results_reach_record_101_and_reauthorize_each_page(self):
        grant = self.issue()
        route = '/external/grants/' + grant + '/tasks/A/results'
        rows = []
        for i in range(101):
            status, row = self.request(route, body=dict(kind='result' if i == 100 else 'progress',
                text=f'synthetic-{i}', source='fixture'))
            self.assertEqual(status, 201)
            rows.append(row)
        # Legacy callers still receive the original bounded list shape.
        self.assertEqual(self.request(route, 'observer-token'), (200, rows[:100]))
        status, first = self.request(route + '?limit=100', 'observer-token')
        self.assertEqual(status, 200, first)
        self.assertEqual(first['items'], rows[:100])
        self.assertTrue(first['has_more'])
        cursor = first['next_cursor']
        status, appended = self.request(route, body=dict(kind='progress', text='append-during-pagination', source='fixture'))
        self.assertEqual(status, 201)
        status, last = self.request(route + '?cursor=' + cursor, 'observer-token')
        self.assertEqual(status, 200, last)
        self.assertEqual(last['items'], [rows[100], appended])
        self.assertFalse(last['has_more'])
        self.assertIsNone(last['next_cursor'])
        self.assertEqual(self.request(route + '?cursor=' + cursor, 'local-token')[0], 403)
        other = self.issue()
        self.assertEqual(self.request('/external/grants/' + other + '/tasks/A/results?cursor=' + cursor,
                                      'observer-token')[0], 400)
        for query in ['limit=0', 'limit=101', 'limit=1&limit=2', 'cursor=unknown', 'offset=100']:
            self.assertEqual(self.request(route + '?' + query, 'observer-token')[0], 400)
        self.now += timedelta(hours=24)
        self.assertEqual(self.request(route + '?cursor=' + cursor, 'observer-token')[0], 403)
        self.now -= timedelta(hours=24)
        self.assertEqual(self.request('/external/grants/' + grant + '/revoke', 'issuer-token', {})[0], 200)
        self.assertEqual(self.request(route + '?cursor=' + cursor, 'observer-token')[0], 403)

    def test_roundtrip_manifest_submission_observer_revoke(self):
        grant = self.issue()
        self.assertEqual(self.store.get(grant).expires_at, self.now + timedelta(hours=24))
        prefix = '/external/grants/' + grant
        status, result = self.request(prefix + '/resources')
        self.assertEqual(status, 200)
        self.assertEqual(len(result), 2)
        workspace = next(x for x in result if x['kind'] == 'workspace')
        self.assertFalse(workspace['complete'])
        self.assertEqual(workspace['excluded_count'], 1)
        self.assertEqual(base64.b64decode(workspace['files'][0]['content_base64']), b'selected review bytes')
        self.assertNotIn(str(Path(self.tmp.name)), json.dumps(result))
        route = prefix + '/tasks/A/results'
        status, row = self.request(route, body={'kind':'result','text':'Reviewed','source':'session-1'})
        self.assertEqual(status, 201)
        self.assertEqual(row['actor'], 'grok-cloud')
        self.assertEqual(self.request(route, 'observer-token'), (200, [row]))
        self.assertEqual(self.request(prefix + '/revoke', 'issuer-token', {})[0], 200)
        self.assertEqual(self.request(prefix+'/resources')[0],403)
        for path, token, body in [(prefix+'/resources/workspace/review','cloud-token',None),
                (route,'observer-token',None), (route,'cloud-token',{'kind':'result','text':'late','source':'s'})]:
            self.assertEqual(self.request(path, token, body)[0], 403)
        self.assertTrue(any(x['event']=='revoked' for x in self.store.audit()))

    def test_adversarial_scope_identity_and_shared_routes(self):
        grant = self.issue()
        prefix = '/external/grants/' + grant
        for token in ['local-token', 'bad-token', '']:
            self.assertEqual(self.request(prefix+'/resources/workspace/review',token)[0],403)
        for path in ['/mcp','/memory/recall','/control/tasks','/registry','/external/mcp']:
            self.assertEqual(self.request(path)[0],403)
        for suffix in ['/resources/workspace/adjacent','/resources/artifact/etc', '/tasks/B/results']:
            self.assertEqual(self.request(prefix+suffix)[0],403)
        self.assertEqual(self.request(prefix+'/tasks/A/results',body={
            'kind':'result','text':'forged','source':'s','actor':'marlow'})[0],400)
        self.assertEqual(self.request('/external/grants','reader-token',dict(
            recipient='grok-cloud',resources=self.resources,operations=self.ops,provenance='x'))[0],403)
        self.assertEqual(self.request('/external/grants',body=dict(
            recipient='grok-local',resources=self.resources,operations=self.ops,provenance='x'))[0],403)

    def test_expiry_authority_loss_exclusion_and_hash_change(self):
        grant = self.issue()
        path = '/external/grants/'+grant+'/resources/workspace/review'
        self.now += timedelta(hours=24)
        self.assertEqual(self.request(path)[0],403)
        self.now -= timedelta(hours=1)
        self.store.set_excluded('workspace:review')
        self.assertEqual(self.request(path)[0],403)
        self.store.set_excluded('workspace:review', False)
        self.store.set_authority('marlow',resources=self.resources,operations=self.ops,can_issue=True,can_export=False)
        self.assertEqual(self.request(path)[0],403)
        self.store.set_authority('marlow',resources=self.resources,operations=self.ops,can_issue=True,can_export=True)
        (Path(self.tmp.name)/'safe.txt').write_text('tampered')
        self.assertEqual(self.request(path)[0],400)

    def test_concurrent_independent_store_revoke_serializes_export(self):
        from unittest.mock import patch
        from arvyx_control.external_workspace import export_snapshot as real_export
        grant = self.issue()
        path = '/external/grants/'+grant+'/resources/workspace/review'
        entered, release, revoked = threading.Event(), threading.Event(), threading.Event()
        other = ExternalGrantStore(Path(self.tmp.name)/'grant.db', clock=lambda: self.now)
        self.addCleanup(other.close)
        result = []
        def blocked(snapshot):
            entered.set()
            if not release.wait(3):
                raise RuntimeError('test synchronization timeout')
            return real_export(snapshot)
        def revoke():
            with authority_context(self.vault, self.state):
                other.revoke(grant, actor='marlow')
                revoked.set()
        with patch('arvyx_control.external_api.export_snapshot', side_effect=blocked):
            reader = threading.Thread(target=lambda: result.append(self.request(path)))
            reader.start()
            self.assertTrue(entered.wait(2))
            revoker = threading.Thread(target=revoke)
            revoker.start()
            try:
                self.assertFalse(revoked.wait(.1))
            finally:
                release.set()
                reader.join(4)
                revoker.join(4)
        self.assertTrue(revoked.is_set())
        self.assertEqual(result[0][0], 200)
        self.assertEqual(self.request(path)[0],403)

    def test_existing_shared_listener_rejects_external_credentials_even_in_demo(self):
        from http.server import ThreadingHTTPServer
        from arvyx_control.api import make_handler
        root = Path(self.tmp.name)
        for demo in (False, True):
            server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(
                root/'vault', root/'state', allow_unauthenticated_demo=demo))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for path in ['/memory/recall','/mcp','/control/tasks']:
                    req = Request('http://127.0.0.1:'+str(server.server_port)+path,
                        data=b'{}',headers={'Authorization':'Bearer cloud-token'})
                    with self.assertRaises(HTTPError) as raised:
                        urlopen(req,timeout=3)
                    self.assertEqual(raised.exception.code,401)
                    raised.exception.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_malformed_json_and_framing_are_bounded(self):
        import http.client
        for raw in [b'{', b'[]', b'{"recipient":"x","recipient":"y"}', b'x'*32769]:
            client = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
            try:
                client.request('POST','/external/grants', body=raw,
                    headers={'Authorization':'Bearer issuer-token'})
                response = client.getresponse()
                self.assertEqual(response.status,400)
                self.assertNotIn('Traceback',response.read().decode())
            finally:
                client.close()

    def test_oversized_manifest_refused_before_any_file_export(self):
        from dataclasses import replace
        from unittest.mock import patch
        from arvyx_control.external_api import MAX_RESPONSE_FILE_BYTES
        snapshot = self.api.workspaces['review']
        self.api.workspaces['review'] = replace(snapshot,
            files=(replace(snapshot.files[0], size=MAX_RESPONSE_FILE_BYTES + 1),))
        grant = self.issue()
        prefix = '/external/grants/' + grant + '/resources'
        with patch('arvyx_control.external_api.export_snapshot', side_effect=AssertionError('must not read files')) as export:
            self.assertEqual(self.request(prefix)[0], 400)
            self.assertEqual(self.request(prefix + '/workspace/review')[0], 400)
            export.assert_not_called()

    def test_read_only_does_not_submit_and_audit_failure_denies(self):
        grant = self.issue(operations=['read'])
        prefix = '/external/grants/'+grant
        self.assertEqual(self.request(prefix+'/resources/workspace/review')[0],200)
        self.assertEqual(self.request(prefix+'/tasks/A/results',body={
            'kind':'result','text':'no','source':'s'})[0],403)
        self.store.db.execute("CREATE TRIGGER no_audit BEFORE INSERT ON external_grant_audit BEGIN SELECT RAISE(ABORT,'unavailable'); END")
        self.assertEqual(self.request(prefix+'/resources/workspace/review')[0],403)
