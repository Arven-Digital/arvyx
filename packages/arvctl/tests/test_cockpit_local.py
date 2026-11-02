from arvyx_control.local_executor import ExecutionPolicy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from arvyx_control.cockpit_local import build_local_server, inspect_existing_owner, write_browser_connection


class LocalConnectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_connection_rejects_fixture_before_owner_io(self):
        connection = self.base / 'connection.json'
        connection.write_text(json.dumps({'home': str(self.base), 'fixture_only': True}))
        with self.assertRaisesRegex(ValueError, 'synthetic'):
            inspect_existing_owner(connection)

    def test_connection_file_is_exclusive_and_private(self):
        target = self.base / 'browser.json'
        write_browser_connection(target, 'http://127.0.0.1:1234', 'secret')
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(target.read_text())['mode'], 'real-local')
        with self.assertRaises(FileExistsError):
            write_browser_connection(target, 'http://127.0.0.1:1234', 'other')

    def test_real_connection_validates_identity_without_writes(self):
        # An absent native DB must not be created by metadata inspection.
        connection = self.base / 'connection.json'
        connection.write_text(json.dumps({'home': str(self.base)}))
        before = set(self.base.rglob('*'))
        with self.assertRaises((OSError, ValueError, RuntimeError)):
            inspect_existing_owner(connection)
        self.assertEqual(before, set(self.base.rglob('*')))


class HarmlessOwnerConnectionTests(unittest.TestCase):
    def setUp(self):
        import socketserver
        from arvyx_control.machine_enrollment import enroll
        from arvyx_control.cockpit import LocalCockpit
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / 'owner'
        enroll(self.home,'synthetic-shell-only',confirmed=True)
        (self.home/'vault/registry/runtimes').mkdir()
        (self.home/'vault/registry/agents').mkdir()
        registry_dir = self.home / 'vault' / 'registry'
        (registry_dir / 'machines').mkdir(exist_ok=True)
        (registry_dir / 'runtimes').mkdir(exist_ok=True)
        (registry_dir / 'runtimes' / 'shell-only.json').write_text(json.dumps(dict(id='shell-only', harness='gemini')))
        for agent in ('alpha', 'beta'):
            p = self.home / 'vault' / 'registry' / 'agents' / (agent + '.json')
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(dict(id=agent, machine_id='synthetic-shell-only', runtime_id='shell-only', scopes=['control.read'])))
        workspace = self.home / 'workspace'
        workspace.mkdir()
        class HarmlessRuntime:
            def reserve(runtime, conversation): return None  # Disposable test adapter only.
            def plan(runtime, conversation, workspace):
                return ['/bin/cat'], dict(PATH='/usr/bin:/bin', HOME=str(self.home), TERM='dumb')
        self.owner = LocalCockpit(self.home / 'runtime', self.home / 'vault', self.home / 'events.jsonl',
            'synthetic-shell-only', native_runtimes={'gemini': HarmlessRuntime()},
            organizers={a:dict(tool='gemini', conversation='synthetic-'+a, workspace=str(workspace)) for a in ('alpha','beta')}, execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))
        self.addCleanup(self.owner.close)
        self.sessions = {}
        for agent in ('alpha','beta'):
            row = self.owner.open_organizer(agent, actor='operator')
            self.sessions[agent] = row['id']
            self.owner.start_native(row['id'], actor='operator', allow_provider=True, environment='host')
        owner = self.owner
        class Handler(socketserver.StreamRequestHandler):
            def handle(handler):
                # Exercise the real envelope/deadline dispatcher. Wire metadata
                # is not part of the owner's operation method signatures.
                from arvyx_control.cockpit import handle_connection
                handle_connection(handler.request, owner, owner)
        self.socket = socketserver.UnixStreamServer(str(self.home / 'runtime' / 'cockpit.sock'), Handler)
        threading.Thread(target=self.socket.serve_forever, daemon=True).start()
        self.addCleanup(self.socket.server_close)
        self.addCleanup(self.socket.shutdown)
        self.connection = self.home / 'connection.json'
        self.connection.write_text(json.dumps(dict(home=str(self.home), fixture_only=False)))
        frontend = self.home / 'frontend'
        frontend.mkdir()
        (frontend / 'index.html').write_text('<html>Harmless local test</html>')
        self.server = build_local_server(self.connection, frontend, operator_secret='existing-operator-test',
                                        capability='browser-local-test-capability-32bytes')
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def http(self, path, body=None, auth=True, origin=True):
        headers = {}
        if auth:
            headers['Authorization'] = 'Bearer ' + self.server.capability
        if body is not None:
            headers['Content-Type'] = 'application/json'
            if origin:
                headers['Origin'] = self.server.origin
        req = Request(self.server.origin+path, headers=headers,
                      data=json.dumps(body).encode() if body is not None else None)
        try:
            with urlopen(req) as response:
                return response.status, json.load(response)
        except HTTPError as response:
            return response.code, json.load(response)

    def test_actual_socket_native_election_selection_disconnect_and_persistence(self):
        before = self.owner.snapshot(actor='operator')['sessions']
        self.assertEqual(self.http('/api/local-connection', auth=False)[0], 403)
        status, connection = self.http('/api/local-connection')
        self.assertEqual(status, 200)
        self.assertEqual(connection, dict(mode='real-local', owner_connected=True,
                                         native_session_control=False, external_delegation=False))
        self.assertNotIn('existing-operator-test', json.dumps(connection))
        state = self.http('/api/primary-agent')[1]
        self.assertEqual(state['primary_agent_id'], 'alpha')
        self.assertTrue(state['primary_connected'])
        self.assertEqual(self.http('/api/primary-agent', dict(agent_id='beta', revision=1), origin=False)[0],403)
        self.assertEqual(self.http('/api/primary-agent', dict(agent_id='beta', revision=1))[0],200)
        self.assertEqual(self.http('/api/primary-agent', dict(agent_id='alpha', revision=1))[0],409)
        self.assertEqual(self.owner.snapshot(actor='operator')['sessions'], before)
        self.assertEqual(self.http('/external/config')[0],404)
        self.assertEqual(self.http('/api/end', dict(sid=self.sessions['alpha']))[0],405)
        self.owner.end(self.sessions['beta'], actor='operator')
        state = self.http('/api/primary-agent')[1]
        self.assertEqual(state['primary_agent_id'], 'beta')
        self.assertFalse(state['primary_connected'])
        import sqlite3
        with sqlite3.connect(self.home / 'events.jsonl.primary.sqlite') as db:
            self.assertEqual(db.execute('SELECT agent_id,revision FROM primary_agent').fetchone(), ('beta',2))

    def test_binding_mismatch_and_owner_loss_fail_closed(self):
        self.owner.db.execute("UPDATE identity SET vault=?", (str(self.home / 'wrong-vault'),))
        self.owner.db.commit()
        self.assertEqual(self.http('/api/local-connection')[0], 503)
        self.assertEqual(self.http('/api/primary-agent')[0], 503)
        self.assertEqual(self.server.primary.registry.snapshot()['revision'], 1)

    def test_fixture_marker_is_not_silently_accepted_after_connection(self):
        self.connection.write_text(json.dumps(dict(home=str(self.home), fixture_only=True)))
        self.assertEqual(self.http('/api/local-connection')[0], 503)

    def test_canary_does_not_elect_or_modify_native_owner(self):
        before = self.owner.snapshot(actor='operator')['sessions']
        self.assertEqual(inspect_existing_owner(self.connection)['eligible_agents'], ['alpha','beta'])
        self.assertEqual(self.server.primary.registry.snapshot()['revision'],1)
        self.assertEqual(self.owner.snapshot(actor='operator')['sessions'], before)
