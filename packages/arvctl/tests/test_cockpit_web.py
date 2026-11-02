import json
from pathlib import Path
import threading
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import patch

from arvyx_control import cockpit_web
from arvyx_control.cockpit_team import TeamAuthority


class WebTests(unittest.TestCase):
    def setUp(self):
        self.server = cockpit_web.DashboardServer(Path('/unused'), port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.thread.join, 3)
        self.addCleanup(self.server.shutdown)
        self.origin = 'http://127.0.0.1:' + str(self.server.server_address[1])

    def fetch(self, path, body=None, authorized=True, origin=None):
        headers = {}
        if authorized:
            headers['Authorization'] = 'Bearer ' + self.server.capability
        if body is not None:
            headers['Content-Type'] = 'application/json'
            headers['Origin'] = self.origin if origin is None else origin
        req = Request(self.origin + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
        return urlopen(req, timeout=3)

    def test_data_is_not_available_without_capability(self):
        with self.assertRaises(HTTPError) as result:
            self.fetch('/api/dashboard', authorized=False)
        self.assertEqual(result.exception.code, 403)
        with self.fetch('/', authorized=False) as response:
            self.assertIn(b'Local AMC', response.read())
            self.assertIn("default-src 'none'", response.headers['Content-Security-Policy'])
            self.assertNotIn(self.server.capability, str(response.headers))

    def test_packaged_brand_assets_are_public_but_only_allowlisted(self):
        for name, mime in (('arvyx-wordmark.png', 'image/png'), ('favicon.png', 'image/png')):
            with self.fetch('/assets/' + name, authorized=False) as response:
                self.assertEqual(response.headers['Content-Type'], mime)
                self.assertGreater(len(response.read()), 100)
                self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
        with self.fetch('/', authorized=False) as response:
            page = response.read()
            self.assertIn(b'src="/assets/arvyx-wordmark.png"', page)
            self.assertIn(b'alt="Arvyx"', page)
            self.assertIn(b'rel="icon"', page)
        for path in ('/assets/../cockpit_web.py', '/assets/missing.png', '/assets/arvyx-wordmark.png?x=1'):
            with self.assertRaises(HTTPError):
                self.fetch(path, authorized=False)

    def test_live_dashboard_uses_existing_projection(self):
        model = {'sessions': [], 'tasks': [], 'view': {'selected': None, 'revision': 0}, 'host': 'local'}
        with patch.object(cockpit_web, 'snapshot', return_value=model) as reader:
            with self.fetch('/api/dashboard') as response:
                page = response.read()
                self.assertIn(b'No sessions', page)
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
            reader.assert_called_once_with(Path('/unused'))

    def test_mutation_requires_origin_and_explicit_end_confirmation(self):
        with patch.object(cockpit_web, 'request') as rpc:
            with self.assertRaises(HTTPError) as result:
                self.fetch('/api/end', {'sid': 'abc', 'confirm': 'abc'}, origin='https://attacker.invalid')
            self.assertEqual(result.exception.code, 403)
            with self.assertRaises(HTTPError) as result:
                self.fetch('/api/end', {'sid': 'abc', 'confirm': 'wrong'})
            self.assertEqual(result.exception.code, 400)
            rpc.assert_not_called()
            rpc.return_value = {'status': 'ended'}
            with self.fetch('/api/end', {'sid': 'abc', 'confirm': 'abc'}) as response:
                self.assertEqual(json.load(response)['status'], 'ended')
            rpc.assert_called_once_with(Path('/unused'), 'end', sid='abc', actor='operator')

    def test_selection_preserves_compare_and_swap(self):
        with patch.object(cockpit_web, 'request', return_value={'selected': 'abc', 'revision': 3}) as rpc:
            with self.fetch('/api/select', {'sid': 'abc', 'revision': 2}) as response:
                self.assertEqual(json.load(response)['revision'], 3)
            rpc.assert_called_once_with(Path('/unused'), 'select', sid='abc', revision=2, actor='operator')

    def test_take_control_is_explicit_revocation_not_process_end(self):
        with patch.object(cockpit_web, 'request', return_value={'status': 'revoked'}) as rpc:
            with self.fetch('/api/take-control', {'sid': 'abc'}) as response:
                self.assertEqual(json.load(response)['status'], 'revoked')
            rpc.assert_called_once_with(Path('/unused'), 'take_control', sid='abc', actor='operator')

    def test_no_browser_terminal_input_or_approval_bypass_endpoint(self):
        with patch.object(cockpit_web, 'request') as rpc:
            for route in ('write', 'approve', 'start', 'autopilot'):
                with self.assertRaises(HTTPError) as result:
                    self.fetch('/api/' + route, {'sid': 'abc'})
                self.assertEqual(result.exception.code, 404)
            rpc.assert_not_called()

    def test_duplicate_json_and_invalid_revision_do_not_dispatch(self):
        with patch.object(cockpit_web, 'request') as rpc:
            raw = b'{"sid":"abc","sid":"other","revision":0}'
            headers = {'Authorization': 'Bearer ' + self.server.capability,
                       'Content-Type': 'application/json', 'Origin': self.origin}
            req = Request(self.origin + '/api/select', data=raw, headers=headers)
            with self.assertRaises(HTTPError) as result:
                urlopen(req, timeout=3)
            self.assertEqual(result.exception.code, 400)
            with self.assertRaises(HTTPError):
                self.fetch('/api/select', {'sid': 'abc', 'revision': True})
            rpc.assert_not_called()

    def test_loopback_only_and_invalid_port_rejected(self):
        self.assertEqual(self.server.server_address[0], '127.0.0.1')
        for port in (-1, 65536, True):
            with self.assertRaises(ValueError):
                cockpit_web.DashboardServer(Path('/unused'), port=port)

    def test_team_http_uses_real_authority_and_does_not_echo_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = root / 'vault'
            vault.mkdir(mode=0o700)
            fixture_identity = 'fixture-web-identity'
            self.server.team = TeamAuthority(vault, root / 'events.jsonl',
                                            bearer_secret=fixture_identity,
                                            authorization='Bearer ' + fixture_identity)
            payload = {'action': 'task-create', 'payload': {'title': 'HTTP task', 'owner': 'nova',
                                                          'idempotency_key': 'web-test-task-create-1'}}
            with self.fetch('/api/team/action', payload) as response:
                self.assertEqual(response.status, 201)
            local = {'sessions': [], 'host': 'fixture'}
            with patch.object(cockpit_web, 'snapshot', return_value=local):
                with self.fetch('/api/team') as response:
                    page = response.read().decode()
                    self.assertIn('HTTP task', page)
                    self.assertNotIn('fixture-web-identity', page)
            with self.assertRaises(HTTPError) as failure:
                self.fetch('/api/team/action', payload)
            self.assertEqual(failure.exception.code, 409)
            self.assertEqual(len(self.server.team.read()['tasks']['tasks']), 1)

    def test_team_cross_origin_no_identity_and_injected_fields_fail_closed(self):
        payload = {'action': 'task-create', 'payload': {'title': 'x', 'owner': 'nova',
                                                      'idempotency_key': 'web-negative-task-1'}}
        for authorized, origin, code in [(False, None, 403), (True, 'https://evil.invalid', 403),
                                          (True, None, 503)]:
            with self.assertRaises(HTTPError) as failure:
                self.fetch('/api/team/action', payload, authorized=authorized, origin=origin)
            self.assertEqual(failure.exception.code, code)

    def test_team_refresh_is_explicit_and_forms_are_outside_polling_container(self):
        self.assertIn('update(); refreshTeam(); setInterval(update, 2000)', cockpit_web.SCRIPT)
        self.assertNotIn('setInterval(refreshTeam', cockpit_web.SCRIPT)
        self.assertIn('if (form.dataset.pending) return', cockpit_web.SCRIPT)
        self.assertIn('button.disabled = true', cockpit_web.SCRIPT)
        self.assertIn('No retry.', cockpit_web.SCRIPT)

    def test_machine_offline_does_not_erase_available_amc_team_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = root / 'vault'
            vault.mkdir(mode=0o700)
            identity = 'synthetic-offline-operator'
            self.server.team = TeamAuthority(vault, root / 'events.jsonl', bearer_secret=identity,
                                            authorization='Bearer ' + identity)
            with patch.object(cockpit_web, 'snapshot', side_effect=OSError('fixture owner offline')):
                with self.fetch('/api/team') as response:
                    page = json.load(response)['html']
            self.assertIn('Machine: unavailable', page)
            self.assertIn('AMC control: available', page)
