import json
import threading
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from test_cockpit_primary import PrimaryTests
from arvyx_control.cockpit_primary import NativePrimaryAuthority, PrimaryAgentRegistry
from arvyx_control.cockpit_paperclip import PaperclipServer


class IntegratedPrimaryTests(PrimaryTests):
    def setUp(self):
        super().setUp()
        self.present = ['alpha', 'beta']
        self.authority = NativePrimaryAuthority(self.registry, lambda: self.present,
                                               authorization=self.human)
        frontend = self.base / 'frontend'
        frontend.mkdir()
        (frontend / 'index.html').write_text('<html>Integrated test</html>')
        self.server = PaperclipServer(self.base, frontend, capability='browser-human-session-capability-32bytes', primary=self.authority)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def record_native_connection(self):
        # Fixture event precedes presentation; native presence remains reconciled.
        with self.registry._transaction():
            self.registry.db.execute('INSERT OR REPLACE INTO primary_connections VALUES(?,?,1)',
                                     ('native:alpha', 'alpha'))
            self.registry._elect_locked('alpha', actor='native-owner',
                                         reason='first validated native connection')

    def http(self, data=None, *, auth='browser-human-session-capability-32bytes', origin=True, raw=None):
        headers = {'Authorization': 'Bearer ' + auth}
        if data is not None or raw is not None:
            headers['Content-Type'] = 'application/json'
            if origin:
                headers['Origin'] = self.server.origin
        req = Request(self.server.origin + '/api/primary-agent',
                      data=raw if raw is not None else json.dumps(data).encode() if data is not None else None,
                      headers=headers)
        try:
            with urlopen(req) as response:
                return response.status, json.load(response)
        except HTTPError as response:
            return response.code, json.load(response)

    def test_http_election_change_disconnect_and_cas(self):
        self.record_native_connection()
        status, state = self.http()
        self.assertEqual(status, 200)
        self.assertEqual(state['primary_agent_id'], 'alpha')
        self.assertTrue(state['can_set_primary'])
        self.assertEqual(self.http({'agent_id': 'beta', 'revision': 1})[0], 200)
        self.assertEqual(self.http({'agent_id': 'alpha', 'revision': 1})[0], 409)
        self.present = ['alpha']
        state = self.http()[1]
        self.assertEqual(state['primary_agent_id'], 'beta')
        self.assertFalse(state['primary_connected'])
        self.assertEqual(self.make_registry().snapshot()['agent_id'], 'beta')

    def test_http_negative_boundaries(self):
        self.assertEqual(self.http(auth='wrong')[0], 403)
        self.assertEqual(self.http({'agent_id': 'beta', 'revision': 1}, origin=False)[0], 403)
        self.assertEqual(self.http({'agent_id': 'beta', 'revision': 1, 'role': 'operator'})[0], 400)
        self.assertEqual(self.http(raw=b'{"agent_id":"beta","revision":1,"revision":1}')[0], 400)
        self.authority.authorization = self.headers['alpha']
        self.assertFalse(self.http()[1]['can_set_primary'])
        self.assertEqual(self.http({'agent_id': 'beta', 'revision': 1})[0], 403)

    def test_http_rejects_host_origin_media_and_duplicate_framing(self):
        import http.client
        def send(extra, body=b'{}'):
            connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port)
            connection.putrequest('POST', '/api/primary-agent', skip_host=True)
            for name, value in [('Host', self.server.origin.removeprefix('http://')),
                                ('Authorization', 'Bearer browser-human-session-capability-32bytes'),
                                ('Origin', self.server.origin), ('Content-Type', 'application/json'),
                                ('Content-Length', str(len(body)))] + extra:
                connection.putheader(name, value)
            connection.endheaders(body)
            response = connection.getresponse()
            status = response.status
            response.read()
            connection.close()
            return status
        self.assertEqual(send([('Host', 'evil.example')]), 403)
        self.assertEqual(send([('Origin', 'https://evil.example')]), 403)
        self.assertEqual(send([('Content-Type', 'text/plain')]), 400)
        self.assertEqual(send([('Content-Length', '2')]), 400)

    def test_recreated_authority_reconciles_presence_without_re_election(self):
        self.record_native_connection()
        self.assertEqual(self.http()[1]['primary_agent_id'], 'alpha')
        recreated = NativePrimaryAuthority(self.make_registry(), lambda: ['beta'], authorization=self.human)
        state = recreated.read()
        self.assertEqual(state['primary_agent_id'], 'alpha')
        self.assertFalse(state['primary_connected'])
        self.assertEqual(state['revision'], 1)

    def test_unregistered_native_bindings_are_not_connected_identities(self):
        self.record_native_connection()
        self.present = ['not-registered', 'beta']
        state = self.http()[1]
        self.assertEqual(state['primary_agent_id'], 'alpha')
        self.assertFalse(state['primary_connected'])
        self.assertEqual([a['id'] for a in state['agents'] if a['connected']], ['beta'])
        self.assertEqual(next(a for a in state['agents'] if a['id'] == 'alpha')['connected'], False)
        self.assertNotIn('not-registered', [a['id'] for a in state['agents']])

    def test_unavailable_source_is_503_not_stale_success(self):
        self.http()
        def unavailable():
            raise OSError('native owner unavailable')
        self.authority.source = unavailable
        self.assertEqual(self.http()[0], 503)

    def test_default_organizer_uses_global_primary_without_starting_task(self):
        # Point the test registry at the exact coordinator authority path.
        registry = PrimaryAgentRegistry(self.owner, self.owner.state.with_name(self.owner.state.name + '.primary.sqlite'),
                                        shared_secret='fixture-human-secret')
        self.addCleanup(registry.close)
        authority = NativePrimaryAuthority(registry, lambda: ['beta', 'alpha'], authorization=self.human)
        registry.connect(authorization=self.headers['beta'])
        authority.read()
        self.owner.organizer_bindings = {
            name: dict(tool='fixture', conversation='fixture-' + name, workspace=str(self.base))
            for name in ('alpha', 'beta')}
        session = self.owner.open_organizer(actor='operator')
        self.assertEqual(session['name'], 'organizer-beta')
        self.assertEqual(session['status'], 'stopped')
        self.assertIsNone(session['task'])
        authority.select('alpha', revision=1)
        self.assertEqual(self.owner.open_organizer(actor='operator')['name'], 'organizer-alpha')
        self.assertEqual(registry.db.execute('SELECT COUNT(*) FROM primary_events').fetchone()[0], 2)

    def test_source_loss_does_not_advertise_stale_connection(self):
        self.record_native_connection()
        self.http()
        self.present = []
        self.assertFalse(self.http()[1]['primary_connected'])
        self.present = ['beta']
        self.assertEqual(self.http()[1]['primary_agent_id'], 'alpha')
