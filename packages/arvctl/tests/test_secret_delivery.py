"""Real edge -> synthetic JWT -> mTLS -> atomic writer."""
import contextlib
import dataclasses
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
import unittest
import importlib.util
import time
from unittest.mock import patch

from arvyx_control.api import handle_api_request, make_handler
from arvyx_control.auth import issue_token
from arvyx_control.secret_delivery import SecretDelivery
from arvyx_control.secret_delivery_protocol import Receipts, Rejected, Target
from arvyx_control.secret_delivery_receiver import Receiver
from arvyx_control.secret_delivery_server import SecretTLSServer
from arvyx_control.secret_delivery_writer import Destination
from arvyx_control.vault import init_vault


def edge_module():
    path = Path(__file__).resolve().parents[3]/'scripts/control_plane_edge_proxy.py'
    spec = importlib.util.spec_from_file_location('secret_test_edge', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def certificates(root):
    """Ephemeral, test-only identity. Private keys never in argv/output/artifacts."""
    def run(*args):
        subprocess.run(['openssl', *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # RFC 5280 profile: Python 3.13 verifies with VERIFY_X509_STRICT by default, so the
    # CA must carry a critical keyUsage with keyCertSign and the leaves must declare
    # their own key usage; an operator's real PKI already does.
    run('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=Synthetic CA',
        '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
        '-keyout', str(root/'ca.key'), '-out', str(root/'ca.pem'))
    for name in ('server', 'operator', 'sender', 'other'):
        run('req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-keyout', str(root/(name+'.key')), '-out', str(root/(name+'.csr')))
        ext = root/(name+'.ext')
        ext.write_text('basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                       'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth,clientAuth\n')
        run('x509', '-req', '-days', '1', '-in', str(root/(name+'.csr')), '-CA', str(root/'ca.pem'), '-CAkey', str(root/'ca.key'), '-CAcreateserial', '-extfile', str(ext), '-out', str(root/(name+'.pem')))
    for path in root.glob('*.key'):
        path.chmod(0o600)


def pin(path):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(path.read_text())).hexdigest()


@unittest.skipUnless(os.name == 'posix', 'secret delivery destinations are defined by POSIX uid and mode semantics')
class SecretDeliveryE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = tempfile.TemporaryDirectory()
        cls.certs = Path(cls.pki.name)
        certificates(cls.certs)
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from arvyx_control.secret_delivery_access import AccessVerifier
        cls.jwt_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(cls.jwt_key.public_key()))
        cls.jwk.update(kid='synthetic-key', alg='RS256', use='sig')
        class LocalVerifier(AccessVerifier):
            # Test-only key source. Production config cannot supply keys or URLs.
            def _fetch_jwks(self):
                return {'keys': [cls.jwk]}
        cls.verifier_class = LocalVerifier

    def token(self, **changes):
        import jwt
        claims = dict(iss='https://synthetic.cloudflareaccess.com', aud=['synthetic-app'],
                      sub='human-a', type='app', iat=int(time.time())-1,
                      nbf=int(time.time())-1, exp=int(time.time())+600)
        claims.update(changes)
        return jwt.encode(claims, self.jwt_key, algorithm='RS256', headers={'kid':'synthetic-key'})

    @classmethod
    def tearDownClass(cls):
        cls.pki.cleanup()

    def context(self, name=None, server=False):
        if server:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.certs/'server.pem', self.certs/'server.key')
            context.load_verify_locations(self.certs/'ca.pem')
            context.verify_mode = ssl.CERT_OPTIONAL
        else:
            context = ssl.create_default_context(cafile=str(self.certs/'ca.pem'))
            if name:
                context.load_cert_chain(self.certs/(name+'.pem'), self.certs/(name+'.key'))
        return context

    def start(self, handler, require_client=False):
        context = self.context(server=True)
        if require_client:
            context.verify_mode = ssl.CERT_REQUIRED
        server = SecretTLSServer(('127.0.0.1', 0), handler, context)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.02}, daemon=True)
        thread.start()
        self.servers.append((server, thread))
        return server

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.vault = self.root/'vault'
        init_vault(self.vault)
        self.servers = []
        self.destdir = self.root/'destination'
        self.destdir.mkdir(mode=0o700)
        self.destination = Destination(str(self.destdir), '.env', os.getuid(), allowed_keys=frozenset({'anthtropic_auth', 'OTHER'}))
        self.receiver = Receiver('synthetic-target', 'demobot', 'codex-demo', [pin(self.certs/'sender.pem')], self.destination, Receipts(self.root/'receiver.sqlite'))
        receiver = self.start(self.receiver.handler(), require_client=True)
        self.target = Target('synthetic-target', 'demobot', 'codex-demo', f'https://localhost:{receiver.server_port}/v1/deliver', pin(self.certs/'server.pem'), str(self.certs/'ca.pem'), str(self.certs/'sender.pem'), str(self.certs/'sender.key'), ('anthtropic_auth', 'OTHER'))
        # Worker threads cannot inherit a parent ContextVar authority binding.
        self.service = SecretDelivery('https://control.party', [self.target], Receipts(self.root/'ingress.sqlite'), vault=self.vault)
        self.bearer = secrets.token_urlsafe(32)
        from arvyx_control.api import BoundedThreadingHTTPServer
        from arvyx_control.secret_delivery_access import SecretEdge
        upstream = BoundedThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.vault, self.root/'events.jsonl', bearer_secret=self.bearer))
        thread = threading.Thread(target=upstream.serve_forever, kwargs={'poll_interval':.02}, daemon=True)
        thread.start(); self.servers.append((upstream, thread))
        edge = edge_module()
        self.verifier = self.verifier_class('https://synthetic.cloudflareaccess.com', 'synthetic-app', ['human-a', 'human-b'])
        adapter = SecretEdge(self.verifier, self.service)
        self.assertion = self.token()
        # Test-only TLS termination. Production uses loopback HTTP behind Access.
        context = self.context(server=True)
        context.verify_mode = ssl.CERT_NONE
        class TestTLSProxy(edge.ProxyServer):
            def process_request_thread(server, request, address):
                secured = None
                try:
                    request.settimeout(3)
                    secured = context.wrap_socket(request, server_side=True)
                    server.finish_request(secured, address)
                except Exception:
                    pass
                finally:
                    server.shutdown_request(secured or request)
                    server._workers.release()
        self.ingress = TestTLSProxy(('127.0.0.1', 0), edge.ProxyHandler, bearer=self.bearer,
                                   upstream_host='127.0.0.1', upstream_port=upstream.server_port,
                                   upstream_timeout=3, secret_edge=adapter, incoming_bearer=self.bearer)
        self.ingress.allowed_hosts = frozenset({f"localhost:{self.ingress.server_port}"})
        thread = threading.Thread(target=self.ingress.serve_forever, kwargs={'poll_interval':.02}, daemon=True)
        thread.start(); self.servers.append((self.ingress, thread))
        self.cookie, self.csrf = '', ''
        self.bootstrap()

    def tearDown(self):
        for server, thread in self.servers:
            server.shutdown(); server.server_close(); thread.join(2)
        self.tmp.cleanup()

    def request(self, action, payload, *, headers=None, client='operator', path=None, raw=None, receiver=False):
        server = self.servers[0][0] if receiver else self.ingress
        connection = http.client.HTTPSConnection('localhost', server.server_port, context=self.context(client), timeout=3)
        fields = {'Cf-Access-Jwt-Assertion': self.assertion, 'Content-Type': 'application/json', 'Origin': self.service.origin, 'X-Secret-Delivery': '1', 'Cookie': self.cookie, 'X-Secret-CSRF': self.csrf}
        fields.update(headers or {})
        fields = {k:v for k,v in fields.items() if v is not None}
        connection.request('POST', path or '/secret-delivery/'+action, json.dumps(payload).encode() if raw is None else raw, fields)
        response = connection.getresponse()
        result = response.read()
        cookie = response.getheader('Set-Cookie')
        status = response.status
        connection.close()
        return status, json.loads(result), cookie

    def bootstrap(self):
        status, data, cookie = self.request('bootstrap', {})
        self.assertEqual(status, 200)
        self.cookie = cookie.split(';')[0]
        self.csrf = data['csrf']
        return data

    def prepare(self, key='anthtropic_auth'):
        status, prepared, _ = self.request('prepare', {'target': self.target.id, 'key': key})
        self.assertEqual(status, 200)
        return prepared

    def send(self, value='synthetic-value', prepared=None, **extra):
        prepared = prepared or self.prepare()
        payload = {'target': prepared['target'], 'key': prepared['key'], 'value': value, 'delivery_id': secrets.token_hex(16), 'confirmation': prepared['confirmation'], 'overwrite': prepared['exists']}
        payload.update(extra)
        status, result, _ = self.request('send', payload)
        return status, result, payload

    def test_real_tls_delivery_and_metadata_only(self):
        marker = 'synthetic-'+secrets.token_hex(16)
        logs = io.StringIO()
        with contextlib.redirect_stdout(logs), contextlib.redirect_stderr(logs), patch('arvyx_control.api.claim_mutation', side_effect=AssertionError('generic journal reached')):
            status, result, payload = self.send(marker)
        self.assertEqual(status, 200)
        self.assertEqual(result['receipt']['status'], 'saved')
        self.assertIn(marker.encode(), (self.destdir/'.env').read_bytes())
        self.assertNotIn(marker, json.dumps(result)+logs.getvalue())
        for path in self.root.rglob('*'):
            if path.is_file() and path != self.destdir/'.env':
                self.assertNotIn(marker.encode(), path.read_bytes(), str(path))
        self.assertFalse((self.root/'events.jsonl').exists())
        self.assertEqual(self.request('status', {'delivery_id': payload['delivery_id']})[1], result)
        self.assertEqual((self.destdir/'.env').stat().st_mode & 0o777, 0o600)

    def test_overwrite_confirmation_and_cas(self):
        self.assertEqual(self.send('first')[1]['receipt']['status'], 'saved')
        prepared = self.prepare()
        self.assertTrue(prepared['exists'])
        self.assertEqual(self.send('unconfirmed', prepared, overwrite=False)[0], 400)
        prepared = self.prepare()
        current = self.destination.prepare('anthtropic_auth')
        self.destination.write('anthtropic_auth', 'intervening', overwrite_version=current.version)
        self.assertEqual(self.send('stale', prepared)[1]['receipt']['status'], 'version-conflict')
        self.assertEqual(self.send('confirmed')[1]['receipt']['status'], 'saved')

    def test_confirmation_bound_target_key_and_session(self):
        prepared = self.prepare()
        self.assertEqual(self.send(prepared=prepared, key='OTHER')[0], 400)
        prepared = self.prepare()
        self.bootstrap()
        self.assertEqual(self.send(prepared=prepared)[0], 400)

    def test_dedupe_no_value_fingerprint_or_resend(self):
        _, result, payload = self.send('first')
        payload['value'] = 'different'
        with patch.object(Target, 'exchange', side_effect=AssertionError('blind resend')):
            self.assertEqual(self.request('send', payload)[1], result)
        self.assertIn(b'first', (self.destdir/'.env').read_bytes())
        # Restarted metadata store preserves terminal receipt.
        self.assertEqual(Receipts(self.root/'ingress.sqlite').get(payload['delivery_id'], 'human-a'), result['receipt'])

    def test_timeout_after_possible_write_is_ambiguous(self):
        prepared = self.prepare()
        exchange = Target.exchange
        def lost_reply(target, payload):
            exchange(target, payload)
            raise TimeoutError('never expose raw details')
        with patch.object(Target, 'exchange', lost_reply):
            _, result, payload = self.send('written-before-timeout', prepared)
        self.assertEqual(result['receipt']['status'], 'ambiguous')
        self.assertIn(b'written-before-timeout', (self.destdir/'.env').read_bytes())
        with patch.object(Target, 'exchange', side_effect=AssertionError('retry')):
            self.assertEqual(self.request('send', payload)[1], result)

    def test_crash_reservation_survives_restart_without_dispatch(self):
        delivery_id = secrets.token_hex(16)
        self.service.receipts.reserve(delivery_id, self.target.id, 'anthtropic_auth', 'human-a')
        self.service.receipts = Receipts(self.root/'ingress.sqlite')
        prepared = self.prepare()
        with patch.object(Target, 'exchange', side_effect=AssertionError('crash retry')):
            _, result, _ = self.send('must-not-write', prepared, delivery_id=delivery_id)
        self.assertEqual(result['receipt']['status'], 'ambiguous')
        self.assertFalse((self.destdir/'.env').exists())

    def test_receiver_dedupe_and_fixed_exception_surface(self):
        payload = {'action':'prepare','target':self.target.id,'agent':self.target.agent,'runtime':self.target.runtime,'key':'OTHER','actor':'human-a'}
        prepared = self.target.exchange(payload)
        payload.update(action='send', value='synthetic-exception-marker', delivery_id=secrets.token_hex(16), version=prepared['version'], overwrite=False)
        logs = io.StringIO()
        with contextlib.redirect_stdout(logs), contextlib.redirect_stderr(logs), patch.object(self.destination, 'write', side_effect=ValueError(payload['value'])):
            result = self.target.exchange(payload)
        self.assertEqual(result, {'status':'ambiguous'})
        self.assertNotIn(payload['value'], logs.getvalue())
        self.receiver.receipts = Receipts(self.root/'receiver.sqlite')
        with patch.object(self.destination, 'write', side_effect=AssertionError('receiver retry')):
            self.assertEqual(self.target.exchange(payload), result)

    def test_auth_before_body_and_agent_rejection(self):
        agent = issue_token(self.vault, 'demobot', scopes=['control.write']).token
        for authorization in (None, 'Bearer '+agent, 'Bearer invalid'):
            status, result, _ = self.request('send', {}, headers={'Cf-Access-Jwt-Assertion':None, 'Authorization': authorization, 'Content-Length': '99999'}, raw=b'')
            self.assertEqual(status, 403)
            self.assertEqual(result, {'error': 'secret-delivery-denied'})
        self.assertEqual(self.request('bootstrap', {}, client=None)[0], 200)
        self.assertEqual(self.request('bootstrap', {}, client='other')[0], 200)

    def test_csrf_origin_content_type_query_and_bound_body(self):
        for fields in ({'Origin': None}, {'Origin': 'https://evil.invalid'}, {'X-Secret-Delivery': None}, {'X-Secret-CSRF': None}, {'Cookie': None}, {'Sec-Fetch-Site': 'cross-site'}, {'Content-Type': 'text/plain'}, {'Transfer-Encoding': 'chunked'}):
            self.assertEqual(self.request('prepare', {'target': self.target.id, 'key': 'OTHER'}, headers=fields)[0], 400)
        self.assertEqual(self.request('send', {}, path='/secret-delivery/send?value=synthetic')[0], 400)
        # Oversized declared length is refused before any body byte is read; sending the
        # bytes races the server's early close (SSLEOF), so only the declaration is sent.
        self.assertEqual(self.request('send', {}, headers={'Content-Length': str(98304 + 1)}, raw=b'')[0], 400)
        self.assertEqual(self.request('send', {}, raw=b'{"value":broken}')[1], {'error':'secret-delivery-rejected'})

    def test_target_key_and_injected_paths_rejected(self):
        for payload in ({'target':'unknown','key':'OTHER'}, {'target':self.target.id,'key':'NOT_ALLOWED'}, {'target':self.target.id,'key':'A\nB'}, {'target':self.target.id,'key':'OTHER','path':'/tmp/escape'}):
            self.assertEqual(self.request('prepare', payload)[0], 400)
        payload = {'action':'prepare','target':self.target.id,'agent':'wrong','runtime':self.target.runtime,'key':'OTHER','actor':'human-a'}
        self.assertEqual(self.request('', payload, client='sender', path='/v1/deliver', receiver=True)[0], 400)
        self.assertEqual(self.request('', payload, client='operator', path='/v1/deliver', receiver=True)[0], 400)

    def test_tls_pin_ca_and_redirect_fail_closed(self):
        payload = {'action':'prepare','target':self.target.id,'agent':self.target.agent,'runtime':self.target.runtime,'key':'OTHER','actor':'human-a'}
        with self.assertRaises(Rejected):
            dataclasses.replace(self.target, server_pin='0'*64).exchange(payload)
        with self.assertRaises(Rejected):
            dataclasses.replace(self.target, ca_file=str(self.certs/'other.pem')).exchange(payload)
        from http.server import BaseHTTPRequestHandler
        class Redirect(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                self.send_response(307); self.send_header('Location', 'https://never-contact.invalid/'); self.end_headers()
        redirect = self.start(Redirect)
        with self.assertRaises(Rejected):
            dataclasses.replace(self.target, url=f'https://localhost:{redirect.server_port}/v1/deliver').exchange(payload)
        with patch.dict(os.environ, {'HTTPS_PROXY':'http://127.0.0.1:1', 'https_proxy':'http://127.0.0.1:1'}):
            self.assertIn('version', self.target.exchange(payload))

    def test_default_disabled_and_non_http_journal_guard(self):
        handler = make_handler(self.vault, self.root/'events.jsonl', bearer_secret=self.bearer)
        original = self.ingress
        self.ingress = self.start(handler)
        self.assertEqual(self.request('send', {'value':'synthetic'})[0], 503)
        self.ingress = original
        with patch('arvyx_control.api.claim_mutation', side_effect=AssertionError('journal')):
            result = handle_api_request('POST', '/secret-delivery/send', {'value':'synthetic'}, self.vault, self.root/'events.jsonl')
        self.assertEqual(result.status, 503)

    def test_manifest_registration_and_owner_only(self):
        manifest = {'enabled':True, 'origin':self.service.origin, 'targets':[dataclasses.asdict(self.target)], 'receipts':str(self.root/'manifest.sqlite')}
        path = self.root/'manifest.json'
        path.write_text(json.dumps(manifest)); path.chmod(0o600)
        self.assertEqual(list(SecretDelivery.from_manifest(path, self.vault).targets), [self.target.id])
        manifest['targets'][0]['runtime'] = 'not-registered'
        path.write_text(json.dumps(manifest))
        with self.assertRaises(Rejected): SecretDelivery.from_manifest(path, self.vault)
        path.chmod(0o644)
        with self.assertRaises(Rejected): SecretDelivery.from_manifest(path, self.vault)

    @unittest.skipUnless(os.environ.get('ARVYX_SECRET_TEST_PLAYWRIGHT'), 'optional browser dependency supplied by operator; no installation')
    def test_browser_e2e_real_dashboard(self):
        # Test-only origin for an ephemeral local browser TLS port.
        self.service.origin = f'https://localhost:{self.ingress.server_port}'
        marker = 'synthetic-browser-' + secrets.token_hex(12)
        config = self.root/'browser.json'
        config.write_text(json.dumps({'origin':self.service.origin, 'assertion':self.assertion, 'marker':marker}))
        config.chmod(0o600)
        script = Path(__file__).resolve().parents[3]/'scripts/secret_delivery_browser_smoke.mjs'
        result = subprocess.run(['node', str(script), str(config)], capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)['ok'])
        self.assertIn((marker+'-replacement').encode(), (self.destdir/'.env').read_bytes())
        config.unlink()
        for path in self.root.rglob('*'):
            if path.is_file() and path != self.destdir/'.env':
                self.assertNotIn(marker.encode(), path.read_bytes(), str(path))

    def test_static_ui_secret_lane_is_separate(self):
        html = (Path(__file__).parents[1]/'src/arvyx_control/static/index.html').read_text()
        lane = html.split('// Dedicated secret lane:')[1].split('</script>')[0]
        for prohibited in ('Authorization', 'bearer', 'sessionStorage', 'localStorage', 'console.', 'mutate(', 'pendingOperationKeys', 'sendBeacon', 'setInterval', 'setTimeout'):
            self.assertNotIn(prohibited, lane)
        self.assertIn('type="password"', html)
        self.assertIn('window.confirm', lane)
        self.assertIn('value.value = ""', lane)


if __name__ == '__main__':
    unittest.main()
