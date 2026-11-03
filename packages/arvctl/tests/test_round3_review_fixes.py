from arvyx_control.replica_authority import authority_context
"""Disposable transport and owner regressions; no provider or native starts."""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError
from unittest.mock import patch

import pytest
from arvyx_control import control, embeddings, replica, public_onboarding_api, external_api
from safe_mcp_bridge import cli as bridge

pytestmark = pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'), reason='raw Unix-socket owner transport; Windows uses the loopback endpoint (test_owner_endpoint)')


@contextlib.contextmanager
def serving(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


@pytest.mark.parametrize('client', ['replica', 'embeddings'])
@pytest.mark.parametrize('cross_origin', [False, True])
@pytest.mark.parametrize('code', [301, 302, 303, 307, 308])
def test_credential_clients_refuse_real_redirects(client, cross_origin, code, monkeypatch):
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self): self.respond()
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', 0)))
            self.respond()
        def respond(self):
            seen.append((self.server.server_port, self.path, self.headers.get('Authorization')))
            data = b'{"data":[{"index":0,"embedding":[1.0]}]}'
            self.send_response(code if self.path == '/source' else 200)
            if self.path == '/source': self.send_header('Location', destination)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    with serving(ThreadingHTTPServer(('127.0.0.1', 0), Handler)) as source, serving(ThreadingHTTPServer(('127.0.0.1', 0), Handler)) as sink:
        destination = f'http://127.0.0.1:{sink.server_port}/collector' if cross_origin else '/collector'
        url = f'http://127.0.0.1:{source.server_port}/source'
        monkeypatch.setenv('ROUND3_SYNTHETIC_KEY', 'synthetic-only')
        with pytest.raises((ValueError, embeddings.EmbeddingError)):
            if client == 'replica': replica._get_json(url, 'synthetic-only', 2)
            else: embeddings._embed_batch(embeddings.EmbeddingConfig('http', url, 'fixture', 'ROUND3_SYNTHETIC_KEY', 2, 1), ['fixture'])
        assert seen == [(source.server_port, '/source', 'Bearer synthetic-only')]


@pytest.mark.parametrize('client', ['replica', 'embeddings'])
def test_https_downgrade_is_refused_by_actual_client_opener(client, monkeypatch, tmp_path):
    import ssl
    from urllib.request import HTTPSHandler, build_opener
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=IP:127.0.0.1'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', 0)))
            self.do_GET()
        def do_GET(self):
            seen.append(self.path)
            data = b'{"data":[{"index":0,"embedding":[1.0]}]}'
            self.send_response(302 if self.path == '/source' else 200)
            if self.path == '/source': self.send_header('Location', destination)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers(); self.wfile.write(data)
    source = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); tls.load_cert_chain(cert, key)
    source.socket = tls.wrap_socket(source.socket, server_side=True)
    module = replica if client == 'replica' else embeddings
    # Change certificate trust only; exercise the actual production transport.
    trusted = ssl.create_default_context(cafile=str(cert))
    monkeypatch.setattr(ssl, '_create_default_https_context', lambda: trusted)
    monkeypatch.setenv('ROUND3_SYNTHETIC_KEY', 'synthetic-only')
    with serving(source), serving(ThreadingHTTPServer(('127.0.0.1', 0), Handler)) as sink:
        destination = f'http://127.0.0.1:{sink.server_port}/collector'
        url = f'https://127.0.0.1:{source.server_port}/source'
        with pytest.raises((ValueError, embeddings.EmbeddingError)):
            if client == 'replica': replica._get_json(url, 'synthetic-only', 2)
            else: embeddings._embed_batch(embeddings.EmbeddingConfig('http', url, 'fixture', 'ROUND3_SYNTHETIC_KEY', 2, 1), ['fixture'])
        assert seen == ['/source']


class ErrorBody(io.BytesIO):
    def __init__(self, mode):
        super().__init__(b'x' * (2 * 1024 * 1024))
        self.mode, self.sizes = mode, []
    def read(self, size=-1):
        self.sizes.append(size)
        if self.mode == 'interrupted': raise OSError('synthetic interrupted body')
        return super().read(size)


@pytest.mark.parametrize('client', ['bridge', 'replica', 'embeddings', 'deadman', 'health', 'health_ops', 'notifiers', 'canary', 'agent', 'dogfood'])
@pytest.mark.parametrize('mode', ['oversized', 'interrupted'])
def test_http_errors_are_bounded_closed_and_contained(client, mode, monkeypatch, tmp_path):
    from arvyx_control import liveness, health, health_ops, notifiers, delivery_canary
    body = ErrorBody(mode)
    error = HTTPError('http://fixture.invalid', 503, 'fixture', {}, body)
    def fail(*args, **kwargs): raise error
    url = 'http://fixture.invalid'
    if client == 'bridge':
        monkeypatch.setattr(bridge._OPENER, 'open', fail)
        call = lambda: bridge._post_json({'target': {'url': url}}, {})
    elif client == 'replica':
        monkeypatch.setattr(replica, 'urlopen', fail)
        if hasattr(replica, '_OPENER'): monkeypatch.setattr(replica._OPENER, 'open', fail)
        call = lambda: replica._get_json(url, None, 1)
    elif client == 'embeddings':
        monkeypatch.setattr(embeddings, 'urlopen', fail)
        if hasattr(embeddings, '_OPENER'): monkeypatch.setattr(embeddings._OPENER, 'open', fail)
        call = lambda: embeddings._embed_batch(embeddings.EmbeddingConfig('http', url, 'fixture', None, 1, 1), ['fixture'])
    elif client == 'deadman': call = lambda: liveness.ping_deadman(url, fail=False, opener=fail)
    elif client == 'health':
        monkeypatch.setattr(health, 'urlopen', fail)
        from urllib.request import Request
        call = lambda: health._request_json(Request(url), 1)
    elif client == 'health_ops':
        monkeypatch.setattr(health_ops.BoundedOpener, 'open', fail)
        call = lambda: health_ops._probe_endpoint({'name': 'fixture', 'url': url}, 'fixture', 1)
    elif client == 'notifiers':
        monkeypatch.setattr(notifiers, 'urlopen', fail)
        call = lambda: notifiers._post_json(url, {}, 1)
    elif client == 'dogfood':
        from arvyx_control import dogfood
        monkeypatch.setattr(dogfood, '_post_json', fail)
        call = lambda: dogfood._check_unauthorized_recall(url)
    elif client == 'agent':
        from arvyx_control import agent_delivery
        from types import SimpleNamespace
        item = SimpleNamespace(id='fixture', target='fixture', subject_id='fixture', payload={})
        route = agent_delivery.AgentRoute('fixture', 'hermes-webhook', 'URL', 'KEY')
        monkeypatch.setattr(agent_delivery._OPENER, 'open', fail)
        call = lambda: agent_delivery.deliver_outbox_item(item, route, environ={'URL': 'http://127.0.0.1:1', 'KEY': 'synthetic'})
    else:
        monkeypatch.setattr(delivery_canary._API_OPENER, 'open', fail)
        call = lambda: delivery_canary.http_json('GET', url, None, {}, 1)
    try:
        with authority_context(tmp_path / "vault"):
            call()
    except (ValueError, embeddings.EmbeddingError, bridge.BridgeError): pass
    assert body.closed, client
    if client in {'replica', 'embeddings', 'deadman', 'health', 'health_ops', 'notifiers', 'agent', 'dogfood'}:
        assert body.sizes == [], 'status-only branches must not consume error bodies'
    assert all(0 < size <= 1024 * 1024 + 1 for size in body.sizes), body.sizes


@pytest.mark.parametrize('kind', ['public', 'external', 'local'])
@pytest.mark.parametrize('drip', [False, True])
def test_actual_listener_compositions_expire_preheaders(kind, drip, tmp_path, monkeypatch):
    from arvyx_control.cockpit_local import LocalServer, LocalHandler
    class API:
        def dispatch(self, *args): return 200, {'fixture': True}
    monkeypatch.setattr(public_onboarding_api.BoundedWorkers, 'request_lifetime_seconds', .2, raising=False)
    if kind == 'external': server = external_api.make_server(API())
    elif kind == 'public': server = public_onboarding_api.make_server(API())
    else:
        frontend = tmp_path / 'frontend'; frontend.mkdir()
        (frontend / 'index.html').write_text('<html>Fixture</html>')
        server = LocalServer(tmp_path, frontend)
        server.RequestHandlerClass = LocalHandler
        server.primary = server.onboarding = None
        server.origin = f'http://127.0.0.1:{server.server_port}'
    # Exercise exhaustion/recovery with exactly one worker, using each real
    # composition rather than a replacement HTTP handler/server.
    server.socket_timeout = 1
    server._workers = threading.BoundedSemaphore(1)
    with serving(server):
        with socket.create_connection(server.server_address, timeout=1) as client:
            client.settimeout(1)
            start = time.monotonic()
            client.sendall(b'GET / HTTP/1.0\r\nX-Incomplete: ')
            if drip:
                while time.monotonic() - start < .5:
                    try: client.sendall(b'x')
                    except OSError: break
                    time.sleep(.025)
            assert client.recv(4096) == b''
            assert time.monotonic() - start < .9
        # Slots must be recovered after both idle and absolute expiry.
        deadline = time.monotonic() + 1
        semaphore = getattr(server, '_workers', getattr(server, '_worker_slots', None))
        assert semaphore is not None
        while not semaphore.acquire(blocking=False):
            assert time.monotonic() < deadline
            time.sleep(.01)
        semaphore.release()
        with socket.create_connection(server.server_address, timeout=1) as healthy:
            healthy.sendall(f'GET / HTTP/1.0\r\nHost: 127.0.0.1:{server.server_port}\r\n\r\n'.encode())
            assert healthy.recv(4096).startswith(b'HTTP/1.0 ')


def test_large_event_log_keeps_incremental_anchor_across_small_appends(tmp_path):
    state = tmp_path / 'events.jsonl'
    def line(i, padding=''):
        return json.dumps(dict(id=str(i), type='fixture', task_id='fixture', timestamp='2026-01-01T00:00:00Z', payload={'padding': padding})) + '\n'
    state.write_text(line(1, 'x' * 200000))
    with patch.object(control, 'parse_event_lines', wraps=control.parse_event_lines) as parse:
        assert len(control.read_events(state)) == 1
        for i in range(2, 5):
            with state.open('a') as out: out.write(line(i))
            assert [e.id for e in control.read_events(state)] == list(map(str, range(1, i + 1)))
            parsed = parse.call_args.args[0]
            assert 'x' * 1000 not in parsed, 'unexpected full parse after small append'
        cached = control._EVENT_CACHE[str(state.resolve())]
        assert cached[6] == control._EVENT_ANCHOR_BYTES
        # Keep tail rewrite detection, not just append performance.
        raw = state.read_text(); state.write_text(raw.replace('"id": "4"', '"id": "9"'))
        assert control.read_events(state)[-1].id == '9'


def test_launcher_docs_identify_current_policy_and_fence_history():
    from arvyx_control.native_artifact_policy import NATIVE_MOUSE_BINARY_SHA256
    doc = Path(__file__).resolve().parents[3] / 'docs/cockpit-arvyx-frontend.md'
    if not doc.is_file():
        pytest.skip('private frontend record is not part of this checkout')
    text = doc.read_text()
    assert NATIVE_MOUSE_BINARY_SHA256 in text
    assert 'accepts only these two' not in text
    assert 'Historical launcher command (not accepted by current policy)' in text


def test_explicit_native_archive_overflow_preserves_socket_owner():
    import tempfile
    temporary = tempfile.TemporaryDirectory(prefix='r3-')
    tmp_path = Path(temporary.name)
    # This starts only a disposable Python owner and a plain shell, never a
    # provider/native frontend. The transcript adapter is synthetic and inert.
    vault = Path(__file__).resolve().parents[3] / 'fixtures/synthetic-vault'
    script = '''
import sys
from pathlib import Path
from arvyx_control import cockpit, cockpit_archive, control
from arvyx_control.replica_authority import authority_context

root, vault = map(Path, sys.argv[1:])
state = root/'events.jsonl'
# Task creation is a state mutation and requires the exact caller-owned binding.
with authority_context(vault, state):
    tasks = [control.create_task(state, 'Synthetic archive test', owner='demobot').task for _ in range(2)]
original = cockpit.LocalCockpit
# Synthetic inert source identity: archive provenance is bound to the native
# home/store incarnation, so even the fake runtime must name both.
(root/'native-home').mkdir()
(root/'native-home/state.db').write_bytes(b'')
class Runtime:
    home = root/'native-home'
    store = root/'native-home/state.db'
    def plan(self, *a): return None
    def transcript(self, *a, **k): return [dict(id=1, role='user', content='capacity trigger')]
def factory(*a, **k):
    owner = original(*a, **k)
    owner.native_runtimes['codex'] = Runtime()
    one = owner.open(project='demo-agent', task=tasks[0].id, name='archive', actor='operator')
    owner.bind_native(one['id'], tool='codex', conversation='synthetic-archive', actor='operator')
    other = owner.open(project='demo-agent', task=tasks[1].id, name='unrelated', actor='operator')
    # The unrelated plain shell launches only under the explicit test-owned host policy.
    owner.start(other['id'], actor='operator', environment='host')
    cockpit_archive.CAPTURE_CAPACITY = 1
    (root/'ids.json').write_text(__import__('json').dumps([one['id'], other['id']]))
    return owner
cockpit.LocalCockpit = factory
sys.argv = ['owner', '--root', str(root/'owner'), '--vault', str(vault), '--state', str(state), '--host', 'fixture',
            '--execution-policy', str(root/'execution-policy.json'), 'serve']
cockpit.main()
'''
    # Disposable, private host-only policy for the non-root test UID (no root, no sandbox).
    policy_file = tmp_path / 'execution-policy.json'
    policy_file.write_text(json.dumps(dict(host_uid=os.geteuid(), allow_host=True, allow_root=False, sandbox_launcher=None)))
    policy_file.chmod(0o600)
    log = (tmp_path / 'owner.log').open('w+')
    process = subprocess.Popen([sys.executable, '-c', script, str(tmp_path), str(vault)], stdout=log, stderr=log)
    try:
        endpoint = tmp_path / 'owner/cockpit.sock'
        deadline = time.monotonic() + 5
        while not endpoint.exists():
            assert process.poll() is None, 'owner failed to initialize'
            assert time.monotonic() < deadline
            time.sleep(.01)
        one, other = json.loads((tmp_path / 'ids.json').read_text())
        def request(operation, **fields):
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(2); client.connect(str(endpoint))
                client.sendall(json.dumps(dict(operation=operation, **fields)).encode() + b'\n')
                with client.makefile('rb') as stream:
                    raw = stream.readline()
                assert raw, 'owner closed connection instead of returning archive refusal'
                return json.loads(raw)
        before = request('list')['result']
        pid = next(x['pid'] for x in before if x['id'] == other)
        result = request('native_archive', sid=one, actor='operator')
        assert not result['ok'] and 'capacity' in result['error']
        assert process.poll() is None
        assert request('list')['result'] == before
        os.kill(pid, 0)
        import sqlite3
        with contextlib.closing(sqlite3.connect(tmp_path / 'owner/sessions.sqlite')) as db, db:
            assert db.execute('SELECT COUNT(*) FROM native_archive_cursor').fetchone()[0] == 0
            assert db.execute('SELECT COUNT(*) FROM work_capture').fetchone()[0] == 0
    finally:
        if process.poll() is None: process.send_signal(signal.SIGINT)
        process.wait(timeout=10)
        log.close()
        temporary.cleanup()
