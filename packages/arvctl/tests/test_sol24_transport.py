"""Round-five candidate-23 transport reproductions, synthetic offline only."""
import hashlib
import http.client
import io
import socket
import ssl
from contextlib import contextmanager
from dataclasses import replace
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.request import Request

import pytest
from arvyx_control import http_bounds, secret_delivery_access as access
from arvyx_control import secret_delivery_protocol as protocol
from arvyx_control.secret_delivery import SecretDelivery, Session
from safe_mcp_bridge import http_bounds as bridge_bounds, cli as bridge
import os

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='secret delivery destinations are defined by POSIX uid and mode semantics')


class WireSocket:
    def __init__(self, wire): self.wire = wire
    def makefile(self, *args, **kwargs): return io.BytesIO(self.wire)
    def getpeercert(self, **kwargs): return b'synthetic-certificate'


def capture(monkeypatch, module, headers, body=b'{"status":"saved"}'):
    responses, requests = [], []
    class Connection:
        sock = WireSocket(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n' + headers + b'\r\n\r\n' + body)
        def __init__(self, *args, **kwargs): pass
        def connect(self): pass
        def request(self, *args, **kwargs): requests.append(args)
        def getresponse(self):
            response = http.client.HTTPResponse(self.sock)
            response.begin()
            responses.append(response)
            return response
        def close(self): pass
    if module in (http_bounds, bridge_bounds):
        monkeypatch.setattr(http.client, 'HTTPConnection', Connection)
    else:
        monkeypatch.setattr(module, 'http', SimpleNamespace(client=SimpleNamespace(HTTPSConnection=Connection)))
        context = Mock()
        monkeypatch.setattr(module.ssl, 'create_default_context', lambda **kwargs: context)
    return responses, requests


@pytest.mark.parametrize('headers', [b'Content-Length: '+b'9'*5000, b'Transfer-Encoding: chunked '])
@pytest.mark.parametrize('module', [http_bounds, bridge_bounds])
def test_parser_framing_agreement(monkeypatch, module, headers):
    capture(monkeypatch, module, headers, b'{}')
    with pytest.raises(ValueError, match='framing'):
        with module.BoundedOpener().open(Request('http://synthetic.invalid/')) as response:
            response.read(100)


@pytest.mark.parametrize('headers', [b'Content-Length: '+b'9'*5000, b'Transfer-Encoding: chunked '])
def test_bridge_actual_entrypoint_refuses_malformed_success(monkeypatch, tmp_path, headers, capsys):
    body = b'{"jsonrpc":"2.0","id":"doctor-tools","result":{"tools":[]}}'
    capture(monkeypatch, bridge_bounds, headers, body)
    path = tmp_path/'bridge.json'
    path.write_text('{"target":{"url":"http://synthetic.invalid/"},"policy":{"allow_tools":[]}}')
    assert bridge.main(['doctor', str(path), '--json']) == 1
    assert '"ok": true' not in capsys.readouterr().out


def target():
    return protocol.Target('target', 'agent', 'runtime', 'https://synthetic.invalid/v1/deliver',
                           hashlib.sha256(b'synthetic-certificate').hexdigest(), 'synthetic-ca',
                           'synthetic-cert', 'synthetic-key', ('KEY',))


@pytest.mark.parametrize('headers', [b'Content-Length: 100', b'Content-Length: '+b'9'*5000,
                                    b'Transfer-Encoding: chunked ',
                                    b'Content-Length: 18\r\nTransfer-Encoding: chunked'])
def test_service_retains_durable_ambiguous_on_bad_framing(monkeypatch, tmp_path, headers):
    responses, requests = capture(monkeypatch, protocol, headers)
    tmp_path.chmod(0o700)
    from arvyx_control.vault import init_vault
    from arvyx_control.replica_authority import authority_context
    vault=tmp_path/'vault';init_vault(vault)
    receipts = protocol.Receipts(tmp_path/'receipts.sqlite')
    service = SecretDelivery('https://control.party', [target()], receipts, vault=vault)
    session = Session(actor='synthetic-human', csrf='csrf', expires=time.time()+60)
    session.preparations['confirm'] = ('target', 'KEY', 'version', False, time.time()+60)
    payload = dict(target='target', key='KEY', value='synthetic-value', delivery_id='delivery',
                   confirmation='confirm', overwrite=False)
    with authority_context(vault,tmp_path/'events.jsonl'):
        assert service.operate('send', payload, session)['receipt']['status'] == 'ambiguous'
    assert receipts.get('delivery', session.actor)['status'] == 'ambiguous'
    assert len(requests) == 1
    assert responses[0].isclosed()


@pytest.mark.parametrize('client,timeout', [('jwks', 3), ('target', 5)])
def test_real_client_dns_has_complete_deadline(monkeypatch, client, timeout):
    """Hold synthetic DNS; no sockets/external DNS. Bound actual entrypoint."""
    release = threading.Event()
    entered = threading.Event()
    def resolve(*args):
        entered.set()
        release.wait(10)
        raise OSError('synthetic DNS stopped')
    monkeypatch.setattr(http_bounds.socket, 'getaddrinfo', resolve)
    if client == 'jwks':
        verifier = object.__new__(access.AccessVerifier)
        verifier.issuer = 'https://synthetic.cloudflareaccess.com'
        call = verifier._fetch_jwks
    else:
        context = Mock()
        monkeypatch.setattr(protocol.ssl, 'create_default_context', lambda **kwargs: context)
        call = lambda: target().exchange({'action': 'send'})
    done = threading.Event()
    errors = []
    def run():
        try: call()
        except Exception as exc: errors.append(exc)
        finally: done.set()
    worker = threading.Thread(target=run, daemon=True)
    started = time.monotonic()
    worker.start()
    try:
        assert entered.wait(1)
        assert done.wait(timeout+0.7), 'client remained blocked beyond complete-operation deadline'
        assert time.monotonic()-started < timeout+0.9
        assert errors
    finally:
        release.set()
        worker.join(2)


@pytest.fixture(scope='module')
def pki(tmp_path_factory):
    from test_secret_delivery import certificates
    root = tmp_path_factory.mktemp('sol24-pki')
    certificates(root)
    return root


@contextmanager
def tls_wire(pki, headers, body=b'{"status":"saved"}', phase=None):
    """Raw synthetic wire over verified loopback TLS, with request body drained."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(pki/'server.pem', pki/'server.key')
    context.load_verify_locations(pki/'ca.pem')
    context.verify_mode = ssl.CERT_REQUIRED
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    listener.settimeout(2)
    stop = threading.Event()
    requests = []
    def serve():
        try:
            raw, _ = listener.accept()
            with raw:
                if phase == 'handshake':
                    stop.wait(2)
                    return
                with context.wrap_socket(raw, server_side=True) as stream:
                    stream.settimeout(2)
                    request = b''
                    while b'\r\n\r\n' not in request:
                        part = stream.recv(4096)
                        if not part: return
                        request += part
                    head, received = request.split(b'\r\n\r\n', 1)
                    length = 0
                    for line in head.split(b'\r\n')[1:]:
                        if line.lower().startswith(b'content-length:'):
                            length = int(line.split(b':', 1)[1])
                    while len(received) < length:
                        part = stream.recv(4096)
                        if not part: return
                        received += part
                    requests.append(head)
                    prefix = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'+headers+b'\r\n\r\n'
                    if phase == 'headers':
                        stream.sendall(b'HTTP/1.1 200 OK\r\nX-Synthetic: ')
                        data = b'x'*100
                    else:
                        stream.sendall(prefix)
                        data = body
                    for byte in data:
                        stream.sendall(bytes([byte]))
                        if phase and stop.wait(.02): break
        except (OSError, ssl.SSLError):
            pass
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert((pki/'server.pem').read_text())).hexdigest()
    target = protocol.Target('target', 'agent', 'runtime',
        f'https://localhost:{listener.getsockname()[1]}/v1/deliver', pin,
        str(pki/'ca.pem'), str(pki/'sender.pem'), str(pki/'sender.key'), ('KEY',))
    try:
        yield target, requests
    finally:
        stop.set()
        listener.close()
        worker.join(3)
        assert not worker.is_alive()


@pytest.mark.parametrize('headers,body', [
    (b'Content-Length: 18', b'{"status":"saved"}'),
    (b'Transfer-Encoding: chunked', b'12\r\n{"status":"saved"}\r\n0\r\n\r\n'),
    (b'Connection: close', b'{"status":"saved"}'),
])
def test_target_verified_mtls_valid_framings(pki, headers, body):
    with tls_wire(pki, headers, body) as (target, requests):
        assert target.exchange({'action': 'send'}) == {'status': 'saved'}
        assert len(requests) == 1


@pytest.mark.parametrize('headers', [b'Content-Length: 100', b'Transfer-Encoding: chunked ',
                                    b'Content-Length: '+b'9'*5000])
def test_target_real_tls_refuses_incomplete_framing(pki, headers):
    with tls_wire(pki, headers) as (target, requests):
        with pytest.raises(protocol.Rejected): target.exchange({'action': 'send'})
        assert len(requests) == 1


@pytest.mark.parametrize('policy', ['untrusted-ca', 'wrong-hostname', 'wrong-pin'])
def test_target_tls_policy_checked_before_http(pki, policy):
    with tls_wire(pki, b'Content-Length: 18') as (target, requests):
        if policy == 'untrusted-ca':
            target = replace(target, ca_file=str(pki/'other.pem'))
        elif policy == 'wrong-hostname':
            target = replace(target, url=target.url.replace('localhost', '127.0.0.1'))
        else:
            target = replace(target, server_pin='0'*64)
        with pytest.raises(protocol.Rejected):
            target.exchange({'action': 'send'})
        assert not requests


@pytest.mark.parametrize('phase', ['handshake', 'headers', 'body'])
@pytest.mark.parametrize('client', ['jwks', 'target'])
def test_real_clients_interrupt_tls_and_http_trickle(monkeypatch, pki, phase, client):
    # Default budgets are separately exercised by the real-entrypoint DNS test.
    # Accelerate only the shared budget here, not sockets/readers/TLS policy.
    module = access if client == 'jwks' else protocol
    original = http_bounds.bounded_connection
    def bounded(connection, timeout):
        assert timeout == (3 if client == 'jwks' else 5)
        return original(connection, .2)
    monkeypatch.setattr(module, 'bounded_connection', bounded)
    with tls_wire(pki, b'Content-Length: 100', b' '*100, phase) as (target, requests):
        if client == 'jwks':
            real_context = ssl.create_default_context
            def context():
                result = real_context(cafile=target.ca_file)
                result.load_cert_chain(target.client_cert, target.client_key)
                return result
            monkeypatch.setattr(access.ssl, 'create_default_context', context)
            verifier = object.__new__(access.AccessVerifier)
            verifier.issuer = target.url.removesuffix('/v1/deliver')
            call = verifier._fetch_jwks
        else:
            call = lambda: target.exchange({'action': 'send'})
        start = time.monotonic()
        with pytest.raises((protocol.Rejected, OSError, ValueError)):
            call()
        assert time.monotonic()-start < .8


def test_jwks_outstanding_dns_work_bounded(monkeypatch):
    release = threading.Event()
    lock = threading.Lock()
    started = []
    def resolve(*args):
        with lock: started.append(args)
        release.wait(2)
        raise OSError('synthetic DNS released')
    monkeypatch.setattr(http_bounds.socket, 'getaddrinfo', resolve)
    original = http_bounds.bounded_connection
    monkeypatch.setattr(access, 'bounded_connection', lambda connection, timeout: original(connection, .15))
    verifier = object.__new__(access.AccessVerifier)
    verifier.issuer = 'https://synthetic.cloudflareaccess.com'
    errors = []
    def fetch():
        try: verifier._fetch_jwks()
        except Exception as exc: errors.append(exc)
    workers = [threading.Thread(target=fetch) for _ in range(6)]
    try:
        for worker in workers: worker.start()
        for worker in workers: worker.join(1)
        assert all(not worker.is_alive() for worker in workers)
        assert len(errors) == 6
        assert len(started) == 4
    finally:
        release.set()
        for worker in workers: worker.join(2)
