"""Candidate-15 findings 3, 4, 8; synthetic offline transport tests."""
import io
import json
import threading
import time
from urllib.request import Request

import pytest
from arvyx_control import cli, mcp, http_bounds
from safe_mcp_bridge import cli as bridge
from safe_mcp_bridge import http_bounds as bridge_bounds


@pytest.mark.parametrize('module_name', ['arvyx_control.stdio_bounds', 'safe_mcp_bridge.stdio_bounds'])
@pytest.mark.parametrize('payload', [b'x' * (1024 * 1024 + 1), ('é' * (600000)).encode(), b'\xff\n'],
                         ids=['over-cap', 'utf8-600k', 'invalid-utf8'])  # short ids: the test id lands in an environment variable
def test_bounded_intake_eof_and_unicode(module_name, payload):
    import importlib
    module = importlib.import_module(module_name)
    assert list(module.bounded_lines(io.BytesIO(payload))) == [None]


@pytest.mark.parametrize('module', [http_bounds, bridge_bounds])
@pytest.mark.parametrize('scheme', ['http', 'https'])
def test_real_socket_stall_deadline(module, scheme):
    import socket
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    release = threading.Event()
    def serve():
        peer, _ = listener.accept()
        try:
            release.wait(2)
        finally:
            peer.close()
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    start = time.monotonic()
    try:
        with pytest.raises(OSError):
            with module.BoundedOpener().open(Request(f'{scheme}://127.0.0.1:{listener.getsockname()[1]}/'), timeout=.08):
                pytest.fail('unexpected response')
        assert time.monotonic() - start < .4
    finally:
        release.set()
        listener.close()
        worker.join(2)


def test_integer_refusal_is_parse_error(tmp_path):
    result = mcp.handle_json_line('{"n":' + '1' * 5000 + '}', vault=tmp_path)
    assert json.loads(result)['error']['code'] == -32700


def test_integer_refusal_keeps_stdio_alive(monkeypatch, tmp_path, capsys):
    import sys
    before = sys.get_int_max_str_digits()
    data = '{"n":' + '1' * 5000 + '}\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
    monkeypatch.setattr('sys.stdin', io.StringIO(data))
    assert cli.main(['mcp', '--vault', str(tmp_path)]) == 0
    rows = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert rows[0]['error']['code'] == -32700
    assert rows[1]['id'] == 2 and 'result' in rows[1]
    assert sys.get_int_max_str_digits() == before


@pytest.mark.parametrize('module', [http_bounds, bridge_bounds])
def test_real_http_success_and_redirect_refusal(module):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.error import HTTPError
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302 if self.path == '/redirect' else 200)
            self.send_header('Content-Length', '2')
            self.send_header('Location', '/ok')
            self.end_headers()
            self.wfile.write(b'ok')
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        base = f'http://127.0.0.1:{server.server_port}'
        with module.BoundedOpener().open(Request(base + '/ok'), timeout=1) as response:
            assert response.read() == b'ok'
        with pytest.raises(HTTPError) as exc:
            with module.BoundedOpener().open(Request(base + '/redirect'), timeout=1):
                pytest.fail('redirect followed')
        assert exc.value.code == 302
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)


@pytest.mark.parametrize('entry', ['main', 'bridge'])
def test_stdio_oversize_refusal_and_next_ping(monkeypatch, tmp_path, capsys, entry):
    data = b' ' * (2 * 1024 * 1024 + 100) + b'\n' + b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n'
    class BoundedInput(io.BytesIO):
        def readline(self, size=-1):
            assert 0 < size <= 1024 * 1024 + 1, 'unbounded stdin read'
            return super().readline(size)
    monkeypatch.setattr('sys.stdin', BoundedInput(data))
    if entry == 'main':
        assert cli.main(['mcp', '--vault', str(tmp_path)]) == 0
    else:
        monkeypatch.setattr(bridge, '_post_json', lambda config, payload: {'jsonrpc': '2.0', 'id': payload['id'], 'result': {}})
        assert bridge._run({'policy': {'allow_tools': []}}) == 0
    rows = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert rows[0]['error']['code'] == -32700
    assert rows[1]['id'] == 2 and 'result' in rows[1]


@pytest.mark.parametrize('module', [http_bounds, bridge_bounds])
def test_dns_deadline_and_bounded_workers(module, monkeypatch):
    release = threading.Event()
    entered = []
    def blocked(*args, **kwargs):
        entered.append(1)
        release.wait(2)
        return []
    monkeypatch.setattr(module.socket, 'getaddrinfo', blocked)
    start = time.monotonic()
    try:
        for _ in range(8):
            with pytest.raises(OSError):
                with module.BoundedOpener().open(Request('http://example.invalid/'), timeout=.02):
                    pytest.fail('unexpected response')
        assert time.monotonic() - start < .7
        assert len(entered) <= 4
    finally:
        release.set()


@pytest.mark.parametrize('module', [http_bounds, bridge_bounds])
def test_connect_attempts_share_deadline(module, monkeypatch):
    monkeypatch.setattr(module.socket, 'getaddrinfo', lambda *a, **kw: [(2, 1, 6, '', ('127.0.0.1', 9))] * 10)
    class SlowSocket:
        def settimeout(self, timeout): self.timeout = timeout
        def connect(self, address):
            time.sleep(self.timeout)
            raise TimeoutError('synthetic connect timeout')
        def close(self): pass
        def shutdown(self, how): pass
    monkeypatch.setattr(module.socket, 'socket', lambda *a, **kw: SlowSocket())
    start = time.monotonic()
    with pytest.raises(OSError):
        with module.BoundedOpener().open(Request('http://example.invalid/'), timeout=.03):
            pytest.fail('unexpected response')
    assert time.monotonic() - start < .15
