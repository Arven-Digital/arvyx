"""SOL17-PAIRING-20261028: synthetic loopback transport regressions only."""
import contextlib
import http.client
import io
import json
import errno
import socket
import threading
import time
from unittest.mock import patch

import pytest
from arvyx_control import machine_pairing_transport as pairing


class Intake:
    def __init__(self): self.calls = []
    def challenge(self, data):
        self.calls.append(data)
        return {'ok': True}


@contextlib.contextmanager
def server(transport):
    instance = pairing.make_server(transport)
    instance.request_lifetime_seconds = .25
    thread = threading.Thread(target=instance.serve_forever, kwargs={'poll_interval': .01})
    thread.start()
    try: yield instance
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(2)


def exchange(instance, raw):
    with socket.create_connection(instance.server_address, timeout=1) as peer:
        # A saturated server may close before reading; the peer then sees the close
        # on send/shutdown instead of recv. Either way no response bytes may arrive.
        try:
            peer.sendall(raw)
            peer.shutdown(socket.SHUT_WR)
        except (BrokenPipeError, ConnectionResetError):
            return b''
        except OSError as error:
            if error.errno != errno.ENOTCONN:
                raise
            return b''
        chunks = []
        while True:
            try:
                part = peer.recv(65536)
            except ConnectionResetError:
                return b''.join(chunks)
            if not part: return b''.join(chunks)
            chunks.append(part)


@pytest.mark.parametrize('headers,body', [
    (b'Content-Length: 100\r\n', b'{}'),
    (b'Content-Length: 2\r\nContent-Length: 100\r\n', b'{}'),
    (b'Content-Length: 2\r\nContent-Length: 2\r\n', b'{}'),
    (b'Content-Length: 2\r\nTransfer-Encoding: identity\r\n', b'{}'),
    (b'Content-Length: 2\r\nTransfer-Encoding: \r\n', b'{}'),
    (b'Content-Length: +2\r\n', b'{}'),
    (b'Content-Length: 13\r\n', b'{"a":1,"a":2}'),
])
def test_intake_rejects_before_dispatch(headers, body):
    intake = Intake()
    with server(intake) as instance:
        result = exchange(instance, b'POST /challenge HTTP/1.0\r\n' + headers + b'\r\n' + body)
    assert b' 400 ' in result
    assert intake.calls == []


def test_preheader_trickle_expires_and_other_client_progresses():
    intake = Intake()
    with server(intake) as instance:
        with socket.create_connection(instance.server_address, timeout=1) as slow:
            slow.sendall(b'POST /challenge HTTP/1.0\r\nX: ')
            result = exchange(instance, b'POST /challenge HTTP/1.0\r\nContent-Length: 2\r\n\r\n{}')
            assert b' 200 ' in result
            started = time.monotonic()
            while time.monotonic() - started < .65:
                try: slow.sendall(b'x')
                except OSError: break
                time.sleep(.04)
            slow.settimeout(.3)
            assert slow.recv(4096) == b''


def test_worker_capacity_is_bounded():
    with server(Intake()) as instance:
        assert hasattr(instance, '_workers')
        held = []
        while instance._workers.acquire(blocking=False): held.append(1)
        try:
            assert held and len(held) <= 16
            assert exchange(instance, b'POST /challenge HTTP/1.0\r\nContent-Length: 2\r\n\r\n{}') == b''
        finally:
            for _ in held: instance._workers.release()


@contextlib.contextmanager
def response_peer(payload, declared=None, trickle=False):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0)); listener.listen()
    errors = []
    def run():
        try:
            with listener.accept()[0] as peer:
                peer.settimeout(1)
                request = b''
                while b'\r\n\r\n' not in request: request += peer.recv(4096)
                header, body = request.split(b'\r\n\r\n', 1)
                lengths = [int(line.split(b':', 1)[1]) for line in header.split(b'\r\n') if line.lower().startswith(b'content-length:')]
                remaining = (lengths[0] if lengths else 0) - len(body)
                while remaining > 0:
                    chunk = peer.recv(min(4096, remaining))
                    if not chunk: break
                    remaining -= len(chunk)
                peer.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: ' + str(declared if declared is not None else len(payload)).encode() + b'\r\n\r\n')
                if trickle:
                    for byte in payload:
                        peer.sendall(bytes([byte])); time.sleep(.04)
                else: peer.sendall(payload)
        except OSError: pass
        except Exception as exc: errors.append(exc)
    thread = threading.Thread(target=run); thread.start()
    try: yield 'http://127.0.0.1:%d' % listener.getsockname()[1]
    finally:
        listener.close(); thread.join(3)
        assert not thread.is_alive()
        assert not errors


def test_client_short_response_rejected_before_json(tmp_path):
    with response_peer(b'{}', declared=25) as url:
        with pytest.raises(ValueError, match='incomplete'):
            pairing.remote_action(tmp_path / 'identity', url, 'synthetic', 'check')


def test_client_overflow_rejected(tmp_path):
    with response_peer(b' ' * 16384 + b'{}') as url:
        with pytest.raises(ValueError, match='large|size|limit'):
            pairing.remote_action(tmp_path / 'identity', url, 'synthetic', 'check')


def test_client_nonrenewable_deadline(tmp_path):
    from arvyx_control.http_bounds import BoundedOpener
    original = BoundedOpener.open
    def short(self, request, timeout=10): return original(self, request, timeout=.15)
    with response_peer(b' ' * 20 + b'{}', trickle=True) as url:
        with patch.object(BoundedOpener, 'open', short):
            started = time.monotonic()
            with pytest.raises(Exception): pairing.remote_action(tmp_path / 'identity', url, 'synthetic', 'check')
            assert time.monotonic() - started < .6


@pytest.mark.parametrize('truncated_stage', ['/challenge', '/prove', None])
def test_complete_exchange_and_each_incomplete_stage(tmp_path, truncated_stage):
    transport = pairing.PairingTransport(tmp_path / 'server')
    calls = []
    class Wire:
        def __init__(self, payload): self.payload = payload
        def makefile(self, *args): return io.BytesIO(self.payload)
    @contextlib.contextmanager
    def open_response(self, request, timeout=10):
        stage = request.full_url.rsplit('/', 1)[-1]
        calls.append('/' + stage)
        data = json.loads(request.data)
        value = transport.challenge(data) if stage == 'challenge' else transport.prove(data)
        body = json.dumps(value).encode()
        extra = 23 if '/' + stage == truncated_stage else 0
        response = http.client.HTTPResponse(Wire(
            b'HTTP/1.0 200 OK\r\nContent-Length: ' + str(len(body) + extra).encode() + b'\r\n\r\n' + body))
        response.begin()
        try: yield response
        finally: response.close()
    try:
        with patch.object(pairing.BoundedOpener, 'open', open_response):
            if truncated_stage:
                with pytest.raises(ValueError, match='incomplete'):
                    pairing.remote_action(tmp_path / 'client', 'http://127.0.0.1:1', 'synthetic', 'check')
            else:
                assert pairing.remote_action(tmp_path / 'client', 'http://127.0.0.1:1', 'synthetic', 'check')['allowed'] is False
        assert calls == (['/challenge'] if truncated_stage == '/challenge' else ['/challenge', '/prove'])
    finally: transport.close()
