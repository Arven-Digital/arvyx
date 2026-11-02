"""Real offline Unix socket regressions; no application owner/provider starts."""
import json
from pathlib import Path
import socket
import threading
import time
from unittest.mock import patch

import pytest
from arvyx_control import cockpit_client as rpc


def trickle(peer, payload, delay=.02):
    try:
        for byte in payload:
            peer.sendall(bytes([byte]))
            time.sleep(delay)
    except OSError:
        pass
    finally:
        peer.close()


class Connected:
    def __init__(self, sock):
        self.sock = sock
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.sock.close()
    def connect(self, path):
        pass
    def settimeout(self, seconds):
        self.sock.settimeout(min(seconds, .1))
    def __getattr__(self, name):
        return getattr(self.sock, name)


def test_client_trickle_has_total_deadline():
    client, peer = socket.socketpair()
    worker = threading.Thread(target=trickle, args=(peer, b'{"ok":true,"result":"trickled"}\n'))
    worker.start()
    started = time.monotonic()
    try:
        with patch.object(rpc, 'REQUEST_TIMEOUT', .12, create=True), patch.object(rpc.socket, 'socket', return_value=Connected(client)):
            with pytest.raises(TimeoutError):
                rpc.request(Path('/synthetic'), 'write', data='once')
        assert time.monotonic() - started < .4
    finally:
        client.close()
        worker.join(2)


def test_owner_trickle_releases_intake_and_next_request_works():
    from arvyx_control import cockpit
    from types import SimpleNamespace
    calls = []
    service = SimpleNamespace(host='fixture', state='/synthetic', list=lambda: calls.append('list') or [])
    client, peer = socket.socketpair()
    worker = threading.Thread(target=trickle, args=(peer, b'{"operation":"list"}\n'))
    worker.start()
    started = time.monotonic()
    with patch.object(cockpit, 'OWNER_TIMEOUT', .12), client:
        cockpit.handle_connection(client, service, service)
    worker.join(2)
    assert time.monotonic() - started < .4
    assert calls == []
    client, peer = socket.socketpair()
    with client, peer:
        peer.sendall(b'{"operation":"list"}\n')
        cockpit.handle_connection(client, service, service)
        assert json.loads(peer.recv(4096)) == {'ok': True, 'result': []}
    assert calls == ['list']


@pytest.mark.parametrize('raw', [b'x' * 16384, b'[]\n', b'{"operation":"list","_endpoint_identity":{"host":"wrong"}}\n'])
def test_owner_caps_shape_and_identity_before_dispatch(raw):
    from arvyx_control import cockpit
    from types import SimpleNamespace
    calls = []
    service = SimpleNamespace(host='fixture', state='/synthetic', list=lambda: calls.append(1))
    client, peer = socket.socketpair()
    with client, peer:
        peer.sendall(raw)
        cockpit.handle_connection(client, service, service)
        assert json.loads(peer.recv(4096))['ok'] is False
    assert not calls


def test_send_backpressure_is_total_bounded():
    client, peer = socket.socketpair()
    with client, peer:
        client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        start = time.monotonic()
        with pytest.raises(TimeoutError):
            rpc.send_frame(client, b'x' * 900000 + b'\n', start + .1, rpc.RESPONSE_CAP)
        assert time.monotonic() - start < .4


@pytest.mark.parametrize('raw', [b'x' * 32, b'{"ok":true}'])
def test_response_requires_bounded_complete_frame(raw):
    client, peer = socket.socketpair()
    with client, peer:
        peer.sendall(raw)
        peer.shutdown(socket.SHUT_WR)
        with pytest.raises(ValueError):
            rpc.receive_frame(client, time.monotonic() + .2, 32)


def test_local_listener_fleet_identity_and_mutation_share_budget(tmp_path):
    # A synthetic listener only: never instantiate LocalCockpit or start native processes.
    from arvyx_control.cockpit_transport import Endpoint
    from tempfile import TemporaryDirectory
    import os
    # Short socket path: the system temp root (TMPDIR when set), not pytest's long tmp_path.
    import tempfile
    with TemporaryDirectory(prefix='sol27-', dir=tempfile.gettempdir()) as directory:
        root = Path(directory)
        (root / 'runtime').mkdir()
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(root / 'runtime/cockpit.sock'))
        listener.listen(2)
        listener.settimeout(.5)
        operations = []
        def serve():
            try:
                for result in [{'host': 'fixture', 'state': '/synthetic'}, 'mutated']:
                    conn, _ = listener.accept()
                    with conn:
                        raw = rpc.receive_frame(conn, time.monotonic() + .5, rpc.REQUEST_CAP)
                        operations.append(json.loads(raw)['operation'])
                        time.sleep(.08)
                        try:
                            conn.sendall(json.dumps({'ok': True, 'result': result}).encode() + b'\n')
                        except OSError:
                            pass
            finally:
                listener.close()
        worker = threading.Thread(target=serve)
        worker.start()
        start = time.monotonic()
        try:
            with patch('arvyx_control.cockpit_transport.REQUEST_TIMEOUT', .12):
                with pytest.raises(TimeoutError):
                    Endpoint(root, 'fixture', '/synthetic').call('write', data='once')
            assert time.monotonic() - start < .3
        finally:
            worker.join(2)
        assert not worker.is_alive()
        assert operations == ['snapshot', 'write']  # uncertain mutation is never retried


def test_owner_forwarded_call_inherits_intake_budget():
    from arvyx_control import cockpit
    from types import SimpleNamespace
    client, peer = socket.socketpair()
    outbound, upstream = socket.socketpair()
    calls = []
    def snapshot():
        calls.append('forwarded')
        return rpc.request(Path('/synthetic-forward'), 'snapshot')
    service = SimpleNamespace(host='fixture', state='/synthetic', snapshot=snapshot)
    peer.sendall(b'{"operation":"snapshot"}\n')
    worker = threading.Thread(target=trickle, args=(upstream, b'{"ok":true,"result":"trickled"}\n'))
    worker.start()
    start = time.monotonic()
    try:
        with client, peer, patch.object(cockpit, 'OWNER_TIMEOUT', .12), patch.object(rpc.socket, 'socket', return_value=Connected(outbound)):
            cockpit.handle_connection(client, service, service)
        assert time.monotonic() - start < .4
        assert calls == ['forwarded']
    finally:
        outbound.close()
        worker.join(2)


def test_oversized_request_is_not_sent():
    client, peer = socket.socketpair()
    with client, peer:
        with pytest.raises(ValueError):
            rpc.send_frame(client, b'x' * rpc.REQUEST_CAP + b'\n', time.monotonic() + .2, rpc.REQUEST_CAP)
        peer.settimeout(.02)
        with pytest.raises(TimeoutError):
            peer.recv(1)


def test_inherited_deadline_is_not_renewed_and_context_resets():
    with rpc.exchange_deadline(.1) as outer:
        with rpc.exchange_deadline(5) as inner:
            assert inner == outer
    assert rpc._deadline.get() is None
