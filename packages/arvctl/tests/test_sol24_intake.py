"""Synthetic socket-pair regressions; no owner/provider/native applications."""
import importlib.util
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from arvyx_control.secret_delivery_server import SecretTLSServer

spec = importlib.util.spec_from_file_location('sol23_edge', Path(__file__).resolve().parents[3] / 'scripts/control_plane_edge_proxy.py')
assert spec and spec.loader
edge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(edge)


@unittest.skipUnless(os.name == 'posix', 'secret delivery destinations are defined by POSIX uid and mode semantics')
class DeadlineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        root = Path(cls.temp.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-keyout', str(root/'key'), '-out', str(root/'cert')], check=True, capture_output=True)
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(root/'cert', root/'key')
        cls.client_context = ssl.create_default_context(cafile=str(root/'cert'))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def exercise(self, tls=False, body=False, handshake=False, complete=False):
        entered = threading.Event()
        finished = threading.Event()

        class Handler(edge.ProxyHandler):
            timeout = .15

            def do_POST(self):
                entered.set()
                self.rfile.read(int(self.headers.get('Content-Length', '0')))

        if tls:
            server = SecretTLSServer(('127.0.0.1', 0), Handler, self.context)
            slots = server._worker_slots
        else:
            server = edge.ProxyServer(('127.0.0.1', 0), Handler, bearer='synthetic', upstream_host='127.0.0.1', upstream_port=1, upstream_timeout=1, max_workers=1)
            slots = server._workers
        server.request_lifetime_seconds = .25
        server.handshake_timeout = 2 if handshake else .15
        left, right = socket.socketpair()
        self.assertTrue(slots.acquire(False))

        def run():
            try:
                server.process_request_thread(left, ('127.0.0.1', 1))
            finally:
                finished.set()

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        peer = right
        try:
            if tls and not handshake:
                peer = self.client_context.wrap_socket(right, server_hostname='localhost')
            peer.settimeout(.1)
            if body or complete:
                peer.sendall(b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: ' + (b'0' if complete else b'1000') + b'\r\nConnection: close\r\n\r\n')
                self.assertTrue(entered.wait(.5))
            elif not handshake:
                peer.sendall(b'POST / HTTP/1.1\r\nX-Trickle: ')
            if complete:
                self.assertTrue(finished.wait(.2), 'normal completion did not release worker')
            else:
                end = time.monotonic() + .65
                while time.monotonic() < end and not finished.is_set():
                    try:
                        if not handshake:
                            peer.sendall(b'x')
                    except OSError:
                        break
                    time.sleep(.025)
                self.assertTrue(finished.wait(.1), 'renewable traffic retained worker beyond lifetime')
            self.assertTrue(slots.acquire(False), 'worker admission slot was not returned')
            slots.release()
        finally:
            peer.close()
            right.close()
            worker.join(1)
            server.server_close()

    def test_edge_trickled_headers(self):
        self.exercise()

    def test_edge_trickled_body(self):
        self.exercise(body=True)

    def test_tls_trickled_headers(self):
        self.exercise(tls=True)

    def test_tls_trickled_body(self):
        self.exercise(tls=True, body=True)

    def test_tls_trickled_handshake(self):
        self.exercise(tls=True, handshake=True)

    def test_edge_normal_completion(self):
        self.exercise(complete=True)

    def test_tls_normal_completion(self):
        self.exercise(tls=True, complete=True)
