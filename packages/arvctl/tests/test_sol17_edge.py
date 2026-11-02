import http.client
import importlib.util
from pathlib import Path
import socket
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location('sol17_edge', Path(__file__).resolve().parents[3] / 'scripts/control_plane_edge_proxy.py')
assert spec and spec.loader
edge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(edge)


class EdgeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.seen = []
        self.mode = 'ok'
        self.listener = socket.create_server(('127.0.0.1', 0))
        self.listener.settimeout(.1)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.upstream, daemon=True)
        self.thread.start()
        self.proxy = edge.ProxyServer(('127.0.0.1', 0), edge.ProxyHandler,
            bearer='synthetic-downstream-only', upstream_host='127.0.0.1',
            upstream_port=self.listener.getsockname()[1], upstream_timeout=.25)
        # Set explicitly also on the original implementation for meaningful RED.
        self.proxy.incoming_bearer = 'synthetic-incoming-only'
        self.proxy.allowed_hosts = frozenset({'edge.example.test'})
        self.proxy.allowed_origins = frozenset({'https://edge.example.test'})
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()

    def upstream(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except (TimeoutError, OSError):
                continue
            def serve(conn):
                with conn:
                    data = b''
                    while b'\r\n\r\n' not in data:
                        block = conn.recv(65536)
                        if not block:
                            return
                        data += block
                    self.seen.append(data)
                    try:
                        if self.mode == 'short':
                            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 34\r\n\r\n{"ok":true}')
                        elif self.mode in ('chunked', 'badchunk', 'close', 'duplicate'):
                            wires = {
                                'chunked': b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n',
                                'badchunk': b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n',
                                'close': b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok',
                                'duplicate': b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok',
                            }
                            conn.sendall(wires[self.mode])
                        elif self.mode == 'large':
                            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n')
                        elif self.mode in ('drip', 'headers'):
                            wire = (b'HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n' + b'x'*20)
                            if self.mode == 'drip':
                                conn.sendall(wire[:-20])
                                wire = wire[-20:]
                            for byte in wire:
                                conn.sendall(bytes([byte]))
                                time.sleep(.04)
                        else:
                            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
                    except OSError:
                        pass
            threading.Thread(target=serve, args=(conn,), daemon=True).start()

    def tearDown(self):
        self.proxy.shutdown()
        self.proxy.server_close()
        self.stop.set()
        self.listener.close()
        self.thread.join(1)

    def request(self, method='GET', extra=(), auth=True, host: str | None='edge.example.test'):
        headers = [('Host', host)] if host is not None else []
        if auth:
            headers.append(('Authorization', 'Bearer synthetic-incoming-only'))
        headers += list(extra)
        conn = http.client.HTTPConnection('127.0.0.1', self.proxy.server_port, timeout=3)
        conn.putrequest(method, '/control/tasks', skip_host=True)
        for k, v in headers:
            conn.putheader(k, v)
        conn.putheader('Connection', 'close')
        conn.endheaders()
        response = conn.getresponse()
        result = response.status, response.read()
        conn.close()
        return result

    def test_authentication_before_injection(self):
        self.assertEqual(self.request(auth=False)[0], 401)
        self.assertEqual(self.request(extra=[('Authorization', 'Bearer wrong')])[0], 401)
        self.assertEqual(self.seen, [])
        self.assertEqual(self.request()[0], 200)
        self.assertIn(b'Authorization: Bearer synthetic-downstream-only', self.seen[0])
        self.assertNotIn(b'synthetic-incoming-only', self.seen[0])

    def test_host_and_mutation_origin_fail_closed(self):
        for host in (None, 'hostile.test', 'edge.example.test:443'):
            self.assertEqual(self.request(host=host)[0], 403)
        self.assertEqual(self.request(extra=[('Host', 'edge.example.test')])[0], 403)
        for origins in ([], [('Origin', 'null')], [('Origin', 'https://hostile.test')], [('Origin', 'https://edge.example.test')]*2):
            self.assertEqual(self.request('POST', origins)[0], 403)
        self.assertEqual(self.seen, [])
        self.assertEqual(self.request('POST', [('Origin', 'https://edge.example.test')])[0], 200)

    def test_unconfigured_boundary_denies(self):
        self.proxy.incoming_bearer = ''
        self.assertEqual(self.request()[0], 401)
        self.assertEqual(self.seen, [])

    def test_truncated_upstream_is_not_success(self):
        self.mode = 'short'
        self.assertEqual(self.request()[0], 502)

    def test_oversized_declared_upstream_fails_without_wait(self):
        self.mode = 'large'
        self.assertEqual(self.request()[0], 502)

    def test_framing_and_overflow(self):
        for mode in ('chunked', 'close'):
            self.mode = mode
            self.assertEqual(self.request(), (200, b'ok'))
        for mode in ('badchunk', 'duplicate'):
            self.mode = mode
            self.assertEqual(self.request()[0], 502)
        self.mode = 'ok'
        original = edge.MAX_RESPONSE
        try:
            edge.MAX_RESPONSE = 1
            self.assertEqual(self.request()[0], 502)
        finally:
            edge.MAX_RESPONSE = original

    def test_head_preserves_representation_length(self):
        self.assertEqual(self.request('HEAD'), (200, b''))

    def test_total_deadline_covers_body_and_headers(self):
        for mode in ('drip', 'headers'):
            self.mode = mode
            start = time.monotonic()
            self.assertEqual(self.request()[0], 502)
            self.assertLess(time.monotonic()-start, .7)


if __name__ == '__main__':
    unittest.main()
