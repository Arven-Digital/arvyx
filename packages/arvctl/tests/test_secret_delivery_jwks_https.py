"""Production JWKS reader against real loopback TLS; no external services."""
from contextlib import contextmanager
import http.client
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from test_secret_delivery import certificates
from arvyx_control.secret_delivery_access import AccessVerifier, MAX_JWKS
from arvyx_control.secret_delivery_protocol import Rejected


@unittest.skipUnless(os.name == 'posix', 'secret delivery destinations are defined by POSIX uid and mode semantics')
class JwksHttpsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        certificates(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @contextmanager
    def endpoint(self, body=b'{"keys":[{"kid":"synthetic"}]}', framing='length',
                 status=200, advertised=None, trickle=False, trust=True, host='localhost'):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(self.root/'server.pem', self.root/'server.key')
        client_context = ssl.create_default_context(cafile=str(self.root/'ca.pem') if trust else None)
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        listener.settimeout(5)

        stop = threading.Event()
        self.requests, self.connections, self.reads, self.responses = [], [], [], []

        def serve():
            try:
                raw, _ = listener.accept()
                with raw, server_context.wrap_socket(raw, server_side=True) as stream:
                    stream.settimeout(5)
                    request = b''
                    while b'\r\n\r\n' not in request:
                        part = stream.recv(4096)
                        if not part:
                            return
                        request += part
                    self.requests.append(request)
                    header = f'HTTP/1.1 {status} Test\r\nConnection: close\r\n'
                    if framing == 'length':
                        header += f'Content-Length: {len(body) if advertised is None else advertised}\r\n'
                    elif framing == 'chunked':
                        header += 'Transfer-Encoding: chunked\r\n'
                    if status != 200:
                        header += 'Location: https://redirect.invalid/keys\r\n'
                    stream.sendall((header+'\r\n').encode())
                    if trickle:
                        for byte in body:
                            stream.sendall(bytes([byte]))
                            if stop.wait(.15):
                                break
                    elif framing == 'chunked':
                        stream.sendall(f'{len(body):x}\r\n'.encode()+body+b'\r\n0\r\n\r\n')
                    else:
                        stream.sendall(body)
            except (OSError, ssl.SSLError):
                pass  # Expected when verification, size or deadline rejects.

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        real_connection = http.client.HTTPSConnection
        real_read = http.client.HTTPResponse.read1
        real_response = http.client.HTTPSConnection.getresponse
        def connection(issuer, port, **kwargs):
            self.assertEqual((issuer, port), ('synthetic.cloudflareaccess.com', 443))
            result = real_connection(host, listener.getsockname()[1], **kwargs)
            self.connections.append(result)
            return result
        def read(response, size):
            transport = response.fp.raw._sock
            result = real_read(response, size)
            self.reads.append((len(result), response.isclosed(), response.length, transport.fileno()))
            return result
        def getresponse(connection):
            response = real_response(connection)
            self.responses.append(response)
            return response
        try:
            with patch('arvyx_control.secret_delivery_access.ssl.create_default_context', return_value=client_context), \
                 patch('arvyx_control.secret_delivery_access.http', SimpleNamespace(client=SimpleNamespace(HTTPSConnection=connection))), \
                 patch.object(http.client.HTTPResponse, 'read1', read), \
                 patch.object(http.client.HTTPSConnection, 'getresponse', getresponse):
                yield AccessVerifier('https://synthetic.cloudflareaccess.com', 'synthetic-app', ['human-a'])
        finally:
            stop.set()
            listener.close()
            thread.join(6)
            self.assertFalse(thread.is_alive())
            for response in self.responses:
                self.assertTrue(response.isclosed(), 'response makefile leaked')

    def test_content_length_auto_closes_after_nonempty_final_read(self):
        body = json.dumps({'keys': [{'kid': 'synthetic'}], 'padding': 'x'*20000}).encode()
        with self.endpoint(body) as verifier:
            self.assertEqual(verifier._fetch_jwks(), json.loads(body))
            self.assertEqual(sum(row[0] for row in self.reads), len(body))
            self.assertGreater(self.reads[-1][0], 0)
            self.assertEqual(self.reads[-1][1:], (True, 0, -1))
            self.assertIn(b'GET /cdn-cgi/access/certs HTTP/1.1', self.requests[0])
            self.assertEqual(len(self.connections), 1)

    def test_chunked_and_close_delimited_complete_body(self):
        for framing in ('chunked', 'close'):
            with self.subTest(framing=framing), self.endpoint(framing=framing) as verifier:
                self.assertEqual(verifier._fetch_jwks(), {'keys': [{'kid': 'synthetic'}]})

    def test_truncated_content_length_rejects_valid_json(self):
        with self.endpoint(b'{"keys":[]}', advertised=100) as verifier:
            with self.assertRaises(Rejected):
                verifier._fetch_jwks()

    def test_oversized_all_framings(self):
        for framing in ('length', 'chunked', 'close'):
            with self.subTest(framing=framing), self.endpoint(b' '*(MAX_JWKS+1), framing=framing) as verifier:
                with self.assertRaises(Rejected):
                    verifier._fetch_jwks()
                self.assertLessEqual(sum(row[0] for row in self.reads), MAX_JWKS+1)

    def test_slow_trickle_has_total_deadline(self):
        with self.endpoint(b' '*100, trickle=True) as verifier:
            start = time.monotonic()
            with self.assertRaises((Rejected, OSError, ValueError)):
                verifier._fetch_jwks()
            elapsed = time.monotonic()-start
            self.assertGreater(elapsed, 2)
            self.assertLess(elapsed, 4.5)

    def test_tls_rejects_untrusted_ca_and_wrong_hostname(self):
        for trust, host in ((False, 'localhost'), (True, '127.0.0.1')):
            with self.subTest(trust=trust, host=host), self.endpoint(trust=trust, host=host) as verifier:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    verifier._fetch_jwks()
                self.assertFalse(self.requests)

    def test_redirects_not_followed(self):
        for status in (301, 302, 307, 308):
            with self.subTest(status=status), self.endpoint(status=status) as verifier:
                with self.assertRaises(Rejected):
                    verifier._fetch_jwks()
                self.assertEqual(len(self.connections), 1)
                self.assertEqual(len(self.requests), 1)


if __name__ == '__main__':
    unittest.main()
