from __future__ import annotations

import argparse
import importlib.util
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "control_plane_edge_proxy.py"
SPEC = importlib.util.spec_from_file_location("control_plane_edge_proxy", SCRIPT)
assert SPEC and SPEC.loader
edge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(edge)
AUTH_SCHEME = "Bear" + "er "


class _Upstream(BaseHTTPRequestHandler):
    seen: dict[str, str] = {}
    body = b""
    method = ""

    def _handle(self) -> None:
        type(self).seen = {key.lower(): value for key, value in self.headers.items()}
        type(self).body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        type(self).method = self.command
        payload = b"control-plane-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

    def log_message(self, format: str, *args: object) -> None:
        return


class ControlPlaneEdgeProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
        threading.Thread(target=self.upstream.serve_forever, daemon=True).start()
        self.proxy = edge.ProxyServer(
            ("127.0.0.1", 0),
            edge.ProxyHandler,
            bearer="server-side-placeholder",
            upstream_host="127.0.0.1",
            upstream_port=self.upstream.server_port,
            upstream_timeout=2,
            incoming_bearer="browser-placeholder",
            allowed_hosts=("localhost",),
            allowed_origins=("https://localhost",),
        )
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.proxy.server_port}"

    def tearDown(self) -> None:
        self.proxy.shutdown()
        self.upstream.shutdown()
        self.proxy.server_close()
        self.upstream.server_close()

    def _raw(self, request: bytes) -> bytes:
        request = request.replace(b"Host: localhost\r\n", b"Host: localhost\r\nAuthorization: Bearer browser-placeholder\r\nOrigin: https://localhost\r\n")
        with socket.create_connection(("127.0.0.1", self.proxy.server_port), timeout=3) as sock:
            sock.sendall(request)
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while chunk := sock.recv(65536):
                chunks.append(chunk)
            return b"".join(chunks)

    def test_loopback_only_and_server_side_bearer_injection(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            edge._loopback("0.0.0.0")
        request = Request(
            f"{self.base}/control-plane",
            headers={
                "Authorization": AUTH_SCHEME + "browser-placeholder",
                "Host": "localhost",
                "Cookie": "CF_AppSession=private",
                "Cf-Access-Jwt-Assertion": "private-jwt",
                "X-Forwarded-For": "spoofed",
            },
        )
        with urlopen(request, timeout=3) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"control-plane-ok")
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(
            _Upstream.seen["authorization"],
            AUTH_SCHEME + "server-side-placeholder",
        )
        for dropped in ("cookie", "cf-access-jwt-assertion", "x-forwarded-for"):
            self.assertNotIn(dropped, _Upstream.seen)

    def test_mutation_methods_forward_exact_bounded_body(self) -> None:
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            body = f'{{"method":"{method}"}}'.encode()
            request = Request(
                f"{self.base}/mutation",
                data=body,
                method=method,
                headers={"Content-Type": "application/json", "Idempotency-Key": "synthetic-key", "Host": "localhost", "Origin": "https://localhost", "Authorization": AUTH_SCHEME + "browser-placeholder"},
            )
            with urlopen(request, timeout=3) as response:
                self.assertEqual(response.status, 200)
            self.assertEqual(_Upstream.method, method)
            self.assertEqual(_Upstream.body, body)
            self.assertEqual(_Upstream.seen["idempotency-key"], "synthetic-key")

    def test_chunked_and_conflicting_content_length_fail_closed(self) -> None:
        chunked = self._raw(
            b"POST /mutation HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n"
        )
        self.assertIn(b" 501 ", chunked.split(b"\r\n", 1)[0])
        empty_transfer_encoding = self._raw(
            b"POST /mutation HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding:\r\n\r\nsmuggled"
        )
        self.assertIn(b" 501 ", empty_transfer_encoding.split(b"\r\n", 1)[0])
        conflicting = self._raw(
            b"POST /mutation HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx"
        )
        self.assertIn(b" 400 ", conflicting.split(b"\r\n", 1)[0])

    def test_upstream_failure_is_opaque_and_never_returns_bearer(self) -> None:
        self.upstream.shutdown()
        self.upstream.server_close()
        request = Request(f"{self.base}/control-plane", headers={"Host": "localhost", "Authorization": AUTH_SCHEME + "browser-placeholder"})
        with self.assertRaises(HTTPError) as caught:
            urlopen(request, timeout=3)
        payload = caught.exception.read()
        self.assertEqual(caught.exception.code, 502)
        self.assertNotIn(b"server-side-placeholder", payload)
        self.assertIn(b"upstream unavailable", payload)


if __name__ == "__main__":
    unittest.main()
