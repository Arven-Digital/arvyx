#!/usr/bin/env python3
"""Loopback-only Cloudflare Access origin adapter for the Control Plane.

The generic adapter authenticates an incoming operator bearer before injecting a
separate V2 bearer on the numeric-loopback hop. Cloudflare headers alone do not
establish operator authority. Reserved secret delivery keeps its own verifier.
"""
from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import threading
import hmac
import math
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import urlsplit

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}
FORWARD_REQUEST = {
    "accept", "accept-encoding", "content-type", "idempotency-key",
    "if-none-match", "range", "user-agent",
}
MAX_BODY = 2 * 1024 * 1024
MAX_RESPONSE = 16 * 1024 * 1024
_LOG = logging.getLogger("arvyx.control_plane_edge")


def _loopback(value: str) -> str:
    if not ipaddress.ip_address(value).is_loopback:
        raise argparse.ArgumentTypeError("address must be loopback")
    return value


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ArvyxControlPlaneEdge/1"
    timeout = 15

    def _reject(self, status: int, message: str) -> None:
        self.close_connection = True
        payload = json.dumps({"error": message}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _proxy(self) -> None:
        # Reserved namespace is consumed BEFORE any generic body read/forward.
        # No Access token or submitted value may reach V2's generic journal.
        if urlsplit(self.path).path.startswith('/secret-delivery'):
            server = cast('ProxyServer', self.server)
            if server.secret_edge is None:
                self._reject(503, 'secret-delivery-disabled')
            else:
                server.secret_edge.handle(self)
            return
        server = cast("ProxyServer", self.server)
        authorization = self.headers.get_all("Authorization") or []
        if (not server.incoming_bearer or len(authorization) != 1
                or not hmac.compare_digest(authorization[0].encode(),
                                           f"Bearer {server.incoming_bearer}".encode())):
            self._reject(401, "operator authentication required")
            return
        hosts = self.headers.get_all("Host") or []
        origins = self.headers.get_all("Origin") or []
        if len(hosts) != 1 or hosts[0] not in server.allowed_hosts:
            self._reject(403, "host not allowed")
            return
        if ((origins and (len(origins) != 1 or origins[0] not in server.allowed_origins))
                or (self.command not in {"GET", "HEAD", "OPTIONS"} and not origins)):
            self._reject(403, "origin not allowed")
            return
        if not self.path.startswith("/") or self.path.startswith("//"):
            self._reject(400, "invalid request target")
            return
        if self.headers.get_all("Transfer-Encoding") is not None:
            self._reject(501, "transfer encoding is not supported")
            return
        raw_lengths = self.headers.get_all("Content-Length") or ["0"]
        normalized = [value.strip() for value in raw_lengths]
        if len(set(normalized)) != 1 or not re.fullmatch(r"[0-9]{1,10}", normalized[0], re.ASCII):
            self._reject(400, "invalid content length")
            return
        length = int(normalized[0])
        if length > MAX_BODY:
            self._reject(413, "request body too large")
            return
        try:
            body = self.rfile.read(length) if length else None
        except OSError:
            self._reject(408, "request body timeout")
            return
        if body is not None and len(body) != length:
            self._reject(400, "incomplete request body")
            return
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() in FORWARD_REQUEST
        }
        server = cast("ProxyServer", self.server)
        headers["Authorization"] = f"Bearer {server.bearer}"
        headers["Host"] = f"{server.upstream_host}:{server.upstream_port}"
        headers["Connection"] = "close"
        conn = http.client.HTTPConnection(
            server.upstream_host,
            server.upstream_port,
            timeout=server.upstream_timeout,
        )
        response_started = False
        deadline = time.monotonic() + server.upstream_timeout
        timer = None
        try:
            # Numeric loopback only: no unbounded DNS phase. A socket shutdown,
            # not a renewable per-read timeout, bounds headers and body alike.
            conn.connect()
            upstream_socket = conn.sock
            assert upstream_socket is not None

            def expire() -> None:
                try:
                    upstream_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("upstream deadline")
            timer = threading.Timer(remaining, expire)
            timer.daemon = True
            timer.start()
            conn.request(self.command, self.path, body=body, headers=headers)
            response = conn.getresponse()
            lengths = response.headers.get_all("Content-Length") or []
            transfers = response.headers.get_all("Transfer-Encoding") or []
            if (len(lengths) > 1 or (lengths and not re.fullmatch(r"[0-9]{1,10}", lengths[0], re.ASCII))
                    or (transfers and (lengths or len(transfers) != 1 or transfers[0].lower() != "chunked"))):
                raise http.client.HTTPException("invalid upstream framing")
            upstream_length = lengths[0] if lengths else "0"
            body_expected = self.command != "HEAD" and response.status not in {204, 304} and response.status >= 200
            if body_expected and lengths and int(upstream_length) > MAX_RESPONSE:
                raise http.client.HTTPException("upstream response too large")
            payload = response.read(MAX_RESPONSE + 1)
            if (len(payload) > MAX_RESPONSE or response.length not in (None, 0)
                    or (body_expected and lengths and len(payload) != int(upstream_length))):
                raise http.client.HTTPException("incomplete or oversized upstream response")
            if time.monotonic() >= deadline:
                raise TimeoutError("upstream deadline")
            self.send_response(response.status)
            response_started = True
            for key, value in response.getheaders():
                if key.lower() not in HOP_BY_HOP and key.lower() != "content-length":
                    self.send_header(key, value)
            response_length = upstream_length if self.command == "HEAD" and upstream_length.isascii() and upstream_length.isdigit() else str(len(payload))
            self.send_header("Content-Length", response_length)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        except Exception as exc:
            _LOG.warning("control plane upstream failure: %s", type(exc).__name__)
            if not response_started and not self.wfile.closed:
                self._reject(502, "control plane upstream unavailable")
            else:
                self.close_connection = True
        finally:
            if timer is not None:
                timer.cancel()
            conn.close()

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _proxy

    def log_message(self, format: str, *args: object) -> None:
        # Access logs live at Cloudflare/V2. Paths, headers and bodies stay out.
        return


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32
    request_lifetime_seconds = 30

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], *, bearer: str, upstream_host: str, upstream_port: int, upstream_timeout: float, max_workers: int = 32, secret_edge: Any = None, incoming_bearer: str = "", allowed_hosts: tuple[str, ...] = (), allowed_origins: tuple[str, ...] = ()) -> None:
        _loopback(upstream_host)
        if not math.isfinite(upstream_timeout) or upstream_timeout <= 0:
            raise ValueError("upstream timeout must be positive and finite")
        (self.incoming_bearer,) = (incoming_bearer,)
        self.allowed_hosts = frozenset(allowed_hosts)
        self.allowed_origins = frozenset(allowed_origins)
        self._workers = threading.BoundedSemaphore(max_workers)
        super().__init__(address, handler)
        (self.bearer,) = (bearer,)
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.upstream_timeout = upstream_timeout
        self.secret_edge = secret_edge

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._workers.acquire(blocking=False):
            try:
                request.settimeout(5)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._workers.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        # Start before request-line parsing; arriving bytes cannot renew this cap.
        def expire() -> None:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        deadline = threading.Timer(self.request_lifetime_seconds, expire)
        deadline.daemon = True
        started = False
        try:
            deadline.start()
            started = True
            super().process_request_thread(request, client_address)
        finally:
            deadline.cancel()
            if started:
                deadline.join()
            if not started:
                self.shutdown_request(request)
            self._workers.release()


def main() -> int:
    parser = argparse.ArgumentParser(description="Loopback-only Control Plane edge adapter")
    parser.add_argument("--host", type=_loopback, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--upstream-host", type=_loopback, default="127.0.0.1")
    parser.add_argument("--upstream-port", type=int, default=8766)
    parser.add_argument("--upstream-timeout", type=float, default=20.0, help="Non-renewable total upstream deadline in seconds")
    parser.add_argument("--allowed-host", action="append", required=True, help="Exact incoming Host authority; repeat for each allowed authority")
    parser.add_argument("--allowed-origin", action="append", required=True, help="Exact browser origin; required for every mutation")
    parser.add_argument('--secret-delivery-config', type=Path, help='Explicit opt-in private Access/destination configuration')
    args = parser.parse_args()
    if not (1 <= args.port <= 65535 and 1 <= args.upstream_port <= 65535):
        parser.error("ports must be between 1 and 65535")
    bearer = os.environ.get("ARVYX_V2_CONTROL_SECRET", "").strip()
    if not re.fullmatch(r"[!-~]{16,4096}", bearer, re.ASCII):
        parser.error("ARVYX_V2_CONTROL_SECRET is missing or malformed")
    incoming_bearer = os.environ.get("ARVYX_EDGE_OPERATOR_SECRET", "").strip()
    if (not re.fullmatch(r"[!-~]{16,4096}", incoming_bearer, re.ASCII)
            or hmac.compare_digest(incoming_bearer, bearer)):
        parser.error("ARVYX_EDGE_OPERATOR_SECRET must be valid and distinct from downstream authority")
    if not math.isfinite(args.upstream_timeout) or args.upstream_timeout <= 0:
        parser.error("upstream timeout must be positive and finite")
    for host in args.allowed_host:
        parsed = urlsplit("https://" + host)
        if not parsed.hostname or parsed.netloc != host or parsed.username or parsed.password or any(c.isspace() for c in host):
            parser.error("invalid allowed host")
    for origin in args.allowed_origin:
        parsed = urlsplit(origin)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or origin != f"{parsed.scheme}://{parsed.netloc}" or parsed.username or parsed.password):
            parser.error("invalid allowed origin")
    secret_edge = None
    if args.secret_delivery_config:
        try:
            from arvyx_control.secret_delivery_access import SecretEdge
            secret_edge = SecretEdge.from_config(args.secret_delivery_config)
        except Exception:
            parser.error('secret-delivery-config-or-dependency-unavailable')
    server = ProxyServer(
        (args.host, args.port), ProxyHandler,
        bearer=bearer,
        upstream_host=args.upstream_host,
        upstream_port=args.upstream_port,
        upstream_timeout=args.upstream_timeout,
        incoming_bearer=incoming_bearer,
        allowed_hosts=tuple(args.allowed_host),
        allowed_origins=tuple(args.allowed_origin),
        secret_edge=secret_edge,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
