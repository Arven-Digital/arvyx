"""HTTP transport and command-line entry point.

Run with ``python -m arvyx_control_center_api --vault <vault> --state <log>``.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
import sys
import uuid
from arvyx_control.diagnostics import TRACE, capture
from typing import Any, Sequence

# Reused rather than re-implemented: the operator API's bounded worker pool,
# its loopback rule, and the CLI's bearer-secret validation.
from arvyx_control.api import BoundedThreadingHTTPServer, _is_loopback_host
from arvyx_control.cli import _credential_value

from . import SCHEMA, SERVICE, __version__
from .app import AppConfig, Response, handle_request
from .views import Sources

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8766
# A refused request's body is discarded (never parsed) up to this size so
# the client reliably receives the 405 instead of a connection reset.
MAX_DISCARDED_BODY_BYTES = 65_536
DISCARD_TIMEOUT_SECONDS = 2
SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("Cache-Control", "no-store"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
    ("Referrer-Policy", "no-referrer"),
)


def make_handler(config: AppConfig) -> type[BaseHTTPRequestHandler]:
    class ControlCenterReadHandler(BaseHTTPRequestHandler):
        server_version = "ArvyxControlCenterAPI/1"
        sys_version = ""

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch(send_body=True)

        def do_HEAD(self) -> None:  # noqa: N802
            self._discard_body()
            self._dispatch(send_body=False)

        def __getattr__(self, name: str) -> Any:
            # BaseHTTPRequestHandler answers a method without a do_<METHOD>
            # with 501. Every non-GET method (POST, PUT, PATCH, DELETE,
            # OPTIONS, and arbitrary tokens) must be a deterministic 405.
            if name.startswith("do_"):
                return self._refuse
            raise AttributeError(name)

        def _refuse(self) -> None:
            self._discard_body()
            self._dispatch(send_body=True)

        def _discard_body(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return
            if 0 < length <= MAX_DISCARDED_BODY_BYTES:
                try:
                    self.connection.settimeout(DISCARD_TIMEOUT_SECONDS)
                    self.rfile.read(length)
                except OSError:
                    pass

        def _dispatch(self, *, send_body: bool) -> None:
            self.diagnostic_trace = uuid.uuid4().hex
            trace_token = TRACE.set(self.diagnostic_trace)
            try:
                response = handle_request(self.command, self.path, self.headers.get("Authorization"), config)
            except Exception as exc:  # noqa: BLE001 - never leak a traceback
                capture(exc, component="api", code="read_model_http")
                response = Response(
                    500, {"ok": False, "schema": SCHEMA, "error": "internal_error", "message": "internal error"}
                )
            finally:
                TRACE.reset(trace_token)
            self._write(response, send_body=send_body)

        def _write(self, response: Response, *, send_body: bool) -> None:
            data = (json.dumps(response.body, sort_keys=True) + "\n").encode("utf-8")
            self.close_connection = True
            try:
                self.send_response(response.status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("X-AMC-Trace-ID", self.diagnostic_trace)
                for name, value in SECURITY_HEADERS + response.headers:
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                if send_body:
                    self.wfile.write(data)
            except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
                return

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return

    return ControlCenterReadHandler


def build_server(host: str, port: int, config: AppConfig) -> BoundedThreadingHTTPServer:
    """Bind the server; loopback by default, as the operator API does."""
    if not _is_loopback_host(host) and not config.bearer_secret:
        raise ValueError(
            "refusing to bind a non-loopback host without an operator bearer secret (--auth-env or --auth-file)"
        )
    return BoundedThreadingHTTPServer((host, port), make_handler(config))


def serve(host: str, port: int, config: AppConfig) -> None:
    server = build_server(host, port, config)
    bound_port = server.server_address[1]
    print(
        f"{SERVICE} {__version__}: read-only (GET only, bearer control.read) on http://{host}:{bound_port}/v1",
        file=sys.stderr,
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m arvyx_control_center_api",
        description="Serve the read-only Control Center read-model API.",
    )
    parser.add_argument("--vault", type=Path, required=True,
                        help="Vault root: registry, agent memory counts, and token hashes. Read only.")
    parser.add_argument("--state", type=Path, required=True,
                        help="Append-only control-event log (JSONL), the same file `arvyx serve-api --state` uses. "
                             "Read only.")
    parser.add_argument("--delivery-routes", type=Path,
                        help="Authoritative agent-delivery route document. Without it the fleet verdict is red "
                             "(route_configuration_unavailable).")
    parser.add_argument("--audit-log", type=Path,
                        help="Hash-chained audit log to verify (default: <state dir>/audit-log.jsonl). Read only.")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Bind address (default: {DEFAULT_HOST}).")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Bind port (default: {DEFAULT_PORT}).")
    auth = parser.add_mutually_exclusive_group()
    auth.add_argument("--auth-env", help="Environment variable holding the operator bearer secret.")
    auth.add_argument("--auth-file", type=Path, help="File holding the operator bearer secret on one line.")
    parser.add_argument("--version", action="version", version=f"{SERVICE} {__version__}")
    return parser


def config_from_args(args: argparse.Namespace) -> AppConfig:
    if not args.vault.is_dir():
        raise ValueError("--vault must be an existing vault directory")
    if args.state.exists() and not args.state.is_file():
        raise ValueError("--state must be the control-event log file, not a directory")
    if not 0 <= args.port <= 65535:
        raise ValueError("--port must be between 0 and 65535")
    secret = _credential_value(auth_env=args.auth_env, auth_file=args.auth_file)
    if args.auth_env and secret is None:
        raise ValueError(f"--auth-env names an unset environment variable: {args.auth_env}")
    return AppConfig(
        sources=Sources(
            vault=args.vault,
            state=args.state,
            delivery_routes=args.delivery_routes,
            audit_log=args.audit_log,
        ),
        bearer_secret=secret,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = config_from_args(args)
        serve(args.host, args.port, config)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0
