"""Tests for the read-only Control Center read-model API.

The app lives in ``apps/control-center-api``; these tests sit in the CI
discovery root so every gate that runs ``unittest discover packages/arvctl/tests``
exercises it. All data is synthetic and built with the same helpers the rest
of the suite uses (``init_vault``, ``issue_token``, the control lifecycle).
"""

from __future__ import annotations
from arvyx_control.replica_authority import authority_context

import ast
from contextlib import redirect_stderr
from datetime import datetime, timezone
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import threading
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[3]
APP_ROOT = ROOT / "apps" / "control-center-api"
APP_PACKAGE = APP_ROOT / "src" / "arvyx_control_center_api"
sys.path.insert(0, str(ROOT / "packages" / "arvctl" / "src"))
sys.path.insert(0, str(APP_ROOT / "src"))

from arvyx_control.api import handle_api_request  # noqa: E402
from arvyx_control.audit_log import append_audit  # noqa: E402
from arvyx_control.auth import issue_token, revoke_token  # noqa: E402
from arvyx_control.control import (  # noqa: E402
    accept_handoff,
    acknowledge_thread,
    complete_task,
    create_handoff,
    create_task,
    post_thread,
    post_thread_message,
    request_approval,
    review_handoff,
)
from arvyx_control.security import SECRET_REDACTION, contains_literal_secret  # noqa: E402
from arvyx_control.vault import init_vault  # noqa: E402

from arvyx_control_center_api import SCHEMA  # noqa: E402
from arvyx_control_center_api.app import ROUTES, AppConfig, Response, handle_request  # noqa: E402
from arvyx_control_center_api.server import build_server, main as cli_main  # noqa: E402
from arvyx_control_center_api.views import MAX_STRING_CHARS, TRUNCATION_MARKER, Sources, sanitize  # noqa: E402

MEMORY_MARKER = "synthetic memory content marker"
BODY_MARKER = "synthetic body marker"
REASON_MARKER = "synthetic approval reason marker"
COMMAND_MARKER = "synthetic-command-marker"
# RFC 5737 documentation address: never a real host, and never a wildcard.
NON_LOOPBACK_HOST = "192.0.2.10"
DATA_ROUTES = [route.path for route in ROUTES if not route.public]
PUBLIC_ROUTES = [route.path for route in ROUTES if route.public]
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT", "PURGE", "get")
SAFE_EVENT_KEYS = {
    "id", "type", "subject_id", "timestamp", "actor", "owner", "target", "from_agent", "to_agent", "title",
    "status", "severity", "channel", "posted_by", "acked_by", "done_by", "reviewer", "completed_by",
    "performed_by", "route_target",
}


def _snapshot(root: Path) -> dict[str, tuple[object, ...]]:
    """Every path under root with its size, content hash, and mtime."""
    result: dict[str, tuple[object, ...]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            result[relative] = ("dir",)
        else:
            data = path.read_bytes()
            result[relative] = (len(data), hashlib.sha256(data).hexdigest(), path.stat().st_mtime_ns)
    return result


class _Fixture:
    """A synthetic vault, event log, audit log, route map, and credentials."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True)
        self.vault = root / "vault"
        init_vault(self.vault)
        raw = self.vault / "agents" / "demobot" / "raw"
        raw.mkdir(parents=True, exist_ok=True)
        (raw / "2026-09-01.md").write_text(MEMORY_MARKER + "\n", encoding="utf-8", newline="\n")

        self.state = root / "events.jsonl"
        with authority_context(self.vault, self.state):
            self.queued_task = create_task(state=self.state, title="Review synthetic fleet", owner="demobot").task
            self.done_task = create_task(state=self.state, title="Close synthetic drill", owner="vesper").task
            complete_task(state=self.state, task_id=self.done_task.id)
            self.active_handoff = create_handoff(
                state=self.state, title="Verify synthetic fleet", from_agent="demobot", to_agent="vesper",
                summary=BODY_MARKER,
            ).handoff
            accept_handoff(state=self.state, handoff_id=self.active_handoff.id, actor="vesper")
            self.review_handoff = create_handoff(
                state=self.state, title="Audit synthetic lane", from_agent="vesper", to_agent="demobot",
            ).handoff
            accept_handoff(state=self.state, handoff_id=self.review_handoff.id, actor="demobot")
            review_handoff(state=self.state, handoff_id=self.review_handoff.id, reviewer="operator", notes=BODY_MARKER)
            self.blocker = post_thread(
                state=self.state, title="Synthetic blocker", body=BODY_MARKER, actor="operator", target="demobot",
                thread_type="blocker",
            ).thread
            acknowledge_thread(state=self.state, thread_id=self.blocker.id, actor="demobot")
            post_thread_message(state=self.state, thread_id=self.blocker.id, actor="demobot", text=BODY_MARKER)
            self.approval = request_approval(
                state=self.state, command=COMMAND_MARKER, requester="demobot", reason=REASON_MARKER
            ).approval

            self.audit_log = root / "audit-log.jsonl"
            append_audit(self.audit_log, {"surface": "synthetic", "decision": "allowed", "route": "/synthetic"})
            self.routes = root / "routes.json"
            self.routes.write_text(
                json.dumps({"routes": {"vesper": {
                    "runtime": "hermes-webhook",
                    "url_env": "ARVYX_SYNTHETIC_VESPER_URL",
                    "credential_env": "ARVYX_SYNTHETIC_VESPER_CREDENTIAL",
                }}}),
                encoding="utf-8",
            )

            self.reader_token = issue_token(self.vault, "vesper", scopes=["control.read"]).token
            self.memory_token = issue_token(self.vault, "demobot", scopes=["memory.read"]).token
            self.revoked_token = issue_token(self.vault, "demobot", scopes=["control.read"], slot="revoked").token
            revoke_token(self.vault, "demobot", slot="revoked")
            self.operator_secret = secrets.token_urlsafe(32)
            self.config = AppConfig(
                sources=Sources(vault=self.vault, state=self.state, delivery_routes=self.routes),
                bearer_secret=self.operator_secret,
            )

    def get(self, path: str, token: str | None = None, *, config: AppConfig | None = None) -> Response:
        credential = self.reader_token if token is None else token
        authorization = f"Bearer {credential}" if credential else None
        return handle_request("GET", path, authorization, config or self.config)

    def control_plane(self, operator_audit: Path) -> dict[str, object]:
        """The operator API's own projection, for parity checks.

        The operator API audits reads, so its audit log is pointed outside
        the fixture root to keep the fixture byte-identical.
        """
        response = handle_api_request(
            "GET", "/control-plane", {}, vault=self.vault, state=self.state,
            bearer_secret=self.operator_secret, authorization=f"Bearer {self.operator_secret}",
            delivery_routes=self.routes, audit_log=operator_audit,
        )
        assert response.status == 200, response.body
        assert isinstance(response.body, dict)
        return response.body

    def append_raw_event(self, **payload_updates: object) -> str:
        """Append a legacy-shaped task event that bypassed write-time linting."""
        template = json.loads(self.state.read_text(encoding="utf-8").splitlines()[0])
        suffix = secrets.token_hex(6)
        template["id"] = f"event_legacy_{suffix}"
        template["task_id"] = f"task_legacy_{suffix}"
        template["payload"] = {**template["payload"], "id": template["task_id"], **payload_updates}
        with self.state.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(template, sort_keys=True) + "\n")
        return str(template["task_id"])


class ControlCenterApiTestCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.fx = _Fixture(self.tmp / "fixture")

    def ok(self, path: str, token: str | None = None, **kwargs: object) -> dict[str, object]:
        response = self.fx.get(path, token, **kwargs)  # type: ignore[arg-type]
        self.assertEqual(response.status, 200, response.body)
        return response.body


class AuthAndMethodTests(ControlCenterApiTestCase):
    def test_health_is_public_liveness_that_reads_no_state(self) -> None:
        missing = AppConfig(sources=Sources(vault=self.tmp / "no-vault", state=self.tmp / "no-state.jsonl"))
        for config in (self.fx.config, missing):
            response = handle_request("GET", "/v1/health", None, config)
            self.assertEqual(response.status, 200)
            self.assertEqual(response.body["schema"], SCHEMA)
            self.assertEqual(response.body["api_version"], "v1")
            self.assertIs(response.body["read_only"], True)
            self.assertNotIn("source", response.body)
            self.assertNotIn("data", response.body)

    def test_route_index_is_machine_readable_and_every_listed_route_answers(self) -> None:
        index = handle_request("GET", "/v1/routes", None, self.fx.config)
        self.assertEqual(index.status, 200)
        routes = index.body["routes"]
        self.assertEqual([route["path"] for route in routes], [route.path for route in ROUTES])
        self.assertEqual(index.body["methods"], ["GET"])
        self.assertEqual(index.body["auth"]["required_scope"], "control.read")
        self.assertEqual(index.body["auth"]["public_routes"], ["/v1/health", "/v1/routes"])
        for route in routes:
            self.assertTrue(route["path"].startswith("/v1/"))
            self.assertEqual(route["method"], "GET")
            if route["path"] in PUBLIC_ROUTES:
                self.assertEqual((route["auth"], route["scope"]), ("none", None))
            else:
                self.assertEqual((route["auth"], route["scope"]), ("bearer", "control.read"))
            for param in route["params"]:
                if param["type"] == "integer":
                    self.assertGreaterEqual(param["maximum"], param["default"])
            body = self.ok(route["path"])
            self.assertIs(body["ok"], True)
            if route["path"] in DATA_ROUTES:
                self.assertEqual(body["view"], route["view"])
                self.assertEqual(body["schema"], SCHEMA)

    def test_data_routes_fail_closed_without_a_valid_control_read_identity(self) -> None:
        denied_401 = {
            "no header": None,
            "unknown token": "Bearer " + secrets.token_hex(24),
            "wrong scheme": "Basic " + secrets.token_hex(24),
            "empty bearer": "Bearer ",
            "revoked token": f"Bearer {self.fx.revoked_token}",
            "oversized header": "Bearer " + "x" * 5000,
        }
        for path in [*DATA_ROUTES, "/v1/not-a-route", "/", "/control-plane", "/v1"]:
            for label, authorization in denied_401.items():
                with self.subTest(path=path, case=label):
                    response = handle_request("GET", path, authorization, self.fx.config)
                    self.assertEqual(response.status, 401)
                    self.assertEqual(response.body["error"], "unauthorized")
                    self.assertIn(("WWW-Authenticate", 'Bearer realm="arvyx-control-center", scope="control.read"'),
                                  response.headers)
            with self.subTest(path=path, case="memory.read only"):
                response = handle_request("GET", path, f"Bearer {self.fx.memory_token}", self.fx.config)
                self.assertEqual(response.status, 403)
                self.assertEqual(response.body["error"], "insufficient_scope")

    def test_no_configured_credentials_still_denies_every_data_route(self) -> None:
        vault = self.tmp / "tokenless-vault"
        init_vault(vault)
        config = AppConfig(sources=Sources(vault=vault, state=self.fx.state))
        for path in DATA_ROUTES:
            with self.subTest(path=path):
                self.assertEqual(handle_request("GET", path, None, config).status, 401)
                self.assertEqual(handle_request("GET", path, "Bearer " + "a" * 40, config).status, 401)

    def test_agent_token_and_operator_secret_are_both_accepted(self) -> None:
        for token in (self.fx.reader_token, self.fx.operator_secret):
            for path in DATA_ROUTES:
                with self.subTest(path=path):
                    self.assertEqual(self.fx.get(path, token).status, 200)
            unknown = self.fx.get("/v1/not-a-route", token)
            self.assertEqual(unknown.status, 404)
            self.assertEqual(unknown.body["error"], "not_found")

    def test_every_non_get_method_is_refused_with_405_before_auth(self) -> None:
        for path in [*DATA_ROUTES, *PUBLIC_ROUTES, "/v1/not-a-route"]:
            for method in WRITE_METHODS:
                for authorization in (None, f"Bearer {self.fx.reader_token}", f"Bearer {self.fx.operator_secret}"):
                    with self.subTest(path=path, method=method, authenticated=authorization is not None):
                        response = handle_request(method, path, authorization, self.fx.config)
                        self.assertEqual(response.status, 405)
                        self.assertEqual(response.body["error"], "method_not_allowed")
                        self.assertIn(("Allow", "GET"), response.headers)


class TransportTests(ControlCenterApiTestCase):
    def _serve(self) -> int:
        server = build_server("127.0.0.1", 0, self.fx.config)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return int(server.server_address[1])

    def _http(
        self, port: int, method: str, path: str, *, bearer: str | None = None, body: bytes | None = None
    ) -> tuple[int, http.client.HTTPResponse, bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        self.addCleanup(connection.close)
        headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response, response.read()

    def test_http_server_serves_reads_refuses_writes_and_never_mutates_sources(self) -> None:
        port = self._serve()
        before = _snapshot(self.fx.root)

        status, response, data = self._http(port, "GET", "/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(response.getheader("Content-Type"), "application/json; charset=utf-8")
        self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.getheader("Cache-Control"), "no-store")
        self.assertIn("default-src 'none'", response.getheader("Content-Security-Policy") or "")
        self.assertIs(json.loads(data)["ok"], True)

        status, response, _ = self._http(port, "GET", "/v1/work-board")
        self.assertEqual(status, 401)
        self.assertIn("Bearer", response.getheader("WWW-Authenticate") or "")

        status, _, data = self._http(port, "GET", "/v1/work-board?lane=active", bearer=self.fx.reader_token)
        self.assertEqual(status, 200)
        self.assertEqual(list(json.loads(data)["data"]["lanes"]), ["active"])

        payload = json.dumps({"title": "should never be created", "owner": "demobot"}).encode("utf-8")
        for method in ("POST", "PUT", "PATCH", "DELETE", "PURGE"):
            with self.subTest(method=method):
                status, response, data = self._http(
                    port, method, "/v1/work-board", bearer=self.fx.operator_secret, body=payload
                )
                self.assertEqual(status, 405)
                self.assertEqual(response.getheader("Allow"), "GET")
                self.assertEqual(json.loads(data)["error"], "method_not_allowed")
        status, response, data = self._http(port, "HEAD", "/v1/health")
        self.assertEqual(status, 405)
        self.assertEqual(data, b"")

        self.assertEqual(_snapshot(self.fx.root), before)

    def test_build_server_refuses_non_loopback_without_operator_secret(self) -> None:
        config = AppConfig(sources=self.fx.config.sources)
        with self.assertRaisesRegex(ValueError, "non-loopback"):
            build_server(NON_LOOPBACK_HOST, 0, config)


class ReadOnlyTests(ControlCenterApiTestCase):
    def test_projection_and_auth_faults_only_write_separate_telemetry(self) -> None:
        from dataclasses import replace
        from unittest.mock import patch
        from arvyx_control import diagnostics
        from arvyx_control_center_api import app
        before = _snapshot(self.fx.root)
        reporter = diagnostics.Reporter(self.tmp / 'dedicated-diagnostics.sqlite')
        try:
            with patch.object(diagnostics, '_reporter', reporter):
                def broken(*args):
                    raise OSError('synthetic projection fault')
                route = replace(app.ROUTE_TABLE['/v1/work-board'], build=broken)
                with patch.dict(app.ROUTE_TABLE, {'/v1/work-board': route}):
                    self.assertEqual(self.fx.get('/v1/work-board', self.fx.reader_token).status, 503)
                with patch.object(app, 'resolve_identity', side_effect=OSError('synthetic auth fault')):
                    self.assertEqual(self.fx.get('/v1/work-board', self.fx.reader_token).status, 503)
                self.assertTrue(reporter.flush(10))
                self.assertEqual({g['code'] for g in reporter.read()['groups']},
                                 {'read_model_projection', 'read_model_auth'})
        finally:
            reporter.close()
        self.assertEqual(_snapshot(self.fx.root), before)

    def test_views_never_write_to_vault_event_log_or_audit_log(self) -> None:
        before = _snapshot(self.fx.root)
        queries = [
            "/v1/work-board?lane=queued&owner=demobot&kind=task&limit=5",
            "/v1/squad?agent=vesper&limit=1",
            "/v1/signal?limit=3",
            "/v1/governance?limit=1",
            "/v1/work-board?limit=0",
            "/v1/not-a-route",
        ]
        for token in (self.fx.reader_token, self.fx.operator_secret, "", self.fx.memory_token):
            for path in [*DATA_ROUTES, *PUBLIC_ROUTES, *queries]:
                self.fx.get(path, token)
                handle_request("POST", path, f"Bearer {token}", self.fx.config)
        self.assertEqual(_snapshot(self.fx.root), before)

    def test_package_imports_only_stdlib_and_read_only_arvyx_control_names(self) -> None:
        allowed_arvyx_imports = {
            "arvyx_control": {"__version__"},
            "arvyx_control.api": {
                "_approval_effective_status", "_control_plane", "_count_by_status", "_health_age",
                "_memory_queue", "_thread_counts", "BoundedThreadingHTTPServer", "_is_loopback_host",
            },
            # Telemetry-only exception: no Reporter, writer, or business mutation imports.
            # Fault-path byte immutability is asserted above; see error-diagnostics.md.
            "arvyx_control.diagnostics": {"TRACE", "capture"},
            "arvyx_control.audit_log": {"default_audit_log", "verify_chain"},
            "arvyx_control.auth": {"SCOPE_CONTROL_READ", "resolve_identity"},
            "arvyx_control.cli": {"_credential_value"},
            "arvyx_control.control": {"list_approvals", "list_handoffs", "list_tasks", "list_thread_inbox",
                                      "read_events"},
            "arvyx_control.replica": {"replica_status"},
            "arvyx_control.security": {"redact_secrets"},
            "arvyx_control.store": {"manifest_state"},
        }
        stdlib = set(sys.stdlib_module_names)
        modules = sorted(APP_PACKAGE.glob("*.py"))
        self.assertTrue(modules)
        for module in modules:
            tree = ast.parse(module.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertIn(alias.name.split(".")[0], stdlib, f"{module.name}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    root = node.module.split(".")[0]
                    if root in stdlib or node.module == "__future__":
                        continue
                    self.assertIn(node.module, allowed_arvyx_imports, f"{module.name}: from {node.module}")
                    for alias in node.names:
                        self.assertIn(alias.name, allowed_arvyx_imports[node.module],
                                      f"{module.name}: {alias.name} from {node.module} is not an allowed read")

    def test_pyproject_installs_the_app_without_runtime_dependencies(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertIn("apps/control-center-api/src", project["tool"]["setuptools"]["packages"]["find"]["where"])
        self.assertEqual(project["project"]["dependencies"], [])

    def test_readme_documents_every_route_and_the_entry_point(self) -> None:
        readme = (APP_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("Planned extraction area", readme)
        self.assertIn("python -m arvyx_control_center_api", readme)
        for route in ROUTES:
            self.assertIn(f"`{route.path}`", readme)


class ViewTests(ControlCenterApiTestCase):
    def test_storage_retired_card_withholds_full_disposition(self):
        from arvyx_control.retirement import abandon_stale_thread
        from arvyx_control.control import post_thread
        from arvyx_control.replica_authority import authority_context
        with authority_context(self.fx.vault, self.fx.state):
            subject = post_thread(self.fx.state, title='Synthetic obsolete work', actor='operator', target='demobot').thread
            abandon_stale_thread(self.fx.state, thread_id=subject.id, reason='No longer needed',
                                 approval_reference='secret://approvals/synthetic', dry_run=False)
        body = self.ok('/v1/work-board?lane=retired')
        card = next(card for card in body['data']['lanes']['retired'] if card['id'] == subject.id)
        self.assertNotIn('retirement', card)
        self.assertNotIn('secret://approvals/synthetic', json.dumps(body))
        self.assertEqual(card['lane'], 'retired')

    def _lane_ids(self, lanes: dict[str, list[dict[str, object]]]) -> dict[str, set[str]]:
        return {lane: {str(card["id"]) for card in cards} for lane, cards in lanes.items()}

    def test_every_view_carries_the_envelope_and_explicit_freshness(self) -> None:
        latest = max(json.loads(line)["timestamp"] for line in self.fx.state.read_text(encoding="utf-8").splitlines())
        now = datetime.now(timezone.utc)
        for path in DATA_ROUTES:
            with self.subTest(path=path):
                body = self.ok(path)
                self.assertEqual(set(body), {"ok", "schema", "view", "generated_at", "source", "bounds", "data"})
                generated = datetime.fromisoformat(str(body["generated_at"]).replace("Z", "+00:00"))
                self.assertLess(abs((generated - now).total_seconds()), 120)
                source = body["source"]
                self.assertEqual(source["last_timestamp"], latest)
                self.assertIsInstance(source["freshness_seconds"], int)
                self.assertEqual(source["retention"], "append-only-jsonl")
                self.assertGreater(source["event_count"], 0)

    def test_work_board_is_the_operator_control_plane_projection(self) -> None:
        body = self.ok("/v1/work-board")
        lanes = self._lane_ids(body["data"]["lanes"])
        self.assertEqual(set(lanes), {"queued", "active", "review", "done", "retired"})
        self.assertIn(self.fx.queued_task.id, lanes["queued"])
        self.assertIn(self.fx.done_task.id, lanes["done"])
        self.assertIn(self.fx.active_handoff.id, lanes["active"])
        self.assertIn(self.fx.blocker.id, lanes["active"])
        self.assertIn(self.fx.review_handoff.id, lanes["review"])
        operator = self.fx.control_plane(self.tmp / "operator-audit.jsonl")
        self.assertEqual(lanes, self._lane_ids(operator["kanban"]))
        cards = [card for lane in body["data"]["lanes"].values() for card in lane]
        self.assertTrue(all("summary" not in card and "body" not in card for card in cards))

        active = self.ok("/v1/work-board?lane=active")
        self.assertEqual(list(active["data"]["lanes"]), ["active"])
        self.assertEqual(active["data"]["filters"]["lane"], "active")
        owned = self.ok("/v1/work-board?owner=demobot")
        owned_cards = [card for lane in owned["data"]["lanes"].values() for card in lane]
        self.assertTrue(owned_cards)
        self.assertEqual({card["owner"] for card in owned_cards}, {"demobot"})
        handoffs = self.ok("/v1/work-board?kind=handoff")
        handoff_cards = [card for lane in handoffs["data"]["lanes"].values() for card in lane]
        self.assertEqual({card["kind"] for card in handoff_cards}, {"handoff"})
        self.assertEqual(len(handoff_cards), 2)

    def test_squad_matches_operator_agents_and_withholds_memory_content(self) -> None:
        body = self.ok("/v1/squad")
        operator = self.fx.control_plane(self.tmp / "operator-audit.jsonl")
        agents = body["data"]["agents"]
        self.assertEqual([agent["id"] for agent in agents], [agent["id"] for agent in operator["agents"]])
        self.assertEqual([agent["work"] for agent in agents], [agent["work"] for agent in operator["agents"]])
        demobot = next(agent for agent in agents if agent["id"] == "demobot")
        self.assertEqual(demobot["blockers"]["count"], 1)
        self.assertEqual(demobot["status"], "blocked")
        self.assertEqual(demobot["memory"]["raw_documents"], 1)
        self.assertEqual(demobot["skills"], {"reported": False, "count": 0, "items": []})
        self.assertNotIn(MEMORY_MARKER, json.dumps(body))
        self.assertEqual(body["bounds"]["agents"]["registry_invalid"], 0)

        only = self.ok("/v1/squad?agent=vesper")
        self.assertEqual([agent["id"] for agent in only["data"]["agents"]], ["vesper"])
        self.assertEqual(self.ok("/v1/squad?agent=nobody")["data"]["agents"], [])

    def test_signal_is_newest_first_safe_event_metadata(self) -> None:
        body = self.ok("/v1/signal")
        operator = self.fx.control_plane(self.tmp / "operator-audit.jsonl")
        events = body["data"]["events"]
        self.assertEqual([event["id"] for event in events], [event["id"] for event in operator["events"]][: len(events)])
        for event in events:
            self.assertLessEqual(set(event), SAFE_EVENT_KEYS)
        self.assertEqual(len(body["data"]["activity"]["buckets"]), 12)
        serialized = json.dumps(body)
        for marker in (BODY_MARKER, REASON_MARKER, COMMAND_MARKER):
            self.assertNotIn(marker, serialized)

    def test_command_deck_reports_verdict_counts_and_lane_pressure(self) -> None:
        body = self.ok("/v1/command-deck")
        data = body["data"]
        self.assertIn(data["fleet"]["verdict"], {"green", "amber", "red"})
        self.assertNotIn("route_configuration_unavailable", data["fleet"]["red"])
        self.assertEqual(data["counts"]["tasks"], {"total": 2, "open": 1, "done": 1})
        self.assertEqual(data["counts"]["handoffs"], {"total": 2, "accepted": 1, "reviewed": 1})
        self.assertEqual(data["counts"]["approvals"], {"total": 1, "requested": 1})
        self.assertEqual(data["counts"]["threads"]["pending"], 1)
        self.assertEqual(data["work"]["lanes"], {"queued": 1, "active": 2, "review": 1, "done": 1, "retired": 0})
        self.assertFalse(body["bounds"]["lane_counts"]["truncated"])
        self.assertGreaterEqual(data["squad"]["registered"], 2)

        unrouted = AppConfig(sources=Sources(vault=self.fx.vault, state=self.fx.state),
                             bearer_secret=self.fx.operator_secret)
        deck = self.ok("/v1/command-deck", config=unrouted)
        self.assertEqual(deck["data"]["fleet"]["verdict"], "red")
        self.assertIn("route_configuration_unavailable", deck["data"]["fleet"]["red"])
        delivery = self.ok("/v1/delivery", config=unrouted)
        self.assertEqual(delivery["data"]["route_configuration"], "not_configured")
        self.assertEqual(delivery["data"]["verdict"], "red")

    def test_delivery_matches_the_fleet_verdict_and_reports_bounds(self) -> None:
        body = self.ok("/v1/delivery")
        deck = self.ok("/v1/command-deck")
        self.assertEqual(body["data"]["verdict"], deck["data"]["fleet"]["verdict"])
        self.assertEqual(body["data"]["route_configuration"], "configured")
        self.assertIn("dispatcher", body["data"]["delivery"])
        self.assertIn("execution", body["data"]["fleet"])
        self.assertEqual(body["bounds"]["truncated_lists"], {})
        self.assertEqual(body["bounds"]["list_limit"], 50)

    def test_governance_exposes_posture_not_payloads(self) -> None:
        body = self.ok("/v1/governance")
        data = body["data"]
        (item,) = data["approvals"]["items"]
        self.assertEqual(
            set(item),
            {"id", "requester", "approver", "status", "effective_status", "created_at", "updated_at", "expires_at"},
        )
        self.assertEqual(item["id"], self.fx.approval.id)
        self.assertEqual(data["approvals"]["counts"], {"total": 1, "requested": 1})
        self.assertEqual(data["audit"], {"status": "ok", "events": 1, "first_break_line": None})
        self.assertEqual(data["replica"]["role"], "primary")
        self.assertNotIn("vault", data["replica"])
        self.assertNotIn("source", data["replica"])
        self.assertEqual(data["retention"]["retention"], "append-only-jsonl")
        serialized = json.dumps(body)
        for marker in (REASON_MARKER, COMMAND_MARKER, str(self.tmp)):
            self.assertNotIn(marker, serialized)

        lines = self.fx.audit_log.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[0])
        tampered["decision"] = "denied"
        self.fx.audit_log.write_text(json.dumps(tampered) + "\n", encoding="utf-8")
        broken = self.ok("/v1/governance")["data"]["audit"]
        self.assertEqual((broken["status"], broken["first_break_line"]), ("broken", 1))
        self.fx.audit_log.unlink()
        self.assertEqual(self.ok("/v1/governance")["data"]["audit"]["status"], "absent")


class BoundsAndSafetyTests(ControlCenterApiTestCase):
    def test_list_bounds_are_enforced_and_reported(self) -> None:
        with authority_context(self.fx.vault, self.fx.state):
            for index in range(230):
                create_task(state=self.fx.state, title=f"Synthetic bulk task {index}", owner="vesper")

            board = self.ok("/v1/work-board")
            queued = board["bounds"]["lanes"]["queued"]
            self.assertEqual((queued["returned"], queued["limit"], queued["truncated"]), (50, 50, True))
            self.assertEqual(len(board["data"]["lanes"]["queued"]), 50)
            self.assertTrue(board["bounds"]["projection"]["truncated"])
            self.assertGreater(board["bounds"]["projection"]["cards_total"], board["bounds"]["projection"]["cards_projected"])
            # The upstream projection caps the whole board (current work first),
            # so a maximal per-lane limit returns every projected queued card.
            widest = self.ok("/v1/work-board?limit=200&lane=queued")
            self.assertGreater(len(widest["data"]["lanes"]["queued"]), 150)
            self.assertEqual(len(widest["data"]["lanes"]["queued"]), widest["bounds"]["lanes"]["queued"]["total"])
            self.assertFalse(widest["bounds"]["lanes"]["queued"]["truncated"])
            self.assertTrue(widest["bounds"]["projection"]["truncated"])
            self.assertTrue(self.ok("/v1/command-deck")["bounds"]["lane_counts"]["truncated"])

            signal = self.ok("/v1/signal")
            self.assertEqual(len(signal["data"]["events"]), 50)
            self.assertTrue(signal["bounds"]["events"]["truncated"])
            self.assertEqual(len(self.ok("/v1/signal?limit=100")["data"]["events"]), 100)
            squad = self.ok("/v1/squad?limit=1")
            self.assertEqual(len(squad["data"]["agents"]), 1)
            self.assertTrue(squad["bounds"]["agents"]["truncated"])

            for path in DATA_ROUTES:
                with self.subTest(path=path):
                    self.assertLess(len(json.dumps(self.ok(path))), 1_000_000)

    def test_query_parameters_are_validated_strictly(self) -> None:
        invalid = [
            "/v1/work-board?limit=0",
            "/v1/work-board?limit=201",
            "/v1/work-board?limit=ten",
            "/v1/work-board?limit=",
            "/v1/work-board?limit=5&limit=6",
            "/v1/work-board?lane=blocked",
            "/v1/work-board?kind=approval",
            "/v1/work-board?owner=Atlas%21",
            "/v1/work-board?unknown=1",
            "/v1/squad?limit=101",
            "/v1/signal?limit=101",
            "/v1/governance?limit=101",
            "/v1/command-deck?limit=5",
            "/v1/delivery?verbose=1",
            "/v1/squad?" + "&".join(f"p{index}=1" for index in range(20)),
        ]
        for path in invalid:
            with self.subTest(path=path):
                response = self.fx.get(path)
                self.assertEqual(response.status, 400)
                self.assertEqual(response.body["error"], "invalid_query")

    def test_long_free_text_is_capped(self) -> None:
        with authority_context(self.fx.vault, self.fx.state):
            create_task(state=self.fx.state, title="L" * 5000, owner="demobot")
            cards = self.ok("/v1/work-board?lane=queued&owner=demobot")["data"]["lanes"]["queued"]
            longest = max(len(str(card["title"])) for card in cards)
            self.assertEqual(longest, MAX_STRING_CHARS)
            self.assertTrue(any(str(card["title"]).endswith(TRUNCATION_MARKER) for card in cards))

    def test_responses_carry_no_secret_shaped_values_credentials_or_private_paths(self) -> None:
        # A legacy event that predates write-time secret linting.
        leaked = "ghp_" + "Z" * 30
        legacy_id = self.fx.append_raw_event(title=f"rotate {leaked} now", owner="demobot")
        card = next(
            card for card in self.ok("/v1/work-board?lane=queued")["data"]["lanes"]["queued"] if card["id"] == legacy_id
        )
        self.assertIn(SECRET_REDACTION, card["title"])
        forbidden = [
            leaked, self.fx.reader_token, self.fx.memory_token, self.fx.operator_secret, str(self.tmp),
            MEMORY_MARKER, BODY_MARKER, REASON_MARKER, COMMAND_MARKER,
        ]
        for token in (self.fx.reader_token, self.fx.operator_secret):
            for path in [*DATA_ROUTES, *PUBLIC_ROUTES]:
                with self.subTest(path=path):
                    serialized = json.dumps(self.ok(path, token))
                    self.assertFalse(contains_literal_secret(serialized))
                    for value in forbidden:
                        self.assertNotIn(value, serialized)

    def test_sanitize_redacts_and_caps_nested_strings_and_keys(self) -> None:
        leaked = "sk-" + "q" * 30
        value = sanitize({"outer": [{"title": f"x {leaked}"}, "y" * 2000], leaked: 3, "n": 1, "b": None})
        self.assertNotIn(leaked, json.dumps(value))
        self.assertEqual(len(value["outer"][1]), MAX_STRING_CHARS)
        self.assertEqual((value["n"], value["b"]), (1, None))

    def test_corrupt_event_log_fails_closed_with_503(self) -> None:
        with self.fx.state.open("a", encoding="utf-8") as handle:
            handle.write("{torn final line\n")
        with redirect_stderr(io.StringIO()):
            for path in DATA_ROUTES:
                with self.subTest(path=path):
                    response = self.fx.get(path)
                    self.assertEqual(response.status, 503)
                    self.assertEqual(response.body["error"], "projection_unavailable")
                    self.assertNotIn(str(self.tmp), json.dumps(response.body))
        self.assertEqual(handle_request("GET", "/v1/health", None, self.fx.config).status, 200)


class CliTests(ControlCenterApiTestCase):
    def _run(self, *argv: str) -> tuple[int, str]:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = cli_main(list(argv))
        return code, stderr.getvalue()

    def test_cli_refuses_unsafe_or_invalid_configuration_without_binding(self) -> None:
        base = ["--vault", str(self.fx.vault), "--state", str(self.fx.state), "--port", "0"]
        code, err = self._run(*base, "--host", NON_LOOPBACK_HOST)
        self.assertEqual(code, 2)
        self.assertIn("non-loopback", err)

        code, err = self._run("--vault", str(self.tmp / "missing"), "--state", str(self.fx.state))
        self.assertEqual(code, 2)
        self.assertIn("--vault", err)

        code, err = self._run("--vault", str(self.fx.vault), "--state", str(self.fx.root))
        self.assertEqual(code, 2)
        self.assertIn("--state", err)

        unset = "ARVYX_CONTROL_CENTER_TEST_UNSET_" + secrets.token_hex(4).upper()
        os.environ.pop(unset, None)
        code, err = self._run(*base, "--auth-env", unset)
        self.assertEqual(code, 2)
        self.assertIn(unset, err)

        weak = "ARVYX_CONTROL_CENTER_TEST_WEAK_" + secrets.token_hex(4).upper()
        os.environ[weak] = "short"
        self.addCleanup(os.environ.pop, weak, None)
        code, err = self._run(*base, "--host", NON_LOOPBACK_HOST, "--auth-env", weak)
        self.assertEqual(code, 2)
        self.assertNotIn("short", err.replace("32-4096", ""))


if __name__ == "__main__":
    unittest.main()
