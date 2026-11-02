from __future__ import annotations

from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError

from arvyx_control.replica_authority import authority_context
from arvyx_control.agent_delivery import AgentDeliveryResult, AgentRoute
from arvyx_control.api import handle_api_request
from arvyx_control.auth import issue_token
from arvyx_control.cli import main as cli_main
from arvyx_control.delivery_canary import (
    CANARY_MARKER,
    LEGS,
    CanaryOptions,
    ChainObserver,
    run_canary,
    summarize_canary,
    validate_api_url,
)
from arvyx_control.execution import (
    _execution_id,
    claim_execution,
    deliver_execution_attempt,
    heartbeat_execution,
)
from arvyx_control.vault import init_vault

TARGET = "alpha"
AUTHOR = "canary-bot"
THREAD = "thread_canary_000001"
EXECUTION = _execution_id("thread", THREAD, TARGET)
ATTEMPT = "attempt_000001"
AGENT_TOKEN = "t" * 48
API = "http://127.0.0.1:8766"


class FakeApi:
    """The two API calls the canary makes, with the author's identity."""

    def __init__(self, *, create_status: int = 201, identity_bound: bool = True,
                 readback: dict[str, object] | None = None, unreachable: bool = False) -> None:
        self.create_status = create_status
        self.identity_bound = identity_bound
        self.readback = readback if readback is not None else {"id": THREAD, "status": "done", "done_by": TARGET,
                                                               "done_at": "2026-09-11T12:04:00Z"}
        self.unreachable = unreachable
        self.calls: list[tuple[str, str, dict[str, object] | None, dict[str, str]]] = []

    def __call__(self, method, url, body, headers, timeout):  # type: ignore[no-untyped-def]
        self.calls.append((method, url, body, dict(headers)))
        if self.unreachable:
            raise URLError("connection refused")
        if url.endswith("/threads"):
            if self.create_status != 201:
                return self.create_status, {'status': self.create_status,
                                             'body': {"ok": False, "error": "unauthorized"}}
            return 201, {'status': 201, 'body': {
                "thread": {"id": THREAD, "actor": AUTHOR, "target": TARGET, "status": "open",
                           "created_at": "2026-09-11T12:00:00Z"},
                "event": {"payload": {"id": THREAD, "actor": AUTHOR, "target": TARGET,
                                      "actor_identity_bound": self.identity_bound}},
            }}
        if url.endswith("/mcp"):
            assert body is not None and body["params"]["name"] == "control.thread_get"
            return 200, {"jsonrpc": "2.0", "id": body["id"],
                         "result": {"structuredContent": {"thread": {**self.readback}}}}
        return 404, {"ok": False, "error": "not found"}


class Chain:
    """Appends the target-side legs of the chain to a synthetic control log."""

    def __init__(self, state: Path) -> None:
        self.state = state
        self.count = 0

    def event(self, event_type: str, task_id: str, payload: dict[str, object]) -> None:
        self.count += 1
        record = {"id": f"event_c{self.count}", "type": event_type, "task_id": task_id,
                  "timestamp": f"2026-09-11T12:0{min(self.count, 9)}:00Z", "payload": payload}
        with self.state.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    def execution(self, event_type: str, status: str, **extra: object) -> None:
        self.event(event_type, EXECUTION, {"id": EXECUTION, "subject_id": THREAD, "subject_type": "thread",
                                           "target": TARGET, "status": status, "attempts": 1,
                                           "attempt_id": ATTEMPT, **extra})

    def created(self) -> None:
        self.event("thread.created", THREAD, {"id": THREAD, "actor": AUTHOR, "target": TARGET,
                                              "type": "ask", "actor_identity_bound": True})
        self.execution("execution.created", "pending")

    def wake(self, status: str = "delivered", failure: str = "") -> None:
        self.event(f"outbox.{'delivered' if status == 'delivered' else 'dead_lettered'}",
                   "execution_delivery_000001", {
                       "id": "execution_delivery_000001", "target": TARGET, "status": status,
                       "failure_detail": failure,
                       "payload": {"delivery_mode": "execution", "execution_id": EXECUTION,
                                   "attempt_id": ATTEMPT},
                   })

    def heartbeat(self, identity_bound: bool = True) -> None:
        extra: dict[str, object] = {"heartbeat_by": TARGET, "actor_identity_bound": True} if identity_bound else {}
        self.execution("execution.heartbeat", "leased", **extra)

    def done(self) -> None:
        self.event("thread.done", THREAD, {"id": THREAD, "done_by": TARGET, "actor_identity_bound": True})
        self.execution("execution.completed", "completed", terminal_event_type="thread.done",
                       terminal_event_id=f"event_c{self.count}")


class CanaryHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "state" / "control-events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.vault.mkdir(exist_ok=True)
        self.enterContext(authority_context(self.vault, self.state))
        self.state.parent.mkdir()
        self.state.write_text('{"id": "old", "type": "thread.created", "task_id": "' + THREAD + '", '
                              '"timestamp": "2026-09-10T00:00:00Z", "payload": {}}\n', encoding="utf-8")
        self.chain = Chain(self.state)
        self.now = 0.0

    def clock(self) -> float:
        return self.now

    def run_with(self, steps: list, api: FakeApi | None = None, timeout: int = 120) -> dict[str, object]:
        """Each poll's sleep advances the clock and applies the next step."""
        pending = list(steps)

        def sleep(seconds: float) -> None:
            self.now += seconds
            if pending:
                pending.pop(0)()

        options = CanaryOptions(api=API, bearer=AGENT_TOKEN, target=TARGET, state=self.state,
                                timeout_seconds=timeout, poll_seconds=15)
        with mock.patch("arvyx_control.delivery_canary.time.sleep", side_effect=AssertionError("real sleep")):
            return run_canary(options, http=api or FakeApi(), sleep=sleep, clock=self.clock,
                              now=lambda: datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc))


class CanaryChainTests(CanaryHarness):
    def test_terminal_must_reference_exact_target_bound_done(self) -> None:
        for bound, actor, terminal in ((False, TARGET, 'done-exact'),
                                       (True, 'other-agent', 'done-exact'),
                                       (True, TARGET, 'done-unrelated'),
                                       (True, TARGET, 'done-exact')):
            with self.subTest(bound=bound, actor=actor, terminal=terminal):
                observer = ChainObserver(self.state, THREAD, TARGET, 0)
                observer._apply({'id': 'done-exact', 'type': 'thread.done', 'task_id': THREAD,
                    'payload': {'id': THREAD, 'done_by': actor, 'actor_identity_bound': bound}})
                observer._apply({'id': 'completed', 'type': 'execution.completed', 'task_id': EXECUTION,
                    'payload': {'status': 'completed', 'subject_type': 'thread', 'subject_id': THREAD,
                                'target': TARGET, 'terminal_event_type': 'thread.done',
                                'terminal_event_id': terminal}})
                self.assertEqual(observer.legs['execution_completed'].ok,
                                 bound and actor == TARGET and terminal == 'done-exact')

    def test_malformed_explicit_rest_body_cannot_use_outer_thread_fields(self) -> None:
        class MalformedApi(FakeApi):
            def __call__(self, method, url, body, headers, timeout):  # type: ignore[no-untyped-def]
                status, payload = super().__call__(method, url, body, headers, timeout)
                if url.endswith('/threads'):
                    return status, {**payload['body'], 'body': None}
                return status, payload
        report = self.run_with([], MalformedApi())
        self.assertEqual(report['stopped_at'], 'thread_created')
        self.assertFalse(report['legs']['thread_created']['ok'])  # type: ignore[index]

    def test_full_chain_is_ok(self) -> None:
        api = FakeApi()
        report = self.run_with([self.chain.created, self.chain.wake, self.chain.heartbeat, self.chain.done], api)
        self.assertEqual((report["verdict"], report["stopped_at"]), ("ok", None))
        self.assertTrue(all(leg["ok"] for leg in report["legs"].values()))  # type: ignore[union-attr]
        self.assertEqual(report["execution_id"], EXECUTION)
        self.assertEqual(report["execution_status"], "completed")
        method, url, body, headers = api.calls[0]
        self.assertEqual((method, url), ("POST", f"{API}/threads"))
        assert body is not None
        self.assertEqual((body["type"], body["target"]), ("ask", TARGET))
        self.assertTrue(str(body["title"]).startswith(CANARY_MARKER))
        self.assertEqual(headers["Idempotency-Key"], body["idempotency_key"])
        self.assertEqual(api.calls[-1][1], f"{API}/mcp")
        self.assertNotIn(AGENT_TOKEN, json.dumps(report))

    def test_history_before_the_run_is_never_reread(self) -> None:
        observer = ChainObserver(self.state, THREAD, TARGET, offset=self.state.stat().st_size)
        observer.poll()
        self.assertFalse(any(leg.ok for leg in observer.legs.values()))

    def test_stops_at_thread_created(self) -> None:
        unauthorized = self.run_with([], FakeApi(create_status=401))
        self.assertEqual((unauthorized["verdict"], unauthorized["stopped_at"]), ("failed", "thread_created"))
        self.assertIn("HTTP 401", unauthorized["legs"]["thread_created"]["detail"])  # type: ignore[index]
        operator = self.run_with([], FakeApi(identity_bound=False))
        self.assertEqual(operator["stopped_at"], "thread_created")
        self.assertIn("not identity-bound", operator["legs"]["thread_created"]["detail"])  # type: ignore[index]
        down = self.run_with([], FakeApi(unreachable=True))
        self.assertIn("API unreachable", down["legs"]["thread_created"]["detail"])  # type: ignore[index]

    def test_stops_at_execution_created(self) -> None:
        report = self.run_with([], timeout=60)
        self.assertEqual((report["verdict"], report["stopped_at"]), ("failed", "execution_created"))
        self.assertGreaterEqual(report["elapsed_seconds"], 60)

    def test_stops_at_wake_delivered_with_the_wake_failure(self) -> None:
        report = self.run_with([self.chain.created, lambda: self.chain.wake("dead_lettered", "HTTP 404")], timeout=60)
        self.assertEqual(report["stopped_at"], "wake_delivered")
        self.assertIn("last wake failure: HTTP 404", report["legs"]["wake_delivered"]["detail"])  # type: ignore[index]

    def test_stops_at_target_heartbeat(self) -> None:
        # a worker heartbeat is not the target's identity-bound heartbeat
        report = self.run_with([self.chain.created, self.chain.wake, lambda: self.chain.heartbeat(False)], timeout=60)
        self.assertEqual((report["verdict"], report["stopped_at"]), ("failed", "target_heartbeat"))

    def test_completion_without_heartbeat_is_degraded(self) -> None:
        report = self.run_with([self.chain.created, self.chain.wake, self.chain.done], timeout=60)
        self.assertEqual((report["verdict"], report["stopped_at"]), ("degraded", "target_heartbeat"))

    def test_stops_at_execution_completed_and_exits_early_on_hold(self) -> None:
        report = self.run_with([self.chain.created, self.chain.wake, self.chain.heartbeat], timeout=60)
        self.assertEqual(report["stopped_at"], "execution_completed")
        # the API already shows the thread done, but no execution.completed was
        # observed: the chain stopped at the worker's terminal reconciliation
        # A readback label without an observed identity-bound DONE is not proof.
        self.assertFalse(report["legs"]["thread_done_readback"]["ok"])  # type: ignore[index]
        held = self.run_with(
            [self.chain.created, self.chain.wake, self.chain.heartbeat,
             lambda: self.chain.execution("execution.held", "held", hold_reason="target reported BLOCKED twice")],
            FakeApi(readback={"status": "acked", "done_by": ""}), timeout=900,
        )
        self.assertEqual(held["stopped_at"], "execution_completed")
        self.assertIn("execution held: target reported BLOCKED", held["legs"]["execution_completed"]["detail"])  # type: ignore[index]
        self.assertLess(held["elapsed_seconds"], 900)

    def test_stops_at_thread_done_readback(self) -> None:
        api = FakeApi(readback={"status": "acked", "done_by": ""})
        report = self.run_with([self.chain.created, self.chain.wake, self.chain.heartbeat, self.chain.done], api)
        self.assertEqual((report["verdict"], report["stopped_at"]), ("failed", "thread_done_readback"))
        self.assertEqual(report["legs"]["thread_done_readback"]["detail"], "thread status acked")  # type: ignore[index]

    def test_summary_names_every_leg(self) -> None:
        report = self.run_with([self.chain.created], timeout=30)
        title, text = summarize_canary(report, label="lab")
        self.assertEqual(title, "[arvyx delivery canary lab] FAILED: stopped at wake_delivered")
        for leg in LEGS:
            self.assertIn(leg, text)

    def test_http_json_is_bounded_and_never_crashes_on_torn_responses(self) -> None:
        from http.client import IncompleteRead

        from arvyx_control import delivery_canary

        def unauthorized(request, timeout):  # type: ignore[no-untyped-def]
            raise HTTPError(request.full_url, 401, "Unauthorized", {}, io.BytesIO(b'{"error": "unauthorized"}'))

        with mock.patch.object(delivery_canary._API_OPENER, "open", side_effect=unauthorized):
            self.assertEqual(delivery_canary.http_json("POST", f"{API}/threads", {}, {}, 1),
                             (401, {"error": "unauthorized"}))
        with mock.patch.object(delivery_canary._API_OPENER, "open", side_effect=IncompleteRead(b"")):
            with self.assertRaises(OSError):
                delivery_canary.http_json("POST", f"{API}/threads", {}, {}, 1)
        from arvyx_control.http_bounds import BoundedOpener
        self.assertIsInstance(delivery_canary._API_OPENER, BoundedOpener)

    def test_api_url_rules(self) -> None:
        self.assertEqual(validate_api_url("http://127.0.0.1:8766/"), "http://127.0.0.1:8766")
        self.assertEqual(validate_api_url("https://control.example.test"), "https://control.example.test")
        for bad in ("http://control.example.test", "https://u:p@control.example.test", "ftp://127.0.0.1",
                    "https://control.example.test/?x=1"):
            with self.assertRaises(ValueError):
                validate_api_url(bad)


class CanaryAgainstRealApiTests(unittest.TestCase):
    """The canary's two API calls, and the chain behind them, through the real router.

    The author and the target are identity-bound agents with their own tokens;
    the worker runs the production claim/wake/reconcile path with only the
    network transport replaced. This pins the endpoints and payload shapes the
    canary relies on (``POST /threads`` with an idempotency key, the created
    event's ``actor_identity_bound`` flag, and the author's ``control.thread_get``).
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.vault = root / "vault"
        self.state = root / "state" / "control-events.jsonl"
        self.enterContext(authority_context(self.vault, self.state))
        self.state.parent.mkdir()
        self.state.touch()
        init_vault(self.vault)
        self.operator_secret = "operator-shared-secret-for-canary-tests"
        scopes = ["control.read", "control.write", "control.delivery"]
        self.author_bearer = issue_token(self.vault, "demobot", scopes=scopes, slot="canary").token
        self.target_bearer = issue_token(self.vault, "vesper", scopes=scopes, slot="runtime").token
        self.route = AgentRoute("vesper", "hermes-webhook", "CANARY_WAKE_URL", "CANARY_WAKE_SECRET")
        self.env = {"CANARY_WAKE_URL": "http://127.0.0.1:9/wake", "CANARY_WAKE_SECRET": "synthetic-wake"}

    def http(self, method, url, body, headers, timeout):  # type: ignore[no-untyped-def]
        response = handle_api_request(
            method=method, path=url.removeprefix(API), body=body, vault=self.vault, state=self.state,
            bearer_secret=self.operator_secret, authorization=headers.get("Authorization"),
            mcp_profile="operator", idempotency_key=headers.get("Idempotency-Key"),
        )
        # Match the HTTP writer, not the in-process domain body's shape:
        # REST dictionaries are wrapped, whereas serialized JSON-RPC is raw.
        payload = json.loads(response.body) if isinstance(response.body, str) else json.loads(response.to_json())
        return response.status, payload

    def target_tool(self, name: str, arguments: dict[str, object]) -> dict[str, object]:
        status, body = self.http("POST", f"{API}/mcp", {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": {**arguments, "idempotency_key": f"target-{name}-0123456789"}},
        }, {"Authorization": f"Bearer {self.target_bearer}"}, 5)
        self.assertEqual(status, 200, body)
        self.assertNotIn("error", body, body)
        return body["result"]["structuredContent"]

    def worker_tick(self) -> None:
        accepted = AgentDeliveryResult(True, "accepted", 202, "accepted")
        with mock.patch("arvyx_control.execution.deliver_outbox_item", return_value=accepted):
            execution = claim_execution(self.state, worker="canary-test-worker",
                                        execution_capable_targets={"vesper"}, lease_seconds=120)
            if execution is not None:
                delivery = deliver_execution_attempt(execution, self.route, environ=self.env,
                                                     lease_seconds=120, state=self.state)
                heartbeat_execution(self.state, execution_id=execution.id, attempt_id=execution.attempt_id,
                                    worker="canary-test-worker", lease_seconds=120,
                                    detail=json.dumps(delivery.to_dict()))
                self.live = execution

    def test_full_chain_through_the_router_is_ok(self) -> None:
        def target_heartbeats() -> None:
            self.target_tool("control.execution_heartbeat", {
                "execution_id": self.live.id, "attempt_id": self.live.attempt_id, "lease_seconds": 120,
            })

        def target_completes() -> None:
            thread_id = self.live.subject_id
            self.target_tool("control.thread_done", {"thread_id": thread_id, "text": "canary ok"})

        steps = [self.worker_tick, target_heartbeats, target_completes, self.worker_tick]
        clock = [0.0]

        def sleep(seconds: float) -> None:
            clock[0] += seconds
            if steps:
                steps.pop(0)()

        options = CanaryOptions(api=API, bearer=self.author_bearer, target="vesper", state=self.state,
                                timeout_seconds=120, poll_seconds=15)
        report = run_canary(options, http=self.http, sleep=sleep, clock=lambda: clock[0])
        self.assertEqual((report["verdict"], report["stopped_at"]), ("ok", None), report)
        self.assertEqual(report["thread"]["done_by"], "vesper")  # type: ignore[index]

    def test_operator_secret_is_refused_as_the_canary_identity(self) -> None:
        options = CanaryOptions(api=API, bearer=self.operator_secret, target="vesper", state=self.state,
                                timeout_seconds=30)
        report = run_canary(options, http=self.http, sleep=lambda _: None, clock=lambda: 0.0)
        self.assertEqual(report["stopped_at"], "thread_created")
        self.assertIn("explicit author/owner identity is required", report["legs"]["thread_created"]["detail"])  # type: ignore[index]


class CanaryCommandTests(CanaryHarness):
    def run_cli(self, *extra: str, steps: list | None = None, api: FakeApi | None = None,
                env: dict[str, str] | None = None) -> tuple[int, dict[str, object]]:
        from arvyx_control import delivery_canary

        pending = list(steps or [])
        pings: list[str] = []
        self.pings = pings

        def sleep(seconds: float) -> None:
            self.now += seconds
            if pending:
                pending.pop(0)()

        def opener(request, timeout):  # type: ignore[no-untyped-def]
            pings.append(request.full_url)

            class Response:
                status = 200

                def __enter__(self):  # type: ignore[no-untyped-def]
                    return self

                def __exit__(self, *exc):  # type: ignore[no-untyped-def]
                    return None

            return Response()

        stdout = io.StringIO()
        original = delivery_canary.run_canary_command

        def patched(args):  # type: ignore[no-untyped-def]
            return original(args, stdout=stdout, stderr=io.StringIO(), http=api or FakeApi(),
                            sleep=sleep, clock=self.clock, deadman_opener=opener)

        argv = ["delivery", "canary", "--api", API, "--target", TARGET, "--state", str(self.state),
                "--timeout-seconds", "60", "--json", *extra]
        environment = {"CANARY_TOKEN": AGENT_TOKEN, "CANARY_DEADMAN": "https://checks.example.test/ping/canary",
                       **(env or {})}
        with mock.patch.dict(os.environ, environment), mock.patch("arvyx_control.cli.run_canary_command", patched):
            code = cli_main(["--authority-vault", str(self.vault), *argv])
        return code, json.loads(stdout.getvalue())

    def test_command_ok_alerts_on_failure_and_pings_deadman(self) -> None:
        notify = Path(self._tmp.name) / "notify.json"
        alerts = Path(self._tmp.name) / "alerts.jsonl"
        notify.write_text(json.dumps({"adapter": "file", "path": str(alerts)}), encoding="utf-8")
        code, report = self.run_cli("--auth-env", "CANARY_TOKEN", "--deadman-url-env", "CANARY_DEADMAN",
                                    "--notify-config", str(notify))
        self.assertEqual((code, report["verdict"], report["stopped_at"]), (1, "failed", "execution_created"))
        self.assertEqual((report["alert"]["reason"], report["alert"]["status"]), ("transition", "recorded"))
        self.assertEqual(self.pings, ["https://checks.example.test/ping/canary/fail"])
        row = json.loads(alerts.read_text(encoding="utf-8").splitlines()[0])
        self.assertIn("stopped at execution_created", row["title"])
        self.assertNotIn(AGENT_TOKEN, json.dumps(report) + alerts.read_text(encoding="utf-8"))
        code, report = self.run_cli(
            "--auth-env", "CANARY_TOKEN", "--deadman-url-env", "CANARY_DEADMAN", "--notify-config", str(notify),
            steps=[self.chain.created, self.chain.wake, self.chain.heartbeat, self.chain.done],
        )
        self.assertEqual((code, report["verdict"], report["alert"]["reason"]), (0, "ok", "recovery"))
        self.assertEqual(self.pings, ["https://checks.example.test/ping/canary"])

    def test_usage_errors_exit_2_before_any_thread_is_created(self) -> None:
        api = FakeApi()
        code, report = self.run_cli("--auth-env", "CANARY_TOKEN", env={"CANARY_TOKEN": "short"}, api=api)
        self.assertEqual((code, report["verdict"]), (2, "error"))
        code, _ = self.run_cli(api=api)
        self.assertEqual(code, 2)
        code, report = self.run_cli("--auth-env", "CANARY_TOKEN", "--api", "http://control.example.test", api=api)
        self.assertEqual(code, 2)
        self.state.unlink()
        code, report = self.run_cli("--auth-env", "CANARY_TOKEN", "--deadman-url-env", "CANARY_DEADMAN", api=api)
        self.assertEqual(code, 2)
        self.assertEqual(report["deadman"]["endpoint"], "fail")
        self.assertEqual(api.calls, [])


if __name__ == "__main__":
    unittest.main()
