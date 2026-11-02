from __future__ import annotations

from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from arvyx_control.replica_authority import authority_context
from arvyx_control.agent_delivery import AgentRoute
from arvyx_control.cli import main as cli_main
from arvyx_control.delivery_probe import (
    PROBE_ALERT_STATE_NAME,
    ProbeConfig,
    iter_log_lines,
    run_probe,
    scan_event_log,
    summarize,
)
from arvyx_control.liveness import (
    DISPATCHER_COMPONENT,
    WORKER_COMPONENT,
    liveness_dir,
    write_tick_record,
)
from arvyx_control.outbox import claim_due, enqueue, mark_delivered
from arvyx_control.notifiers import _PostOutcome

NOW = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
ROUTES = {
    "alpha": AgentRoute("alpha", "hermes-webhook", "PROBE_ALPHA_URL", "PROBE_ALPHA_CREDENTIAL"),
    "bravo": AgentRoute("bravo", "openclaw-hook", "PROBE_BRAVO_URL", "PROBE_BRAVO_CREDENTIAL"),
}
ENV = {
    "PROBE_ALPHA_URL": "https://alpha.example.test/hooks/wake",
    "PROBE_ALPHA_CREDENTIAL": "synthetic-alpha-credential",
    "PROBE_BRAVO_URL": "https://bravo.example.test:8443/hooks/agent",
    "PROBE_BRAVO_CREDENTIAL": "synthetic-bravo-credential",
}
DEADMAN = "https://checks.example.test/ping/synthetic-probe"


def _ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def reachable(url: str, timeout: int) -> dict[str, object]:
    if not url:
        return {"endpoint": "", "ok": False, "detail": "url env not configured"}
    return {"endpoint": url.split("/")[2], "ok": True}


class Log:
    """Synthetic control log with the production event shapes."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch()
        self.counter = 0

    def event(self, event_type: str, task_id: str, at: datetime, payload: dict[str, object]) -> None:
        self.counter += 1
        record = {"id": f"event_{self.counter:06d}", "type": event_type, "task_id": task_id,
                  "timestamp": _ts(at), "payload": payload}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    def raw(self, text: str) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(text)

    def item(self, event_type: str, item_id: str, target: str, at: datetime, *, status: str,
             created: datetime | None = None, mode: str = "direct", failure: str = "",
             resolved_by: str = "") -> None:
        self.event(event_type, item_id, at, {
            "id": item_id, "subject_id": f"thread_{item_id}", "target": target,
            "payload": {"delivery_mode": mode, "source_event_type": "thread.created"},
            "payload_hash": "0" * 64, "epoch": 0, "status": status, "attempts": 1,
            "created_at": _ts(created or at), "updated_at": _ts(at), "next_attempt_at": _ts(at),
            "failure_detail": failure, "resolved_by": resolved_by,
        })

    def delivered_item(self, item_id: str, target: str, at: datetime) -> None:
        self.item("outbox.enqueued", item_id, target, at - timedelta(seconds=20), status="pending")
        self.item("outbox.delivered", item_id, target, at, status="delivered",
                  created=at - timedelta(seconds=20))

    def execution(self, event_type: str, execution_id: str, target: str, at: datetime, *,
                  status: str, lease_expires_at: str = "") -> None:
        self.event(event_type, execution_id, at, {
            "id": execution_id, "target": target, "status": status, "attempts": 1,
            "subject_id": f"thread_{execution_id}", "subject_type": "thread",
            "created_at": _ts(at), "updated_at": _ts(at), "lease_expires_at": lease_expires_at,
        })


class ProbeHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.state = self.root / "state" / "control-events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.vault.mkdir(exist_ok=True)
        self.enterContext(authority_context(self.vault, self.state))
        self.log = Log(self.state)

    def fresh_ticks(self, at: datetime = NOW, result: str = "ok") -> None:
        for component in (DISPATCHER_COMPONENT, WORKER_COMPONENT):
            write_tick_record(self.state, component=component, result=result, now=at - timedelta(seconds=2))

    def probe(self, *, prober=reachable, **config: object) -> dict[str, object]:
        report = run_probe(self.state, routes=ROUTES, now=NOW, config=ProbeConfig(**config),
                           environ=ENV, prober=prober)
        return report.payload

    def codes(self, payload: dict[str, object]) -> list[tuple[str, str]]:
        findings = payload["findings"]
        assert isinstance(findings, list)
        return [(finding.get("target", ""), finding["code"]) for finding in findings]


class ProbeCheckTests(ProbeHarness):
    def test_ok_path(self) -> None:
        self.fresh_ticks()
        for index in range(3):
            self.log.delivered_item(f"outbox_a{index}", "alpha", NOW - timedelta(minutes=10 + index))
        self.log.delivered_item("outbox_b0", "bravo", NOW - timedelta(minutes=30))
        self.log.execution("execution.created", "execution_a", "alpha", NOW - timedelta(minutes=20), status="pending")
        self.log.execution("execution.completed", "execution_a", "alpha", NOW - timedelta(minutes=5), status="completed")
        payload = self.probe()
        self.assertEqual(payload["verdict"], "ok", payload["findings"])
        alpha = payload["targets"]["alpha"]  # type: ignore[index]
        self.assertEqual(alpha["delivery"]["delivered"], 3)
        self.assertEqual(alpha["execution"], {"created": 1, "completed": 1, "lease_expired": 0,
                                              "dead_lettered": 0, "held": 0, "live": 0})
        self.assertTrue(alpha["transport"]["ok"])
        self.assertEqual(payload["ticks"]["dispatcher"]["status"], "fresh")  # type: ignore[index]

    def test_transport_and_route_config_failures(self) -> None:
        self.fresh_ticks()

        def prober(url: str, timeout: int) -> dict[str, object]:
            if "bravo" in url:
                return {"endpoint": "bravo.example.test:8443", "ok": False, "detail": "TimeoutError"}
            return reachable(url, timeout)

        payload = self.probe(prober=prober)
        self.assertEqual(payload["verdict"], "failed")
        self.assertIn(("bravo", "transport_unreachable"), self.codes(payload))
        self.assertNotIn("hooks/agent", json.dumps(payload))
        missing_env = run_probe(self.state, routes=ROUTES, now=NOW, config=ProbeConfig(),
                                environ={}, prober=reachable).payload
        self.assertIn(("", "route_config_invalid"), self.codes(missing_env))

    def test_missing_stale_errored_and_corrupt_ticks(self) -> None:
        payload = self.probe()
        self.assertEqual(self.codes(payload), [("", "tick_missing"), ("", "tick_missing")])
        write_tick_record(self.state, component=DISPATCHER_COMPONENT, result="ok", now=NOW - timedelta(seconds=31))
        write_tick_record(self.state, component=WORKER_COMPONENT, result="error", detail="wake failed",
                          now=NOW - timedelta(seconds=3))
        payload = self.probe()
        self.assertEqual(self.codes(payload), [("", "tick_stale"), ("", "tick_error")])
        self.assertEqual(payload["ticks"]["dispatcher"]["age_seconds"], 31)  # type: ignore[index]
        self.assertEqual(payload["ticks"]["dispatcher"]["stale_after_seconds"], 30)  # type: ignore[index]
        # configurable: a longer expected interval tolerates the same age
        relaxed = self.probe(dispatcher_interval_seconds=20)
        self.assertEqual(self.codes(relaxed), [("", "tick_error")])
        self.assertEqual(relaxed["verdict"], "degraded")
        (liveness_dir(self.state) / "execution-worker.json").write_text("{", encoding="utf-8")
        self.assertIn(("", "tick_unreadable"), self.codes(self.probe(dispatcher_interval_seconds=20)))
        only_dispatcher = self.probe(dispatcher_interval_seconds=20, tick_components=(DISPATCHER_COMPONENT,))
        self.assertEqual(only_dispatcher["verdict"], "ok")

    def test_enqueued_without_delivery_fails_after_grace(self) -> None:
        self.fresh_ticks()
        self.log.item("outbox.enqueued", "outbox_a1", "alpha", NOW - timedelta(minutes=2), status="pending")
        self.assertEqual(self.probe()["verdict"], "ok")  # still inside the 5 minute grace
        self.log.item("outbox.enqueued", "outbox_a2", "alpha", NOW - timedelta(minutes=12), status="pending")
        payload = self.probe()
        self.assertEqual(self.codes(payload), [("alpha", "no_delivery_in_window")])
        self.assertIn("2 enqueued, 0 delivered in the last 60m", json.dumps(payload))

    def test_dead_letter_and_failure_ratios(self) -> None:
        self.fresh_ticks()
        at = NOW - timedelta(minutes=15)
        self.log.delivered_item("outbox_a0", "alpha", at)
        for index in range(3):
            self.log.item("outbox.dead_lettered", f"outbox_d{index}", "alpha", at, status="dead_lettered",
                          failure="HTTP 404 from hook")
        payload = self.probe()
        self.assertIn(("alpha", "dead_letter_ratio"), self.codes(payload))
        top = payload["targets"]["alpha"]["delivery"]["top_failures"]  # type: ignore[index]
        self.assertEqual(top, [{"detail": "HTTP 404 from hook", "count": 3}])
        self.assertIn("top failure: HTTP 404 from hook x3", json.dumps(payload["findings"]))
        # retries (not dead letters) degrade instead of fail
        for index in range(3):
            self.log.item("outbox.attempt.failed", f"outbox_r{index}", "bravo", at, status="pending",
                          failure="delivery adapter raised TimeoutError")
        self.log.delivered_item("outbox_b0", "bravo", at)
        bravo = self.probe()["targets"]["bravo"]  # type: ignore[index]
        self.assertEqual(bravo["verdict"], "degraded")
        self.assertEqual([f["code"] for f in bravo["findings"]], ["failure_ratio"])

    def test_ratio_needs_enough_outcomes_and_ignores_gate_refusals(self) -> None:
        self.fresh_ticks()
        at = NOW - timedelta(minutes=15)
        self.log.delivered_item("outbox_a0", "alpha", at)
        self.log.item("outbox.dead_lettered", "outbox_d0", "alpha", at, status="dead_lettered", failure="HTTP 400")
        self.assertEqual(self.probe()["verdict"], "ok")  # 2 outcomes < min 4
        for index in range(4):
            self.log.item("outbox.dead_lettered", f"outbox_s{index}", "bravo", at, status="dead_lettered",
                          failure="execution attempt is no longer live", resolved_by="dispatcher")
        self.log.delivered_item("outbox_b0", "bravo", at)
        bravo = self.probe()["targets"]["bravo"]  # type: ignore[index]
        self.assertEqual(bravo["verdict"], "ok")
        self.assertEqual(bravo["delivery"]["dead_lettered_refused"], 4)

    def test_oldest_undelivered_age(self) -> None:
        self.fresh_ticks()
        self.log.delivered_item("outbox_a0", "alpha", NOW - timedelta(minutes=5))
        # enqueued long before the window, still pending: invisible to window
        # counters but not to the undelivered-age check
        self.log.item("outbox.enqueued", "outbox_old", "alpha", NOW - timedelta(hours=5), status="pending")
        self.log.item("outbox.attempt.failed", "outbox_old", "alpha", NOW - timedelta(hours=4), status="pending",
                      created=NOW - timedelta(hours=5), failure="HTTP 503")
        # an unfinalized execution wake is reported, never judged
        self.log.item("outbox.enqueued", "execution_delivery_x", "bravo", NOW - timedelta(hours=3),
                      status="leased", mode="execution")
        payload = self.probe()
        self.assertEqual(self.codes(payload), [("alpha", "undelivered_too_old")])
        delivery = payload["targets"]["alpha"]["delivery"]  # type: ignore[index]
        self.assertEqual((delivery["undelivered"], delivery["oldest_undelivered_age_seconds"]), (1, 5 * 3600))
        self.assertEqual(delivery["oldest_undelivered_id"], "outbox_old")
        self.assertEqual(delivery["enqueued"], 1)  # only the fresh, delivered item
        self.assertEqual(payload["targets"]["bravo"]["delivery"]["unfinalized_execution_wakes"], 1)  # type: ignore[index]

    def test_lease_expiries_without_completion_degrade(self) -> None:
        self.fresh_ticks()
        start = NOW - timedelta(minutes=30)
        self.log.execution("execution.created", "execution_b", "bravo", start - timedelta(hours=2), status="pending")
        self.log.execution("execution.attempt.started", "execution_b", "bravo", start, status="leased",
                           lease_expires_at=_ts(start + timedelta(minutes=2)))
        self.log.execution("execution.attempt.started", "execution_b", "bravo", start + timedelta(minutes=5),
                           status="leased", lease_expires_at=_ts(NOW + timedelta(minutes=1)))
        payload = self.probe()
        self.assertEqual(self.codes(payload), [("bravo", "lease_expiries_without_completion")])
        execution = payload["targets"]["bravo"]["execution"]  # type: ignore[index]
        self.assertEqual((execution["lease_expired"], execution["live"], execution["created"]), (1, 1, 0))
        self.log.execution("execution.completed", "execution_c", "bravo", NOW - timedelta(minutes=1), status="completed")
        self.assertEqual(self.probe()["verdict"], "ok")

    def test_window_bounds_counts(self) -> None:
        self.fresh_ticks()
        self.log.item("outbox.enqueued", "outbox_x", "alpha", NOW - timedelta(minutes=90), status="pending")
        self.log.item("outbox.delivered", "outbox_x", "alpha", NOW - timedelta(minutes=70), status="delivered")
        self.log.item("outbox.dead_lettered", "outbox_y", "alpha", NOW - timedelta(minutes=61), status="dead_lettered")
        self.log.item("outbox.enqueued", "outbox_z", "alpha", NOW + timedelta(hours=1), status="delivered")
        self.log.delivered_item("outbox_w", "alpha", NOW - timedelta(minutes=59))
        payload = self.probe()
        delivery = payload["targets"]["alpha"]["delivery"]  # type: ignore[index]
        self.assertEqual((delivery["enqueued"], delivery["delivered"], delivery["dead_lettered"]), (1, 1, 0))
        narrow = self.probe(window_seconds=120, delivery_grace_seconds=60)["targets"]["alpha"]["delivery"]  # type: ignore[index]
        self.assertEqual((narrow["enqueued"], narrow["delivered"]), (0, 0))

    def test_scan_is_bounded_and_tolerates_bad_lines(self) -> None:
        self.fresh_ticks()
        padding = json.dumps({"id": "p", "type": "thread.created", "task_id": "t", "timestamp": _ts(NOW),
                              "payload": {"body": "x" * 4000}})
        for _ in range(64):
            self.log.raw(padding + "\n")
        self.log.item("outbox.dead_lettered", "outbox_early", "alpha", NOW - timedelta(minutes=3),
                      status="dead_lettered")
        for _ in range(64):
            self.log.raw(padding + "\n")
        self.log.raw('{"type": "outbox.delivered", torn json}\n')
        self.log.raw('{"type": "outbox.enqueued", "payload": {"x": "' + "y" * 5000 + '"}}\n')
        self.log.delivered_item("outbox_late", "alpha", NOW - timedelta(minutes=2))
        self.log.raw('{"id": "partial", "type": "outbox.delivered"')  # write in progress: no newline
        with mock.patch("arvyx_control.control.read_events", side_effect=AssertionError("full read")):
            full = scan_event_log(self.state, now=NOW, config=ProbeConfig(max_line_bytes=4096 + 512))
            tail = scan_event_log(self.state, now=NOW,
                                  config=ProbeConfig(max_scan_bytes=64 * 1024, max_line_bytes=4096 + 512))
        self.assertFalse(full.truncated)
        self.assertEqual(full.flows["alpha"].dead_lettered, 1)
        self.assertEqual((full.malformed_lines, full.overlong_lines), (1, 1))
        self.assertTrue(tail.truncated)
        self.assertLessEqual(tail.bytes_scanned, 64 * 1024)
        self.assertEqual(tail.flows["alpha"].dead_lettered, 0)
        self.assertEqual(tail.flows["alpha"].delivered, 1)
        # the scan stops at the size it saw: the unterminated tail is not an event
        self.assertEqual(full.flows["alpha"].delivered, 1)

    def test_iter_log_lines_resynchronizes_mid_line(self) -> None:
        self.log.raw("a" * 50 + "\n" + "b" * 50 + "\n" + "c" * 10 + "\n")
        lines = [line for _, line in iter_log_lines(self.state, max_scan_bytes=1024 + 40, max_line_bytes=1024)]
        self.assertEqual(len(lines), 3)
        lines = [line for _, line in iter_log_lines(self.state, max_scan_bytes=1030, max_line_bytes=1024)]
        self.assertEqual(lines, [b"a" * 50 + b"\n", b"b" * 50 + b"\n", b"c" * 10 + b"\n"])

    def test_real_domain_events_are_understood(self) -> None:
        self.fresh_ticks()
        item = enqueue(self.state, subject_id="thread_real", target="alpha",
                       payload={"source_event_type": "thread.created"}, now=NOW - timedelta(minutes=20))
        claimed = claim_due(self.state, worker="w", now=NOW - timedelta(minutes=19), targets={"alpha"},
                            deliver_after="2026-09-01T00:00:00Z", max_watermark_age_seconds=10 ** 9)
        self.assertEqual([entry.id for entry in claimed], [item.id])
        mark_delivered(self.state, outbox_id=item.id, worker="w", claim_attempts=next(c.attempts for c in claimed if c.id == item.id), now=NOW - timedelta(minutes=19))
        payload = self.probe()
        delivery = payload["targets"]["alpha"]["delivery"]  # type: ignore[index]
        self.assertEqual((delivery["enqueued"], delivery["delivered"], delivery["undelivered"]), (1, 1, 0))
        self.assertEqual(payload["verdict"], "ok")

    def test_unrouted_targets_are_reported_not_judged(self) -> None:
        self.fresh_ticks()
        self.log.item("outbox.enqueued", "outbox_h", "human-desk", NOW - timedelta(hours=2), status="pending")
        payload = self.probe()
        self.assertEqual(payload["verdict"], "ok")
        self.assertFalse(payload["targets"]["human-desk"]["routed"])  # type: ignore[index]

    def test_missing_event_log_fails(self) -> None:
        self.fresh_ticks()
        self.state.unlink()
        self.assertIn(("", "event_log_unreadable"), self.codes(self.probe()))

    def test_summary_is_concise(self) -> None:
        payload = self.probe()
        title, text = summarize(payload, label="lab")
        self.assertEqual(title, "[arvyx delivery probe lab] FAILED")
        self.assertIn("tick_missing", text)
        self.assertLess(len(text), 1200)


class ProbeCommandTests(ProbeHarness):
    def setUp(self) -> None:
        super().setUp()
        self.routes = self.root / "routes.json"
        self.routes.write_text(json.dumps({"routes": {
            "alpha": {"runtime": "hermes-webhook", "url_env": "PROBE_ALPHA_URL",
                      "credential_env": "PROBE_ALPHA_CREDENTIAL", "timeout_seconds": 5},
        }}), encoding="utf-8")
        self.alerts = self.root / "alerts.jsonl"
        self.notify = self.root / "notify.json"
        self.notify.write_text(json.dumps({"adapter": "file", "path": str(self.alerts)}), encoding="utf-8")
        self.pings: list[str] = []

    def opener(self, request, timeout):  # type: ignore[no-untyped-def]
        self.pings.append(request.full_url)

        class Response:
            status = 200

            def __enter__(self):  # type: ignore[no-untyped-def]
                return self

            def __exit__(self, *exc):  # type: ignore[no-untyped-def]
                return None

        return Response()

    def run_cli(self, *extra: str, env: dict[str, str] | None = None) -> tuple[int, dict[str, object]]:
        from arvyx_control import delivery_probe

        argv = ["delivery", "probe", "--state", str(self.state), "--routes", str(self.routes),
                "--now", _ts(NOW), "--json", *extra]
        stdout = io.StringIO()
        original = delivery_probe.run_probe_command

        def patched(args):  # type: ignore[no-untyped-def]
            return original(args, stdout=stdout, stderr=io.StringIO(), prober=reachable,
                            deadman_opener=self.opener)

        with mock.patch.dict(os.environ, {**ENV, "PROBE_DEADMAN": DEADMAN, **(env or {})}), \
                mock.patch("arvyx_control.cli.run_probe_command", patched):
            code = cli_main(["--authority-vault", str(self.vault), *argv])
        return code, json.loads(stdout.getvalue())

    def test_exit_codes_and_deadman(self) -> None:
        self.fresh_ticks()
        code, payload = self.run_cli("--deadman-url-env", "PROBE_DEADMAN")
        self.assertEqual((code, payload["verdict"]), (0, "ok"))
        self.assertEqual(payload["deadman"], {"configured": True, "endpoint": "success", "status": "sent"})
        write_tick_record(self.state, component=WORKER_COMPONENT, result="error", now=NOW)
        code, payload = self.run_cli("--deadman-url-env", "PROBE_DEADMAN")
        self.assertEqual((code, payload["verdict"], payload["deadman"]["endpoint"]), (1, "degraded", "success"))
        write_tick_record(self.state, component=WORKER_COMPONENT, result="ok", now=NOW - timedelta(minutes=5))
        code, payload = self.run_cli("--deadman-url-env", "PROBE_DEADMAN")
        self.assertEqual((code, payload["verdict"], payload["deadman"]["endpoint"]), (1, "failed", "fail"))
        self.assertEqual(self.pings, [DEADMAN, DEADMAN, DEADMAN + "/fail"])
        self.assertNotIn("synthetic-probe", json.dumps(payload))

    def test_usage_errors_exit_2_and_flip_the_deadman(self) -> None:
        code, payload = self.run_cli("--deadman-url-env", "PROBE_DEADMAN", "--window-minutes", "0.5")
        self.assertEqual((code, payload["verdict"]), (2, "error"))
        self.assertEqual(payload["deadman"]["endpoint"], "fail")
        self.routes.write_text("{not json", encoding="utf-8")
        code, payload = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("invalid routes", str(payload["error"]))
        code, payload = self.run_cli("--deadman-url-env", "PROBE_DEADMAN",
                                     env={"PROBE_DEADMAN": "http://checks.example.test/x"})
        self.assertEqual(code, 2)
        self.assertIn("https", str(payload["error"]))
        code, payload = self.run_cli("--notify-config", str(self.root / "absent.json"))
        self.assertEqual(code, 2)
        with self.assertRaises(SystemExit) as raised, mock.patch("sys.stderr", io.StringIO()):
            cli_main(["--authority-vault", str(self.vault), *["delivery", "probe", "--state", str(self.state)]])
        self.assertEqual(raised.exception.code, 2)

    def test_alerts_deduplicate_and_recover_through_the_notifier(self) -> None:
        code, payload = self.run_cli("--notify-config", str(self.notify))
        self.assertEqual((code, payload["alert"]["reason"], payload["alert"]["status"]), (1, "transition", "recorded"))
        _, payload = self.run_cli("--notify-config", str(self.notify))
        self.assertEqual(payload["alert"]["reason"], "suppressed")
        self.fresh_ticks()
        _, payload = self.run_cli("--notify-config", str(self.notify))
        self.assertEqual((payload["verdict"], payload["alert"]["reason"]), ("ok", "recovery"))
        rows = [json.loads(line) for line in self.alerts.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([row["severity"] for row in rows], ["critical", "info"])
        self.assertTrue(rows[0]["title"].startswith("[arvyx delivery probe] FAILED"))
        self.assertTrue((liveness_dir(self.state) / PROBE_ALERT_STATE_NAME).is_file())

    def test_notifier_failure_does_not_change_the_verdict(self) -> None:
        self.notify.write_text(json.dumps({"adapter": "webhook", "url_env": "PROBE_WEBHOOK"}), encoding="utf-8")
        with mock.patch("arvyx_control.notifiers._post_json", return_value=_PostOutcome("ambiguous", "acceptance unknown: HTTP 500")) as post:
            code, payload = self.run_cli("--notify-config", str(self.notify),
                                         env={"PROBE_WEBHOOK": "https://alerts.example.test/hook"})
        post.assert_called_once()
        self.assertEqual((code, payload["verdict"]), (1, "failed"))
        self.assertEqual((payload["alert"]["status"], payload["alert"]["detail"]),
                         ("ambiguous", "acceptance unknown: HTTP 500"))
        self.fresh_ticks()
        with mock.patch("arvyx_control.notifiers._post_json", return_value=_PostOutcome("sent")):
            code, payload = self.run_cli("--notify-config", str(self.notify),
                                         env={"PROBE_WEBHOOK": "https://alerts.example.test/hook"})
        # An uncertain alert may have landed: recovery must still be announced.
        self.assertEqual((code, payload["verdict"], payload["alert"]["reason"]), (0, "ok", "recovery"))


if __name__ == "__main__":
    unittest.main()
