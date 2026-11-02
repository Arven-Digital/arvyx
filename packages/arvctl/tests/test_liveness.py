from __future__ import annotations
from arvyx_control.replica_authority import authority_context

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.error import HTTPError, URLError

from arvyx_control import dispatcher as dispatcher_module
from arvyx_control.cli import _probe_route_endpoint, main as cli_main
from arvyx_control.liveness import (
    DISPATCHER_COMPONENT,
    WORKER_COMPONENT,
    decide_alert,
    liveness_dir,
    load_alert_state,
    load_deadman_url,
    ping_deadman,
    read_tick_record,
    run_alerting,
    tick_record_path,
    validate_deadman_url,
    write_tick_record,
)

NOW = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
ROUTES = {"routes": {"alpha": {"runtime": "hermes-webhook", "url_env": "LIVENESS_TEST_URL",
                               "credential_env": "LIVENESS_TEST_CREDENTIAL", "timeout_seconds": 5}}}
ROUTE_ENV = {"LIVENESS_TEST_URL": "http://127.0.0.1:9/wake", "LIVENESS_TEST_CREDENTIAL": "synthetic-credential-value"}
DEADMAN = "https://checks.example.test/ping/synthetic-check"


def _state(tmp: str) -> Path:
    state = Path(tmp) / "state" / "control-events.jsonl"
    state.parent.mkdir(parents=True)
    state.write_text("", encoding="utf-8")
    return state


def _routes(tmp: str) -> Path:
    path = Path(tmp) / "routes.json"
    path.write_text(json.dumps(ROUTES), encoding="utf-8")
    return path


class TickRecordTests(unittest.TestCase):
    def test_record_is_written_next_to_the_state_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = _state(tmp)
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self.assertTrue(write_tick_record(
                    state, component=DISPATCHER_COMPONENT, result="ok", detail="claimed=1  delivered=1",
                    route_revision="r1", route_sha256="a" * 64, now=NOW,
                    environ={"ARVYX_RELEASE_BUILD_ID": "build-42"},
                ))
                path = tick_record_path(state, DISPATCHER_COMPONENT)
                self.assertEqual(path, liveness_dir(state) / "dispatcher.json")
                record = read_tick_record(state, DISPATCHER_COMPONENT)
                assert record is not None
                self.assertEqual(record["component"], "dispatcher")
                self.assertEqual(record["finished_at"], "2026-09-11T12:00:00Z")
                self.assertEqual(record["result"], "ok")
                self.assertEqual(record["detail"], "claimed=1 delivered=1")
                self.assertEqual(record["route_revision"], "r1")
                self.assertEqual(record["build_id"], "build-42")
                self.assertIn("code_version", record)
                # operational telemetry never lands in the append-only event log
                self.assertEqual(state.read_text(encoding="utf-8"), "")
                self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ["dispatcher.json"])

    def test_unknown_result_is_recorded_as_error_and_detail_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = _state(tmp)
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                leaked = "ghp_" + "Z" * 30
                write_tick_record(state, component=WORKER_COMPONENT, result="healthy", detail=f"boom {leaked}")
                record = read_tick_record(state, WORKER_COMPONENT)
                assert record is not None
                self.assertEqual(record["result"], "error")
                self.assertNotIn(leaked, json.dumps(record))

    def test_replace_failure_keeps_previous_record_and_leaves_no_temp_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = _state(tmp)
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                write_tick_record(state, component=WORKER_COMPONENT, result="idle", now=NOW)
                stderr = io.StringIO()
                with mock.patch("arvyx_control.liveness.os.replace", side_effect=OSError("disk full")):
                    ok = write_tick_record(
                        state, component=WORKER_COMPONENT, result="ok", now=NOW + timedelta(seconds=5), stderr=stderr,
                    )
                self.assertFalse(ok)
                self.assertIn("liveness record", stderr.getvalue())
                record = read_tick_record(state, WORKER_COMPONENT)
                assert record is not None
                self.assertEqual(record["result"], "idle")
                self.assertEqual(record["finished_at"], "2026-09-11T12:00:00Z")
                self.assertEqual([p.name for p in liveness_dir(state).iterdir()], ["execution-worker.json"])

    def test_unwritable_liveness_dir_is_swallowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = _state(tmp)
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                liveness_dir(state).parent.mkdir(parents=True, exist_ok=True)
                liveness_dir(state).write_text("not a directory", encoding="utf-8")
                stderr = io.StringIO()
                self.assertFalse(write_tick_record(state, component=DISPATCHER_COMPONENT, result="ok", stderr=stderr))
                self.assertTrue(stderr.getvalue().startswith("warning: liveness record"))

    def test_corrupt_and_missing_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = _state(tmp)
            self.assertIsNone(read_tick_record(state, DISPATCHER_COMPONENT))
            path = tick_record_path(state, DISPATCHER_COMPONENT)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{torn", encoding="utf-8")
            with self.assertRaises(ValueError):
                read_tick_record(state, DISPATCHER_COMPONENT)
            path.write_text(json.dumps({"component": "execution-worker", "finished_at": "2026-09-11T12:00:00Z"}))
            with self.assertRaises(ValueError):
                read_tick_record(state, DISPATCHER_COMPONENT)


class TickWriterIntegrationTests(unittest.TestCase):
    def _dispatch(self, vault: Path, state: Path, routes: Path, *extra: str) -> int:
        with mock.patch.dict(os.environ, ROUTE_ENV), redirect_stdout(io.StringIO()):
            return dispatcher_module.main([
                "--vault", str(vault),
                "--state", str(state), "--routes", str(routes),
                "--deliver-after", "2026-09-11T00:00:00Z", *extra,
            ])

    def test_dispatcher_tick_writes_idle_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state, routes = _state(tmp), _routes(tmp)
            self._dispatch(Path(tmp) / "vault", state, routes, "--max-watermark-age-seconds", str(10 ** 9))
            record = read_tick_record(state, DISPATCHER_COMPONENT)
            assert record is not None
            self.assertEqual(record["result"], "idle")
            self.assertIn("claimed=0", str(record["detail"]))

    def test_dispatcher_refusal_and_crash_still_record_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = _state(tmp)
            code = self._dispatch(Path(tmp) / "vault", state, Path(tmp) / "missing-routes.json")
            self.assertEqual(code, 2)
            record = read_tick_record(state, DISPATCHER_COMPONENT)
            assert record is not None
            self.assertEqual(record["result"], "error")
            self.assertIn("tick refused", str(record["detail"]))
            routes = _routes(tmp)
            with mock.patch.object(dispatcher_module, "dispatch_once", side_effect=RuntimeError("boom")):
                with self.assertRaises(RuntimeError):
                    self._dispatch(Path(tmp) / "vault", state, routes)
            record = read_tick_record(state, DISPATCHER_COMPONENT)
            assert record is not None
            self.assertEqual(record["detail"], "tick did not finish")

    def test_dispatcher_dry_run_does_not_refresh_liveness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state, routes = _state(tmp), _routes(tmp)
            self._dispatch(Path(tmp) / "vault", state, routes, "--dry-run")
            self.assertIsNone(read_tick_record(state, DISPATCHER_COMPONENT))

    def test_liveness_failure_never_changes_the_dispatcher_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state, routes = _state(tmp), _routes(tmp)
            liveness_dir(state).parent.mkdir(parents=True, exist_ok=True)
            liveness_dir(state).write_text("blocked", encoding="utf-8")
            with redirect_stderr(io.StringIO()) as stderr:
                code = self._dispatch(Path(tmp) / "vault", state, routes, "--max-watermark-age-seconds", str(10 ** 9))
            self.assertEqual(code, 0)
            self.assertIn("liveness record", stderr.getvalue())

    def _worker(self, vault: Path, state: Path, routes: Path) -> int:
        with mock.patch.dict(os.environ, ROUTE_ENV), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return cli_main([
                "--authority-vault", str(vault),
                "execution", "worker", "--state", str(state), "--worker", "worker-a",
                "--routes", str(routes), "--lease-seconds", "30", "--json",
            ])

    def test_worker_tick_writes_idle_and_error_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state, routes = _state(tmp), _routes(tmp)
            self.assertEqual(self._worker(Path(tmp) / "vault", state, routes), 0)
            record = read_tick_record(state, WORKER_COMPONENT)
            assert record is not None
            self.assertEqual(record["result"], "idle")
            self.assertEqual(self._worker(Path(tmp) / "vault", state, Path(tmp) / "absent.json"), 2)
            record = read_tick_record(state, WORKER_COMPONENT)
            assert record is not None
            self.assertEqual(record["result"], "error")
            self.assertIn("invalid execution routes", str(record["detail"]))

    def test_worker_exit_code_survives_a_liveness_write_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state, routes = _state(tmp), _routes(tmp)
            liveness_dir(state).parent.mkdir(parents=True, exist_ok=True)
            liveness_dir(state).write_text("blocked", encoding="utf-8")
            self.assertEqual(self._worker(Path(tmp) / "vault", state, routes), 0)

    def test_routes_doctor_probe_uses_the_shared_endpoint_probe(self) -> None:
        with mock.patch("arvyx_control.http_bounds.bounded_tcp_connection", side_effect=ConnectionRefusedError()) as connect:
            result = _probe_route_endpoint("https://hook.example.test:8443/path", 30)
        self.assertEqual(result, {"endpoint": "hook.example.test:8443", "ok": False, "detail": "ConnectionRefusedError"})
        self.assertEqual(connect.call_args.kwargs["timeout"], 5.0)


@dataclass
class _Delivery:
    status: str
    detail: str = ""


class _Notifier:
    def __init__(self, *statuses: str, raises: bool = False) -> None:
        self.statuses = list(statuses) or ["sent"]
        self.raises = raises
        self.sent: list[dict[str, str]] = []

    def deliver(self, candidate: dict[str, str], dry_run: bool) -> _Delivery:
        self.sent.append(candidate)
        if self.raises:
            raise RuntimeError("adapter exploded")
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        return _Delivery(status, "HTTP 502" if status == "failed" else "")


class AlertDedupeTests(unittest.TestCase):
    def test_confirmed_local_adapters_dedupe_and_announce_recovery(self) -> None:
        from io import StringIO
        from arvyx_control.notifiers import _FileNotifier, _StdoutNotifier

        with tempfile.TemporaryDirectory() as tmp:
            for adapter, notifier, status in (
                ('stdout', _StdoutNotifier(stream=StringIO()), 'printed'),
                ('file', _FileNotifier(path=Path(tmp) / 'deliveries.jsonl'), 'recorded'),
            ):
                with self.subTest(adapter=adapter):
                    path = Path(tmp) / (adapter + '-alerts.json')
                    def run(verdict, now):
                        return run_alerting(state_path=path, verdict=verdict, title='t',
                                            text='synthetic', notifier=notifier, now=now,
                                            realert_seconds=3600)
                    first = run('failed', NOW)
                    self.assertEqual(first['status'], status)
                    state, _ = load_alert_state(path)
                    self.assertEqual(state['alerted_verdict'], 'failed')
                    self.assertEqual(run('failed', NOW + timedelta(seconds=1))['reason'], 'suppressed')
                    recovery = run('ok', NOW + timedelta(seconds=2))
                    self.assertEqual((recovery['reason'], recovery['status']), ('recovery', status))
                    self.assertEqual(load_alert_state(path)[0]['alerted_verdict'], 'ok')

    def test_dry_run_and_unknown_status_never_advance_alerted_verdict(self) -> None:
        for status in ('dry-run', 'unknown'):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'alert.json'
                run_alerting(state_path=path, verdict='failed', title='t', text='synthetic',
                             notifier=_Notifier(status), now=NOW)
                self.assertEqual(load_alert_state(path)[0]['alerted_verdict'], 'ok')

    def test_decisions(self) -> None:
        state = {"alerted_verdict": "ok", "last_alert_at": ""}
        self.assertEqual(decide_alert(state, "ok", now=NOW, realert_seconds=60).reason, "steady_ok")
        self.assertEqual(decide_alert(state, "failed", now=NOW, realert_seconds=60).reason, "transition")
        failing = {"alerted_verdict": "failed", "last_alert_at": "2026-09-11T11:59:30Z"}
        self.assertEqual(decide_alert(failing, "failed", now=NOW, realert_seconds=60).reason, "suppressed")
        self.assertEqual(decide_alert(failing, "failed", now=NOW + timedelta(seconds=30), realert_seconds=60).reason, "realert")
        self.assertEqual(decide_alert(failing, "degraded", now=NOW, realert_seconds=60).reason, "transition")
        self.assertEqual(decide_alert(failing, "ok", now=NOW, realert_seconds=60).reason, "recovery")

    def test_dedupe_realert_and_recovery_across_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "liveness" / "alert.json"
            notifier = _Notifier()

            def run(verdict: str, at: datetime) -> dict[str, object]:
                return run_alerting(state_path=path, verdict=verdict, title=f"probe {verdict}",
                                    text="details", notifier=notifier, now=at, realert_seconds=6 * 3600)

            self.assertEqual(run("ok", NOW)["reason"], "steady_ok")
            first = run("failed", NOW + timedelta(minutes=5))
            self.assertEqual((first["reason"], first["status"]), ("transition", "sent"))
            self.assertEqual(run("failed", NOW + timedelta(minutes=10))["reason"], "suppressed")
            self.assertEqual(run("failed", NOW + timedelta(hours=3))["reason"], "suppressed")
            self.assertEqual(run("failed", NOW + timedelta(hours=6, minutes=6))["reason"], "realert")
            self.assertEqual(run("failed", NOW + timedelta(hours=6, minutes=11))["reason"], "suppressed")
            recovered = run("ok", NOW + timedelta(hours=7))
            self.assertEqual((recovered["reason"], recovered["status"]), ("recovery", "sent"))
            self.assertEqual(run("ok", NOW + timedelta(hours=8))["reason"], "steady_ok")
            self.assertEqual([c["severity"] for c in notifier.sent], ["critical", "critical", "info"])
            self.assertEqual(notifier.sent[0]["target"], "operator")

    def test_notifier_failure_is_retried_next_run_and_never_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alert.json"
            failing = _Notifier("failed", "sent")
            report = run_alerting(state_path=path, verdict="failed", title="t", text="x",
                                  notifier=failing, now=NOW)
            self.assertEqual((report["status"], report["detail"]), ("failed", "HTTP 502"))
            state, _ = load_alert_state(path)
            self.assertEqual(state["alerted_verdict"], "ok")
            retry = run_alerting(state_path=path, verdict="failed", title="t", text="x",
                                 notifier=failing, now=NOW + timedelta(minutes=5))
            self.assertEqual((retry["reason"], retry["status"]), ("transition", "sent"))
            exploding = run_alerting(state_path=Path(tmp) / "other.json", verdict="degraded", title="t",
                                     text="x", notifier=_Notifier(raises=True), now=NOW)
            self.assertEqual(exploding["status"], "failed")
            self.assertIn("RuntimeError", str(exploding["detail"]))

    def test_ambiguous_alert_is_not_success_and_is_interval_suppressed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alert.json"
            notifier = _Notifier("ambiguous", "sent")
            report = run_alerting(state_path=path, verdict="failed", title="t", text="x",
                                  notifier=notifier, now=NOW, realert_seconds=60)
            self.assertEqual(report["status"], "ambiguous")
            state, _ = load_alert_state(path)
            self.assertEqual(state["alerted_verdict"], "ok")
            self.assertEqual(state["last_alert_at"], "")
            self.assertEqual(state["uncertain_verdict"], "failed")
            self.assertEqual(decide_alert(state, "failed", now=NOW, realert_seconds=60).reason,
                             "uncertain_suppressed")
            self.assertEqual(decide_alert(state, "failed", now=NOW + timedelta(seconds=60),
                                          realert_seconds=60).reason, "uncertain_realert")
            recovery = run_alerting(state_path=path, verdict="ok", title="t", text="x",
                                    notifier=notifier, now=NOW + timedelta(seconds=1))
            self.assertEqual((recovery["reason"], recovery["status"]), ("recovery", "sent"))
            state, _ = load_alert_state(path)
            self.assertNotIn("uncertain_verdict", state)

    def test_corrupt_state_resets_to_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alert.json"
            path.write_text("[]", encoding="utf-8")
            report = run_alerting(state_path=path, verdict="failed", title="t", text="x",
                                  notifier=_Notifier(), now=NOW)
            self.assertEqual(report["reason"], "transition")
            self.assertIn("reset", str(report["state_note"]))

    def test_alert_text_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            notifier = _Notifier()
            leaked = "xoxb-" + "1" * 20
            run_alerting(state_path=Path(tmp) / "a.json", verdict="failed", title="t",
                         text=f"detail {leaked}", notifier=notifier, now=NOW)
            self.assertNotIn(leaked, notifier.sent[0]["text"])


class _Response:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class DeadmanTests(unittest.TestCase):
    def test_url_validation(self) -> None:
        self.assertEqual(validate_deadman_url(f" {DEADMAN} "), DEADMAN)
        for bad in ("http://checks.example.test/ping/x", "https://user:pw@checks.example.test/x",
                    "https://checks.example.test/a b", "ftp://checks.example.test/x", ""):
            with self.assertRaises(ValueError):
                validate_deadman_url(bad)

    def test_url_is_loaded_by_reference_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(load_deadman_url(env_name=None, file=None))
            self.assertEqual(load_deadman_url(env_name="DM", file=None, environ={"DM": DEADMAN}), DEADMAN)
            with self.assertRaises(ValueError):
                load_deadman_url(env_name="DM", file=None, environ={})
            path = Path(tmp) / "deadman.url"
            path.write_text(DEADMAN + "\n", encoding="utf-8")
            self.assertEqual(load_deadman_url(env_name=None, file=path), DEADMAN)
            path.write_text(DEADMAN + "\n" + DEADMAN + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_deadman_url(env_name=None, file=path)
            with self.assertRaises(ValueError):
                load_deadman_url(env_name="DM", file=path, environ={"DM": DEADMAN})

    def test_success_and_fail_pings(self) -> None:
        seen: list[tuple[str, str, bytes, float]] = []

        def opener(request, timeout):  # type: ignore[no-untyped-def]
            seen.append((request.full_url, request.get_method(), request.data, timeout))
            return _Response(200)

        ok = ping_deadman(DEADMAN, fail=False, body="all good", timeout=4, opener=opener)
        failed = ping_deadman(DEADMAN + "/?rid=7", fail=True, body="broken", opener=opener)
        self.assertEqual((ok["endpoint"], ok["status"]), ("success", "sent"))
        self.assertEqual((failed["endpoint"], failed["status"]), ("fail", "sent"))
        self.assertEqual(seen[0][:2], (DEADMAN, "POST"))
        self.assertEqual(seen[0][3], 4)
        self.assertEqual(seen[1][0], "https://checks.example.test/ping/synthetic-check/fail?rid=7")
        self.assertEqual(seen[1][2], b"broken")

    def test_ping_failures_never_leak_the_url(self) -> None:
        def http_error(request, timeout):  # type: ignore[no-untyped-def]
            raise HTTPError(request.full_url, 404, "nope", {}, None)

        def unreachable(request, timeout):  # type: ignore[no-untyped-def]
            raise URLError(f"cannot reach {request.full_url}")

        first = ping_deadman(DEADMAN, fail=True, opener=http_error)
        second = ping_deadman(DEADMAN, fail=False, opener=unreachable)
        self.assertEqual((first["status"], first["detail"]), ("failed", "HTTP 404"))
        self.assertEqual(second["status"], "failed")
        self.assertNotIn("synthetic-check", json.dumps([first, second]))


if __name__ == "__main__":
    unittest.main()
