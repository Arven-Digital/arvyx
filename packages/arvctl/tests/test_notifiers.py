from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from arvyx_control.replica_authority import authority_context
from arvyx_control.cli import main
from arvyx_control.control import (
    THREAD_NOTIFICATION_EVENT,
    THREAD_NOTIFICATION_FAILED_EVENT,
    post_thread,
    project_thread_notifications,
    read_events,
)
from arvyx_control.notifiers import notify_and_deliver, validate_dashboard_url
from arvyx_control import notifiers
from datetime import datetime, timedelta, timezone


class _CaptureHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        self.server.captured.append((self.path, json.loads(body)))
        status = 500 if self.path.startswith("/fail") else 200
        self.send_response(status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


class NotifierTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.vault.mkdir(exist_ok=True)
        self.enterContext(authority_context(self.vault, self.state))

    def _seed_pending(self, title: str = "Needs attention") -> str:
        return post_thread(state=self.state, title=title, thread_type="ask", target="vesper", actor="demobot").thread.id

    def _notification_events(self) -> list:
        return [event for event in read_events(self.state) if event.type == THREAD_NOTIFICATION_EVENT]

    def _start_server(self) -> str:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _CaptureHandler)
        server.captured = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.server = server
        return f"http://127.0.0.1:{server.server_address[1]}"


class StdoutAndFileAdapterTests(NotifierTestCase):
    def test_late_failure_releases_only_its_exact_claim_generation(self) -> None:
        thread_id = self._seed_pending()
        start = datetime(2099, 1, 1, tzinfo=timezone.utc)
        with patch("arvyx_control.health_ops._utcnow", return_value=start), \
             patch("arvyx_control.control._now", return_value="2099-01-01T00:00:00Z"):
            first = notifiers.notify_check(self.state, dedupe_window_minutes=1)
        a = next(c for c in first.candidates if c["kind"] == "notification")
        # Claims use the control event timestamp; advance both clocks together.
        with patch("arvyx_control.health_ops._utcnow", return_value=start + timedelta(minutes=2)), \
             patch("arvyx_control.control._now", return_value="2099-01-01T00:02:00Z"):
            second = notifiers.notify_check(self.state, dedupe_window_minutes=1)
            b = next(c for c in second.candidates if c["kind"] == "notification")
            self.assertNotEqual(a["claim_event_id"], b["claim_event_id"])
            before = self.state.read_bytes()
            self.assertFalse(notifiers.record_thread_notification_failure(
                self.state, thread_id, "notification", "late refusal",
                claim_event_id=a["claim_event_id"]))
            self.assertEqual(self.state.read_bytes(), before)
            self.assertFalse(any(c["kind"] == "notification" for c in
                notifiers.notify_check(self.state, dedupe_window_minutes=1).candidates))
            self.assertTrue(notifiers.record_thread_notification_failure(
                self.state, thread_id, "notification", "current refusal",
                claim_event_id=b["claim_event_id"]))
            retry = notifiers.notify_check(self.state, dedupe_window_minutes=1)
            self.assertTrue(any(c["kind"] == "notification" for c in retry.candidates))

    def test_stdout_adapter_prints_expected_text(self) -> None:
        self._seed_pending()
        out = StringIO()
        with redirect_stdout(out):
            result = notify_and_deliver(state=self.state, adapter="stdout")
        self.assertIn("[notice] ask for vesper: Needs attention", out.getvalue())
        self.assertEqual([delivery.status for delivery in result.deliveries], ["printed"])
        self.assertTrue(result.ok)

    def test_file_adapter_writes_jsonl_delivery_row(self) -> None:
        thread_id = self._seed_pending()
        deliveries = Path(self._tmp.name) / "deliveries.jsonl"
        result = notify_and_deliver(state=self.state, adapter="file", deliveries_path=deliveries)
        self.assertEqual([delivery.status for delivery in result.deliveries], ["recorded"])
        rows = [json.loads(line) for line in deliveries.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["thread_id"], thread_id)
        self.assertEqual(rows[0]["adapter"], "file")
        self.assertEqual(rows[0]["kind"], "notification")
        self.assertIn("Needs attention", rows[0]["text"])

    def test_file_adapter_requires_deliveries_path(self) -> None:
        self._seed_pending()
        with self.assertRaises(ValueError):
            notify_and_deliver(state=self.state, adapter="file")

    def test_secret_shaped_text_is_redacted_in_delivery_records(self) -> None:
        # the domain rejects secret-shaped thread text at post time; the
        # adapter layer still redacts defensively at delivery time
        from arvyx_control.notifiers import _FileNotifier

        deliveries = Path(self._tmp.name) / "deliveries.jsonl"
        candidate = {
            "kind": "notification",
            "thread_id": "thread_test",
            "target": "vesper",
            "channel": "ops",
            "severity": "notice",
            "title": "leaky",
            "text": "password = hunter2hunter2",
        }
        delivery = _FileNotifier(path=deliveries).deliver(candidate, dry_run=False)
        self.assertNotIn("hunter2hunter2", delivery.text)
        self.assertIn("[REDACTED-SECRET]", delivery.text)
        row = json.loads(deliveries.read_text(encoding="utf-8").splitlines()[0])
        self.assertNotIn("hunter2hunter2", json.dumps(row))

    def test_dry_run_has_no_side_effects(self) -> None:
        self._seed_pending()
        deliveries = Path(self._tmp.name) / "deliveries.jsonl"
        out = StringIO()
        with redirect_stdout(out):
            result = notify_and_deliver(state=self.state, adapter="file", deliveries_path=deliveries, dry_run=True)
        self.assertEqual([delivery.status for delivery in result.deliveries], ["dry-run"])
        self.assertFalse(deliveries.exists())
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(self._notification_events(), [])

    def test_dedupe_state_works_across_adapter_runs(self) -> None:
        self._seed_pending()
        with redirect_stdout(StringIO()):
            first = notify_and_deliver(state=self.state, adapter="stdout")
        self.assertEqual(len(first.candidates), 1)
        deliveries = Path(self._tmp.name) / "deliveries.jsonl"
        second = notify_and_deliver(state=self.state, adapter="file", deliveries_path=deliveries)
        self.assertEqual(second.candidates, [])
        self.assertEqual(len(second.suppressed), 1)
        self.assertEqual(second.deliveries, [])
        self.assertFalse(deliveries.exists())


class WebhookAdapterTests(NotifierTestCase):
    def test_webhook_posts_to_local_fake_server(self) -> None:
        thread_id = self._seed_pending()
        base = self._start_server()
        with patch.dict(os.environ, {"ARVYX_TEST_WEBHOOK": f"{base}/hook"}):
            result = notify_and_deliver(state=self.state, adapter="webhook", webhook_url_env="ARVYX_TEST_WEBHOOK")
        self.assertEqual([delivery.status for delivery in result.deliveries], ["sent"])
        self.assertTrue(result.ok)
        (path, body), = self.server.captured
        self.assertEqual(path, "/hook")
        self.assertEqual(body["thread_id"], thread_id)
        self.assertEqual(body["kind"], "notification")

    def test_webhook_failure_is_reported_not_raised(self) -> None:
        self._seed_pending()
        base = self._start_server()
        with patch.dict(os.environ, {"ARVYX_TEST_WEBHOOK": f"{base}/fail"}):
            result = notify_and_deliver(state=self.state, adapter="webhook", webhook_url_env="ARVYX_TEST_WEBHOOK")
        self.assertEqual([delivery.status for delivery in result.deliveries], ["ambiguous"])
        self.assertIn("HTTP 500", result.deliveries[0].detail)
        self.assertFalse(result.ok)

    def test_webhook_failure_retains_claim_without_immediate_retry(self) -> None:
        self._seed_pending()
        base = self._start_server()
        with patch.dict(os.environ, {"ARVYX_TEST_WEBHOOK": f"{base}/fail"}):
            first = notify_and_deliver(
                state=self.state,
                adapter="webhook",
                webhook_url_env="ARVYX_TEST_WEBHOOK",
            )
            second = notify_and_deliver(
                state=self.state,
                adapter="webhook",
                webhook_url_env="ARVYX_TEST_WEBHOOK",
            )
        self.assertEqual([delivery.status for delivery in first.deliveries], ["ambiguous"])
        self.assertEqual(second.deliveries, [])
        self.assertTrue(project_thread_notifications(self.state))
        failure_events = [
            event for event in read_events(self.state) if event.type == THREAD_NOTIFICATION_FAILED_EVENT
        ]
        self.assertEqual(len(failure_events), 0)
        self.assertEqual(len(self.server.captured), 1)

    def test_webhook_requires_env_before_claiming_candidates(self) -> None:
        self._seed_pending()
        os.environ.pop("ARVYX_TEST_WEBHOOK_ABSENT", None)
        with self.assertRaises(ValueError):
            notify_and_deliver(state=self.state, adapter="webhook", webhook_url_env="ARVYX_TEST_WEBHOOK_ABSENT")
        # misconfiguration must fail before any dedupe event is written
        self.assertEqual(self._notification_events(), [])
        with patch.dict(os.environ, {"ARVYX_TEST_WEBHOOK_ABSENT": "ftp://127.0.0.1/x"}):
            with self.assertRaises(ValueError):
                notify_and_deliver(state=self.state, adapter="webhook", webhook_url_env="ARVYX_TEST_WEBHOOK_ABSENT")
        self.assertEqual(self._notification_events(), [])


class TelegramAdapterTests(NotifierTestCase):
    def _config(self, api_base: str | None = None) -> Path:
        path = Path(self._tmp.name) / "telegram.json"
        spec = {
            "adapter": "telegram",
            "bot_token_env": "ARVYX_TEST_TG_TOKEN",
            "chat_id_env": "ARVYX_TEST_TG_CHAT",
        }
        if api_base:
            spec["api_base_url"] = api_base
        path.write_text(json.dumps(spec), encoding="utf-8")
        return path

    def test_refuses_without_config_or_env_and_fails_safely(self) -> None:
        self._seed_pending()
        with self.assertRaises(ValueError):
            notify_and_deliver(state=self.state, adapter="telegram")
        os.environ.pop("ARVYX_TEST_TG_TOKEN", None)
        os.environ.pop("ARVYX_TEST_TG_CHAT", None)
        with self.assertRaises(ValueError) as ctx:
            notify_and_deliver(state=self.state, adapter="telegram", config=self._config())
        self.assertIn("refuses to run", str(ctx.exception))
        # refusal claims nothing: the next configured run still notifies
        self.assertEqual(self._notification_events(), [])

    _TEST_GATE_ENV = {
        "ARVYX_TEST_TG_TOKEN": "1234567890:TESTTOKENVALUE",
        "ARVYX_TEST_TG_CHAT": "-100200300",
        "ARVYX_ALLOW_TELEGRAM_TEST_API_BASE": "1",
    }

    def test_sends_via_gated_test_api_base_and_scrubs_token(self) -> None:
        self._seed_pending()
        base = self._start_server()
        with patch.dict(os.environ, self._TEST_GATE_ENV):
            result = notify_and_deliver(state=self.state, adapter="telegram", config=self._config(api_base=base))
        self.assertEqual([delivery.status for delivery in result.deliveries], ["sent"])
        (path, body), = self.server.captured
        self.assertTrue(path.endswith("/sendMessage"))
        self.assertIn("/bot1234567890:TESTTOKENVALUE/", path)
        self.assertEqual(body["chat_id"], "-100200300")
        self.assertIn("Needs attention", body["text"])

    def test_failure_detail_never_contains_the_token(self) -> None:
        self._seed_pending()
        base = self._start_server()
        with patch.dict(os.environ, self._TEST_GATE_ENV):
            result = notify_and_deliver(
                state=self.state, adapter="telegram", config=self._config(api_base=f"{base}/fail")
            )
        delivery = result.deliveries[0]
        self.assertEqual(delivery.status, "ambiguous")
        self.assertNotIn("TESTTOKENVALUE", delivery.detail)
        self.assertNotIn("TESTTOKENVALUE", json.dumps(result.to_dict()))

    def test_production_rejects_non_default_api_base_before_claiming(self) -> None:
        # exfiltration guard: without the explicit test gate, a config that
        # redirects api_base_url must be refused outright — the token would
        # otherwise be POSTed to that host
        self._seed_pending()
        env = {"ARVYX_TEST_TG_TOKEN": "1234567890:AAF4realLookingSecretValue0123456", "ARVYX_TEST_TG_CHAT": "-100200300"}
        os.environ.pop("ARVYX_ALLOW_TELEGRAM_TEST_API_BASE", None)
        with patch.dict(os.environ, env):
            with self.assertRaises(ValueError) as ctx:
                notify_and_deliver(
                    state=self.state,
                    adapter="telegram",
                    config=self._config(api_base="https://attacker.example.test"),
                )
        self.assertIn("https://api.telegram.org", str(ctx.exception))
        # rejection claims nothing: no dedupe events were written
        self.assertEqual(self._notification_events(), [])
        # the real default base is accepted without any gate (env checks pass,
        # construction succeeds; nothing is sent because there is no network here)
        with patch.dict(os.environ, env):
            from arvyx_control.notifiers import _build_notifier

            notifier = _build_notifier(
                adapter="telegram",
                deliveries_path=None,
                webhook_url_env=None,
                config=self._config(),
                timeout=1.0,
                quiet_stdout=True,
            )
        self.assertEqual(notifier.api_base, "https://api.telegram.org")

    def test_test_gate_also_requires_test_shaped_token(self) -> None:
        # even with the env gate on, a real-shaped token never leaves for a
        # non-default base
        self._seed_pending()
        env = {
            "ARVYX_TEST_TG_TOKEN": "1234567890:AAF4realLookingSecretValue0123456",
            "ARVYX_TEST_TG_CHAT": "-100200300",
            "ARVYX_ALLOW_TELEGRAM_TEST_API_BASE": "1",
        }
        base = self._start_server()
        with patch.dict(os.environ, env):
            with self.assertRaises(ValueError) as ctx:
                notify_and_deliver(state=self.state, adapter="telegram", config=self._config(api_base=base))
        self.assertIn("not test-shaped", str(ctx.exception))
        self.assertEqual(self._notification_events(), [])
        self.assertEqual(self.server.captured, [])

    def test_config_adapter_field_mismatch_fails_clearly(self) -> None:
        self._seed_pending()
        webhook_config = Path(self._tmp.name) / "webhook.json"
        webhook_config.write_text(
            json.dumps({"adapter": "webhook", "url_env": "ARVYX_TEST_WEBHOOK"}), encoding="utf-8"
        )
        with self.assertRaises(ValueError) as ctx:
            notify_and_deliver(state=self.state, adapter="telegram", config=webhook_config)
        self.assertIn("declares adapter 'webhook'; expected 'telegram'", str(ctx.exception))
        telegram_config = self._config()
        with self.assertRaises(ValueError) as ctx:
            notify_and_deliver(state=self.state, adapter="webhook", config=telegram_config)
        self.assertIn("declares adapter 'telegram'; expected 'webhook'", str(ctx.exception))
        self.assertEqual(self._notification_events(), [])


class DashboardUrlValidationTests(NotifierTestCase):
    def test_accepts_clean_public_url_on_any_adapter(self) -> None:
        url = "https://ops.example.test/dashboard"
        for adapter in ("stdout", "file", "webhook", "telegram"):
            self.assertEqual(validate_dashboard_url(url, adapter), url)

    def test_rejects_malformed_and_dangerous_urls(self) -> None:
        bad = [
            "ftp://ops.example.test/dashboard",
            "https://ops.example.test/dash board",
            "https://ops.example.test/dash\nboard",
            "https://operator:hunter2secret@ops.example.test/dashboard",
            "https://ops.example.test/dashboard?token=abcdef123456789",  # gitleaks:allow
            "   ",
        ]
        for url in bad:
            with self.assertRaises(ValueError, msg=url):
                validate_dashboard_url(url, "stdout")

    def test_loopback_links_are_local_adapter_only(self) -> None:
        url = "http://127.0.0.1:8765/dashboard"
        self.assertEqual(validate_dashboard_url(url, "stdout"), url)
        self.assertEqual(validate_dashboard_url(url, "file"), url)
        for adapter in ("webhook", "telegram"):
            with self.assertRaises(ValueError):
                validate_dashboard_url(url, adapter)
        with self.assertRaises(ValueError):
            validate_dashboard_url("http://localhost:8765/dashboard", "webhook")

    def test_validation_happens_before_message_construction(self) -> None:
        self._seed_pending()
        with self.assertRaises(ValueError):
            notify_and_deliver(
                state=self.state,
                adapter="webhook",
                webhook_url_env="ARVYX_TEST_WEBHOOK",
                dashboard_url="http://127.0.0.1:8765/dashboard",
            )
        # rejected before candidates were computed or claimed
        self.assertEqual(self._notification_events(), [])

    def test_loopback_dashboard_link_flows_into_local_output(self) -> None:
        self._seed_pending()
        out = StringIO()
        with redirect_stdout(out):
            result = notify_and_deliver(
                state=self.state, adapter="stdout", dashboard_url="http://127.0.0.1:8765/dashboard"
            )
        self.assertIn("| http://127.0.0.1:8765/dashboard", out.getvalue())
        self.assertTrue(result.ok)


class NotifierCliTests(NotifierTestCase):
    def _run(self, argv: list[str]) -> tuple[int, str, str]:
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(["--authority-vault", str(self.vault), *argv])
        return code, out.getvalue(), err.getvalue()

    def test_file_adapter_cli_end_to_end(self) -> None:
        self._seed_pending()
        deliveries = Path(self._tmp.name) / "deliveries.jsonl"
        code, out, _ = self._run(
            [
                "health",
                "notify-check",
                "--state",
                str(self.state),
                "--adapter",
                "file",
                "--deliveries",
                str(deliveries),
                "--json",
            ]
        )
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["adapter"], "file")
        self.assertEqual(len(payload["deliveries"]), 1)
        self.assertTrue(payload["ok"])
        self.assertTrue(deliveries.exists())

    def test_misconfigured_telegram_cli_exits_nonzero(self) -> None:
        self._seed_pending()
        code, _, err = self._run(
            ["health", "notify-check", "--state", str(self.state), "--adapter", "telegram", "--json"]
        )
        self.assertEqual(code, 1)
        self.assertIn("telegram adapter requires --config", err)

    def test_cli_rejects_redirected_telegram_api_base_before_claiming(self) -> None:
        self._seed_pending()
        config = Path(self._tmp.name) / "telegram.json"
        config.write_text(
            json.dumps(
                {
                    "adapter": "telegram",
                    "api_base_url": "https://attacker.example.test",
                    "bot_token_env": "ARVYX_TEST_TG_TOKEN",
                    "chat_id_env": "ARVYX_TEST_TG_CHAT",
                }
            ),
            encoding="utf-8",
        )
        os.environ.pop("ARVYX_ALLOW_TELEGRAM_TEST_API_BASE", None)
        env = {
            "ARVYX_TEST_TG_TOKEN": "1234567890:AAF4realLookingSecretValue0123456",
            "ARVYX_TEST_TG_CHAT": "-100200300",
        }
        with patch.dict(os.environ, env):
            code, _, err = self._run(
                [
                    "health",
                    "notify-check",
                    "--state",
                    str(self.state),
                    "--adapter",
                    "telegram",
                    "--config",
                    str(config),
                    "--json",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("api.telegram.org", err)
        self.assertEqual(self._notification_events(), [])

    def test_failed_webhook_delivery_exits_nonzero(self) -> None:
        self._seed_pending()
        base = self._start_server()
        with patch.dict(os.environ, {"ARVYX_TEST_WEBHOOK": f"{base}/fail"}):
            code, out, _ = self._run(
                [
                    "health",
                    "notify-check",
                    "--state",
                    str(self.state),
                    "--adapter",
                    "webhook",
                    "--webhook-url-env",
                    "ARVYX_TEST_WEBHOOK",
                    "--json",
                ]
            )
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["deliveries"][0]["status"], "ambiguous")
        self.assertIn("HTTP 500", payload["deliveries"][0]["detail"])


if __name__ == "__main__":
    unittest.main()
