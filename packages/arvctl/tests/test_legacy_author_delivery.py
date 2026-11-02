from arvyx_control.replica_authority import authority_context
"""Legacy author metadata is not a delivery identity."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
import io
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from arvyx_control.control import _append_event_unlocked, _event, read_events
from arvyx_control.outbox import claim_due, project_outbox, project_materialization_skips
from arvyx_control import control
from arvyx_control.api import _actor, handle_api_request
from arvyx_control.auth import Identity
from arvyx_control.cli import main
from arvyx_control.health_ops import daily_handoff
from arvyx_control.agent_delivery import AgentRoute
from arvyx_control.dispatcher import dispatch_once
from arvyx_control.outbox import record_dispatcher_tick, project_dispatcher_tick

NOW = datetime(2026, 9, 23, tzinfo=timezone.utc)


class LegacyAuthorDeliveryTests(unittest.TestCase):
    def test_new_tick_replaces_stale_atlas_skip_without_delivery_or_completion(self):
        with authority_context(self.vault, self.state):
            event = self.source("thread.done", actor="atlas", target="harbor", done_by="harbor", status="done")
            record_dispatcher_tick(self.state, configured_targets=("harbor",), healthy=False,
                                   materialization_remaining=True, skipped_unconfigured_targets=("atlas",), now=NOW)
            route = AgentRoute("harbor", "hermes-webhook", "TEST_URL", "TEST_SECRET")
            with patch("arvyx_control.dispatcher.deliver_outbox_item") as send:
                result = dispatch_once(self.state, routes={"harbor": route}, worker="test",
                                       now=NOW, clock=lambda: NOW,
                                       deliver_after=(NOW - timedelta(hours=1)).isoformat(),
                                       environ={"TEST_URL": "http://127.0.0.1:9999/wake", "TEST_SECRET": "synthetic"},
                                       deliverer=send)
            send.assert_not_called()
            self.assertTrue(result.ok)
            tick = project_dispatcher_tick(self.state)
            self.assertTrue(tick["healthy"])
            self.assertFalse(tick["materialization_remaining"])
            self.assertEqual(tick["skipped_unconfigured_targets"], [])
            skips = [e for e in read_events(self.state) if e.type == "outbox.materialization.skipped"]
            self.assertEqual(skips[0].payload["source_event_ids"], [event.id])
            self.assertEqual(project_outbox(self.state), {})

    def test_daily_handoff_cannot_invent_a_fixture_roster(self):
        with authority_context(self.vault, self.state):
            with self.assertRaisesRegex(ValueError, "explicit.*config"):
                daily_handoff(self.state)
            self.assertEqual(read_events(self.state), [])

    def test_http_thread_omitted_operator_author_refused_agent_author_bound(self):
        for kind, expected_status in (("operator", 400), ("agent", 201)):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / "events.jsonl"
                identity = Identity(agent_id="sage", scopes=frozenset({"control.write"}), kind=kind)
                with patch("arvyx_control.api.resolve_identity", return_value=identity):
                    response = handle_api_request("POST", "/threads", {"title": "canary", "target": "sage"}, Path(tmp), state, idempotency_key="test-author-required")
                self.assertEqual(response.status, expected_status, response.body)
                events = read_events(state)
                if kind == "agent":
                    self.assertEqual(events[0].payload["actor"], "sage")
                    self.assertTrue(events[0].payload["actor_identity_bound"])
                else:
                    self.assertEqual(events, [])

    def test_cli_omitted_author_refuses_without_writing(self):
        with authority_context(self.vault, self.state):
            args = ["--authority-vault", str(self.vault), "thread", "post", "--title", "canary", "--to", "harbor", "--state", str(self.state), "--json"]
            with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                self.assertNotEqual(main(args), 0)
            self.assertEqual(read_events(self.state), [])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(main(args + ["--actor", "sage"]), 0)
            self.assertEqual(read_events(self.state)[0].payload["actor"], "sage")

    def test_missing_identity_never_invents_atlas(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                calls = [
                    lambda: control.create_task(state, "test"),
                    lambda: control.create_handoff(state, "test"),
                    lambda: control.post_thread(state, "test"),
                    lambda: control.post_thread_unlocked(state, "test"),
                    lambda: control.post_bus_message(state, "test"),
                    lambda: control.request_approval(state, "true"),
                ]
                for call in calls:
                    with self.subTest(call=call), self.assertRaises(ValueError):
                        call()
                self.assertEqual(read_events(state), [])

    def test_api_missing_identity_is_refused_but_bound_identity_wins(self):
        with authority_context(self.vault, self.state):
            with self.assertRaises(ValueError):
                _actor(None, None, "")
            identity = Identity(agent_id="sage", scopes=frozenset(), kind="agent")
            self.assertEqual(_actor(identity, "atlas", ""), "sage")

    def test_retired_identity_new_writes_rejected_without_append(self):
        with authority_context(self.vault, self.state):
            calls = [
                lambda: control.create_task(self.state, "test", owner="atlas"),
                lambda: control.create_task(self.state, "test", owner="sage", created_by="atlas"),
                lambda: control.request_approval(self.state, "true", requester="atlas"),
                lambda: control.create_handoff(self.state, "test", from_agent="atlas", to_agent="sage"),
                lambda: control.create_handoff(self.state, "test", from_agent="sage", to_agent="atlas"),
                lambda: control.post_bus_message(self.state, "test", actor="atlas"),
                lambda: control.post_thread(self.state, "test", actor="atlas", target="sage"),
                lambda: control.post_thread_unlocked(self.state, "test", actor="sage", target="atlas"),
            ]
            for call in calls:
                with self.subTest(call=call):
                    before = read_events(self.state)
                    with self.assertRaisesRegex(ValueError, "retired.*atlas"):
                        call()
                    self.assertEqual(read_events(self.state), before)

    def test_cli_explicit_atlas_target_and_owner_rejected_without_append(self):
        with authority_context(self.vault, self.state):
            for args in (["thread", "post", "--title", "test", "--actor", "sage", "--to", "atlas"],
                         ["task", "create", "test", "--owner", "atlas"]):
                with self.subTest(args=args), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    self.assertNotEqual(main(["--authority-vault", str(self.vault), *args, "--state", str(self.state), "--json"]), 0)
                    self.assertEqual(read_events(self.state), [])

    def test_http_explicit_atlas_target_rejected_before_domain_append(self):
        with authority_context(self.vault, self.state):
            identity = Identity(agent_id="sage", scopes=frozenset({"control.write"}), kind="agent")
            with patch("arvyx_control.api.resolve_identity", return_value=identity):
                response = handle_api_request("POST", "/threads", {"title": "test", "target": "atlas"}, Path(self.tmp.name), self.state, idempotency_key="retired-target-test")
            self.assertEqual(response.status, 400, response.body)
            self.assertEqual(read_events(self.state), [])

    def test_http_operator_retired_owner_and_author_rejected_without_append(self):
        with authority_context(self.vault, self.state):
            identity = Identity(agent_id="operator", scopes=frozenset({"control.write"}), kind="operator")
            for route, body in (("/tasks", {"title": "test", "owner": "atlas"}),
                                ("/threads", {"title": "test", "actor": "atlas", "target": "sage"})):
                with self.subTest(route=route), patch("arvyx_control.api.resolve_identity", return_value=identity):
                    response = handle_api_request("POST", route, body, Path(self.tmp.name), self.state, idempotency_key="retired-operator-test-" + route)
                self.assertEqual(response.status, 400, response.body)
                self.assertEqual(read_events(self.state), [])
            for value in ("Atlas", " ATLAS "):
                with self.assertRaisesRegex(ValueError, "retired.*atlas"):
                    control.create_task(self.state, "test", owner=value)
            self.assertEqual(read_events(self.state), [])

    def test_four_live_identities_http_to_outbox_and_human_preserved(self):
        with authority_context(self.vault, self.state):
            for agent in ("sage", "juniper", "keeper", "harbor"):
                identity = Identity(agent_id=agent, scopes=frozenset({"control.write"}), kind="agent")
                with patch("arvyx_control.api.resolve_identity", return_value=identity):
                    response = handle_api_request("POST", "/threads", {"title": agent, "actor": "atlas", "target": "operator"}, Path(self.tmp.name), self.state, idempotency_key="bound-identity-test-" + agent)
                self.assertEqual(response.status, 201, response.body)
                result = control.post_thread(self.state, agent, actor="operator", target=agent)
                self.assertEqual(result.thread.target, agent)
            items = claim_due(self.state, worker="test", now=datetime.now(timezone.utc), deliver_after=(NOW - timedelta(days=1)).isoformat(), targets={"sage", "juniper", "keeper", "harbor"}, limit=10)
            self.assertEqual(sorted(i.target for i in items), ["harbor", "juniper", "keeper", "sage"])
            control.create_task(self.state, "future configured agent", owner="future-agent")

    def test_historical_author_survives_real_completion_and_reply_fence(self):
        with authority_context(self.vault, Path(self.tmp.name) / "seed.jsonl"):
            seed = control.post_thread(Path(self.tmp.name) / "seed.jsonl", "historical", actor="operator", target="harbor")
        with authority_context(self.vault, self.state):
            payload = {**seed.event.payload, "actor": "atlas"}
            historical = _event("thread.created", seed.thread.id, NOW.isoformat(), payload)
            _append_event_unlocked(self.state, historical)
            before = self.state.read_bytes()
            with self.assertRaisesRegex(ValueError, "retired.*atlas"):
                control.post_thread_message(self.state, seed.thread.id, "new reply", actor="atlas")
            self.assertEqual(self.state.read_bytes(), before)
            completed = control.complete_thread(self.state, seed.thread.id, actor="harbor")
            self.assertEqual(completed.thread.actor, "atlas")
            self.assertEqual(completed.thread.status, "done")
            self.assertEqual(completed.event.payload["actor"], "atlas")
            self.assertEqual(control.read_thread(self.state, seed.thread.id).thread.actor, "atlas")

    def test_skip_wire_schema_uses_existing_category_with_exact_reason_and_ids(self):
        with authority_context(self.vault, self.state):
            source = self.source("thread.done", actor="atlas", target="harbor", done_by="harbor")
            self.claim()
            skips = [e for e in read_events(self.state) if e.type == "outbox.materialization.skipped"]
            self.assertEqual(len(skips), 1)
            self.assertEqual(skips[0].payload, {
                "category": "unconfigured_route", "counts_by_target": {"atlas": 1},
                "reason": "obsolete_author", "source_event_ids": [source.id],
            })
            _append_event_unlocked(self.state, _event("outbox.materialization.skipped", "outbox_materialization", NOW.isoformat(), {"category": "unknown-future-category", "counts_by_target": {"atlas": 1}}))
            with self.assertRaisesRegex(ValueError, "malformed"):
                project_materialization_skips(self.state)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "events.jsonl"
        self.vault = Path(self.tmp.name)

    def source(self, kind, **payload):
        with authority_context(self.vault, self.state):
            event = _event(kind, "thread_legacy", NOW.isoformat(), payload)
            _append_event_unlocked(self.state, event)
            return event

    def claim(self, report=None, targets=None, dry_run=False):
        with authority_context(self.vault, self.state):
            return claim_due(
                self.state, worker="test", now=NOW,
                deliver_after=(NOW - timedelta(hours=1)).isoformat(),
                targets=targets if targets is not None else {"sage", "juniper", "keeper", "harbor"},
                materialization_report=report, dry_run=dry_run,
            )

    def test_legacy_author_completion_is_audited_skip_not_recipient(self):
        with authority_context(self.vault, self.state):
            self.source("thread.done", actor="atlas", target="harbor", done_by="harbor", status="done")
            report = {}
            self.assertEqual(self.claim(report), [])
            self.assertFalse(report["remaining"])
            self.assertEqual(report.get("skipped_unconfigured_targets", ()), ())
            self.assertEqual(project_outbox(self.state), {})
            self.assertEqual(project_materialization_skips(self.state)["counts"], {"unconfigured_route": 1})
            self.claim(report)
            self.assertEqual(project_materialization_skips(self.state)["counts"], {"unconfigured_route": 1})
            self.assertFalse(any(e.type in {"outbox.delivered", "outbox.cancelled"} for e in read_events(self.state)))

    def test_even_accidental_route_cannot_promote_obsolete_author(self):
        with authority_context(self.vault, self.state):
            self.source("thread.done", actor="atlas", target="harbor", done_by="harbor")
            self.assertEqual(self.claim(targets={"atlas", "harbor"}), [])
            self.assertEqual(project_outbox(self.state), {})

    def test_unknown_author_stays_blocking_but_does_not_starve_valid_work(self):
        with authority_context(self.vault, self.state):
            self.source("thread.done", actor="unknown-agent", target="harbor", done_by="harbor")
            self.source("thread.created", actor="atlas", target="sage", type="request")
            report = {}
            self.assertEqual([i.target for i in self.claim(report)], ["sage"])
            self.assertTrue(report["remaining"])
            self.assertEqual(report["skipped_unconfigured_targets"], ("unknown-agent",))

    def test_explicit_atlas_assignment_is_not_silently_discarded(self):
        with authority_context(self.vault, self.state):
            self.source("thread.created", actor="sage", target="atlas", type="request")
            report = {}
            self.assertEqual(self.claim(report), [])
            self.assertTrue(report["remaining"])
            self.assertEqual(report["skipped_unconfigured_targets"], ("atlas",))

    def test_current_author_notification_is_preserved(self):
        with authority_context(self.vault, self.state):
            self.source("thread.done", actor="sage", target="harbor", done_by="harbor")
            items = self.claim()
            self.assertEqual([i.target for i in items], ["sage"])
            self.assertEqual(items[0].payload["delivery_mode"], "notification")

    def test_stale_report_is_cleared_and_dry_run_does_not_append(self):
        with authority_context(self.vault, self.state):
            self.source("thread.done", actor="atlas", target="harbor", done_by="harbor")
            before = self.state.read_bytes()
            report = {"skipped_unconfigured_targets": ("atlas",)}
            self.claim(report, dry_run=True)
            self.assertEqual(report.get("skipped_unconfigured_targets", ()), ())
            self.assertFalse(report["remaining"])
            self.assertEqual(self.state.read_bytes(), before)
