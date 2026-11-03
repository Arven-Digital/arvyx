from __future__ import annotations
import contextlib
from contextlib import ExitStack

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.replica_authority import authority_context
from arvyx_control.agent_delivery import AgentRoute
from arvyx_control.cli import main as cli_main
from arvyx_control.control import (
    _append_event_unlocked,
    _event,
    _locked_state,
    list_thread_inbox,
    post_thread,
    acknowledge_thread,
    complete_thread,
)
from arvyx_control.execution import claim_execution, project_executions
from arvyx_control.outbox import claim_due, enqueue, mark_delivered
from arvyx_control.watchdog import (
    WATCHDOG_TICK_EVENT,
    probe_route,
    project_watchdog_tick,
    run_watchdog,
)

UTC = timezone.utc
T0 = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[3]
WATCHDOG_TIMER = ROOT / "deploy" / "systemd" / "arvyx-execution-watchdog.timer"
WORKER_TIMER = ROOT / "deploy" / "systemd" / "arvyx-execution-worker.timer"
DELIVERY_TIMER = ROOT / "deploy" / "systemd" / "arvyx-agent-delivery.timer"

ROUTES = {"amir": AgentRoute("amir", "hermes-webhook", "WD_URL", "WD_SECRET")}
ENV_OK = {"WD_URL": "https://runtime.invalid/hook", "WD_SECRET": "secret-material"}
ENV_BROKEN: dict[str, str] = {}


class WatchdogTests(unittest.TestCase):
    def test_watchdog_timer_has_a_first_activation_trigger(self) -> None:
        if not WATCHDOG_TIMER.is_file():
            self.skipTest('deployment units are not part of this checkout')
        timer = WATCHDOG_TIMER.read_text()
        self.assertIn("OnActiveSec=60s", timer)
        self.assertIn("OnUnitActiveSec=60s", timer)

    def test_execution_worker_timer_has_a_first_activation_trigger(self) -> None:
        if not WORKER_TIMER.is_file():
            self.skipTest('deployment units are not part of this checkout')
        timer = WORKER_TIMER.read_text()
        self.assertIn("OnActiveSec=5s", timer)
        self.assertIn("OnUnitActiveSec=5s", timer)

    def test_agent_delivery_timer_has_a_first_activation_trigger(self) -> None:
        if not DELIVERY_TIMER.is_file():
            self.skipTest('deployment units are not part of this checkout')
        timer = DELIVERY_TIMER.read_text()
        self.assertIn("OnActiveSec=10s", timer)
        self.assertIn("OnUnitActiveSec=10s", timer)

    def _acked(self, state: Path, *, target: str = "amir") -> str:
        with patch(
            "arvyx_control.control._now",
            side_effect=["2026-08-20T11:59:00Z", "2026-08-20T12:00:00Z"],
        ):
            thread = post_thread(
                state, title="durable work", actor="esme", target=target,
                thread_type="ask", actor_identity_bound=True,
            )
            acknowledge_thread(state, thread.thread.id, actor=target, actor_identity_bound=True)
        return thread.thread.id

    def _dead_letter(self, state: Path) -> str:
        """Drive one execution to dead_lettered through real lease mechanics."""
        self._acked(state)
        first = claim_execution(
            state, worker="prod", execution_capable_targets={"amir"},
            now=T0, lease_seconds=1, max_attempts=1,
        )
        assert first is not None
        # Expiry at +1s plus backoff(1)=15s; the next eligible claim exceeds
        # max_attempts and dead-letters.
        gone = claim_execution(
            state, worker="prod", execution_capable_targets={"amir"},
            now=T0 + timedelta(seconds=16), lease_seconds=1, max_attempts=1,
        )
        assert gone is None
        assert project_executions(state)[first.id].status == "dead_lettered"
        return first.id

    def test_ack_without_execution_is_materialized_exactly_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                first = run_watchdog(
                    state, routes=ROUTES, now=T0, environ=ENV_OK, escalate=False,
                )
                second = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=60), environ=ENV_OK, escalate=False,
                )
                self.assertEqual(first["counts"]["materialized"], 1)
                self.assertEqual(second["counts"]["materialized"], 0)
                self.assertEqual(len(project_executions(state)), 1)

    def test_dead_letter_replays_once_then_holds_and_escalates_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution_id = self._dead_letter(state)

                first = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=17), environ=ENV_OK,
                )
                self.assertEqual(first["replayed"], [execution_id])
                self.assertEqual(first["held"], [])
                replayed = project_executions(state)[execution_id]
                self.assertEqual(replayed.status, "pending")
                self.assertEqual(replayed.attempts, 0)

                # Same lineage dead-letters again: fresh claim at +20s (lease 1s,
                # expiry +21s), reclaim eligibility +36s, budget exhausted at +37s.
                claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=20), lease_seconds=1, max_attempts=1,
                )
                claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=37), lease_seconds=1, max_attempts=1,
                )
                self.assertEqual(project_executions(state)[execution_id].status, "dead_lettered")

                second = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=40), environ=ENV_OK,
                )
                self.assertEqual(second["held"], [execution_id])
                self.assertEqual(second["escalated"], [execution_id])
                held = project_executions(state)[execution_id]
                self.assertEqual(held.status, "held")
                self.assertIn("replay budget exhausted", held.hold_reason)

                third = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=100), environ=ENV_OK,
                )
                self.assertEqual(third["counts"]["held"], 0)
                self.assertEqual(third["counts"]["escalated"], 0)
                titles = [
                    thread.title for thread in list_thread_inbox(state=state).threads
                    if "[watchdog]" in thread.title
                ]
                self.assertEqual(len(titles), 1)
                self.assertIn(execution_id, titles[0])

    def _dead_letter_twice_then_watch(self, state: Path, execution_id: str, **kwargs: object) -> dict[str, object]:
        run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=17), environ=ENV_OK, **kwargs)
        claim_execution(state, worker="prod", execution_capable_targets={"amir"},
                        now=T0 + timedelta(seconds=20), lease_seconds=1, max_attempts=1)
        claim_execution(state, worker="prod", execution_capable_targets={"amir"},
                        now=T0 + timedelta(seconds=37), lease_seconds=1, max_attempts=1)
        return run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=40), environ=ENV_OK, **kwargs)

    def test_escalation_reaches_the_configured_agent_with_guidance_and_dedupes(self) -> None:
        # "operator" has no delivery route, so an escalation posted there never reached anyone.
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution_id = self._dead_letter(state)
                second = self._dead_letter_twice_then_watch(state, execution_id, escalation_target="esme")
                self.assertEqual(second["escalated"], [execution_id])
                pages = [t for t in list_thread_inbox(state=state).threads if "[watchdog]" in t.title]
                self.assertEqual([(t.target, t.actor) for t in pages], [("esme", "arvyx-watchdog")])
                self.assertIn("tell the operator", pages[0].body)
                third = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=100), environ=ENV_OK,
                                     escalation_target="esme")
                self.assertEqual(third["counts"]["escalated"], 0)

    def test_escalation_about_a_watchdog_thread_stays_on_operator(self) -> None:
        # Loop guard: a page to an agent wakes an execution; if that one is held, paging the
        # same agent again would loop. The watchdog's own threads escalate to operator only.
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                # Only a pre-provenance page (created before the cutoff with no
                # actor_identity_bound field at all) can still wake an execution,
                # through its target's identity-bound ACK. Current watchdog pages
                # are explicitly unbound and never materialize work, so emulate
                # the historical producer's creation payload exactly.
                from arvyx_control import control as control_module
                current_payload = control_module._thread_event_payload

                def historical_payload(thread):
                    payload = current_payload(thread)
                    payload.pop("actor_identity_bound", None)
                    return payload

                with patch("arvyx_control.control._now",
                           side_effect=["2026-08-20T11:59:00Z", "2026-08-20T12:00:00Z"]):
                    with patch.object(control_module, "_thread_event_payload", historical_payload):
                        page = post_thread(state, title="[watchdog] earlier page", actor="arvyx-watchdog",
                                           target="amir", thread_type="blocker")
                    self.assertNotIn("actor_identity_bound", page.event.payload)
                    acknowledge_thread(state, page.thread.id, actor="amir", actor_identity_bound=True)
                first = claim_execution(state, worker="prod", execution_capable_targets={"amir"},
                                        now=T0, lease_seconds=1, max_attempts=1)
                assert first is not None
                claim_execution(state, worker="prod", execution_capable_targets={"amir"},
                                now=T0 + timedelta(seconds=16), lease_seconds=1, max_attempts=1)
                self.assertEqual(project_executions(state)[first.id].subject_id, page.thread.id)
                second = self._dead_letter_twice_then_watch(state, first.id, escalation_target="amir")
                self.assertEqual(second["escalated"], [first.id])
                escalation = [t for t in list_thread_inbox(state=state).threads
                              if first.id in t.title]
                self.assertEqual([t.target for t in escalation], ["operator"])

    def test_receipt_waiver_baselines_exactly_the_listed_gaps(self) -> None:
        from arvyx_control.watchdog import receipt_waiver_candidates, waive_receipts
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                run_watchdog(state, routes=ROUTES, now=T0, environ=ENV_OK, escalate=False)
                ids = []
                for index in range(2):
                    item = enqueue(state, subject_id=f"thread_{index}", target="amir",
                                   payload={"source_event_id": f"event_{index}", "source_event_type": "thread.created"},
                                   now=T0 + timedelta(seconds=1))
                    delivery_claims = claim_due(state, worker="dispatch", now=T0 + timedelta(seconds=1))
                    mark_delivered(state, outbox_id=item.id, worker="dispatch", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), now=T0 + timedelta(seconds=1))
                    ids.append(item.id)
                before = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=1001), environ=ENV_OK,
                                      escalate=False)
                self.assertEqual(sorted(before["delivered_without_receipt"]), sorted(ids))
                listed = receipt_waiver_candidates(state, before=datetime.now(UTC))
                self.assertEqual(sorted(row["outbox_id"] for row in listed), sorted(ids))

                with self.assertRaisesRegex(ValueError, "reason"):
                    waive_receipts(state, outbox_ids=ids[:1], reason="  ")
                with self.assertRaisesRegex(ValueError, "not a current receipt gap"):
                    waive_receipts(state, outbox_ids=[ids[0], "outbox_unknown"], reason="history")
                waive_receipts(state, outbox_ids=ids[:1], reason="historical agent miss, 2026-09-24")
                with self.assertRaisesRegex(ValueError, "already waived"):
                    waive_receipts(state, outbox_ids=ids[:1], reason="again")

                after = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=1061), environ=ENV_OK,
                                     escalate=False)
                self.assertEqual(after["delivered_without_receipt"], [ids[1]])
                self.assertEqual(after["counts"]["delivered_without_receipt_baselined"],
                                 before["counts"]["delivered_without_receipt_baselined"] + 1)
                self.assertEqual(project_watchdog_tick(state)["receipt_waived_count"], 1)

    def test_cli_receipt_waiver_is_a_dry_run_unless_applied(self) -> None:
        import contextlib, io
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                run_watchdog(state, routes=ROUTES, now=T0, environ=ENV_OK, escalate=False)
                item = enqueue(state, subject_id="thread_x", target="amir",
                               payload={"source_event_id": "event_1", "source_event_type": "thread.created"},
                               now=T0 + timedelta(seconds=1))
                delivery_claims = claim_due(state, worker="dispatch", now=T0 + timedelta(seconds=1))
                mark_delivered(state, outbox_id=item.id, worker="dispatch", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), now=T0 + timedelta(seconds=1))
                size = state.stat().st_size
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(cli_main(["--authority-vault", str(vault), *["receipt-waiver", "--state", str(state), "--before",
                                               "2026-12-31T00:00:00Z", "--json"]]), 0)
                dry = json.loads(out.getvalue())
                self.assertEqual((dry["applied"], dry["count"]), (False, 1))
                self.assertEqual(state.stat().st_size, size)
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(cli_main(["--authority-vault", str(vault), *["receipt-waiver", "--state", str(state), "--before",
                                               "2026-12-31T00:00:00Z", "--apply", "--json"]]), 1)  # no reason
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(cli_main(["--authority-vault", str(vault), *["receipt-waiver", "--state", str(state), "--before",
                                               "2026-12-31T00:00:00Z", "--apply", "--reason", "history", "--json"]]), 0)
                self.assertEqual(json.loads(out.getvalue())["outbox_ids"], [item.id])

    @staticmethod
    def _tick_count(state: Path) -> int:
        from arvyx_control.control import read_events
        return sum(event.type == WATCHDOG_TICK_EVENT for event in read_events(state))

    def test_unchanged_tick_is_coalesced_until_the_heartbeat(self) -> None:
        # Identical ticks were ~40% of the production log's growth.
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                first = run_watchdog(state, routes=ROUTES, now=T0, environ=ENV_OK, escalate=False)
                self.assertTrue(first["tick_recorded"])
                for minute in range(1, 10):
                    quiet = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(minutes=minute),
                                         environ=ENV_OK, escalate=False)
                    self.assertFalse(quiet["tick_recorded"])
                self.assertEqual(self._tick_count(state), 1)
                beat = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=600), environ=ENV_OK, escalate=False)
                self.assertTrue(beat["tick_recorded"])
                self.assertEqual(self._tick_count(state), 2)
                # The receipt boundary is still the first tick's, not the heartbeat's.
                self.assertEqual(project_watchdog_tick(state)["receipt_enforcement_since"], "2026-08-20T12:00:00Z")

    def test_a_changed_tick_is_recorded_at_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                run_watchdog(state, routes=ROUTES, now=T0, environ=ENV_OK, escalate=False)
                broken = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=60), environ=ENV_BROKEN,
                                      escalate=False)
                self.assertTrue(broken["tick_recorded"])
                self.assertEqual(project_watchdog_tick(state)["attention"], ["unreachable_targets"])
                healed = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=120), environ=ENV_OK,
                                      escalate=False)
                self.assertTrue(healed["tick_recorded"])
                self.assertEqual(project_watchdog_tick(state)["attention"], [])
                self.assertNotIn("signature", project_watchdog_tick(state))

    def test_fleet_verdict_flags_a_stopped_watchdog(self) -> None:
        from arvyx_control.api import _fleet_verdict
        from arvyx_control.watchdog import WATCHDOG_TICK_STALE_SECONDS
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                run_watchdog(state, routes=ROUTES, now=T0, environ=ENV_OK, escalate=False)
                fresh = _fleet_verdict(state, delivery={"ok": True}, continuation={}, delivery_routes=None,
                                       now=T0 + timedelta(seconds=WATCHDOG_TICK_STALE_SECONDS - 1))
                stale = _fleet_verdict(state, delivery={"ok": True}, continuation={}, delivery_routes=None,
                                       now=T0 + timedelta(seconds=WATCHDOG_TICK_STALE_SECONDS + 1))
                self.assertNotIn("watchdog_stale", fresh["amber"])
                self.assertIn("watchdog_stale", stale["amber"])

    def test_abandon_retires_an_acked_thread_without_claiming_done(self) -> None:
        from arvyx_control.retirement import abandon_stale_thread
        from arvyx_control.control import read_events
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread_id = self._acked(state)
                size = state.stat().st_size
                dry = abandon_stale_thread(state, thread_id=thread_id, reason="stale canary",
                                           approval_reference="Owner, 2026-09-25")
                self.assertTrue(dry["dry_run"])
                self.assertEqual(state.stat().st_size, size)  # a dry run appends nothing
                done = abandon_stale_thread(state, thread_id=thread_id, reason="stale canary",
                                            approval_reference="Owner, 2026-09-25", dry_run=False)
                self.assertTrue(done["changed"])
                thread = {t.id: t for t in list_thread_inbox(state=state).threads}[thread_id]
                self.assertEqual(thread.status, "retired")
                self.assertEqual(thread.retirement["operation"], "abandon")
                self.assertEqual(thread.retirement["prior_status"], "acked")
                self.assertEqual(thread.done_by, "")  # never recorded as work done
                self.assertFalse(any(e.type == "thread.done" for e in read_events(state)))
                with self.assertRaisesRegex(ValueError, "only open or acknowledged"):
                    abandon_stale_thread(state, thread_id=thread_id, reason="again", approval_reference="x",
                                         dry_run=False)

    def test_abandon_refuses_a_thread_with_live_execution_work(self) -> None:
        from arvyx_control.retirement import abandon_stale_thread
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution_id = self._dead_letter(state)
                subject = project_executions(state)[execution_id].subject_id
                with self.assertRaisesRegex(ValueError, "live execution work"):
                    abandon_stale_thread(state, thread_id=subject, reason="stale", approval_reference="Owner",
                                         dry_run=False)
                for reason, ref in (("", "Owner"), ("stale", "")):
                    with self.assertRaisesRegex(ValueError, "reason|approval"):
                        abandon_stale_thread(state, thread_id=subject, reason=reason, approval_reference=ref)

    def test_cli_thread_abandon_is_a_dry_run_unless_applied(self) -> None:
        import contextlib, io
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread_id = self._acked(state)
                base = ["thread-abandon", thread_id, "--state", str(state), "--reason", "stale",
                        "--approval-reference", "Owner, 2026-09-25", "--json"]
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    self.assertEqual(cli_main(["--authority-vault", str(vault), *base]), 0)
                self.assertTrue(json.loads(out.getvalue())["dry_run"])
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli_main(["--authority-vault", str(vault), *base + ["--apply"]]), 0)
                self.assertEqual({t.id: t for t in list_thread_inbox(state=state).threads}[thread_id].status, "retired")

    def test_stale_acked_thread_is_paged_once_and_again_after_fresh_progress(self) -> None:
        # Owner's rule (2026-09-25): nothing stays stale in AMC; it is solved or paged at once.
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread_id = self._acked(state)
                fresh = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(minutes=30), environ=ENV_OK,
                                     escalation_target="esme")
                self.assertEqual(fresh["counts"]["stale_work"], 0)
                late = T0 + timedelta(hours=3)
                first = run_watchdog(state, routes=ROUTES, now=late, environ=ENV_OK, escalation_target="esme")
                self.assertIn("stale_work", first["attention"])
                pages = [t for t in list_thread_inbox(state=state).threads if t.title.startswith("watchdog stale thread:")]
                self.assertEqual([(t.target, thread_id in t.title) for t in pages], [("esme", True)])
                again = run_watchdog(state, routes=ROUTES, now=late + timedelta(minutes=1), environ=ENV_OK,
                                     escalation_target="esme")
                self.assertEqual(again["counts"]["stale_paged"], 0)

    def test_a_stale_watchdog_page_is_escalated_to_operator_never_to_itself(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with patch("arvyx_control.control._now", side_effect=["2026-08-20T11:59:00Z", "2026-08-20T12:00:00Z"]):
                    page = post_thread(state, title="watchdog stale thread: thread_x since t", actor="arvyx-watchdog",
                                       target="amir", thread_type="blocker")
                    acknowledge_thread(state, page.thread.id, actor="amir", actor_identity_bound=True)
                run_watchdog(state, routes=ROUTES, now=T0 + timedelta(hours=3), environ=ENV_OK, escalation_target="amir")
                about_page = [t for t in list_thread_inbox(state=state).threads
                              if t.title.startswith("watchdog stale thread:") and page.thread.id in t.title]
                self.assertEqual([t.target for t in about_page], ["operator"])

    def test_ambiguous_delivery_is_paged_until_reconciled(self) -> None:
        from arvyx_control.outbox import mark_delivery_ambiguous
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(state, subject_id="session_return_1", target="amir",
                               payload={"delivery_mode": "session_return"}, now=T0)
                delivery_claims = claim_due(state, worker="dispatch", now=T0)
                mark_delivery_ambiguous(state, outbox_id=item.id, worker="dispatch", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), detail="no receipt", now=T0)
                report = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(minutes=5), environ=ENV_OK,
                                      escalation_target="esme")
                self.assertIn("stale_work", report["attention"])
                pages = [t for t in list_thread_inbox(state=state).threads if item.id in t.title]
                self.assertEqual([(t.title.split(":")[0], t.target) for t in pages], [("watchdog ambiguous delivery", "esme")])

    def test_an_agent_reply_that_can_never_reach_the_owner_is_refused(self) -> None:
        # Regression (2026-09-25): Nova's reply to Uma sat unread because Uma's execution for that
        # thread had been closed; a reply wakes nobody by itself.
        from arvyx_control.control import post_thread_message
        from arvyx_control.execution import close_execution
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                live = self._acked(state)
                claim_execution(state, worker="prod", execution_capable_targets={"amir"}, now=T0, lease_seconds=60)
                ok = post_thread_message(state, live, "please also add tests", actor="esme",
                                         idempotency_key="reply-to-live-work-0001", require_live_recipient=True)
                self.assertEqual(ok.thread.id, live)

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution_id = self._dead_letter(state)
                close_execution(state, execution_id=execution_id, resolution_category="no_longer_actionable",
                                reason="obsolete", closed_by="operator")
                subject = project_executions(state)[execution_id].subject_id
                with self.assertRaisesRegex(ValueError, "would never reach them"):
                    post_thread_message(state, subject, "please resend it now", actor="esme",
                                        idempotency_key="reply-to-closed-work-0001", require_live_recipient=True)
                # The owner's own note and an operator record are still accepted.
                post_thread_message(state, subject, "closing note", actor="amir",
                                    idempotency_key="owner-note-closed-work-01", require_live_recipient=True)
                post_thread_message(state, subject, "operator record", actor="operator",
                                    idempotency_key="operator-note-closed-work")

    def test_receipt_waiver_lists_only_gaps_the_watchdog_reports(self) -> None:
        from arvyx_control.watchdog import receipt_waiver_candidates
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                early = enqueue(state, subject_id="thread_early", target="amir",
                                payload={"source_event_id": "event_e", "source_event_type": "thread.created"},
                                now=T0 - timedelta(minutes=5))
                delivery_claims = claim_due(state, worker="dispatch", now=T0 - timedelta(minutes=5))
                mark_delivered(state, outbox_id=early.id, worker="dispatch", claim_attempts=next(c.attempts for c in delivery_claims if c.id == early.id), now=T0 - timedelta(minutes=5))
                run_watchdog(state, routes=ROUTES, now=T0, environ=ENV_OK, escalate=False)  # boundary = T0
                late = enqueue(state, subject_id="thread_late", target="amir",
                               payload={"source_event_id": "event_l", "source_event_type": "thread.created"},
                               now=T0 + timedelta(seconds=1))
                delivery_claims = claim_due(state, worker="dispatch", now=T0 + timedelta(seconds=1))
                mark_delivered(state, outbox_id=late.id, worker="dispatch", claim_attempts=next(c.attempts for c in delivery_claims if c.id == late.id), now=T0 + timedelta(seconds=1))
                listed = [row["outbox_id"] for row in receipt_waiver_candidates(state, before=datetime.now(UTC))]
                self.assertEqual(listed, [late.id])  # the pre-boundary one is already baselined

    def test_unreachable_target_defers_replay_instead_of_blind_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution_id = self._dead_letter(state)
                report = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=17),
                    environ=ENV_BROKEN, escalate=False,
                )
                self.assertEqual(report["deferred_unreachable"], [execution_id])
                self.assertEqual(report["replayed"], [])
                self.assertIn("unreachable_targets", report["attention"])
                self.assertEqual(project_executions(state)[execution_id].status, "dead_lettered")

    def test_delivered_without_receipt_is_detected_after_enforcement_begins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                baseline = run_watchdog(
                    state, routes=ROUTES, now=T0,
                    environ=ENV_OK, escalate=False,
                )
                self.assertEqual(baseline["delivered_without_receipt"], [])
                item = enqueue(
                    state, subject_id="thread_x", target="amir",
                    payload={"source_event_id": "event_1", "source_event_type": "thread.created"},
                    now=T0 + timedelta(seconds=1),
                )
                delivery_claims = claim_due(state, worker="dispatch", now=T0 + timedelta(seconds=1))
                mark_delivered(
                    state, outbox_id=item.id, worker="dispatch", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id),
                    now=T0 + timedelta(seconds=1),
                )
                report = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=1001),
                    environ=ENV_OK, escalate=False,
                )
                self.assertIn(item.id, report["delivered_without_receipt"])
                self.assertIn("delivered_without_receipt", report["attention"])

    def _delivered_after_baseline(self, state: Path, *, payload: dict, provider_receipt: str = "") -> str:
        run_watchdog(state, routes=ROUTES, now=T0, environ=ENV_OK, escalate=False)
        item = enqueue(
            state, subject_id="session_return_x", target="amir",
            payload={"source_event_id": "event_sr", "source_event_type": "execution.session_return.requested", **payload},
            now=T0 + timedelta(seconds=1),
        )
        delivery_claims = claim_due(state, worker="dispatch", now=T0 + timedelta(seconds=1))
        if payload.get("delivery_mode") == "session_return":
            # Production finalizes a session return only after re-validating live
            # execution authority (mark_delivered -> classify_session_return_dispatch);
            # without a live execution it would fence to ambiguous_delivery. Append the
            # finalized event that path writes, so the watchdog sees production's shape.
            from dataclasses import replace
            from arvyx_control.outbox import project_outbox
            stamp = "2026-08-20T12:00:01Z"
            current = project_outbox(state)[item.id]
            finalized = replace(
                current, status="delivered", updated_at=stamp, delivered_at=stamp,
                lease_owner="", lease_expires_at="", provider_receipt=provider_receipt,
            )
            with _locked_state(state):
                _append_event_unlocked(state, _event("outbox.delivered", item.id, stamp, finalized.to_dict()))
        else:
            mark_delivered(
                state, outbox_id=item.id, worker="dispatch", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id),
                now=T0 + timedelta(seconds=1), provider_receipt=provider_receipt,
            )
        return item.id

    def test_provider_receipted_session_return_is_not_a_missing_receipt(self) -> None:
        # A human-facing session return is proven by the provider's native message id.
        # No agent writes an outbox receipt for it, so counting it as receipt-less made
        # the watchdog permanently non-green on production (2026-09-24).
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item_id = self._delivered_after_baseline(
                    state, payload={"delivery_mode": "session_return"}, provider_receipt="57539",
                )
                report = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=1001), environ=ENV_OK, escalate=False,
                )
                self.assertNotIn(item_id, report["delivered_without_receipt"])
                self.assertNotIn("delivered_without_receipt", report["attention"])

    def test_session_return_without_provider_receipt_still_alerts(self) -> None:
        # Fail closed: a "delivered" human send with no provider receipt is exactly the
        # evidence gap the class exists to surface.
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item_id = self._delivered_after_baseline(state, payload={"delivery_mode": "session_return"})
                report = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=1001), environ=ENV_OK, escalate=False,
                )
                self.assertIn(item_id, report["delivered_without_receipt"])
                self.assertIn("delivered_without_receipt", report["attention"])

    def test_session_return_receipt_wake_is_excluded_like_execution_wakes(self) -> None:
        # The receipt-wake's evidence is the agent's identity-bound terminal on the
        # subject; a silent agent is caught by the held/acked-without-execution classes.
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item_id = self._delivered_after_baseline(
                    state, payload={"delivery_mode": "session_return_receipt"},
                )
                report = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=1001), environ=ENV_OK, escalate=False,
                )
                self.assertNotIn(item_id, report["delivered_without_receipt"])

    def test_first_tick_baselines_preexisting_deliveries_without_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                item = enqueue(
                    state, subject_id="thread_legacy", target="amir",
                    payload={"source_event_id": "event_legacy", "source_event_type": "thread.created"},
                    now=T0,
                )
                delivery_claims = claim_due(state, worker="dispatch", now=T0)
                mark_delivered(state, outbox_id=item.id, worker="dispatch", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), now=T0)
                report = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=1000),
                    environ=ENV_OK, escalate=False,
                )
                self.assertNotIn(item.id, report["delivered_without_receipt"])
                self.assertNotIn("delivered_without_receipt", report["attention"])
                self.assertEqual(report["counts"]["delivered_without_receipt_baselined"], 1)
                tick = project_watchdog_tick(state)
                self.assertEqual(tick["receipt_enforcement_since"], "2026-08-20T12:16:40Z")

    def test_old_schema_tick_migrates_boundary_from_last_tick_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                old_tick_at = "2026-08-20T12:05:00Z"
                with _locked_state(state):
                    _append_event_unlocked(
                        state,
                        _event(
                            WATCHDOG_TICK_EVENT,
                            "watchdog",
                            old_tick_at,
                            {"worker": "old-watchdog", "attention": [], "counts": {}},
                        ),
                    )
                run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(minutes=10),
                    environ=ENV_OK, escalate=False,
                )
                tick = project_watchdog_tick(state)
                self.assertEqual(tick["receipt_enforcement_since"], old_tick_at)

    def test_explicit_boundary_survives_a_later_old_binary_tick(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                run_watchdog(
                    state, routes=ROUTES, now=T0,
                    environ=ENV_OK, escalate=False,
                )
                with _locked_state(state):
                    _append_event_unlocked(
                        state,
                        _event(
                            WATCHDOG_TICK_EVENT,
                            "watchdog",
                            "2026-08-20T12:01:00Z",
                            {"worker": "rolled-back-watchdog", "attention": [], "counts": {}},
                        ),
                    )
                run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(minutes=2),
                    environ=ENV_OK, escalate=False,
                )
                tick = project_watchdog_tick(state)
                self.assertEqual(tick["receipt_enforcement_since"], "2026-08-20T12:00:00Z")

    def test_malformed_boundary_fails_loud_without_wedging_watchdog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with _locked_state(state):
                    _append_event_unlocked(
                        state,
                        _event(
                            WATCHDOG_TICK_EVENT,
                            "watchdog",
                            "2026-08-20T12:00:00Z",
                            {
                                "worker": "broken-watchdog",
                                "attention": [],
                                "counts": {},
                                "receipt_enforcement_since": "not-a-timestamp",
                            },
                        ),
                    )
                item = enqueue(
                    state, subject_id="thread_gap", target="amir",
                    payload={"source_event_id": "event_gap", "source_event_type": "thread.created"},
                    now=T0,
                )
                delivery_claims = claim_due(state, worker="dispatch", now=T0)
                mark_delivered(state, outbox_id=item.id, worker="dispatch", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), now=T0)
                report = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=1000),
                    environ=ENV_OK, escalate=False,
                )
                self.assertIn("invalid_receipt_enforcement_boundary", report["attention"])
                self.assertIn(item.id, report["delivered_without_receipt"])
                recovered = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=1001),
                    environ=ENV_OK, escalate=False,
                )
                self.assertNotIn("invalid_receipt_enforcement_boundary", recovered["attention"])

    def test_naive_boundary_is_rejected_without_timezone_comparison_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with _locked_state(state):
                    _append_event_unlocked(
                        state,
                        _event(
                            WATCHDOG_TICK_EVENT,
                            "watchdog",
                            "2026-08-20T12:00:00Z",
                            {
                                "worker": "naive-watchdog",
                                "attention": [],
                                "counts": {},
                                "receipt_enforcement_since": "2026-08-20T12:00:00",
                            },
                        ),
                    )
                report = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=1),
                    environ=ENV_OK, escalate=False,
                )
                self.assertIn("invalid_receipt_enforcement_boundary", report["attention"])

    def test_malformed_old_schema_tick_timestamp_falls_back_loudly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with _locked_state(state):
                    _append_event_unlocked(
                        state,
                        _event(
                            WATCHDOG_TICK_EVENT,
                            "watchdog",
                            "not-a-timestamp",
                            {"worker": "old-watchdog", "attention": [], "counts": {}},
                        ),
                    )
                report = run_watchdog(
                    state, routes=ROUTES, now=T0,
                    environ=ENV_OK, escalate=False,
                )
                self.assertIn("invalid_receipt_enforcement_boundary", report["attention"])
                tick = project_watchdog_tick(state)
                self.assertEqual(tick["receipt_enforcement_since"], "1970-01-01T00:00:00Z")

    def test_stale_heartbeat_detected_without_duplicate_activation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"},
                    now=T0, lease_seconds=600,
                )
                report = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=400),
                    environ=ENV_OK, escalate=False,
                )
                self.assertIn(execution.id, report["health"]["leased_without_recent_heartbeat"])
                self.assertIn("leased_without_recent_heartbeat", report["attention"])
                self.assertEqual(report["counts"]["replayed"], 0)
                self.assertEqual(report["counts"]["held"], 0)
                # The live lease stays exclusive: no duplicate claim happens after
                # the watchdog tick.
                self.assertIsNone(claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=410), lease_seconds=600,
                ))

    def test_attempt_inside_first_heartbeat_window_is_not_reported_stale(self) -> None:
        from arvyx_control.execution import heartbeat_execution

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self._acked(state)
                execution = claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"},
                    now=T0, lease_seconds=120,
                )
                heartbeat_execution(
                    state, execution_id=execution.id, attempt_id=execution.attempt_id,
                    worker="prod", now=T0, lease_seconds=120, first_heartbeat_seconds=600,
                )
                starting = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=400),
                    environ=ENV_OK, escalate=False,
                )
                self.assertEqual(starting["health"]["leased_without_recent_heartbeat"], [])
                self.assertNotIn("leased_without_recent_heartbeat", starting["attention"])
                closed = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=600),
                    environ=ENV_OK, escalate=False,
                )
                self.assertEqual(closed["health"]["leased_without_recent_heartbeat"], [execution.id])
                self.assertIn("leased_without_recent_heartbeat", closed["attention"])

    def test_authoritative_terminal_still_completes_held_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                subject = self._acked(state)
                claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"},
                    now=T0, lease_seconds=1, max_attempts=1,
                )
                claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=16), lease_seconds=1, max_attempts=1,
                )
                run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=17), environ=ENV_OK)
                run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=60), environ=ENV_OK)
                # After hold, a real target-authored DONE still reconciles.
                with patch("arvyx_control.control._now", return_value="2026-08-20T12:02:00Z"):
                    complete_thread(state, subject, actor="amir", actor_identity_bound=True)
                report = run_watchdog(
                    state, routes=ROUTES, now=T0 + timedelta(seconds=130), environ=ENV_OK,
                )
                execution = next(iter(project_executions(state).values()))
                self.assertEqual(execution.status, "completed")
                self.assertNotIn("held_executions", report["attention"])

    def test_probe_route_reports_tcp_reachability_without_secrets(self) -> None:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            env = {"WD_URL": f"http://127.0.0.1:{port}/hook", "WD_SECRET": "secret-material"}
            ok, detail = probe_route(ROUTES["amir"], environ=env)
            self.assertTrue(ok)
            self.assertNotIn(str(port), "")  # sanity
            self.assertNotIn("secret-material", detail)
            self.assertNotIn("/hook", detail)
        finally:
            listener.close()
        env_closed = {"WD_URL": f"http://127.0.0.1:{port}/hook", "WD_SECRET": "secret-material"}
        ok, detail = probe_route(ROUTES["amir"], environ=env_closed)
        self.assertFalse(ok)
        self.assertNotIn("secret-material", detail)

    def test_watchdog_cli_loads_routes_and_runs_real_command_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "events.jsonl"
            routes = root / "routes.json"
            routes.write_text(json.dumps({"routes": {
                "amir": {
                    "runtime": "hermes-webhook",
                    "url_env": "WD_URL",
                    "credential_env": "WD_SECRET",
                    "timeout_seconds": 10,
                }
            }}))
            with patch.dict("os.environ", ENV_OK, clear=False):
                result = cli_main([
                    "--authority-vault", str(root / "vault"),
                    "execution", "watchdog",
                    "--state", str(state),
                    "--routes", str(routes),
                    "--no-escalate",
                    "--json",
                ])
            self.assertEqual(result, 0)
            self.assertTrue(project_watchdog_tick(state)["initialized"])

    def test_watchdog_tick_is_projected_for_health_surfaces(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                self.assertFalse(project_watchdog_tick(state)["initialized"])
                run_watchdog(state, routes=ROUTES, now=T0, environ=ENV_OK, escalate=False)
                tick = project_watchdog_tick(state)
                self.assertTrue(tick["initialized"])
                self.assertEqual(tick["worker"], "arvyx-watchdog")
                self.assertIn("counts", tick)

    def _blocked_hold(self, state: Path) -> str:
        """Drive one execution into the worker's repeated-BLOCKED HOLD."""
        from arvyx_control.control import post_thread_message

        thread_id = self._acked(state)
        first = claim_execution(
            state, worker="prod", execution_capable_targets={"amir"}, now=T0, lease_seconds=1,
        )
        post_thread_message(state, thread_id, "BLOCKED: no authority over odin's attempt", actor="amir")
        claim_execution(
            state, worker="prod", execution_capable_targets={"amir"},
            now=T0 + timedelta(seconds=20), lease_seconds=1,
        )
        post_thread_message(state, thread_id, "BLOCKED: no authority over odin's attempt", actor="amir")
        self.assertIsNone(claim_execution(
            state, worker="prod", execution_capable_targets={"amir"},
            now=T0 + timedelta(seconds=60), lease_seconds=1,
        ))
        self.assertEqual(project_executions(state)[first.id].status, "held")
        return first.id

    def test_an_agent_same_title_thread_cannot_silence_the_operator_escalation(self) -> None:
        """Audit 2026-09-11: dedup matched on title only, so any agent could
        pre-post the escalation title and the operator was never paged."""
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution_id = self._blocked_hold(state)
                title = f"[watchdog] execution {execution_id} held for operator"
                # Identity-bound agent threads with the exact title, to a peer and
                # to the operator, appended after the HOLD.
                post_thread(state, title=title, actor="amir", target="odin", thread_type="status",
                            actor_identity_bound=True)
                post_thread(state, title=title, actor="amir", target="operator", thread_type="status",
                            actor_identity_bound=True)
                result = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=61), environ=ENV_OK)
                self.assertEqual(result["escalated"], [execution_id])
                escalations = [
                    thread for thread in list_thread_inbox(state=state).threads
                    if thread.title == title and thread.actor == "arvyx-watchdog"
                ]
                self.assertEqual(len(escalations), 1)
                self.assertEqual(escalations[0].target, "operator")
                # The watchdog's own escalation still dedupes the next tick.
                again = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=121), environ=ENV_OK)
                self.assertEqual(again["escalated"], [])

    def test_worker_blocked_hold_is_escalated_once_even_after_the_thread_closes(self) -> None:
        from arvyx_control.execution import replay_execution

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                execution_id = self._blocked_hold(state)
                first = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=61), environ=ENV_OK)
                self.assertEqual(first["escalated"], [execution_id])
                self.assertEqual(first["held"], [])
                self.assertIn("held_executions", first["attention"])
                escalation = next(
                    thread for thread in list_thread_inbox(state=state).threads
                    if thread.title == f"[watchdog] execution {execution_id} held for operator"
                )
                self.assertEqual(escalation.target, "operator")
                self.assertIn("BLOCKED", escalation.body)
                # The operator closes the escalation but leaves the HOLD in place:
                # later ticks must not re-post it every minute.
                complete_thread(state, escalation.id, actor="operator")
                second = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=121), environ=ENV_OK)
                self.assertEqual(second["escalated"], [])
                # A fresh HOLD after an operator replay is a new escalation.
                replay_execution(state, execution_id=execution_id, replayed_by="operator")
                thread_id = project_executions(state)[execution_id].subject_id
                from arvyx_control.control import post_thread_message

                claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=130), lease_seconds=1,
                )
                post_thread_message(state, thread_id, "BLOCKED: still no authority", actor="amir")
                claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=150), lease_seconds=1,
                )
                post_thread_message(state, thread_id, "BLOCKED: still no authority", actor="amir")
                claim_execution(
                    state, worker="prod", execution_capable_targets={"amir"},
                    now=T0 + timedelta(seconds=190), lease_seconds=1,
                )
                self.assertEqual(project_executions(state)[execution_id].status, "held")
                third = run_watchdog(state, routes=ROUTES, now=T0 + timedelta(seconds=191), environ=ENV_OK)
                self.assertEqual(third["escalated"], [execution_id])


class ExactRetirementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "events.jsonl"
        self.vault = Path(self.tmp.name)
        self.authority_stack = self.enterContext(ExitStack())
        self.authority_stack.enter_context(authority_context(self.vault, self.state))

    def alert(self):
        from arvyx_control.control import read_events
        from arvyx_control.execution import hold_execution, close_execution
        subject = post_thread(self.state, title="work", actor="esme", target="amir",
                              thread_type="ask", actor_identity_bound=True)
        execution = claim_execution(self.state, worker="worker", execution_capable_targets={"amir"})
        hold_execution(self.state, execution_id=execution.id, reason="operator decision", held_by="operator")
        alert = post_thread(self.state, title=f"[watchdog] execution {execution.id} held for operator",
                            body=f"target=amir subject=thread {subject.thread.id}; operator decision",
                            actor="arvyx-watchdog", target="operator", thread_type="blocker", severity="warn",
                            actor_identity_bound=False)
        close_execution(self.state, execution_id=execution.id, resolution_category="obsolete",
                        reason="obsolete attempt", closed_by="operator")
        terminal = read_events(self.state)[-1]
        request = dict(expected_event_id=alert.event.id, source_event_id=alert.event.id,
                       target="operator", execution_id=execution.id, execution_target="amir",
                       execution_subject_id=subject.thread.id, terminal_event_id=terminal.id,
                       category="obsolete_watchdog_alert", reason="terminal attempt; alert only")
        return alert.thread.id, request

    def rewrite_alert_event(self, event_id, updates, drop=()):
        import json
        rows = [json.loads(line) for line in self.state.read_text().splitlines()]
        for row in rows:
            if row["id"] == event_id:
                row["payload"].update(updates)
                for key in drop:
                    row["payload"].pop(key, None)
        self.state.write_text("".join(json.dumps(row) + "\n" for row in rows))

    def assert_history_denied(self, identifier, request):
        from arvyx_control.auth import OPERATOR_IDENTITY
        from arvyx_control.retirement import retire_thread
        before = self.state.read_bytes()
        for dry_run in (True, False):
            with self.assertRaises(ValueError):
                retire_thread(self.state, thread_id=identifier, request=request,
                              identity=OPERATOR_IDENTITY, dry_run=dry_run)
            self.assertEqual(before, self.state.read_bytes())

    def test_malformed_prior_thread_status_not_hidden(self):
        identifier, request = self.alert()
        self.raw("thread.read", identifier, {"status": "future_unknown_state", "unread": False})
        latest = self.raw("thread.read", identifier, {"status": "open", "unread": False})
        request["expected_event_id"] = latest.id
        self.assert_history_denied(identifier, request)

    def test_malformed_source_type_not_hidden(self):
        identifier, request = self.alert()
        self.rewrite_alert_event(request["source_event_id"], {"type": "ask"})
        latest = self.raw("thread.read", identifier, {"type": "blocker", "unread": False})
        request["expected_event_id"] = latest.id
        self.assert_history_denied(identifier, request)

    def test_prior_thread_done_cannot_be_hidden(self):
        from arvyx_control.control import complete_thread
        identifier, request = self.alert()
        complete_thread(self.state, identifier, actor="operator")
        latest = self.raw("thread.read", identifier, {"status": "open", "done_by": "", "done_at": "",
                                                       "pending": True, "unread": False})
        request["expected_event_id"] = latest.id
        self.assert_history_denied(identifier, request)

    def test_malformed_watchdog_identity_bound_string(self):
        identifier, request = self.alert()
        self.rewrite_alert_event(request["source_event_id"], {"actor_identity_bound": "true"})
        self.assert_history_denied(identifier, request)

    def test_watchdog_creation_requires_explicit_false_not_missing_or_null(self):
        identifier, request = self.alert()
        original = self.state.read_bytes()
        for value in (True, "false", "true", None, 0, 1, [], {}):
            with self.subTest(value=value):
                self.state.write_bytes(original)
                self.rewrite_alert_event(request["source_event_id"], {"actor_identity_bound": value})
                self.assert_history_denied(identifier, request)
        self.state.write_bytes(original)
        self.rewrite_alert_event(request["source_event_id"], {}, drop=("actor_identity_bound",))
        self.assert_history_denied(identifier, request)

    def test_raw_snapshot_types_and_immutable_bindings_cannot_be_hidden(self):
        identifier, request = self.alert()
        original = self.state.read_bytes()
        from arvyx_control.control import read_thread
        for key, value in (("actor", "other"), ("target", "amir"), ("id", "other"),
                           ("created_at", "other"), ("body", "other"), ("type", "ask"),
                           ("unread", "false"), ("unread", None), ("pending", 1),
                           ("actor_identity_bound", "true"), ("actor_identity_bound", None),
                           ("status", None), ("done_by", None), ("retirement", None)):
            with self.subTest(key=key, value=value):
                self.state.write_bytes(original)
                first = read_thread(self.state, identifier)
                latest = read_thread(self.state, identifier)
                self.rewrite_alert_event(first.event.id, {key: value})
                request["expected_event_id"] = latest.event.id
                self.assert_history_denied(identifier, request)
        for key in ("id", "status", "unread", "pending", "type", "actor", "target"):
            with self.subTest(missing=key):
                self.state.write_bytes(original)
                first = read_thread(self.state, identifier)
                latest = read_thread(self.state, identifier)
                self.rewrite_alert_event(first.event.id, {}, drop=(key,))
                request["expected_event_id"] = latest.event.id
                self.assert_history_denied(identifier, request)

    def test_ack_cannot_be_hidden_but_legal_ack_history_validates(self):
        from arvyx_control.control import acknowledge_thread, read_thread, post_thread_message, read_events
        from arvyx_control.retirement import _validate_thread_history
        identifier, request = self.alert()
        acknowledge_thread(self.state, identifier, actor="operator", text="Investigating", actor_identity_bound=True)
        post_thread_message(self.state, identifier, "Acknowledged note", actor="operator")
        latest = read_thread(self.state, identifier)
        _validate_thread_history(read_events(self.state), identifier)
        request["expected_event_id"] = latest.event.id
        # ACK is a legitimate lifecycle, but retirement still requires OPEN.
        self.assert_history_denied(identifier, request)
        latest = self.raw("thread.read", identifier, {"status": "open", "acked_at": "", "acked_by": ""})
        request["expected_event_id"] = latest.id
        self.assert_history_denied(identifier, request)

    def test_legitimate_alert_reads_replies_notifications_and_retry(self):
        from arvyx_control.control import (read_thread, post_thread_message, record_thread_notification,
                                           record_thread_notification_failure, read_events)
        identifier, request = self.alert()
        read_thread(self.state, identifier)
        reply = post_thread_message(self.state, identifier, "Diagnostic note", actor="operator")
        claim = record_thread_notification(self.state, reply.thread, "notification", "Synthetic notification")
        record_thread_notification_failure(self.state, identifier, "notification", "Synthetic failure",
                                           claim_event_id=claim.id)
        latest = read_thread(self.state, identifier)
        request["expected_event_id"] = latest.event.id
        result = self.apply("thread", identifier, request)
        self.assertTrue(result["changed"])
        self.assertEqual(result["record"]["retirement"]["request"], request)
        read_thread(self.state, identifier)
        before = self.state.read_bytes()
        self.assertFalse(self.apply("thread", identifier, request)["changed"])
        self.assertEqual(before, self.state.read_bytes())
        self.assertFalse(any(e.type == "thread.done" and e.task_id == identifier for e in read_events(self.state)))

    def test_delivery_subject_done_history_cannot_resurrect(self):
        from arvyx_control.control import read_events
        from arvyx_control.retirement import _validate_thread_history
        identifier, request = self.delivery()
        _validate_thread_history(read_events(self.state), request["subject_id"])
        self.raw("thread.read", request["subject_id"], {"status": "open", "done_at": "", "done_by": "",
                                                       "pending": True, "unread": False})
        self.raw("thread.done", request["subject_id"], {"status": "done", "done_at": "2026-01-01T00:00:00Z",
                                                       "done_by": "amir", "pending": False})
        before = self.state.read_bytes()
        with self.assertRaises(ValueError):
            self.apply("delivery", identifier, request)
        self.assertEqual(before, self.state.read_bytes())

    def delivery(self):
        from arvyx_control.control import read_events
        subject = post_thread(self.state, title="work", actor="esme", target="amir", thread_type="ask")
        item = enqueue(self.state, subject_id=subject.thread.id, target="amir", payload={
            "schema": "v2.agent-delivery/1", "source_event_id": subject.event.id,
            "source_event_type": "thread.created", "subject_id": subject.thread.id})
        latest = read_events(self.state)[-1]
        terminal = complete_thread(self.state, subject.thread.id, actor="amir")
        request = dict(expected_event_id=latest.id, source_event_id=subject.event.id, target="amir",
                       subject_id=subject.thread.id, payload_hash=item.payload_hash, epoch=item.epoch,
                       terminal_event_id=terminal.event.id, category="obsolete_subject", reason="obsolete wake")
        return item.id, request

    def test_retire_alert_not_completion_idempotent_and_exact(self):
        from arvyx_control import retirement
        from arvyx_control.auth import OPERATOR_IDENTITY
        from arvyx_control.control import _project_threads, read_events, list_pending_threads
        identifier, request = self.alert()
        from arvyx_control.control import post_thread_message
        reply = post_thread_message(self.state, identifier, "Preserved diagnostic note", actor="operator")
        request["expected_event_id"] = reply.event.id
        before = _project_threads(self.state)[identifier]
        self.assertTrue(before.messages)
        result = retirement.retire_thread(self.state, thread_id=identifier, request=request, identity=OPERATOR_IDENTITY)
        self.assertTrue(result["changed"])
        after = _project_threads(self.state)[identifier]
        self.assertEqual(after.status, "retired")
        self.assertFalse(after.pending)
        self.assertEqual(after.messages, before.messages)
        self.assertIsInstance(hash(after), int)
        projected = _project_threads(self.state)[identifier]
        self.assertEqual(after, projected)
        self.assertEqual(hash(after), hash(projected))
        detached = after.retirement
        detached["request"]["reason"] = "cannot mutate frozen record"
        self.assertEqual(after.retirement["request"]["reason"], request["reason"])
        self.assertEqual(hash(after), hash(projected))
        self.assertEqual(after.done_at, before.done_at)
        self.assertEqual(after.done_by, before.done_by)
        self.assertEqual(read_events(self.state)[-1].type, "thread.retired")
        self.assertNotIn(identifier, [t.id for t in list_pending_threads(self.state).threads])
        raw = self.state.read_bytes()
        self.assertFalse(retirement.retire_thread(self.state, thread_id=identifier, request=request,
                                                  identity=OPERATOR_IDENTITY)["changed"])
        self.assertEqual(raw, self.state.read_bytes())
        from arvyx_control.control import read_thread
        read_thread(self.state, identifier)
        raw = self.state.read_bytes()
        retried = retirement.retire_thread(self.state, thread_id=identifier, request=request, identity=OPERATOR_IDENTITY)
        self.assertFalse(retried["changed"])
        self.assertEqual(retried["event_id"], result["event_id"])
        self.assertEqual(raw, self.state.read_bytes())
        with self.assertRaises(ValueError):
            retirement.retire_thread(self.state, thread_id=identifier, request={**request, "reason": "different"},
                                     identity=OPERATOR_IDENTITY)
        self.assertEqual(raw, self.state.read_bytes())

    def test_retire_pending_delivery_preserves_transport_history(self):
        from arvyx_control import retirement
        from arvyx_control.auth import OPERATOR_IDENTITY
        from arvyx_control.outbox import project_outbox
        identifier, request = self.delivery()
        before = project_outbox(self.state)[identifier]
        raw = self.state.read_bytes()
        retirement.retire_pending_delivery(self.state, outbox_id=identifier, request=request,
                                           identity=OPERATOR_IDENTITY, dry_run=True)
        self.assertEqual(raw, self.state.read_bytes())
        retirement.retire_pending_delivery(self.state, outbox_id=identifier, request=request, identity=OPERATOR_IDENTITY)
        after = project_outbox(self.state)[identifier]
        self.assertEqual(after.status, "cancelled")
        self.assertEqual(after.resolution_category, "obsolete_subject")
        for field in ("payload", "payload_hash", "attempts", "failures", "receipt_status", "provider_receipt"):
            self.assertEqual(getattr(before, field), getattr(after, field))
        self.assertEqual(claim_due(self.state, worker="worker", targets={"amir"}), [])

    def apply(self, kind, identifier, request, **kwargs):
        from arvyx_control.retirement import retire_thread, retire_pending_delivery
        from arvyx_control.auth import OPERATOR_IDENTITY
        if kind == "thread":
            return retire_thread(self.state, thread_id=identifier, request=request, identity=OPERATOR_IDENTITY, **kwargs)
        return retire_pending_delivery(self.state, outbox_id=identifier, request=request, identity=OPERATOR_IDENTITY, **kwargs)

    def raw(self, kind, identifier, changes):
        from arvyx_control.control import read_events
        events = read_events(self.state)
        previous = next(e for e in reversed(events) if e.task_id == identifier)
        payload = {**previous.payload, **changes}
        if kind not in {"thread.acknowledged", "thread.done"} and "actor_identity_bound" not in changes:
            # Real non-lifecycle producers re-serialize the projected thread, whose
            # provenance comes only from thread.created (never an ACK/DONE actor's).
            created = next((e for e in events if e.task_id == identifier and e.type == "thread.created"), None)
            if created is not None:
                payload["actor_identity_bound"] = created.payload.get("actor_identity_bound")
        event = _event(kind, identifier, previous.timestamp, payload)
        with _locked_state(self.state):
            _append_event_unlocked(self.state, event)
        return event

    def test_alert_scope_and_raw_unknown_lineage_fences(self):
        for change in ({"actor": "intruder"}, {"target": "amir"}, {"status": "acked"},
                       {"continuation_thread_id": "thread_child"}, {"title": "not a watchdog"}):
            with self.subTest(change=change):
                identifier, request = self.alert()
                event = self.raw("thread.message.posted", identifier, change)
                request["expected_event_id"] = event.id
                raw = self.state.read_bytes()
                with self.assertRaises(ValueError):
                    self.apply("thread", identifier, request)
                self.assertEqual(raw, self.state.read_bytes())
        for kind, fixture in (("thread", self.alert), ("delivery", self.delivery)):
            identifier, request = fixture()
            self.raw("future.unknown", identifier, {})
            raw = self.state.read_bytes()
            with self.assertRaisesRegex(ValueError, "unknown lineage"):
                self.apply(kind, identifier, request)
            self.assertEqual(raw, self.state.read_bytes())

    def test_alert_requires_exact_provenance_terminal_and_no_own_execution(self):
        from arvyx_control.execution import hold_execution
        identifier, request = self.alert()
        for field in ("execution_id", "execution_target", "execution_subject_id", "terminal_event_id"):
            raw = self.state.read_bytes()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.apply("thread", identifier, {**request, field: "different"})
            self.assertEqual(raw, self.state.read_bytes())
        # Same title, body and actor without a preceding HOLD is insufficient.
        unknown = post_thread(self.state, title="[watchdog] execution execution_absent held for operator",
                              actor="arvyx-watchdog", target="operator", thread_type="blocker")
        raw = self.state.read_bytes()
        with self.assertRaises(ValueError):
            self.apply("thread", unknown.thread.id, {**request, "source_event_id": unknown.event.id,
                                                     "expected_event_id": unknown.event.id})
        self.assertEqual(raw, self.state.read_bytes())
        self.raw("execution.future", request["execution_id"], {})
        raw = self.state.read_bytes()
        with self.assertRaises(ValueError):
            self.apply("thread", identifier, request)
        self.assertEqual(raw, self.state.read_bytes())

    def test_delivery_nonpending_and_special_modes_are_never_retired(self):
        from arvyx_control.outbox import project_outbox
        for change in ({"status": "leased"}, {"lease_expires_at": "2000-01-01T00:00:00Z"},
                       {"lease_owner": "worker"}, {"status": "ambiguous_delivery"},
                       {"status": "delivered"}, {"status": "dead_lettered"},
                       {"provider_receipt": "actual-receipt"}, {"receipt_status": "seen"}):
            with self.subTest(change=change):
                identifier, request = self.delivery()
                event = self.raw("outbox.deferred", identifier, change)
                request["expected_event_id"] = event.id
                raw = self.state.read_bytes()
                with self.assertRaises(ValueError):
                    self.apply("delivery", identifier, request)
                self.assertEqual(raw, self.state.read_bytes())
        for mode in ("notification", "execution", "session_return", "direct", "broadcast"):
            identifier, request = self.delivery()
            before = project_outbox(self.state)[identifier]
            special = enqueue(self.state, subject_id=before.subject_id, target=before.target,
                              payload={**before.payload, "delivery_mode": mode})
            from arvyx_control.control import read_events
            updated = {**request, "expected_event_id": read_events(self.state)[-1].id, "payload_hash": special.payload_hash}
            raw = self.state.read_bytes()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.apply("delivery", special.id, updated)
            self.assertEqual(raw, self.state.read_bytes())

    def test_known_predispatch_attempts_allowed_unknown_send_denied(self):
        from arvyx_control.control import read_events
        from arvyx_control.outbox import defer_lease, record_failure
        for outcome in ("deferred", "pre-dispatch", "timeout"):
            with self.subTest(outcome=outcome):
                # Isolate claimed records; no accidental batch activity.
                self.authority_stack.close()
                self.state = Path(self.tmp.name) / (outcome + ".jsonl")
                self.authority_stack.enter_context(authority_context(self.vault, self.state))
                identifier, request = self.delivery()
                claimed = claim_due(self.state, worker="worker", targets={"amir"})
                self.assertEqual([item.id for item in claimed], [identifier])
                if outcome == "deferred":
                    defer_lease(self.state, outbox_id=identifier, worker="worker", claim_attempts=next(c.attempts for c in claimed if c.id == identifier))
                else:
                    record_failure(self.state, outbox_id=identifier, worker="worker", claim_attempts=next(c.attempts for c in claimed if c.id == identifier), transient=True,
                                   detail="delivery URL environment reference is not configured: TEST_URL"
                                   if outcome == "pre-dispatch" else "delivery timed out")
                request["expected_event_id"] = read_events(self.state)[-1].id
                raw = self.state.read_bytes()
                if outcome == "timeout":
                    with self.assertRaisesRegex(ValueError, "pre-dispatch"):
                        self.apply("delivery", identifier, request)
                    self.assertEqual(raw, self.state.read_bytes())
                else:
                    self.assertTrue(self.apply("delivery", identifier, request)["changed"])
                    raw = self.state.read_bytes()
                    self.assertFalse(self.apply("delivery", identifier, request)["changed"])
                    self.assertEqual(raw, self.state.read_bytes())

    def test_completed_reference_and_pending_linked_sources(self):
        from arvyx_control.control import read_events
        from arvyx_control.execution import reconcile_executions
        identifier, request = self.alert()
        complete_thread(self.state, request["execution_subject_id"], actor="amir", actor_identity_bound=True)
        reconcile_executions(self.state)
        request["terminal_event_id"] = next(e.id for e in reversed(read_events(self.state))
                                            if e.task_id == request["execution_id"])
        self.assertTrue(self.apply("thread", identifier, request)["changed"])
        self.assertEqual(project_executions(self.state)[request["execution_id"]].status, "completed")
        identifier, request = self.delivery()
        self.raw("thread.message.posted", request["subject_id"], {"continuation_thread_id": "thread_child"})
        raw = self.state.read_bytes()
        with self.assertRaisesRegex(ValueError, "continuation"):
            self.apply("delivery", identifier, request)
        self.assertEqual(raw, self.state.read_bytes())

    def test_retirement_races_real_claim_under_single_lock(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        from arvyx_control.outbox import project_outbox
        for index in range(12):
            self.authority_stack.close()
            self.state = Path(self.tmp.name) / f"race-{index}.jsonl"
            self.authority_stack.enter_context(authority_context(self.vault, self.state))
            identifier, request = self.delivery()
            barrier = threading.Barrier(2)
            def retire():
                with authority_context(self.vault, self.state):
                    barrier.wait()
                    try:
                        return self.apply("delivery", identifier, request)["changed"]
                    except ValueError:
                        return False
            def claim():
                with authority_context(self.vault, self.state):
                    barrier.wait()
                    return claim_due(self.state, worker="racer", targets={"amir"})
            with ThreadPoolExecutor(max_workers=2) as pool:
                a, b = pool.submit(retire), pool.submit(claim)
                retired, claims = a.result(timeout=10), b.result(timeout=10)
            self.assertNotEqual(retired, bool(claims))
            self.assertEqual(project_outbox(self.state)[identifier].status, "cancelled" if retired else "leased")

    def test_full_checkpoint_sqlite_parity_and_no_side_effects(self):
        import sqlite3
        from arvyx_control import projection_cache
        from arvyx_control.control import read_events, _project_threads
        from arvyx_control.outbox import project_outbox, _project_outbox_state
        from arvyx_control.store import sync_sqlite
        from arvyx_control.api import _control_plane
        alert, alert_request = self.alert()
        delivery, delivery_request = self.delivery()
        before = read_events(self.state)
        before_threads = _project_threads(self.state)
        before_exec = project_executions(self.state)
        projection_cache.build_projection_checkpoint(self.state, force=True)
        self.apply("thread", alert, alert_request)
        self.apply("delivery", delivery, delivery_request)
        after = read_events(self.state)
        self.assertEqual([e.type for e in after[len(before):]], ["thread.retired", "outbox.cancelled"])
        self.assertEqual(before_exec, project_executions(self.state))
        for identifier, thread in before_threads.items():
            if identifier != alert:
                self.assertEqual(thread, _project_threads(self.state)[identifier])
        self.assertEqual(project_outbox(self.state), _project_outbox_state({}, after))
        projection_cache.build_projection_checkpoint(self.state, force=True)
        self.assertEqual(project_outbox(self.state), _project_outbox_state({}, after))
        db = Path(self.tmp.name) / "projection.sqlite"
        sync_sqlite(self.state, db)
        with contextlib.closing(sqlite3.connect(db)) as conn, conn:
            row = conn.execute("SELECT status,pending,done_by,retirement_json FROM threads WHERE id=?", (alert,)).fetchone()
            self.assertEqual(row[:3], ("retired", 0, ""))
            self.assertEqual(json.loads(row[3]), _project_threads(self.state)[alert].retirement)
            row = conn.execute("SELECT status,payload_hash,attempts,retirement_json FROM outbox WHERE id=?", (delivery,)).fetchone()
            self.assertEqual(row[:3], ("cancelled", delivery_request["payload_hash"], 0))
            self.assertEqual(json.loads(row[3]), project_outbox(self.state)[delivery].retirement)
        board = _control_plane(Path(self.tmp.name), self.state)
        self.assertIn(alert, [c["id"] for c in board["kanban"]["retired"]])
        self.assertNotIn(alert, [c["id"] for c in board["kanban"]["done"]])
        self.assertEqual(sum(t.status == "done" for t in before_threads.values()),
                         sum(t.status == "done" for t in _project_threads(self.state).values()))
        from arvyx_control.health_ops import notify_check
        notifications = notify_check(self.state, dry_run=True)
        self.assertNotIn(alert, [c["thread_id"] for c in notifications.candidates])
        # Bounded board history remains a distinct lane, never counted as done.
        from arvyx_control.api import _bound_work_cards, _workload_by_agent
        cards = [{"id": alert, "kind": "thread", "owner": "operator", "updated_at": "now", "lane": "retired"}]
        load, _ = _workload_by_agent(_bound_work_cards(cards, 10))
        self.assertEqual(load["operator"]["done"], 0)
        self.assertEqual(load["operator"]["current"], 0)
        self.assertEqual(load["operator"]["retired"], 1)

    def test_no_resurrection_completion_notification_or_watchdog_repost(self):
        from arvyx_control.control import post_thread_message, read_events
        from arvyx_control.watchdog import _escalated_since_latest_hold
        identifier, request = self.alert()
        self.apply("thread", identifier, request)
        raw = self.state.read_bytes()
        for mutation in (acknowledge_thread, complete_thread):
            with self.assertRaises(ValueError):
                mutation(self.state, identifier)
        with self.assertRaises(ValueError):
            post_thread_message(self.state, identifier, "reopen", actor="operator")
        self.assertEqual(raw, self.state.read_bytes())
        self.assertEqual(_escalated_since_latest_hold(self.state, {request["execution_id"]}, worker="arvyx-watchdog"),
                         {request["execution_id"]})
        self.assertEqual(sum(e.type == "thread.done" for e in read_events(self.state)), 0)

    def test_http_and_cli_use_exact_operator_validator(self):
        import contextlib
        import io
        from arvyx_control.api import handle_api_request
        from arvyx_control.auth import Identity, ALL_SCOPES, OPERATOR_IDENTITY
        for kind, fixture, plural in (("thread", self.alert, "threads"), ("delivery", self.delivery, "deliveries")):
            identifier, request = fixture()
            route = f"/{plural}/{identifier}/retire"
            raw = self.state.read_bytes()
            for identity in (None, Identity("amir", ALL_SCOPES, "agent")):
                for demo in (False, True):
                    with patch("arvyx_control.api.resolve_identity", return_value=identity):
                        result = handle_api_request("POST", route, request, vault=Path(self.tmp.name),
                                                    state=self.state, allow_unauthenticated_demo=demo)
                    self.assertEqual(result.status, 403)
                    self.assertEqual(raw, self.state.read_bytes())
            with patch("arvyx_control.api.resolve_identity", return_value=OPERATOR_IDENTITY):
                result = handle_api_request("POST", route, {**request, "actor": "operator"},
                                            vault=Path(self.tmp.name), state=self.state, idempotency_key=identifier+"-bad")
                self.assertEqual(result.status, 400)
                self.assertEqual(raw, self.state.read_bytes())
                result = handle_api_request("POST", route, {**request, "dry_run": True},
                                            vault=Path(self.tmp.name), state=self.state, idempotency_key=identifier+"-dry")
                self.assertEqual(result.status, 200, result.body)
                self.assertEqual(raw, self.state.read_bytes())
            manifest = Path(self.tmp.name) / "request.json"
            manifest.write_text(json.dumps(request))
            args = [kind, "retire", identifier, "--state", str(self.state), "--manifest", str(manifest), "--json"]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli_main(["--authority-vault", str(self.vault), *args]), 0)
            self.assertEqual(raw, self.state.read_bytes())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli_main(["--authority-vault", str(self.vault), *args, "--apply"]), 0)
            raw = self.state.read_bytes()
            with patch("arvyx_control.api.resolve_identity", return_value=OPERATOR_IDENTITY):
                result = handle_api_request("POST", route, request, vault=Path(self.tmp.name),
                                            state=self.state, idempotency_key=identifier+"-retry")
            self.assertEqual(result.status, 200, result.body)
            self.assertFalse(result.body["changed"])
            self.assertEqual(raw, self.state.read_bytes())

    def test_bad_bindings_and_nonoperators_change_no_state(self):
        from arvyx_control import retirement
        from arvyx_control.auth import OPERATOR_IDENTITY, Identity, ALL_SCOPES
        for operation, fixture, name in ((retirement.retire_thread, self.alert, "thread_id"),
                                         (retirement.retire_pending_delivery, self.delivery, "outbox_id")):
            identifier, request = fixture()
            raw = self.state.read_bytes()
            for field in ("expected_event_id", "source_event_id", "target", "terminal_event_id", "category", "reason"):
                with self.subTest(operation=name, field=field), self.assertRaises(ValueError):
                    operation(self.state, **{name: identifier}, request={**request, field: ""}, identity=OPERATOR_IDENTITY)
                self.assertEqual(raw, self.state.read_bytes())
            for identity in (None, Identity("amir", ALL_SCOPES, "agent")):
                with self.assertRaises(ValueError):
                    operation(self.state, **{name: identifier}, request=request, identity=identity)
                self.assertEqual(raw, self.state.read_bytes())


if __name__ == "__main__":
    unittest.main()
