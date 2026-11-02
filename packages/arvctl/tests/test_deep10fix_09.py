"""Lane 09 regressions using disposable authority and no native/network effects."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.agent_delivery import AgentRoute
from arvyx_control.auth import OPERATOR_IDENTITY
from arvyx_control.control import (
    _append_event, _event, _project_threads, complete_thread, post_thread,
    read_events, read_thread,
)
from arvyx_control.execution import (
    claim_execution, close_execution, hold_execution, project_executions,
    reconcile_executions, replay_execution,
)
from arvyx_control.operator_alert_dismissal import prepare_alert_dismissal, dismiss_alert
from arvyx_control.replica_authority import authority_context
from arvyx_control import watchdog


T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
ROUTES = {"fixturebot": AgentRoute("fixturebot", "hermes-webhook", "FIXTURE_URL", "FIXTURE_SECRET")}
ENV = {"FIXTURE_URL": "https://runtime.invalid/hook", "FIXTURE_SECRET": "synthetic-only"}


class Deep10Fix09Tests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix="deep10fix09-") as directory:
            state = Path(directory) / "events.jsonl"
            vault = Path(directory) / "vault"
            vault.mkdir()
            with authority_context(vault, state):
                yield state

    def tick(self, state, **kwargs):
        return watchdog.run_watchdog(state, routes=ROUTES, environ=ENV,
            now=T0 + timedelta(seconds=100), probe=False, **kwargs)

    def dead_letter(self, state, *, exhausted=False, title="Synthetic assignment"):
        subject = post_thread(state, title=title, actor="operator", target="fixturebot",
            thread_type="ask", actor_identity_bound=True).thread
        execution = claim_execution(state, worker="fixture-worker", execution_capable_targets=set(ROUTES),
            now=T0, lease_seconds=1, max_attempts=1)
        self.assertIsNotNone(execution)
        self.assertIsNone(claim_execution(state, worker="fixture-worker",
            execution_capable_targets=set(ROUTES), now=T0 + timedelta(seconds=16),
            lease_seconds=1, max_attempts=1))
        if exhausted:
            replay_execution(state, execution_id=execution.id, now=T0 + timedelta(seconds=17))
            claim_execution(state, worker="fixture-worker", execution_capable_targets=set(ROUTES),
                now=T0 + timedelta(seconds=20), lease_seconds=1, max_attempts=1)
            claim_execution(state, worker="fixture-worker", execution_capable_targets=set(ROUTES),
                now=T0 + timedelta(seconds=36), lease_seconds=1, max_attempts=1)
        self.assertEqual("dead_lettered", project_executions(state)[execution.id].status)
        return subject, execution.id

    def request(self, state, alert_id):
        return prepare_alert_dismissal(state, record_id=alert_id, identity=OPERATOR_IDENTITY,
            reason="Dismiss only the obsolete fixture notification.",
            approval_reference="synthetic:operator", approval_quote="Dismiss this exact fixture alert only.",
            evidence_references=["synthetic:history"])

    def apply(self, state, alert_id, request, **kwargs):
        return dismiss_alert(state, record_id=alert_id, request=request,
            identity=OPERATOR_IDENTITY, **kwargs)

    def generated_alert(self, state):
        subject, execution_id = self.dead_letter(state, exhausted=True)
        report = self.tick(state)
        self.assertEqual([execution_id], report["held"])
        self.assertEqual([execution_id], report["escalated"])
        source = next(e for e in read_events(state) if e.type == "thread.created"
            and e.payload.get("title") == watchdog._escalation_title(execution_id))
        close_execution(state, execution_id=execution_id, reason="Synthetic closure",
            closed_by="operator", resolution_category="no_longer_actionable")
        return subject, execution_id, source

    def test_09_01_actual_producer_prepare_dryrun_apply_readback_retry(self):
        with self.fixture() as state:
            subject, execution_id, source = self.generated_alert(state)
            request = self.request(state, source.task_id)
            before = state.read_bytes()
            self.assertFalse(self.apply(state, source.task_id, request)["changed"])
            self.assertEqual(before, state.read_bytes())
            first = self.apply(state, source.task_id, request, dry_run=False)
            self.assertTrue(first["changed"])
            read_thread(state, source.task_id)
            retry = self.apply(state, source.task_id, request, dry_run=False)
            self.assertFalse(retry["changed"])
            self.assertEqual(first["event_id"], retry["event_id"])
            projected = _project_threads(state)
            self.assertEqual("retired", projected[source.task_id].status)
            self.assertFalse(projected[source.task_id].pending)
            self.assertFalse(projected[source.task_id].done_at)
            self.assertEqual("open", projected[subject.id].status)
            self.assertEqual("closed", project_executions(state)[execution_id].status)
            events = read_events(state)
            self.assertEqual(1, sum(e.type == "thread.operator_archived" for e in events))
            self.assertFalse(first["record"]["retirement"]["lineage_completion_asserted"])
            self.assertFalse(first["record"]["retirement"]["linked_obligations_authorized"])
            cold = state.with_name("cold-events.jsonl")
            cold.write_bytes(state.read_bytes())
            self.assertEqual("retired", _project_threads(cold)[source.task_id].status)
            next_tick = self.tick(state)
            self.assertEqual([], next_tick["escalated"])
            self.assertEqual([], next_tick["materialized"])
            self.assertFalse(any(e.subject_id == source.task_id for e in project_executions(state).values()))

    def test_09_01_new_operator_body_matches_existing_exact_consumers(self):
        with self.fixture() as state:
            _, execution_id, source = self.generated_alert(state)
            held = next(e for e in read_events(state) if e.task_id == execution_id and e.type == "execution.held")
            p = held.payload
            # REV-0411 / docs/watchdog-alert-contract.md: the shared canonical body
            # ends with exactly one producer-added period; the undotted body is the
            # only historical alternative, and every exact consumer accepts both.
            from arvyx_control.watchdog_alerts import operator_hold_alert_bodies
            canonical = (f"target={p['target']} subject={p['subject_type']} {p['subject_id']}; "
                + p["hold_reason"] + ".")
            self.assertEqual(canonical, source.payload["body"])
            self.assertEqual((canonical, canonical[:-1]), operator_hold_alert_bodies(
                target=p["target"], subject_type=p["subject_type"], subject_id=p["subject_id"],
                hold_reason=p["hold_reason"]))

    def test_09_01_exact_undotted_and_dotted_history_only(self):
        for ending in ("", ".", "..", " altered", ". extra guidance"):
            with self.subTest(ending=ending), self.fixture() as state:
                subject, execution_id = self.dead_letter(state)
                reason = "Synthetic HOLD reason"
                hold_execution(state, execution_id=execution_id, reason=reason, held_by="operator")
                alert = post_thread(state, title=watchdog._escalation_title(execution_id),
                    actor="arvyx-watchdog", target="operator", thread_type="blocker",
                    body=f"target=fixturebot subject=thread {subject.id}; {reason}{ending}").thread
                close_execution(state, execution_id=execution_id, reason="Synthetic closure",
                    closed_by="operator", resolution_category="no_longer_actionable")
                before = state.read_bytes()
                if ending in {"", "."}:
                    self.assertEqual(execution_id, self.request(state, alert.id)["execution_id"])
                else:
                    with self.assertRaisesRegex(ValueError, "HOLD binding mismatch"):
                        self.request(state, alert.id)
                self.assertEqual(before, state.read_bytes())

    def test_09_01_live_origin_and_stale_manifest_still_rejected(self):
        with self.fixture() as state:
            _, execution_id = self.dead_letter(state, exhausted=True)
            self.tick(state)
            alert_id = next(e.task_id for e in read_events(state) if e.type == "thread.created"
                and e.payload.get("title") == watchdog._escalation_title(execution_id))
            with self.assertRaisesRegex(ValueError, "live or unresolved execution"):
                self.request(state, alert_id)
            close_execution(state, execution_id=execution_id, reason="Synthetic closure",
                closed_by="operator", resolution_category="no_longer_actionable")
            request = self.request(state, alert_id)
            post_thread(state, title="Synthetic concurrent event", actor="operator", target="operator")
            with self.assertRaisesRegex(ValueError, "stale exact authority"):
                self.apply(state, alert_id, request, dry_run=False)

    def after_snapshot(self, action):
        """Run a real independent authority operation after snapshot, before iteration."""
        original = watchdog.project_executions
        intercepted = False

        class Snapshot(dict):
            def values(self):
                action()
                return super().values()

        def intercept(*args, **kwargs):
            nonlocal intercepted
            snapshot = original(*args, **kwargs)
            if not intercepted:
                intercepted = True
                return Snapshot(snapshot)
            return snapshot

        return patch.object(watchdog, "project_executions", side_effect=intercept)

    def test_09_02_recovery_revision_wins_for_both_budget_branches(self):
        for exhausted in (False, True):
            for recovery in ("pending", "leased", "closed", "completed", "subject_terminal", "same_snapshot"):
                with self.subTest(exhausted=exhausted, recovery=recovery), self.fixture() as state:
                    subject, execution_id = self.dead_letter(state, exhausted=exhausted)
                    _, sibling_id = self.dead_letter(state, title="Synthetic sibling")
                    newer = []

                    def recover():
                        if recovery in {"pending", "leased"}:
                            replay_execution(state, execution_id=execution_id)
                            if recovery == "leased":
                                claimed = claim_execution(state, worker="new-fixture-worker",
                                    execution_capable_targets=set(ROUTES), now=T0 + timedelta(seconds=90))
                                self.assertEqual(execution_id, claimed.id)
                        elif recovery == "closed":
                            close_execution(state, execution_id=execution_id, reason="Synthetic recovery",
                                closed_by="operator", resolution_category="no_longer_actionable")
                        elif recovery in {"completed", "subject_terminal"}:
                            complete_thread(state, subject.id, actor="fixturebot", actor_identity_bound=True)
                            if recovery == "completed":
                                reconcile_executions(state)
                        else:
                            # A new revision can carry identical projected bytes and time.
                            latest = next(e for e in reversed(read_events(state)) if e.task_id == execution_id)
                            _append_event(state, _event(latest.type, execution_id, latest.timestamp, latest.payload))
                        newer.extend(e for e in read_events(state) if e.task_id == execution_id)

                    with self.after_snapshot(recover):
                        report = self.tick(state, escalate=False)
                    self.assertEqual(newer, [e for e in read_events(state) if e.task_id == execution_id])
                    self.assertNotIn(execution_id, report["held"])
                    self.assertNotIn(execution_id, report["replayed"])
                    self.assertIn(sibling_id, report["replayed"])
                    self.assertTrue(watchdog.project_watchdog_tick(state)["initialized"])
                    if recovery == "leased":
                        current = project_executions(state)[execution_id]
                        self.assertEqual("new-fixture-worker", current.lease_owner)
                        self.assertTrue(current.attempt_id)

    def test_09_02_normal_budget_and_offline_deferral_preserved(self):
        with self.fixture() as state:
            _, execution_id = self.dead_letter(state)
            with patch.object(watchdog, "validate_agent_route", return_value="synthetic offline"):
                report = self.tick(state, escalate=False)
            self.assertEqual([execution_id], report["deferred_unreachable"])
            self.assertEqual("dead_lettered", project_executions(state)[execution_id].status)
            self.assertEqual([execution_id], self.tick(state, escalate=False)["replayed"])

    def test_09_01_nonoperator_guidance_remains_ineligible(self):
        with self.fixture() as state:
            _, execution_id = self.dead_letter(state, exhausted=True)
            report = self.tick(state, escalation_target="fixture-reviewer")
            self.assertEqual([execution_id], report["escalated"])
            source = next(e for e in read_events(state) if e.type == "thread.created"
                and e.payload.get("title") == watchdog._escalation_title(execution_id))
            self.assertIn("Investigate with control.execution_list", source.payload["body"])
            close_execution(state, execution_id=execution_id, reason="Synthetic closure",
                closed_by="operator", resolution_category="no_longer_actionable")
            with self.assertRaisesRegex(ValueError, "operator watchdog notifications"):
                self.request(state, source.task_id)


if __name__ == "__main__":
    unittest.main()
