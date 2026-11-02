from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.replica_authority import authority_context
from arvyx_control.agent_delivery import AgentDeliveryResult, AgentRoute
from arvyx_control.dispatcher import dispatch_once, load_routes
from arvyx_control.outbox import (
    claim_due,
    enqueue,
    project_materialization_checkpoint,
    project_materialization_skips,
    project_outbox,
)
from arvyx_control.control import (
    acknowledge_thread,
    complete_thread,
    create_handoff,
    create_task,
    post_thread,
    read_events,
)
from arvyx_control.execution import claim_execution
from arvyx_control.session_return import request_session_return


NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)
ENV = {"TEST_URL": "http://127.0.0.1:9999/wake", "TEST_SECRET": "test-route-secret"}
ROUTE = AgentRoute("amir", "hermes-webhook", "TEST_URL", "TEST_SECRET")


class DispatcherTests(unittest.TestCase):
    def _state_with_item(self, tmp: str) -> tuple[Path, str]:
        state = Path(tmp) / "events.jsonl"
        item = enqueue(
            state,
            subject_id="handoff_1",
            target="amir",
            payload={"source_event_id": "event_1", "source_event_type": "handoff.created"},
            now=NOW,
        )
        return state, item.id

    def test_pure_noop_tick_within_the_heartbeat_window_is_coalesced(self) -> None:
        """An idle dispatcher must not write "nothing happened" every 10 seconds.

        The tick record is still the liveness authority, so the first tick and the
        bounded heartbeat are always written; only the noise between them is
        coalesced.
        """
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                first = dispatch_once(
                    state, routes={"amir": ROUTE}, worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z", now=NOW, clock=lambda: NOW, environ=ENV,
                )
                self.assertEqual(first.claimed, 0)
                self.assertEqual(len([e for e in read_events(state) if e.type == "outbox.dispatcher.tick"]), 1)

                later = NOW.replace(minute=NOW.minute) + timedelta(seconds=170)
                second = dispatch_once(
                    state, routes={"amir": ROUTE}, worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z", now=later, clock=lambda: later, environ=ENV,
                )
                self.assertEqual(second.delivered, 0)
                ticks = [e for e in read_events(state) if e.type == "outbox.dispatcher.tick"]
                self.assertEqual(len(ticks), 1, "a no-op tick inside the heartbeat window was written")
                # the coalesced window must stay inside the freshness window the
                # delivery-cancel gate and the health surface read (300 seconds)
                age = (later - datetime.fromisoformat(ticks[0].timestamp.replace("Z", "+00:00"))).total_seconds()
                self.assertLess(age, 300)

    def test_noop_tick_after_the_heartbeat_window_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                dispatch_once(
                    state, routes={"amir": ROUTE}, worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z", now=NOW, clock=lambda: NOW, environ=ENV,
                )
                later = NOW + timedelta(seconds=200)
                dispatch_once(
                    state, routes={"amir": ROUTE}, worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z", now=later, clock=lambda: later, environ=ENV,
                )
                ticks = [e for e in read_events(state) if e.type == "outbox.dispatcher.tick"]
                self.assertEqual(len(ticks), 2)

    def test_tick_that_delivers_is_recorded_inside_the_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, Path(tmp) / "events.jsonl"):
                state, _ = self._state_with_item(tmp)

                def accepted(*_args, **_kwargs):
                    return AgentDeliveryResult(True, "accepted", 202, "accepted", "receipt-1")

                first = dispatch_once(
                    state, routes={"amir": ROUTE}, worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z", now=NOW, clock=lambda: NOW, environ=ENV,
                    deliverer=accepted,
                )
                self.assertEqual(first.delivered, 1)
                self.assertEqual(len([e for e in read_events(state) if e.type == "outbox.dispatcher.tick"]), 1)

                # a second tick inside the window, this time with nothing to do,
                # is coalesced even though the previous tick delivered
                later = NOW + timedelta(seconds=30)
                dispatch_once(
                    state, routes={"amir": ROUTE}, worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z", now=later, clock=lambda: later, environ=ENV,
                    deliverer=accepted,
                )
                self.assertEqual(len([e for e in read_events(state) if e.type == "outbox.dispatcher.tick"]), 1)

    def test_invalid_route_config_claims_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, Path(tmp) / "events.jsonl"):
                state, _ = self._state_with_item(tmp)
                before = len(read_events(state))
                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ={},
                )
                self.assertFalse(result.ok)
                self.assertEqual(result.claimed, 0)
                self.assertEqual(len(read_events(state)), before)

    def test_gateway_acceptance_records_delivery_without_forging_target_seen_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, Path(tmp) / "events.jsonl"):
                state, item_id = self._state_with_item(tmp)

                def accepted(*_args, **_kwargs):
                    return AgentDeliveryResult(True, "accepted", 202, "accepted", "receipt-1")

                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    deliverer=accepted,
                )
                self.assertTrue(result.ok)
                self.assertEqual(result.to_dict()["delivered"], 1)
                item = project_outbox(state)[item_id]
                self.assertEqual(item.status, "delivered")
                self.assertEqual(item.provider_receipt, "")
                self.assertEqual(item.receipt_status, "")
                self.assertEqual(item.receipt_by, "")
                self.assertEqual(item.receipt_detail, "")
                self.assertNotIn("outbox.receipt", [event.type for event in read_events(state)])

    def test_stale_session_return_is_dead_lettered_without_calling_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                thread = post_thread(
                    state,
                    title="Return once",
                    thread_type="ask",
                    actor="elin",
                    target="amir",
                    actor_identity_bound=True,
                )
                acknowledge_thread(
                    state,
                    thread.thread.id,
                    actor="amir",
                    actor_identity_bound=True,
                )
                execution = claim_execution(
                    state,
                    worker="runtime-amir",
                    execution_capable_targets={"amir"},
                    now=NOW,
                )
                requested = request_session_return(
                    state,
                    execution_id=execution.id,
                    attempt_id=execution.attempt_id,
                    actor="amir",
                    message="yalnız bir dönüş",
                    expected_word_count=3,
                    idempotency_key="dispatcher-return-0001",
                    now=NOW,
                )
                complete_thread(
                    state,
                    thread.thread.id,
                    actor="amir",
                    actor_identity_bound=True,
                )
                session_adapter_calls = 0

                def accepted(item, *_args, **_kwargs):
                    nonlocal session_adapter_calls
                    if item.payload.get("delivery_mode") == "session_return":
                        session_adapter_calls += 1
                    return AgentDeliveryResult(True, "accepted", 202, "accepted", "provider-message-1")

                route = AgentRoute(
                    "amir",
                    "hermes-webhook",
                    "TEST_URL",
                    "TEST_SECRET",
                    return_url_env="RETURN_URL",
                    return_credential_env="RETURN_SECRET",
                )
                result = dispatch_once(
                    state,
                    routes={"amir": route},
                    worker="dispatcher-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ={
                        **ENV,
                        "RETURN_URL": "http://127.0.0.1:9998/session-return",
                        "RETURN_SECRET": "return-route-secret",
                    },
                    deliverer=accepted,
                )
                returned = next(
                    item for item in project_outbox(state).values()
                    if item.subject_id == requested.request_id
                )
                self.assertEqual(session_adapter_calls, 0)
                self.assertEqual(returned.status, "dead_lettered")
                self.assertIn("terminal", returned.failure_detail)
                self.assertEqual(result.dead_lettered, 1)

    def test_transient_delivery_is_scheduled_for_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, Path(tmp) / "events.jsonl"):
                state, item_id = self._state_with_item(tmp)

                def transient(*_args, **_kwargs):
                    return AgentDeliveryResult(False, "transient", 503, "target returned HTTP 503")

                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    deliverer=transient,
                )
                self.assertFalse(result.ok)
                self.assertEqual(result.retrying, 1)
                self.assertEqual(project_outbox(state)[item_id].status, "pending")
                self.assertGreater(project_outbox(state)[item_id].next_attempt_at, "2026-08-10T12:00:00Z")

    def test_ambiguous_delivery_is_fenced_without_retry_or_dead_letter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, Path(tmp) / "events.jsonl"):
                state, item_id = self._state_with_item(tmp)

                def ambiguous(*_args, **_kwargs):
                    return AgentDeliveryResult(
                        False,
                        "ambiguous",
                        202,
                        "provider may have accepted but omitted its receipt",
                    )

                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    deliverer=ambiguous,
                )

                self.assertFalse(result.ok)
                self.assertEqual(result.ambiguous, 1)
                self.assertEqual(result.retrying, 0)
                self.assertEqual(result.dead_lettered, 0)
                self.assertEqual(project_outbox(state)[item_id].status, "ambiguous_delivery")

    def test_dry_run_reports_materialization_without_append_or_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                for index in range(3):
                    create_task(state, f"Task {index}", owner="amir")
                before = state.read_bytes()
                deliveries = 0

                def deliver(*_args, **_kwargs):
                    nonlocal deliveries
                    deliveries += 1
                    return AgentDeliveryResult(True, "accepted", 202, "accepted")

                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    materialization_limit=2,
                    dry_run=True,
                    deliverer=deliver,
                )

                self.assertTrue(result.ok)
                self.assertEqual(result.materialized, 2)
                self.assertTrue(result.materialization_remaining)
                self.assertTrue(result.dry_run)
                self.assertEqual(deliveries, 0)
                self.assertEqual(state.read_bytes(), before)

    def test_intentional_human_target_is_observed_without_unhealthy_tick(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                human = create_task(state, "Human work", owner="elin")
                agent = create_task(state, "Agent work", owner="amir")

                first = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    intentional_human_targets={"elin"},
                    deliverer=lambda *_args, **_kwargs: AgentDeliveryResult(True, "accepted", 202, "accepted"),
                )
                checkpoint = project_materialization_checkpoint(state)
                second = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-b",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    intentional_human_targets={"elin"},
                    deliverer=lambda *_args, **_kwargs: AgentDeliveryResult(True, "accepted", 202, "accepted"),
                )

                self.assertEqual(first.materialized, 1)
                self.assertEqual(first.delivered, 1)
                self.assertEqual(second.materialized, 0)
                self.assertEqual(second.claimed, 0)
                self.assertNotIn(human.task.id, {item.subject_id for item in project_outbox(state).values()})
                self.assertIn(agent.task.id, {item.subject_id for item in project_outbox(state).values()})
                self.assertTrue(checkpoint["initialized"])
                self.assertEqual(project_materialization_checkpoint(state), checkpoint)
                self.assertTrue(first.ok)
                self.assertEqual(first.skipped_intentional_human_targets, ("elin",))
                self.assertEqual(project_materialization_skips(state)["counts"], {"intentional_human": 1})

    def test_all_broadcast_fans_out_to_registered_routes_except_actor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                broadcast = post_thread(
                    state,
                    title="Fleet broadcast",
                    thread_type="status",
                    actor="odin",
                    target="all",
                )
                routes = {
                    agent: AgentRoute(agent, "hermes-webhook", "TEST_URL", "TEST_SECRET")
                    for agent in ("amir", "esme", "kiran", "odin")
                }
                delivered_to: list[str] = []

                result = dispatch_once(
                    state,
                    routes=routes,
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    limit=5,
                    per_target_limit=5,
                    lease_seconds=70,
                    deliverer=lambda item, *_args, **_kwargs: (
                        delivered_to.append(item.target)
                        or AgentDeliveryResult(True, "accepted", 202, "accepted")
                    ),
                )

                items = [item for item in project_outbox(state).values() if item.subject_id == broadcast.thread.id]
                self.assertTrue(result.ok)
                self.assertEqual(result.materialized, 3)
                self.assertEqual(result.delivered, 3)
                self.assertEqual(sorted(delivered_to), ["amir", "esme", "kiran"])
                self.assertEqual(sorted(item.target for item in items), ["amir", "esme", "kiran"])
                self.assertTrue(all(item.payload.get("delivery_mode") == "broadcast" for item in items))
                self.assertEqual(result.skipped_intentional_human_targets, ())

    def test_all_broadcast_never_poison_blocks_agent_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                broadcast = post_thread(
                    state,
                    title="Broadcast status",
                    thread_type="status",
                    actor="odin",
                    target="all",
                )
                agent = create_task(state, "Agent work after broadcast", owner="amir")

                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    deliverer=lambda *_args, **_kwargs: AgentDeliveryResult(True, "accepted", 202, "accepted"),
                )

                subjects = {item.subject_id for item in project_outbox(state).values()}
                self.assertTrue(result.ok)
                self.assertEqual(result.materialized, 2)
                self.assertEqual(result.delivered, 2)
                self.assertEqual(result.skipped_intentional_human_targets, ())
                self.assertIn(broadcast.thread.id, subjects)
                self.assertIn(agent.task.id, subjects)
                self.assertTrue(project_materialization_checkpoint(state)["initialized"])

    def test_claim_due_core_observes_all_without_wrapper_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                broadcast = post_thread(
                    state,
                    title="Core pull-only broadcast",
                    thread_type="status",
                    actor="odin",
                    target="ALL",
                )
                agent = create_task(state, "Core agent delivery", owner="amir")
                report: dict[str, object] = {}

                claimed = claim_due(
                    state,
                    worker="worker-a",
                    now=NOW,
                    deliver_after="2026-08-10T00:00:00Z",
                    targets={"amir"},
                    limit=5,
                    per_target_limit=5,
                    lease_seconds=70,
                    materialization_report=report,
                )

                self.assertEqual(
                    {item.subject_id for item in claimed},
                    {broadcast.thread.id, agent.task.id},
                )
                self.assertIn(broadcast.thread.id, {item.subject_id for item in project_outbox(state).values()})
                self.assertEqual(report.get("skipped_intentional_human_targets", ()), ())
                self.assertEqual(report["materialized"], 2)
                self.assertTrue(project_materialization_checkpoint(state)["initialized"])

    def test_claim_due_without_allowlist_does_not_enqueue_pull_only_broadcast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                broadcast = post_thread(
                    state,
                    title="Global dashboard status",
                    thread_type="status",
                    actor="odin",
                    target="all",
                )
                report: dict[str, object] = {}

                claimed = claim_due(
                    state,
                    worker="worker-a",
                    now=NOW,
                    deliver_after="2026-08-10T00:00:00Z",
                    targets=None,
                    materialization_report=report,
                )

                self.assertEqual(claimed, [])
                self.assertNotIn(broadcast.thread.id, {item.subject_id for item in project_outbox(state).values()})
                self.assertEqual(report["skipped_intentional_human_targets"], ("all",))

    def test_actionable_task_and_handoff_reject_global_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                with self.assertRaisesRegex(ValueError, "concrete agent owner"):
                    create_task(state, "Invalid global task", owner=" ALL ")
                with self.assertRaisesRegex(ValueError, "concrete target agent"):
                    create_handoff(state, "Invalid global handoff", from_agent="odin", to_agent=" All ")
                with self.assertRaisesRegex(ValueError, "concrete source agent"):
                    create_handoff(state, "Invalid global source", from_agent=" ALL ", to_agent="amir")
                self.assertFalse(state.exists())

    def test_legacy_actionable_all_is_quarantined_not_fanned_out(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                created = create_task(state, "Legacy invalid global task", owner="amir")
                row = json.loads(state.read_text())
                row["payload"]["owner"] = "all"
                state.write_text(json.dumps(row, sort_keys=True) + "\n")
                routes = {
                    agent: AgentRoute(agent, "hermes-webhook", "TEST_URL", "TEST_SECRET")
                    for agent in ("amir", "esme", "kiran", "odin")
                }

                result = dispatch_once(
                    state,
                    routes=routes,
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    deliverer=lambda *_args, **_kwargs: AgentDeliveryResult(True, "accepted", 202, "accepted"),
                )

                self.assertTrue(result.ok)
                self.assertEqual(result.materialized, 0)
                self.assertEqual(result.delivered, 0)
                self.assertEqual(result.skipped_intentional_human_targets, ("all",))
                self.assertNotIn(created.task.id, {item.subject_id for item in project_outbox(state).values()})

    def test_reserved_all_route_fails_loudly_instead_of_bypassing_fanout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                broadcast = post_thread(
                    state,
                    title="Explicitly routed broadcast",
                    thread_type="status",
                    actor="odin",
                    target="all",
                )
                all_route = AgentRoute("all", "hermes-webhook", "TEST_URL", "TEST_SECRET")

                result = dispatch_once(
                    state,
                    routes={"all": all_route},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    deliverer=lambda *_args, **_kwargs: AgentDeliveryResult(True, "accepted", 202, "accepted"),
                )

                self.assertFalse(result.ok)
                self.assertEqual(result.claimed, 0)
                self.assertIn("reserved for registered-agent fanout", result.configuration_errors[0])
                self.assertNotIn(broadcast.thread.id, {item.subject_id for item in project_outbox(state).values()})

    def test_noncanonical_all_route_fails_loudly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                post_thread(state, title="Broadcast", thread_type="status", actor="odin", target="all")
                route = AgentRoute("ALL", "hermes-webhook", "TEST_URL", "TEST_SECRET")

                result = dispatch_once(
                    state,
                    routes={"ALL": route},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                )

                self.assertFalse(result.ok)
                self.assertEqual(result.claimed, 0)
                self.assertIn("reserved for registered-agent fanout", result.configuration_errors[0])

    def test_route_omission_is_append_only_observable_and_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                omitted = create_task(state, "Agent route accidentally omitted", owner="vesper")

                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                )

                self.assertFalse(result.ok)
                self.assertTrue(result.materialization_remaining)
                self.assertEqual(result.skipped_unconfigured_targets, ("vesper",))
                self.assertEqual(project_materialization_skips(state)["counts"], {})
                checkpoint = project_materialization_checkpoint(state)
                self.assertFalse(checkpoint["initialized"])

                repeated = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-b",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                )
                self.assertFalse(repeated.ok)
                self.assertEqual(repeated.skipped_unconfigured_targets, ("vesper",))
                self.assertNotIn(omitted.task.id, {item.subject_id for item in project_outbox(state).values()})

                restored_route = AgentRoute("vesper", "hermes-webhook", "TEST_URL", "TEST_SECRET")
                restored = dispatch_once(
                    state,
                    routes={"amir": ROUTE, "vesper": restored_route},
                    worker="worker-c",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    deliverer=lambda *_args, **_kwargs: AgentDeliveryResult(True, "accepted", 202, "accepted"),
                )
                self.assertTrue(restored.ok)
                self.assertEqual(restored.materialized, 1)
                self.assertIn(omitted.task.id, {item.subject_id for item in project_outbox(state).values()})


    def test_missing_route_does_not_starve_later_configured_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                omitted = create_task(state, "Missing route", owner="vesper")
                ready = create_task(state, "Routable work", owner="amir")
                sent = []

                def deliver(item, *_args, **_kwargs):
                    sent.append(item.subject_id)
                    return AgentDeliveryResult(True, "accepted", 202, "accepted")

                def tick(routes):
                    return dispatch_once(
                        state, routes=routes, worker="worker-a",
                        deliver_after="2026-08-10T00:00:00Z", now=NOW,
                        clock=lambda: NOW, environ=ENV, deliverer=deliver,
                        materialization_limit=1,
                    )

                first = tick({"amir": ROUTE})
                self.assertEqual(first.delivered, 1)
                self.assertEqual(sent, [ready.task.id])
                self.assertFalse(first.ok)
                self.assertEqual(first.skipped_unconfigured_targets, ("vesper",))
                self.assertFalse(project_materialization_checkpoint(state)["initialized"])
                with patch("arvyx_control.outbox._payload_hash", side_effect=AssertionError("rehash")):
                    again = tick({"amir": ROUTE})
                self.assertEqual(again.delivered, 0)
                self.assertEqual(again.configuration_errors, ())
                self.assertEqual(sent, [ready.task.id])
                self.assertFalse(project_materialization_checkpoint(state)["initialized"])
                restored = tick({
                    "amir": ROUTE,
                    "vesper": AgentRoute("vesper", "hermes-webhook", "TEST_URL", "TEST_SECRET"),
                })
                self.assertTrue(restored.ok)
                self.assertEqual(restored.delivered, 1)
                self.assertEqual(sent, [ready.task.id, omitted.task.id])
                self.assertTrue(project_materialization_checkpoint(state)["initialized"])

    def test_stale_bootstrap_signals_failure_but_still_delivers_existing_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, Path(tmp) / "events.jsonl"):
                state, item_id = self._state_with_item(tmp)

                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-08T12:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    max_watermark_age_seconds=86400,
                    deliverer=lambda *_args, **_kwargs: AgentDeliveryResult(True, "accepted", 202, "accepted"),
                )

                self.assertEqual(result.claimed, 1)
                self.assertEqual(result.delivered, 1)
                self.assertFalse(result.ok)
                self.assertIn("bootstrap watermark is older", result.configuration_errors[0])
                self.assertEqual(project_outbox(state)[item_id].status, "delivered")

    def test_route_file_loads_secret_reference_only_session_return_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "routes.json"
            path.write_text(
                json.dumps({
                    "routes": {
                        "amir": {
                            "runtime": "hermes-webhook",
                            "url_env": "URL",
                            "credential_env": "SECRET",
                            "return_runtime": "openclaw-hook",
                            "return_url_env": "RETURN_URL",
                            "return_credential_env": "RETURN_SECRET",
                        }
                    }
                }),
                encoding="utf-8",
            )
            route = load_routes(path)["amir"]
            self.assertEqual(route.return_runtime, "openclaw-hook")
            self.assertEqual(route.return_url_env, "RETURN_URL")
            self.assertEqual(route.return_credential_env, "RETURN_SECRET")

    def test_route_file_rejects_inline_secret_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "routes.json"
            path.write_text(
                '{"routes":{"amir":{"runtime":"hermes-webhook","url_env":"URL","credential_env":"SECRET","secret":"inline"}}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "unsupported keys: secret"):
                load_routes(path)

    def test_unsafe_lease_budget_fails_before_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, Path(tmp) / "events.jsonl"):
                state, _ = self._state_with_item(tmp)
                before = len(read_events(state))
                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    limit=6,
                    lease_seconds=60,
                    environ=ENV,
                )
                self.assertEqual(result.claimed, 0)
                self.assertIn("lease_seconds must be at least 77", result.configuration_errors[0])
                self.assertEqual(len(read_events(state)), before)

    def test_per_target_cap_is_not_reported_when_nothing_was_deferred(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                for index in range(2):
                    enqueue(state, subject_id=f"task_{index}", target="amir", payload={"index": index}, now=NOW)

                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    per_target_limit=2,
                    environ=ENV,
                    deliverer=lambda *_args, **_kwargs: AgentDeliveryResult(True, "accepted", 202, "accepted"),
                )
                self.assertEqual(result.delivered, 2)
                self.assertEqual(result.capped_targets, ())

    def test_deadline_deferral_releases_lease_without_burning_failure_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, Path(tmp) / "events.jsonl"):
                state, item_id = self._state_with_item(tmp)
                late = NOW.replace(minute=1, second=49)
                times = iter((NOW, late, late))
                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: next(times),
                    lease_seconds=120,
                    environ=ENV,
                    deliverer=lambda *_args, **_kwargs: AgentDeliveryResult(True, "accepted", 202, "accepted"),
                )
                item = project_outbox(state)[item_id]
                self.assertEqual(result.deferred_to_next_tick, 1)
                self.assertEqual(item.status, "pending")
                self.assertEqual(item.failures, 0)
                self.assertIn("outbox.deferred", [event.type for event in read_events(state)])

    def test_reclaim_dead_letter_is_reported_by_tick(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, Path(tmp) / "events.jsonl"):
                state, item_id = self._state_with_item(tmp)
                claim_due(state, worker="old-worker", now=NOW, lease_seconds=1, max_attempts=1)
                later = NOW.replace(minute=1)
                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=later,
                    clock=lambda: later,
                    max_attempts=1,
                    environ=ENV,
                )
                self.assertEqual(result.claimed, 0)
                self.assertEqual(result.dead_lettered, 1)
                self.assertFalse(result.ok)
                self.assertEqual(project_outbox(state)[item_id].status, "dead_lettered")

    def test_wall_clock_expiry_prevents_late_finalization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, Path(tmp) / "events.jsonl"):
                state, item_id = self._state_with_item(tmp)
                times = iter((NOW, NOW, NOW, NOW.replace(minute=2, second=1)))
                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: next(times),
                    lease_seconds=120,
                    environ=ENV,
                    deliverer=lambda *_args, **_kwargs: AgentDeliveryResult(True, "accepted", 202, "accepted"),
                )
                self.assertEqual(result.delivered, 0)
                self.assertEqual(result.lost_leases, 1)
                self.assertEqual(project_outbox(state)[item_id].status, "leased")
                self.assertNotIn("outbox.delivered", [event.type for event in read_events(state)])

    def test_per_target_cap_is_enforced_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                for index in range(3):
                    enqueue(state, subject_id=f"task_{index}", target="amir", payload={"index": index}, now=NOW)

                def accepted(*_args, **_kwargs):
                    return AgentDeliveryResult(True, "accepted", 202, "accepted")

                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    limit=5,
                    per_target_limit=2,
                    environ=ENV,
                    deliverer=accepted,
                )
                self.assertEqual(result.claimed, 2)
                self.assertEqual(result.delivered, 2)
                self.assertEqual(result.capped_targets, ("amir",))
                self.assertEqual(len([item for item in project_outbox(state).values() if item.status == "pending"]), 1)

    def test_deliverer_exception_fences_one_item_and_continues_batch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                for index in range(2):
                    enqueue(state, subject_id=f"task_{index}", target="amir", payload={"index": index}, now=NOW)
                calls = 0

                def flaky(*_args, **_kwargs):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        raise RuntimeError("secret should not leak")
                    return AgentDeliveryResult(True, "accepted", 202, "accepted")

                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    deliverer=flaky,
                )
                self.assertEqual(calls, 2)
                self.assertEqual(result.retrying, 0)
                self.assertEqual(result.ambiguous, 1)
                self.assertEqual(result.delivered, 1)
                self.assertNotIn("secret should not leak", str(result.to_dict()))

    def test_lost_lease_does_not_abort_remaining_batch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                for index in range(2):
                    enqueue(state, subject_id=f"task_{index}", target="amir", payload={"index": index}, now=NOW)
                calls = 0

                def steals_first(*_args, **_kwargs):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        claim_due(state, worker="worker-b", now=NOW.replace(minute=2), limit=1, targets={"amir"})
                    return AgentDeliveryResult(True, "accepted", 202, "accepted")

                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    deliverer=steals_first,
                )
                self.assertEqual(calls, 2)
                self.assertEqual(result.lost_leases, 1)
                self.assertEqual(result.delivered, 1)
                self.assertEqual(len(result.processing_errors), 1)

    def test_permanent_delivery_is_dead_lettered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, Path(tmp) / "events.jsonl"):
                state, item_id = self._state_with_item(tmp)

                def permanent(*_args, **_kwargs):
                    return AgentDeliveryResult(False, "permanent", 400, "target returned HTTP 400")

                result = dispatch_once(
                    state,
                    routes={"amir": ROUTE},
                    worker="worker-a",
                    deliver_after="2026-08-10T00:00:00Z",
                    now=NOW,
                    clock=lambda: NOW,
                    environ=ENV,
                    deliverer=permanent,
                )
                self.assertFalse(result.ok)
                self.assertEqual(result.dead_lettered, 1)
                self.assertEqual(project_outbox(state)[item_id].status, "dead_lettered")


if __name__ == "__main__":
    unittest.main()
