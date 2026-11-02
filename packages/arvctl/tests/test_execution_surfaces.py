from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from arvyx_control.replica_authority import authority_context
from arvyx_control.agent_delivery import AgentRoute
from arvyx_control.api import handle_api_request
from arvyx_control.auth import issue_token
from arvyx_control.control import (
    acknowledge_thread,
    complete_thread,
    create_task,
    post_thread,
    read_events,
)
from arvyx_control.execution import claim_execution, project_executions
from arvyx_control.outbox import claim_due, enqueue, mark_delivered, record_dispatcher_tick
from arvyx_control.vault import init_vault
from arvyx_control.watchdog import run_watchdog


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)


class ExecutionSurfaceIdentityTests(unittest.TestCase):
    """Restart rediscovery and webhook-native continuation surfaces: an agent
    can list, read, and renew exactly its own execution attempt over HTTP or
    MCP, and nothing else."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.enterContext(authority_context(self.vault, self.state))
        init_vault(self.vault)
        self.demobot_token = issue_token(
            self.vault, "demobot", scopes=["control.read", "control.write"]
        ).token
        self.vesper_token = issue_token(
            self.vault, "vesper", scopes=["control.read", "control.write"]
        ).token
        self.operator_secret = "operator-shared-secret-for-tests"
        self.routes = Path(self._tmp.name) / "routes.json"
        self.routes.write_text(
            '{"routes":{"demobot":{"runtime":"hermes-webhook","url_env":"URL","credential_env":"SECRET"}}}',
            encoding="utf-8",
        )
        self._request_seq = 0
        thread = post_thread(
            self.state, title="durable work", actor="vesper", target="demobot",
            thread_type="ask", actor_identity_bound=True,
        )
        acknowledge_thread(self.state, thread.thread.id, actor="demobot", actor_identity_bound=True)
        # Claim against the wall clock so the lease is genuinely live for the
        # session-fenced heartbeat surface.
        self.execution = claim_execution(
            self.state, worker="worker-a", execution_capable_targets={"demobot"},
            now=datetime.now(timezone.utc), lease_seconds=3600,
        )
        assert self.execution is not None

    def _api(self, token: str, method: str, path: str, body: dict | None = None):
        self._request_seq += 1
        return handle_api_request(
            method=method,
            path=path,
            body=body,
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {token}",
            idempotency_key=f"execution-surface-test-{self._request_seq:04d}",
            delivery_routes=self.routes,
        )

    def _mcp(self, token: str, name: str, arguments: dict):
        self._request_seq += 1
        return handle_api_request(
            method="POST",
            path="/mcp",
            body={
                "jsonrpc": "2.0",
                "id": self._request_seq,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {token}",
            mcp_profile="agent",
            delivery_routes=self.routes,
        )

    def test_agent_lists_and_reads_only_own_executions_over_http(self) -> None:
        own = self._api(self.demobot_token, "GET", "/executions")
        self.assertEqual(
            [item["id"] for item in own.body["executions"]], [self.execution.id]
        )
        foreign_list = self._api(self.vesper_token, "GET", "/executions")
        self.assertEqual(foreign_list.body["executions"], [])
        denied = self._api(self.vesper_token, "GET", "/executions?target=demobot")
        self.assertEqual(denied.status, 403)
        exact = self._api(self.demobot_token, "GET", f"/executions/{self.execution.id}")
        self.assertEqual(exact.body["execution"]["attempt_id"], self.execution.attempt_id)
        foreign_exact = self._api(self.vesper_token, "GET", f"/executions/{self.execution.id}")
        self.assertEqual(foreign_exact.status, 403)

    def test_http_heartbeat_renews_only_for_the_bound_target(self) -> None:
        renewed = self._api(
            self.demobot_token,
            "POST",
            f"/executions/{self.execution.id}/heartbeat",
            {"attempt_id": self.execution.attempt_id, "lease_seconds": 120},
        )
        self.assertEqual(renewed.status, 200)
        self.assertEqual(renewed.body["attempt_id"], self.execution.attempt_id)
        self.assertEqual(
            project_executions(self.state)[self.execution.id].attempts, 1
        )
        foreign = self._api(
            self.vesper_token,
            "POST",
            f"/executions/{self.execution.id}/heartbeat",
            {"attempt_id": self.execution.attempt_id},
        )
        self.assertEqual(foreign.status, 400)
        self.assertIn("identity-bound target", foreign.body["error"])
        self._request_seq += 1
        operator = handle_api_request(
            method="POST",
            path=f"/executions/{self.execution.id}/heartbeat",
            body={"attempt_id": self.execution.attempt_id},
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {self.operator_secret}",
            idempotency_key=f"execution-surface-operator-{self._request_seq:04d}",
            delivery_routes=self.routes,
        )
        self.assertEqual(operator.status, 403)
        stale = self._api(
            self.demobot_token,
            "POST",
            f"/executions/{self.execution.id}/heartbeat",
            {"attempt_id": "attempt_forged000000000000"},
        )
        self.assertEqual(stale.status, 400)
        self.assertIn("stale", stale.body["error"])

    def test_restart_rediscovery_lists_leased_work_then_resumes_exact_attempt(self) -> None:
        # A restarted runtime that lost its wake payload rediscovers the live
        # execution by listing leased work, then renews the exact attempt.
        listed = self._api(self.demobot_token, "GET", "/executions?status=leased")
        self.assertEqual(
            [(item["id"], item["attempt_id"]) for item in listed.body["executions"]],
            [(self.execution.id, self.execution.attempt_id)],
        )
        resumed = self._api(
            self.demobot_token,
            "POST",
            f"/executions/{self.execution.id}/heartbeat",
            {"attempt_id": self.execution.attempt_id},
        )
        self.assertEqual(resumed.status, 200)
        self.assertEqual(
            project_executions(self.state)[self.execution.id].attempts, 1
        )

    def test_operator_health_replay_and_hold_surfaces(self) -> None:
        agent_denied = self._api(self.demobot_token, "GET", "/executions/health")
        self.assertEqual(agent_denied.status, 403)
        operator_health = self._operator("GET", "/executions/health")
        self.assertEqual(operator_health.status, 200)
        # The fixture lease is live against the wall clock: no ACK gap, one
        # live execution, and the watchdog has never ticked.
        self.assertEqual(operator_health.body["acked_without_live_execution_count"], 0)
        self.assertEqual(operator_health.body["live_execution_count"], 1)
        self.assertIn("held_count", operator_health.body)
        self.assertFalse(operator_health.body["watchdog"]["initialized"])

        replay_denied = self._api(
            self.demobot_token, "POST", f"/executions/{self.execution.id}/replay", {}
        )
        self.assertEqual(replay_denied.status, 403)
        replay_wrong_state = self._operator(
            "POST", f"/executions/{self.execution.id}/replay", {}
        )
        self.assertEqual(replay_wrong_state.status, 400)
        self.assertIn("not dead-lettered or held", replay_wrong_state.body["error"])

        hold_denied = self._api(
            self.demobot_token, "POST", f"/executions/{self.execution.id}/hold",
            {"reason": "triage"},
        )
        self.assertEqual(hold_denied.status, 403)
        held = self._operator(
            "POST", f"/executions/{self.execution.id}/hold", {"reason": "manual triage"}
        )
        self.assertEqual(held.status, 200)
        self.assertEqual(held.body["status"], "held")
        replayed = self._operator(
            "POST", f"/executions/{self.execution.id}/replay", {}
        )
        self.assertEqual(replayed.status, 201)
        self.assertEqual(replayed.body["status"], "pending")
        self.assertEqual(replayed.body["attempts"], 0)

    def test_operator_closes_held_execution_and_agents_cannot(self) -> None:
        held = self._operator(
            "POST", f"/executions/{self.execution.id}/hold",
            {"reason": "superseded canary"},
        )
        self.assertEqual(held.status, 200)
        self.assertEqual(held.body["status"], "held")

        denied = self._api(
            self.demobot_token, "POST", f"/executions/{self.execution.id}/close",
            {"resolution_category": "superseded", "reason": "not mine to close"},
        )
        self.assertEqual(denied.status, 403)

        bad_category = self._operator(
            "POST", f"/executions/{self.execution.id}/close",
            {"resolution_category": "nonsense", "reason": "bad category"},
        )
        self.assertEqual(bad_category.status, 400)
        self.assertIn("unknown resolution category", bad_category.body["error"])

        closed = self._operator(
            "POST", f"/executions/{self.execution.id}/close",
            {
                "resolution_category": "superseded",
                "reason": "superseded by a fresh post-rollout canary",
            },
        )
        self.assertEqual(closed.status, 200)
        self.assertEqual(closed.body["status"], "closed")
        self.assertEqual(closed.body["resolution_category"], "superseded")
        self.assertEqual(closed.body["closed_by"], "operator")

        health = self._operator("GET", "/executions/health")
        self.assertEqual(health.status, 200)
        self.assertEqual(health.body["held_count"], 0)
        self.assertEqual(health.body["closed_count"], 1)
        self.assertEqual(health.body["acked_without_live_execution_count"], 0)
        self.assertEqual(health.body["assigned_without_live_execution"], [])

    def _operator(self, method: str, path: str, body: dict | None = None, *, idempotency_key: str | None = None):
        self._request_seq += 1
        return handle_api_request(
            method=method,
            path=path,
            body=body,
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {self.operator_secret}",
            idempotency_key=idempotency_key or f"execution-operator-test-{self._request_seq:04d}",
            delivery_routes=self.routes,
        )

    def test_operator_close_rejects_unknown_body_keys(self) -> None:
        held = self._operator(
            "POST", f"/executions/{self.execution.id}/hold",
            {"reason": "superseded canary"},
        )
        self.assertEqual(held.status, 200)
        unknown_key = self._operator(
            "POST", f"/executions/{self.execution.id}/close",
            {
                "resolution_category": "superseded",
                "reason": "superseded canary",
                "closed_by": "someone-else",
            },
        )
        self.assertEqual(unknown_key.status, 400)
        self.assertIn("close body", unknown_key.body["error"])
        missing_category = self._operator(
            "POST", f"/executions/{self.execution.id}/close", {"reason": "no category"},
        )
        self.assertEqual(missing_category.status, 400)
        self.assertIn("close body", missing_category.body["error"])
        self.assertEqual(
            project_executions(self.state)[self.execution.id].status, "held"
        )

    def test_operator_close_requires_the_canonical_resolution_category(self) -> None:
        held = self._operator(
            "POST", f"/executions/{self.execution.id}/hold",
            {"reason": "superseded canary"},
        )
        self.assertEqual(held.status, 200)
        # Case is part of the contract: the CLI choices and the sibling
        # operator-resolution route accept only the canonical lowercase
        # categories, so a shouted category must not be silently normalised
        # into a different recorded resolution than the caller asked for.
        shouted = self._operator(
            "POST", f"/executions/{self.execution.id}/close",
            {"resolution_category": "SUPERSEDED", "reason": "shouting"},
        )
        self.assertEqual(shouted.status, 400)
        self.assertIn("unknown resolution category", shouted.body["error"])
        self.assertEqual(
            project_executions(self.state)[self.execution.id].status, "held"
        )

    def test_operator_close_conflicting_repeat_is_refused_over_http(self) -> None:
        held = self._operator(
            "POST", f"/executions/{self.execution.id}/hold",
            {"reason": "superseded canary"},
        )
        self.assertEqual(held.status, 200)
        closed = self._operator(
            "POST", f"/executions/{self.execution.id}/close",
            {
                "resolution_category": "superseded",
                "reason": "superseded by a fresh post-rollout canary",
            },
        )
        self.assertEqual(closed.status, 200)
        conflict = self._operator(
            "POST", f"/executions/{self.execution.id}/close",
            {"resolution_category": "obsolete", "reason": "reclassification"},
        )
        self.assertEqual(conflict.status, 400)
        self.assertIn("already closed as superseded", conflict.body["error"])
        self.assertEqual(
            project_executions(self.state)[self.execution.id].resolution_category,
            "superseded",
        )
        self.assertEqual(
            len([event for event in read_events(self.state) if event.type == "execution.closed"]),
            1,
        )

    def test_close_retry_with_the_same_idempotency_key_does_not_settle_twice(self) -> None:
        held = self._operator(
            "POST", f"/executions/{self.execution.id}/hold",
            {"reason": "superseded canary"},
        )
        self.assertEqual(held.status, 200)
        body = {
            "resolution_category": "superseded",
            "reason": "superseded by a fresh post-rollout canary",
        }
        key = "close-idempotency-surface-test"
        first = self._operator(
            "POST", f"/executions/{self.execution.id}/close", body, idempotency_key=key,
        )
        self.assertEqual(first.status, 200)
        self.assertEqual(first.body["status"], "closed")
        retry = self._operator(
            "POST", f"/executions/{self.execution.id}/close", body, idempotency_key=key,
        )
        self.assertNotEqual(retry.status, 200)
        self.assertEqual(
            len([event for event in read_events(self.state) if event.type == "execution.closed"]),
            1,
        )
        projected = project_executions(self.state)[self.execution.id]
        self.assertEqual(projected.status, "closed")
        self.assertEqual(projected.resolution_category, "superseded")
        self.assertEqual(projected.closed_at, first.body["closed_at"])

    def test_close_accepts_a_body_supplied_idempotency_key(self) -> None:
        """The dashboard sends every execution mutation with the key in the
        body (static/index.html). The platform claims that key before the route
        handler runs, so a body allowlist that rejected it answered 400 after
        the claim was durable: the closure never happened and the caller's
        retry with the same key came back as a no-replay conflict."""
        held = self._operator(
            "POST", f"/executions/{self.execution.id}/hold",
            {"reason": "superseded canary"},
        )
        self.assertEqual(held.status, 200)
        key = "close-body-idempotency-key-test"
        body = {
            "resolution_category": "superseded",
            "reason": "superseded by a fresh post-rollout canary",
            "idempotency_key": key,
        }
        closed = self._body_key_operator(
            "POST", f"/executions/{self.execution.id}/close", body
        )
        self.assertEqual(closed.status, 200)
        self.assertEqual(closed.body["status"], "closed")
        self.assertEqual(closed.body["resolution_category"], "superseded")
        retry = self._body_key_operator(
            "POST", f"/executions/{self.execution.id}/close", body
        )
        self.assertEqual(retry.status, 409)
        self.assertEqual(retry.body["error"], "operation_completed_no_replay")
        self.assertEqual(
            len([event for event in read_events(self.state) if event.type == "execution.closed"]),
            1,
        )

    def _body_key_operator(self, method: str, path: str, body: dict):
        """Operator call that carries its idempotency key in the body only."""
        return handle_api_request(
            method=method,
            path=path,
            body=body,
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {self.operator_secret}",
            idempotency_key=None,
            delivery_routes=self.routes,
        )

    def test_mcp_execution_list_is_target_scoped(self) -> None:
        listed = self._mcp(self.demobot_token, "control.execution_list", {})
        listed_rpc = listed.body if isinstance(listed.body, dict) else json.loads(listed.body)
        self.assertNotIn("error", listed_rpc)
        structured = listed_rpc["result"]["structuredContent"]
        self.assertEqual(
            [item["id"] for item in structured["executions"]], [self.execution.id]
        )
        foreign = self._mcp(self.vesper_token, "control.execution_list", {})
        foreign_rpc = foreign.body if isinstance(foreign.body, dict) else json.loads(foreign.body)
        self.assertEqual(
            foreign_rpc["result"]["structuredContent"]["executions"], []
        )
        cross = self._mcp(self.vesper_token, "control.execution_list", {"target": "demobot"})
        cross_rpc = cross.body if isinstance(cross.body, dict) else json.loads(cross.body)
        self.assertIn("error", cross_rpc)
        self.assertIn("may only access its own inbox", cross_rpc["error"]["message"])


class FleetVerdictTests(unittest.TestCase):
    """The headline fleet verdict must be fail-closed: an empty inbox or an
    empty outbox never masks a red lifecycle layer."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.enterContext(authority_context(self.vault, self.state))
        init_vault(self.vault)
        self.operator_secret = "operator-shared-secret-for-tests"
        self.routes = Path(self._tmp.name) / "routes.json"
        self.routes.write_text(
            '{"routes":{"demobot":{"runtime":"hermes-webhook","url_env":"URL","credential_env":"SECRET"}}}',
            encoding="utf-8",
        )
        self._request_seq = 0
        thread = post_thread(
            self.state, title="fleet verdict work", actor="vesper", target="demobot",
            thread_type="ask", actor_identity_bound=True,
        )
        self.subject_id = thread.thread.id
        acknowledge_thread(self.state, self.subject_id, actor="demobot", actor_identity_bound=True)
        self.execution = claim_execution(
            self.state, worker="worker-a", execution_capable_targets={"demobot"},
            now=NOW, lease_seconds=60,
        )
        assert self.execution is not None
        self.watchdog_routes = {"demobot": AgentRoute("demobot", "hermes-webhook", "URL", "SECRET")}
        self.watchdog_env = {"URL": "https://runtime.invalid/hook", "SECRET": "secret-material"}

    def _operator(self, method: str, path: str, body: dict | None = None, *, routes: Path | None = None):
        self._request_seq += 1
        return handle_api_request(
            method=method,
            path=path,
            body=body,
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {self.operator_secret}",
            idempotency_key=f"fleet-verdict-test-{self._request_seq:04d}",
            delivery_routes=routes or self.routes,
        )

    def _close_execution_and_delivery_layers(self) -> None:
        current = datetime.now(timezone.utc)
        complete_thread(self.state, self.subject_id, actor="demobot", actor_identity_bound=True)
        create_task(self.state, "Fresh checkpoint", owner="demobot")
        claim_due(
            self.state, worker="materializer", now=current,
            deliver_after="2026-08-20T11:59:00Z",
        )
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=current)

    def test_fleet_verdict_is_red_while_execution_or_delivery_layers_are_red(self) -> None:
        # Fixture state against the wall clock: the past ACK has no live
        # execution and the dispatcher has never ticked - both actionable.
        verdict = self._operator("GET", "/fleet/health")
        self.assertEqual(verdict.status, 200)
        self.assertEqual(verdict.body["verdict"], "red")
        self.assertIn("acked_without_live_execution", verdict.body["red"])
        self.assertIn("delivery_attention", verdict.body["red"])
        self.assertIn("watchdog_uninitialized", verdict.body["amber"])
        plane = self._operator("GET", "/control-plane")
        self.assertEqual(plane.body["fleet"]["verdict"], "red")

    def test_missing_route_configuration_is_red_not_silent(self) -> None:
        broken = self._operator(
            "GET", "/fleet/health", routes=Path(self._tmp.name) / "missing-routes.json",
        )
        self.assertEqual(broken.status, 200)
        self.assertEqual(broken.body["verdict"], "red")
        self.assertIn("route_configuration_unavailable", broken.body["red"])

    def test_fleet_verdict_goes_green_only_when_every_layer_affirms(self) -> None:
        self._close_execution_and_delivery_layers()
        report = run_watchdog(
            self.state, routes=self.watchdog_routes,
            now=datetime.now(timezone.utc), environ=self.watchdog_env, escalate=False,
        )
        self.assertTrue(report["ok"])
        verdict = self._operator("GET", "/fleet/health")
        self.assertEqual(verdict.body["red"], [])
        self.assertEqual(verdict.body["amber"], [])
        self.assertEqual(verdict.body["verdict"], "green")

    def test_a_long_watchdog_tick_stamps_writes_when_they_are_appended(self) -> None:
        """An event written late in a long tick must not appear older than a cause
        appended while the tick was running.

        Watchdog ticks take tens of seconds (probes plus remediation). Stamping
        every write with the tick's start time made execution events look older
        than the `thread.created` that caused them, so ordering by timestamp
        contradicted the log.
        """
        start = datetime.now(timezone.utc)
        advancing = iter(
            [start + timedelta(seconds=offset) for offset in (30, 60, 90, 120, 150)]
        )

        def clock() -> datetime:
            return next(advancing, start + timedelta(seconds=180))

        post_thread(
            self.state,
            title="late arrival",
            actor="vesper",
            target="demobot",
            thread_type="ask",
            actor_identity_bound=True,
        )
        run_watchdog(
            self.state,
            routes=self.watchdog_routes,
            now=None,
            clock=clock,
            environ=self.watchdog_env,
            escalate=False,
        )

        created = [event for event in read_events(self.state) if event.type == "execution.created"]
        self.assertTrue(created, "the watchdog did not materialise an execution")
        stamp = datetime.fromisoformat(str(created[-1].timestamp).replace("Z", "+00:00"))
        # The stamp must come from the write-time clock, not from the tick's
        # reference time. Asserting against the injected clock values (rather than
        # only "later than the tick start") is what makes this fail when the write
        # sites go back to `now=current`: the tick reference is `start` itself.
        self.assertGreaterEqual(
            (stamp - start).total_seconds(),
            30,
            "the write was stamped with the tick's start time instead of its append time",
        )
        self.assertIn(
            (stamp - start).total_seconds(),
            {30.0, 60.0, 90.0, 120.0, 150.0, 180.0},
            "the write was not stamped from the injected write clock",
        )
        # the injected-clock path stays deterministic: an explicit `now` still pins it
        pinned = run_watchdog(
            self.state, routes=self.watchdog_routes, now=NOW, environ=self.watchdog_env, escalate=False
        )
        self.assertTrue(pinned["ok"] or not pinned["ok"])  # tick ran; stamps pinned below
        tick_events = [
            event for event in read_events(self.state) if event.type == "execution.watchdog.tick"
        ]
        self.assertEqual(str(tick_events[-1].timestamp), NOW.isoformat().replace("+00:00", "Z"))

    def test_watchdog_attention_degrades_to_amber_even_with_clean_queues(self) -> None:
        self._close_execution_and_delivery_layers()
        # Begin receipt enforcement, then create a receipt-less delivery after
        # that boundary. Clean pre-enforcement history must not degrade fleet
        # health, while a new stale delivery still must.
        baseline = run_watchdog(
            self.state, routes=self.watchdog_routes,
            now=NOW, environ=self.watchdog_env, escalate=False,
        )
        self.assertNotIn("delivered_without_receipt", baseline["attention"])
        stale_item = enqueue(
            self.state, subject_id="thread_receiptless", target="demobot",
            payload={"source_event_id": "event_x", "source_event_type": "thread.created"},
            now=NOW + timedelta(seconds=1),
        )
        delivery_claims = claim_due(self.state, worker="worker-b", now=NOW + timedelta(seconds=1))
        mark_delivered(
            self.state, outbox_id=stale_item.id, worker="worker-b", claim_attempts=next(c.attempts for c in delivery_claims if c.id == stale_item.id),
            now=NOW + timedelta(seconds=1),
        )
        report = run_watchdog(
            self.state, routes=self.watchdog_routes,
            now=NOW + timedelta(seconds=1001), environ=self.watchdog_env, escalate=False,
        )
        self.assertIn("delivered_without_receipt", report["attention"])
        verdict = self._operator("GET", "/fleet/health")
        self.assertEqual(verdict.body["red"], [])
        self.assertIn("watchdog_attention", verdict.body["amber"])
        self.assertEqual(verdict.body["verdict"], "amber")

    def test_dashboard_carries_the_fleet_verdict_surfaces(self) -> None:
        html = (
            Path(__file__).resolve().parents[1]
            / "src" / "arvyx_control" / "static" / "index.html"
        ).read_text(encoding="utf-8")
        self.assertIn('id="metric-fleet"', html)
        self.assertIn("Fleet verdict", html)
        self.assertIn("global source · not filtered by squad desks", html)
        self.assertIn("Global verdict · green", html)
        self.assertIn("Global verdict · red", html)
        self.assertNotIn("Fleet nominal · live", html)
        self.assertIn(".dot.warn", html)
        # Reachability alone must never render the green headline again.
        self.assertNotIn('setText("freshness-label", "Live · bounded polling")', html)


if __name__ == "__main__":
    unittest.main()
