from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import uuid
from pathlib import Path
import tempfile
import unittest

from arvyx_control.replica_authority import authority_context
from arvyx_control.api import handle_api_request
from arvyx_control.auth import issue_token, tools_for_scopes
from arvyx_control.control import create_task, post_thread, read_events
from arvyx_control.outbox import (
    claim_due,
    enqueue,
    mark_delivered,
    mark_delivery_ambiguous,
    project_outbox,
    reconcile_ambiguous_delivery,
    record_dispatcher_tick,
    record_failure,
)
from arvyx_control.mcp import handle_request
from arvyx_control.vault import init_vault


NOW = datetime(2026, 8, 10, 12, 0, tzinfo=timezone.utc)


class DeliveryApiIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.enterContext(authority_context(self.vault, self.state))
        init_vault(self.vault)
        scopes = ["control.delivery"]
        self.demobot_token = issue_token(self.vault, "demobot", scopes=scopes).token
        self.vesper_token = issue_token(self.vault, "vesper", scopes=scopes).token
        self.demobot_control_token = issue_token(
            self.vault, "demobot", scopes=["control.read"], slot="control-read"
        ).token
        self.vesper_control_token = issue_token(
            self.vault, "vesper", scopes=["control.read"], slot="control-read"
        ).token
        self.operator_secret = "operator-shared-secret-for-tests"
        self.routes = Path(self._tmp.name) / "routes.json"
        self.routes.write_text(
            '{"routes":{"demobot":{"runtime":"hermes-webhook","url_env":"URL","credential_env":"SECRET"}}}',
            encoding="utf-8",
        )
        self._request_seq = 0
        self.item = enqueue(
            self.state,
            subject_id="handoff_1",
            target="demobot",
            payload={"source_event_id": "event_1", "source_event_type": "handoff.created"},
            now=NOW,
        )
        delivery_claims = claim_due(self.state, worker="worker-a", now=NOW)
        mark_delivered(self.state, outbox_id=self.item.id, worker="worker-a", claim_attempts=next(c.attempts for c in delivery_claims if c.id == self.item.id), now=NOW)


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
            idempotency_key=f"delivery-receipt-test-{self._request_seq:04d}",
            delivery_routes=self.routes,
        )

    def test_body_supplied_idempotency_key_is_platform_metadata_for_resolve_and_cancel(self) -> None:
        """Every operator delivery mutation must treat a body-supplied
        `idempotency_key` as platform metadata. The key is claimed before the
        handler runs, so a body allowlist that rejected it turned a valid call
        into a 400 with the key already burned."""
        failed = self._dead_letter()
        resolve_body = {
            "resolution_category": "obsolete",
            "detail": "superseded canary from the v1 era",
            "idempotency_key": "resolve-body-idempotency-key-test",
        }
        resolved = self._body_key_api(
            self.operator_secret, "POST", f"/deliveries/{failed.id}/resolve", resolve_body
        )
        self.assertEqual(resolved.status, 200)
        self.assertEqual(resolved.body["resolution_category"], "obsolete")
        resolve_retry = self._body_key_api(
            self.operator_secret, "POST", f"/deliveries/{failed.id}/resolve", resolve_body
        )
        self.assertEqual(resolve_retry.status, 409)
        self.assertEqual(resolve_retry.body["error"], "operation_completed_no_replay")

        pending = enqueue(self.state, subject_id="legacy", target="operator", payload={}, now=NOW)
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=datetime.now(timezone.utc))
        cancel_body = {
            "reason_category": "unroutable_target",
            "idempotency_key": "cancel-body-idempotency-key-test",
        }
        cancelled = self._body_key_api(
            self.operator_secret, "POST", f"/deliveries/{pending.id}/cancel", cancel_body
        )
        self.assertEqual(cancelled.status, 200)
        self.assertEqual(cancelled.body["status"], "cancelled")
        self.assertEqual(
            len([event for event in read_events(self.state) if event.type == "outbox.cancelled"]),
            1,
        )

    def _body_key_api(self, token: str, method: str, path: str, body: dict):
        """Call that carries its idempotency key in the body only."""
        return handle_api_request(
            method=method,
            path=path,
            body=body,
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {token}",
            idempotency_key=None,
            delivery_routes=self.routes,
        )

    def test_agent_lists_only_own_deliveries(self) -> None:
        own = self._api(self.demobot_token, "GET", "/deliveries")
        foreign = self._api(self.vesper_token, "GET", "/deliveries")
        self.assertEqual([item["id"] for item in own.body["deliveries"]], [self.item.id])
        self.assertEqual(foreign.body["deliveries"], [])
        denied = self._api(self.vesper_token, "GET", "/deliveries?target=demobot")
        self.assertEqual(denied.status, 403)

    def test_delivery_scope_does_not_grant_approval_or_general_control_authority(self) -> None:
        allowed = set(tools_for_scopes(frozenset({"control.delivery"})))
        self.assertEqual(
            allowed,
            {"control.delivery_get", "control.delivery_list", "control.delivery_receipt"},
        )
        self.assertNotIn("control.approval_approve", allowed)
        denied = self._api(self.demobot_token, "POST", "/approvals/approval_1/approve", {})
        self.assertEqual(denied.status, 403)
        self.assertEqual(self._api(self.demobot_token, "GET", "/tasks").status, 403)

    def test_target_agent_writes_seen_accepted_completed_progression(self) -> None:
        seen = self._api(
            self.demobot_token,
            "POST",
            f"/deliveries/{self.item.id}/receipt",
            {"status": "seen"},
        )
        self.assertEqual(seen.status, 200)
        self.assertEqual(seen.body["receipt_status"], "seen")
        accepted = self._api(
            self.demobot_token,
            "POST",
            f"/deliveries/{self.item.id}/receipt",
            {"status": "accepted"},
        )
        self.assertEqual(accepted.body["receipt_status"], "accepted")
        completed = self._api(
            self.demobot_token,
            "POST",
            f"/deliveries/{self.item.id}/receipt",
            {"status": "completed", "detail": "work completed"},
        )
        self.assertEqual(completed.body["receipt_status"], "completed")
        self.assertEqual(completed.body["receipt_by"], "demobot")
        self.assertEqual(completed.body["receipt_detail"], "work completed")

    def test_mcp_exact_reads_are_state_invariant_and_need_no_idempotency_key(self) -> None:
        pending = enqueue(
            self.state,
            subject_id="handoff_pending",
            target="demobot",
            payload={"source_event_id": "event_pending", "source_event_type": "handoff.created"},
            now=NOW,
        )
        calls = (
            ("control.delivery_list", {}, self.demobot_token, "deliveries", pending.id),
            ("control.delivery_get", {"delivery_id": pending.id}, self.demobot_token, "delivery", pending.id),
        )
        for index, (name, arguments, token, result_key, expected_id) in enumerate(calls, start=1):
            with self.subTest(name=name):
                state_before = self.state.read_bytes()
                response = handle_api_request(
                    method="POST",
                    path="/mcp",
                    body={
                        "jsonrpc": "2.0",
                        "id": index,
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

                self.assertEqual(response.status, 200)
                rpc_response = json.loads(response.body) if isinstance(response.body, str) else response.body
                self.assertNotIn("error", rpc_response)
                rpc_result = rpc_response["result"]
                if isinstance(rpc_result, str):
                    rpc_result = json.loads(rpc_result)
                self.assertNotIn("error", rpc_result)
                structured = rpc_result["structuredContent"]
                if result_key == "deliveries":
                    self.assertIn(expected_id, [item["id"] for item in structured[result_key]])
                else:
                    self.assertEqual(structured[result_key]["id"], expected_id)
                self.assertEqual(self.state.read_bytes(), state_before)

        foreign = handle_api_request(
            method="POST",
            path="/mcp",
            body={
                "jsonrpc": "2.0",
                "id": 20,
                "method": "tools/call",
                "params": {"name": "control.delivery_get", "arguments": {"delivery_id": pending.id}},
            },
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {self.vesper_token}",
            mcp_profile="agent",
            delivery_routes=self.routes,
        )
        self.assertEqual(foreign.status, 200)
        foreign_rpc = json.loads(foreign.body) if isinstance(foreign.body, str) else foreign.body
        self.assertIn("error", foreign_rpc)
        self.assertIn("may only read its own deliveries", foreign_rpc["error"]["message"])

        thread = post_thread(
            state=self.state,
            title="Exact read canary",
            actor="operator",
            target="demobot",
        ).thread
        state_before = self.state.read_bytes()
        response = handle_api_request(
            method="POST",
            path="/mcp",
            body={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "control.thread_get", "arguments": {"thread_id": thread.id}},
            },
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {self.demobot_control_token}",
            mcp_profile="agent",
            delivery_routes=self.routes,
        )
        self.assertEqual(response.status, 200)
        rpc_response = json.loads(response.body) if isinstance(response.body, str) else response.body
        self.assertNotIn("error", rpc_response)
        rpc_result = rpc_response["result"]
        if isinstance(rpc_result, str):
            rpc_result = json.loads(rpc_result)
        self.assertNotIn("error", rpc_result)
        self.assertEqual(rpc_result["structuredContent"]["thread"]["id"], thread.id)
        self.assertEqual(self.state.read_bytes(), state_before)

        foreign_thread = handle_api_request(
            method="POST",
            path="/mcp",
            body={
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {"name": "control.thread_get", "arguments": {"thread_id": thread.id}},
            },
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {self.vesper_control_token}",
            mcp_profile="agent",
            delivery_routes=self.routes,
        )
        self.assertEqual(foreign_thread.status, 200)
        foreign_rpc = json.loads(foreign_thread.body) if isinstance(foreign_thread.body, str) else foreign_thread.body
        self.assertIn("error", foreign_rpc)
        self.assertIn("not permitted", foreign_rpc["error"]["message"])

    def test_mcp_delivery_receipt_still_requires_idempotency_key(self) -> None:
        state_before = self.state.read_bytes()
        response = handle_api_request(
            method="POST",
            path="/mcp",
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "control.delivery_receipt",
                    "arguments": {"delivery_id": self.item.id, "status": "seen"},
                },
            },
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {self.demobot_token}",
            mcp_profile="agent",
            delivery_routes=self.routes,
        )
        self.assertEqual(response.status, 428)
        # HTTP MCP admission failures are JSON-RPC envelopes correlated to the
        # current request (REV-0535), not REST error dictionaries.
        rpc = json.loads(response.body) if isinstance(response.body, str) else response.body
        self.assertEqual(rpc["jsonrpc"], "2.0")
        self.assertEqual(rpc["id"], 1)
        self.assertNotIn("result", rpc)
        self.assertEqual(rpc["error"]["message"], "idempotency_key_required")
        self.assertEqual(rpc["error"]["data"]["error"], "idempotency_key_required")
        self.assertEqual(self.state.read_bytes(), state_before)

    def test_mcp_binds_delivery_list_and_receipt_to_actor(self) -> None:
        allowed = {"control.delivery_get", "control.delivery_list", "control.delivery_receipt"}
        exact = handle_request(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "tools/call",
                "params": {"name": "control.delivery_get", "arguments": {"delivery_id": self.item.id}},
            },
            vault=self.vault,
            state=self.state,
            allowed_tools=allowed,
            actor="demobot",
        )
        self.assertEqual(exact["result"]["structuredContent"]["delivery"]["id"], self.item.id)
        denied_exact = handle_request(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "tools/call",
                "params": {"name": "control.delivery_get", "arguments": {"delivery_id": self.item.id}},
            },
            vault=self.vault,
            state=self.state,
            allowed_tools=allowed,
            actor="vesper",
        )
        self.assertIn("may only read its own deliveries", denied_exact["error"]["message"])
        unknown_exact = handle_request(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "tools/call",
                "params": {"name": "control.delivery_get", "arguments": {"delivery_id": "outbox_missing"}},
            },
            vault=self.vault,
            state=self.state,
            allowed_tools=allowed,
            actor="demobot",
        )
        self.assertIn("unknown delivery", unknown_exact["error"]["message"])
        listed = handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "control.delivery_list", "arguments": {}}},
            vault=self.vault,
            state=self.state,
            allowed_tools=allowed,
            actor="demobot",
        )
        self.assertEqual([item["id"] for item in listed["result"]["structuredContent"]["deliveries"]], [self.item.id])
        foreign = handle_request(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "control.delivery_list", "arguments": {}}},
            vault=self.vault,
            state=self.state,
            allowed_tools=allowed,
            actor="vesper",
        )
        self.assertEqual(foreign["result"]["structuredContent"]["deliveries"], [])
        receipt = handle_request(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "control.delivery_receipt",
                    "arguments": {"delivery_id": self.item.id, "status": "seen", "actor": "vesper",
                                  "idempotency_key": "receipt-bound-demobot-0001"},
                },
            },
            vault=self.vault,
            state=self.state,
            allowed_tools=allowed,
            actor="demobot",
        )
        self.assertEqual(receipt["result"]["structuredContent"]["receipt_by"], "demobot")
        unbound = handle_request(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "control.delivery_receipt",
                    "arguments": {"delivery_id": self.item.id, "status": "accepted", "actor": "demobot",
                                  "idempotency_key": "receipt-unbound-actor-" + uuid.uuid4().hex},
                },
            },
            vault=self.vault,
            state=self.state,
            allowed_tools=allowed,
            actor=None,
        )
        self.assertIn("authenticated agent actor is required", unbound["error"]["message"])

    def test_foreign_agent_and_operator_cannot_impersonate_receipt_actor(self) -> None:
        foreign = self._api(
            self.vesper_token,
            "POST",
            f"/deliveries/{self.item.id}/receipt",
            {"status": "seen"},
        )
        self.assertEqual(foreign.status, 400)
        self.assertIn("actor does not match", foreign.body["error"])
        operator = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{self.item.id}/receipt",
            {"status": "seen", "actor": "demobot"},
        )
        self.assertEqual(operator.status, 403)
        self.assertIn("agent identity required", operator.body["error"])

    def _dead_letter(self):
        failed = enqueue(
            self.state,
            subject_id="task_failed",
            target="demobot",
            payload={"source_event_type": "task.created"},
            now=NOW,
        )
        delivery_claims = claim_due(self.state, worker="worker-b", now=NOW)
        return record_failure(
            self.state,
            outbox_id=failed.id,
            worker="worker-b", claim_attempts=next(c.attempts for c in delivery_claims if c.id == failed.id),
            detail="invalid payload",
            transient=False,
            now=NOW,
        )

    def test_operator_can_inspect_delivery_health_and_dead_letters(self) -> None:
        failed = self._dead_letter()

        health = self._api(self.operator_secret, "GET", "/deliveries/health")
        dead_letters = self._api(self.operator_secret, "GET", "/deliveries/dead-letter")

        self.assertEqual(health.status, 200)
        self.assertEqual(health.body["counts"], {"dead_lettered": 1, "delivered": 1, "total": 2})
        self.assertEqual(health.body["ok"], False)
        self.assertEqual([item["id"] for item in dead_letters.body["deliveries"]], [failed.id])
        self.assertNotIn("payload", dead_letters.body["deliveries"][0])

    def test_ambiguous_delivery_is_visible_in_health_attention(self) -> None:
        current = datetime.now(timezone.utc)
        item = enqueue(
            self.state,
            subject_id="session_return_ambiguous",
            target="demobot",
            payload={"delivery_mode": "session_return"},
            now=current,
        )
        delivery_claims = claim_due(self.state, worker="worker-b", now=current)
        mark_delivery_ambiguous(
            self.state,
            outbox_id=item.id,
            worker="worker-b", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id),
            detail="provider receipt unavailable",
            now=current,
        )
        create_task(self.state, "Checkpoint", owner="demobot")
        claim_due(
            self.state,
            worker="materializer",
            now=current,
            deliver_after="2026-08-10T11:59:00Z",
        )
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=current)

        health = self._api(self.operator_secret, "GET", "/deliveries/health")

        self.assertFalse(health.body["ok"])
        self.assertEqual(health.body["ambiguous_delivery_count"], 1)
        self.assertIn("ambiguous_delivery", health.body["attention"])

    def test_ambiguous_not_delivered_can_be_reclassified_terminally(self) -> None:
        """A recorded `ambiguous_not_delivered` needs an operator closure path.

        The transport outcome could not be verified, and when the originating
        attempt has ended the replay gate refuses the item; without a terminal
        re-classification the dead letter can only stay unresolved forever and
        delivery health can never clear. The prior category stays on the record.
        """
        current = datetime.now(timezone.utc)
        item = enqueue(
            self.state,
            subject_id="session_return_ambiguous_closure",
            target="demobot",
            payload={"delivery_mode": "session_return"},
            now=current,
        )
        delivery_claims = claim_due(self.state, worker="worker-b", now=current)
        mark_delivery_ambiguous(
            self.state,
            outbox_id=item.id,
            worker="worker-b", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id),
            detail="provider receipt unavailable",
            now=current,
        )
        reconciled = reconcile_ambiguous_delivery(
            self.state,
            outbox_id=item.id,
            resolved_by="operator",
            outcome="not_delivered",
            provider_receipt="",
            detail="transport outcome unverifiable",
        )
        self.assertEqual(reconciled.resolution_category, "ambiguous_not_delivered")
        create_task(self.state, "Checkpoint", owner="demobot")
        claim_due(
            self.state,
            worker="materializer",
            now=current,
            # derive the boundary from the same clock as `now`: a pinned past
            # literal would date-rot if the checkpoint age check ever returns.
            deliver_after=(current - timedelta(minutes=1)).isoformat(),
        )
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=current)

        before = self._api(self.operator_secret, "GET", "/deliveries/health")
        self.assertEqual(before.body["unresolved_dead_letters"], 1)
        self.assertFalse(before.body["ok"])

        closed = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{item.id}/resolve",
            {"resolution_category": "obsolete", "detail": "originating attempt has ended"},
        )
        self.assertEqual(closed.status, 200)
        self.assertEqual(closed.body["resolution_category"], "obsolete")
        self.assertEqual(closed.body["prior_resolution_category"], "ambiguous_not_delivered")

        # the field must survive a projection rebuild, not only the live object
        rebuilt = project_outbox(self.state)[item.id]
        self.assertEqual(rebuilt.prior_resolution_category, "ambiguous_not_delivered")
        self.assertEqual(rebuilt.resolution_detail, "originating attempt has ended")

        # and the browse surface must render it, or a reclassified item looks
        # identical to one resolved on the first try
        listed = self._api(self.operator_secret, "GET", "/deliveries/dead-letter")
        summary = next(row for row in listed.body["deliveries"] if row["id"] == item.id)
        self.assertEqual(summary["resolution_category"], "obsolete")
        self.assertEqual(summary["prior_resolution_category"], "ambiguous_not_delivered")

        after = self._api(self.operator_secret, "GET", "/deliveries/health")
        self.assertEqual(after.body["unresolved_dead_letters"], 0)
        self.assertTrue(after.body["ok"])

        # append-only: both decisions are on the record
        resolved_events = [
            event for event in read_events(self.state) if event.type == "outbox.resolved"
        ]
        self.assertEqual(resolved_events[-1].payload["resolution_category"], "obsolete")
        self.assertEqual(
            resolved_events[-1].payload["prior_resolution_category"], "ambiguous_not_delivered"
        )

    def test_a_terminal_resolution_stays_immutable(self) -> None:
        current = datetime.now(timezone.utc)
        item = enqueue(
            self.state,
            subject_id="session_return_ambiguous_immutable",
            target="demobot",
            payload={"delivery_mode": "session_return"},
            now=current,
        )
        delivery_claims = claim_due(self.state, worker="worker-b", now=current)
        mark_delivery_ambiguous(
            self.state, outbox_id=item.id, worker="worker-b", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), detail="unverifiable", now=current
        )
        reconcile_ambiguous_delivery(
            self.state,
            outbox_id=item.id,
            resolved_by="operator",
            outcome="not_delivered",
            provider_receipt="",
        )
        first = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{item.id}/resolve",
            {"resolution_category": "obsolete"},
        )
        self.assertEqual(first.status, 200)
        second = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{item.id}/resolve",
            {"resolution_category": "superseded"},
        )
        self.assertEqual(second.status, 400)
        self.assertIn("already resolved as obsolete", second.body["error"])

    def test_reclassification_without_a_note_keeps_the_recorded_detail(self) -> None:
        """An empty note must not erase why the item was classified ambiguous."""
        current = datetime.now(timezone.utc)
        item = enqueue(
            self.state,
            subject_id="session_return_ambiguous_no_note",
            target="demobot",
            payload={"delivery_mode": "session_return"},
            now=current,
        )
        delivery_claims = claim_due(self.state, worker="worker-b", now=current)
        mark_delivery_ambiguous(
            self.state, outbox_id=item.id, worker="worker-b", claim_attempts=next(c.attempts for c in delivery_claims if c.id == item.id), detail="unverifiable", now=current
        )
        reconcile_ambiguous_delivery(
            self.state,
            outbox_id=item.id,
            resolved_by="operator",
            outcome="not_delivered",
            provider_receipt="",
            detail="provider readback unverifiable",
        )
        closed = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{item.id}/resolve",
            {"resolution_category": "obsolete"},
        )
        self.assertEqual(closed.status, 200)
        self.assertEqual(closed.body["resolution_category"], "obsolete")
        self.assertEqual(closed.body["resolution_detail"], "provider readback unverifiable")
        rebuilt = project_outbox(self.state)[item.id]
        self.assertEqual(rebuilt.resolution_detail, "provider readback unverifiable")
        self.assertEqual(rebuilt.prior_resolution_category, "ambiguous_not_delivered")

    def test_delivery_health_is_healthy_after_current_dispatch_and_checkpoint(self) -> None:
        current = datetime.now(timezone.utc)
        create_task(self.state, "Current work", owner="demobot")
        claim_due(self.state, worker="materializer", now=current, deliver_after="2026-08-10T11:59:00Z")
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=current)

        health = self._api(self.operator_secret, "GET", "/deliveries/health")

        self.assertTrue(health.body["ok"])
        self.assertEqual(health.body["attention"], [])
        self.assertEqual(health.body["unresolved_dead_letters"], 0)
        self.assertEqual(health.body["work"]["aged_pending_count"], 0)

    def test_replayed_dead_letter_no_longer_latches_health_unhealthy(self) -> None:
        current = datetime.now(timezone.utc)
        failed = self._dead_letter()
        replayed = self._api(self.operator_secret, "POST", f"/deliveries/{failed.id}/replay", {})
        create_task(self.state, "Checkpoint", owner="demobot")
        claim_due(self.state, worker="materializer", now=current, deliver_after="2026-08-10T11:59:00Z")
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=current)

        health = self._api(self.operator_secret, "GET", "/deliveries/health")

        self.assertEqual(replayed.status, 201)
        self.assertEqual(health.body["counts"]["dead_lettered"], 1)
        self.assertEqual(health.body["unresolved_dead_letters"], 0)
        self.assertTrue(health.body["ok"])

    def test_resolved_dead_letter_clears_unresolved_without_replay(self) -> None:
        current = datetime.now(timezone.utc)
        failed = self._dead_letter()
        resolved = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{failed.id}/resolve",
            {"resolution_category": "obsolete", "detail": "superseded canary from the v1 era"},
        )
        create_task(self.state, "Checkpoint", owner="demobot")
        claim_due(self.state, worker="materializer", now=current, deliver_after="2026-08-10T11:59:00Z")
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=current)

        health = self._api(self.operator_secret, "GET", "/deliveries/health")
        listing = self._api(self.operator_secret, "GET", "/deliveries/dead-letter")

        self.assertEqual(resolved.status, 200)
        self.assertEqual(resolved.body["resolution_category"], "obsolete")
        self.assertEqual(resolved.body["resolved_by"], "operator")
        # Evidence is preserved: the record stays dead_lettered.
        self.assertEqual(resolved.body["status"], "dead_lettered")
        self.assertEqual(health.body["unresolved_dead_letters"], 0)
        self.assertTrue(health.body["ok"])
        summary = listing.body["deliveries"][0]
        self.assertEqual(summary["resolution_category"], "obsolete")
        self.assertEqual(summary["resolution_detail"], "superseded canary from the v1 era")

        # Idempotent for the same category; a different category is an
        # explicit conflict, not a silent rewrite.
        again = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{failed.id}/resolve",
            {"resolution_category": "obsolete"},
        )
        self.assertEqual(again.status, 200)
        conflict = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{failed.id}/resolve",
            {"resolution_category": "superseded"},
        )
        self.assertEqual(conflict.status, 400)
        self.assertIn("already resolved as obsolete", conflict.body["error"])

    def test_resolve_is_operator_only_and_dead_letter_only(self) -> None:
        failed = self._dead_letter()
        agent = self._api(
            self.demobot_token,
            "POST",
            f"/deliveries/{failed.id}/resolve",
            {"resolution_category": "obsolete"},
        )
        self.assertEqual(agent.status, 403)
        delivered = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{self.item.id}/resolve",
            {"resolution_category": "obsolete"},
        )
        self.assertEqual(delivered.status, 400)
        self.assertIn("not dead-lettered", delivered.body["error"])
        bad_category = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{failed.id}/resolve",
            {"resolution_category": "because"},
        )
        self.assertEqual(bad_category.status, 400)
        self.assertIn("resolution_category must be one of", bad_category.body["error"])
        extra_keys = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{failed.id}/resolve",
            {"resolution_category": "obsolete", "note": "free-form"},
        )
        self.assertEqual(extra_keys.status, 400)

    def test_dead_letter_listing_reports_replay_eligibility(self) -> None:
        failed = self._dead_letter()
        unroutable = enqueue(
            self.state,
            subject_id="task_unroutable",
            target="vesper",
            payload={"source_event_type": "task.created"},
            now=NOW,
        )
        delivery_claims = claim_due(self.state, worker="worker-b", now=NOW)
        record_failure(
            self.state,
            outbox_id=unroutable.id,
            worker="worker-b", claim_attempts=next(c.attempts for c in delivery_claims if c.id == unroutable.id),
            detail="invalid payload",
            transient=False,
            now=NOW,
        )
        listing = self._api(self.operator_secret, "GET", "/deliveries/dead-letter")
        by_id = {item["id"]: item for item in listing.body["deliveries"]}
        self.assertTrue(by_id[failed.id]["replayable"])
        self.assertEqual(by_id[failed.id]["replay_blocked_reason"], "")
        self.assertFalse(by_id[unroutable.id]["replayable"])
        self.assertIn("not in the authoritative route map", by_id[unroutable.id]["replay_blocked_reason"])

    def test_stale_dispatcher_and_checkpoint_report_explicit_ages(self) -> None:
        old = datetime.now(timezone.utc) - timedelta(hours=1)
        create_task(self.state, "Old checkpoint", owner="demobot")
        claim_due(self.state, worker="materializer", now=old, deliver_after="2026-08-10T11:59:00Z")
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=old)

        health = self._api(self.operator_secret, "GET", "/deliveries/health")

        self.assertFalse(health.body["ok"])
        self.assertGreaterEqual(health.body["dispatcher"]["age_seconds"], 3500)
        self.assertGreaterEqual(health.body["materialization"]["age_seconds"], 3500)
        self.assertNotIn("materialization_stale", health.body["attention"])
        self.assertIn("dispatcher_stale", health.body["attention"])

    def test_aged_unroutable_pending_is_visible_without_route_secrets(self) -> None:
        old = datetime.now(timezone.utc) - timedelta(minutes=10)
        enqueue(self.state, subject_id="unrouted", target="vesper", payload={}, now=old)
        create_task(self.state, "Checkpoint", owner="demobot")
        claim_due(self.state, worker="materializer", now=old, deliver_after="2026-08-10T11:59:00Z")
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=datetime.now(timezone.utc))

        health = self._api(self.operator_secret, "GET", "/deliveries/health")

        self.assertFalse(health.body["ok"])
        self.assertEqual(health.body["work"]["unroutable_count"], 1)
        self.assertGreaterEqual(health.body["work"]["oldest_unroutable_age_seconds"], 590)
        self.assertEqual(health.body["work"]["unroutable_targets"], ["vesper"])
        rendered = str(health.body)
        self.assertNotIn("url", rendered.lower())
        self.assertNotIn("credential", rendered.lower())

    def test_operator_delivery_health_reports_materialization_liveness(self) -> None:
        task = create_task(self.state, "New work", owner="demobot")
        claim_due(
            self.state,
            worker="materializer",
            now=NOW,
            deliver_after="2026-08-10T11:59:00Z",
            limit=2,
        )

        health = self._api(self.operator_secret, "GET", "/deliveries/health")

        self.assertEqual(health.status, 200)
        self.assertTrue(health.body["materialization"]["initialized"])
        self.assertEqual(health.body["materialization"]["advanced_at"], "2026-08-10T12:00:00Z")
        self.assertTrue(health.body["materialization"]["source_event_id"])
        self.assertIn(task.task.id, {item.subject_id for item in project_outbox(self.state).values()})

    def test_operator_replays_dead_letter_without_changing_target(self) -> None:
        failed = self._dead_letter()

        replayed = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{failed.id}/replay",
            {},
        )

        self.assertEqual(replayed.status, 201)
        self.assertEqual(replayed.body["target"], "demobot")
        self.assertEqual(replayed.body["epoch"], 1)
        self.assertEqual(project_outbox(self.state)[replayed.body["id"]].status, "pending")

    def test_agent_delivery_scope_cannot_inspect_or_replay_dlq(self) -> None:
        self.assertEqual(self._api(self.demobot_token, "GET", "/deliveries/health").status, 403)
        self.assertEqual(self._api(self.demobot_token, "GET", "/deliveries/dead-letter").status, 403)
        denied = self._api(
            self.demobot_token,
            "POST",
            f"/deliveries/{self.item.id}/replay",
            {},
        )
        self.assertEqual(denied.status, 403)
        self.assertIn("operator identity required", denied.body["error"])

    def test_operator_cancels_unroutable_pending_idempotently_without_secret_detail(self) -> None:
        pending = enqueue(self.state, subject_id="legacy", target="operator", payload={}, now=NOW)
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=datetime.now(timezone.utc))
        body = {"reason_category": "unroutable_target"}

        first = self._api(self.operator_secret, "POST", f"/deliveries/{pending.id}/cancel", body)
        second = self._api(self.operator_secret, "POST", f"/deliveries/{pending.id}/cancel", body)

        self.assertEqual(first.status, 200)
        self.assertEqual(second.status, 200)
        self.assertEqual(first.body["status"], "cancelled")
        self.assertEqual(first.body["cancellation_reason_category"], "unroutable_target")
        self.assertNotIn("cancellation_detail", first.body)
        cancelled = [event for event in read_events(self.state) if event.type == "outbox.cancelled"]
        self.assertEqual(len(cancelled), 1)
        self.assertEqual(cancelled[0].payload["cancellation_reason_category"], "unroutable_target")

    def test_operator_cannot_cancel_against_a_stale_route_snapshot(self) -> None:
        pending = enqueue(self.state, subject_id="legacy-stale", target="operator", payload={}, now=NOW)
        record_dispatcher_tick(
            self.state,
            configured_targets={"demobot"},
            now=datetime.now(timezone.utc) - timedelta(minutes=6),
        )

        response = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{pending.id}/cancel",
            {"reason_category": "unroutable_target"},
        )

        self.assertEqual(response.status, 400)
        self.assertIn("route configuration is stale", response.body["error"])
        self.assertEqual(project_outbox(self.state)[pending.id].status, "pending")

    def test_cancel_rejects_narrower_fake_tick_when_authoritative_route_still_exists(self) -> None:
        pending = enqueue(self.state, subject_id="still-routable", target="demobot", payload={}, now=NOW)
        record_dispatcher_tick(self.state, configured_targets=set(), now=datetime.now(timezone.utc))

        response = self._api(
            self.operator_secret, "POST", f"/deliveries/{pending.id}/cancel",
            {"reason_category": "unroutable_target"},
        )

        self.assertEqual(response.status, 400)
        self.assertIn("currently routable", response.body["error"])

    def test_cancel_rejects_stale_route_file_when_fresh_tick_contains_target(self) -> None:
        pending = enqueue(self.state, subject_id="route-added-atomically", target="vesper", payload={}, now=NOW)
        record_dispatcher_tick(self.state, configured_targets={"vesper"}, now=datetime.now(timezone.utc))

        response = self._api(
            self.operator_secret, "POST", f"/deliveries/{pending.id}/cancel",
            {"reason_category": "unroutable_target"},
        )

        self.assertEqual(response.status, 400)
        self.assertIn("currently routable", response.body["error"])
        self.assertEqual(project_outbox(self.state)[pending.id].status, "pending")

    def test_cancel_fails_closed_when_route_configuration_is_unavailable(self) -> None:
        pending = enqueue(self.state, subject_id="unknown-routes", target="vesper", payload={}, now=NOW)
        self.routes.unlink()
        record_dispatcher_tick(self.state, configured_targets=set(), now=datetime.now(timezone.utc))

        response = self._api(
            self.operator_secret, "POST", f"/deliveries/{pending.id}/cancel",
            {"reason_category": "unroutable_target"},
        )

        self.assertEqual(response.status, 400)
        self.assertIn("route configuration", response.body["error"])

    def test_stale_tick_does_not_override_current_route_configuration(self) -> None:
        pending = enqueue(self.state, subject_id="new-route", target="vesper", payload={}, now=NOW)
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=NOW - timedelta(days=1))
        self.routes.write_text(
            '{"routes":{"vesper":{"runtime":"hermes-webhook","url_env":"URL","credential_env":"SECRET"}}}',
            encoding="utf-8",
        )

        response = self._api(
            self.operator_secret, "POST", f"/deliveries/{pending.id}/cancel",
            {"reason_category": "unroutable_target"},
        )

        self.assertEqual(response.status, 400)
        self.assertIn("route configuration is stale", response.body["error"])

    def test_cancel_refused_when_dispatcher_attested_hash_diverges_from_loaded_document(self) -> None:
        pending = enqueue(self.state, subject_id="diverged-config", target="operator", payload={}, now=NOW)
        record_dispatcher_tick(
            self.state,
            configured_targets={"demobot"},
            route_revision="2026-08-29-r1",
            route_sha256="a" * 64,
            now=datetime.now(timezone.utc),
        )

        response = self._api(
            self.operator_secret, "POST", f"/deliveries/{pending.id}/cancel",
            {"reason_category": "unroutable_target"},
        )

        self.assertEqual(response.status, 400)
        self.assertIn("does not match the loaded route configuration", response.body["error"])
        self.assertEqual(project_outbox(self.state)[pending.id].status, "pending")

    def test_cancel_allowed_when_dispatcher_attested_hash_matches_loaded_document(self) -> None:
        self.routes.write_text(
            json.dumps(
                {
                    "schema": "v2.agent-delivery-routes/1",
                    "revision": "2026-08-29-r1",
                    "routes": {
                        "demobot": {"runtime": "hermes-webhook", "url_env": "URL", "credential_env": "SECRET"}
                    },
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        pending = enqueue(self.state, subject_id="matched-config", target="operator", payload={}, now=NOW)
        record_dispatcher_tick(
            self.state,
            configured_targets={"demobot"},
            route_revision="2026-08-29-r1",
            route_sha256=hashlib.sha256(self.routes.read_bytes()).hexdigest(),
            now=datetime.now(timezone.utc),
        )

        response = self._api(
            self.operator_secret, "POST", f"/deliveries/{pending.id}/cancel",
            {"reason_category": "unroutable_target"},
        )

        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["status"], "cancelled")

    def test_delivery_health_exposes_dispatcher_route_attestation(self) -> None:
        current = datetime.now(timezone.utc)
        create_task(self.state, "Attested work", owner="demobot")
        claim_due(self.state, worker="materializer", now=current, deliver_after="2026-08-10T11:59:00Z")
        record_dispatcher_tick(
            self.state,
            configured_targets={"demobot"},
            route_revision="2026-08-29-r1",
            route_sha256="b" * 64,
            now=current,
        )

        health = self._api(self.operator_secret, "GET", "/deliveries/health")

        self.assertEqual(health.status, 200)
        self.assertEqual(health.body["dispatcher"]["route_revision"], "2026-08-29-r1")
        self.assertEqual(health.body["dispatcher"]["route_sha256"], "b" * 64)

    def test_operator_cannot_replay_cancelled_even_after_target_is_configured(self) -> None:
        pending = enqueue(self.state, subject_id="recoverable", target="vesper", payload={}, now=NOW)
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=datetime.now(timezone.utc))
        cancelled = self._api(
            self.operator_secret, "POST", f"/deliveries/{pending.id}/cancel",
            {"reason_category": "unroutable_target"},
        )
        blocked = self._api(self.operator_secret, "POST", f"/deliveries/{pending.id}/replay", {})
        self.routes.write_text(
            '{"routes":{"vesper":{"runtime":"hermes-webhook","url_env":"URL","credential_env":"SECRET"}}}',
            encoding="utf-8",
        )
        still_blocked = self._api(self.operator_secret, "POST", f"/deliveries/{pending.id}/replay", {})

        self.assertEqual(cancelled.status, 200)
        self.assertEqual(blocked.status, 400)
        self.assertIn("target is not configured", blocked.body["error"])
        self.assertEqual(still_blocked.status, 400)
        self.assertIn("not dead-lettered", still_blocked.body["error"])
        self.assertEqual(project_outbox(self.state)[pending.id].status, "cancelled")

    def test_operator_cancels_leased_and_retrying_unroutable_deliveries(self) -> None:
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=datetime.now(timezone.utc))
        leased = enqueue(self.state, subject_id="leased-legacy", target="elin", payload={}, now=NOW)
        claim_due(self.state, worker="legacy-worker", now=NOW, targets={"elin"})
        leased_response = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{leased.id}/cancel",
            {"reason_category": "unroutable_target"},
        )
        retrying = enqueue(self.state, subject_id="retry-legacy", target="operator", payload={}, now=NOW)
        delivery_claims = claim_due(self.state, worker="legacy-worker", now=NOW, targets={"operator"})
        record_failure(
            self.state,
            outbox_id=retrying.id,
            worker="legacy-worker", claim_attempts=next(c.attempts for c in delivery_claims if c.id == retrying.id),
            detail="temporary failure",
            transient=True,
            now=NOW,
        )
        retrying_response = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{retrying.id}/cancel",
            {"reason_category": "unroutable_target"},
        )

        self.assertEqual(leased_response.body["status"], "cancelled")
        self.assertEqual(retrying_response.body["status"], "cancelled")
        self.assertEqual(project_outbox(self.state)[retrying.id].failures, 1)

    def test_cancel_rejects_free_form_detail(self) -> None:
        pending = enqueue(self.state, subject_id="legacy-detail", target="operator", payload={}, now=NOW)
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=datetime.now(timezone.utc))
        response = self._api(
            self.operator_secret,
            "POST",
            f"/deliveries/{pending.id}/cancel",
            {"reason_category": "unroutable_target", "detail": "free-form detail must not persist"},
        )
        self.assertEqual(response.status, 400)
        self.assertNotIn("free-form detail must not persist", self.state.read_text(encoding="utf-8"))

    def test_target_agent_cannot_cancel_delivery(self) -> None:
        denied = self._api(
            self.demobot_token,
            "POST",
            f"/deliveries/{self.item.id}/cancel",
            {"reason_category": "unroutable_target"},
        )
        self.assertEqual(denied.status, 403)
        self.assertIn("operator identity required", denied.body["error"])

    def test_operator_cannot_cancel_routable_or_terminal_delivery(self) -> None:
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=datetime.now(timezone.utc))
        delivered = self._api(self.operator_secret, "POST", f"/deliveries/{self.item.id}/cancel", {"reason_category": "unroutable_target"})
        pending = enqueue(self.state, subject_id="routable", target="demobot", payload={}, now=NOW)
        routable = self._api(self.operator_secret, "POST", f"/deliveries/{pending.id}/cancel", {"reason_category": "unroutable_target"})
        dead = self._dead_letter()
        dead_response = self._api(self.operator_secret, "POST", f"/deliveries/{dead.id}/cancel", {"reason_category": "unroutable_target"})

        self.assertEqual(delivered.status, 400)
        self.assertEqual(routable.status, 400)
        self.assertEqual(dead_response.status, 400)
        self.assertEqual(project_outbox(self.state)[pending.id].status, "pending")

    def test_delivery_health_is_green_after_unroutable_delivery_is_cancelled(self) -> None:
        current = datetime.now(timezone.utc)
        pending = enqueue(self.state, subject_id="legacy", target="operator", payload={}, now=current - timedelta(minutes=10))
        create_task(self.state, "Checkpoint", owner="demobot")
        claimed = claim_due(self.state, worker="materializer", now=current, deliver_after="2026-08-10T11:59:00Z", targets={"demobot"})
        for item in claimed:
            mark_delivered(self.state, outbox_id=item.id, worker="materializer", claim_attempts=next(c.attempts for c in claimed if c.id == item.id), now=current)
        record_dispatcher_tick(self.state, configured_targets={"demobot"}, now=current)
        cancelled = self._api(self.operator_secret, "POST", f"/deliveries/{pending.id}/cancel", {"reason_category": "unroutable_target"})

        health = self._api(self.operator_secret, "GET", "/deliveries/health")
        self.assertEqual(cancelled.status, 200)
        self.assertTrue(health.body["ok"])
        self.assertEqual(health.body["counts"]["cancelled"], 1)
        self.assertEqual(health.body["work"]["backlog_count"], 0)
        self.assertEqual(health.body["work"]["unroutable_count"], 0)
    def test_delivery_health_reports_unconfigured_materialization_skip_explicitly(self) -> None:
        current = datetime.now(timezone.utc)
        create_task(self.state, "Checkpoint", owner="demobot")
        claimed = claim_due(self.state, worker="materializer", now=current, deliver_after="2026-08-10T11:59:00Z", targets={"demobot"})
        for item in claimed:
            mark_delivered(self.state, outbox_id=item.id, worker="materializer", claim_attempts=next(c.attempts for c in claimed if c.id == item.id), now=current)
        record_dispatcher_tick(
            self.state,
            configured_targets={"demobot"},
            healthy=False,
            skipped_unconfigured_targets=("vesper",),
            now=current,
        )

        health = self._api(self.operator_secret, "GET", "/deliveries/health")

        self.assertFalse(health.body["ok"])
        self.assertIn("materialization_skipped_unconfigured_targets", health.body["attention"])
        self.assertEqual(health.body["dispatcher"]["skipped_unconfigured_targets"], ["vesper"])


if __name__ == "__main__":
    unittest.main()


class SessionReturnReadAuditGateTests(unittest.TestCase):
    """Regression: control.execution_session_return_get is a pure read.

    Incident 2026-08-31: the /mcp audit-success gate omitted
    control.execution_session_return_get from its read exemption set, so the
    identity-bound read of a valid session return failed with HTTP 428
    idempotency_key_required even though the advertised schema requires only
    request_id. Odin could not read the durable provider receipt and the
    canonical subject could not complete.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.enterContext(authority_context(self.vault, self.state))
        init_vault(self.vault)
        self.demobot_control_token = issue_token(
            self.vault, "demobot", scopes=["control.read"], slot="control-read"
        ).token
        from arvyx_control.control import acknowledge_thread, post_thread
        from arvyx_control.execution import claim_execution
        from arvyx_control.session_return import request_session_return

        created = post_thread(
            state=self.state, title="Return gate", thread_type="ask",
            actor="odin", target="demobot", actor_identity_bound=True,
        )
        acknowledge_thread(
            state=self.state, thread_id=created.thread.id, actor="demobot",
            actor_identity_bound=True,
        )
        execution = claim_execution(
            self.state, worker="w", execution_capable_targets={"demobot"},
            now=NOW, lease_seconds=120,
        )
        self.assertIsNotNone(execution)
        self.requested = request_session_return(
            self.state,
            execution_id=execution.id,
            attempt_id=execution.attempt_id,
            actor="demobot",
            message="receipt readback probe",
            expected_word_count=3,
            idempotency_key="gate-regression-0001",
            now=NOW,
        )

    def test_session_return_get_without_idempotency_key_is_a_plain_read(self) -> None:
        response = handle_api_request(
            method="POST",
            path="/mcp",
            body={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "control.execution_session_return_get",
                    "arguments": {"request_id": self.requested.request_id},
                },
            },
            vault=self.vault,
            state=self.state,
            authorization=f"Bearer {self.demobot_control_token}",
            mcp_profile="agent",
        )
        # 428 here means the read slipped back into the idempotency gate.
        self.assertEqual(response.status, 200)
        body = json.loads(response.body) if isinstance(response.body, str) else response.body
        result = body["result"]
        if isinstance(result, dict) and "content" in result:
            payload = json.loads(result["content"][0]["text"])
        elif isinstance(result, str):
            payload = json.loads(result)
        else:
            payload = result
        self.assertEqual(
            payload["session_return"]["request_id"], self.requested.request_id
        )

    def test_mcp_audit_gate_exempts_every_read_tool(self) -> None:
        from arvyx_control.api import MCP_AUDIT_EXEMPT_TOOLS
        from arvyx_control.mcp import MUTATING_TOOL_NAMES, READ_TOOL_NAMES

        self.assertEqual(MCP_AUDIT_EXEMPT_TOOLS, frozenset(READ_TOOL_NAMES))
        # Pure reads never mutate the control log; writes must stay gated.
        self.assertEqual(
            MCP_AUDIT_EXEMPT_TOOLS.intersection(MUTATING_TOOL_NAMES), frozenset()
        )
        self.assertIn("control.execution_session_return_get", MCP_AUDIT_EXEMPT_TOOLS)
