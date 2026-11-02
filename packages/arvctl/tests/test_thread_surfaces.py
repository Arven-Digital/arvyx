from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
import uuid

from arvyx_control.replica_authority import authority_context
from arvyx_control.api import handle_api_request
from arvyx_control.auth import SCOPE_CONTROL_READ, SCOPE_CONTROL_WRITE, issue_token, tools_for_scopes
from arvyx_control.vault import init_vault
from arvyx_control.bridge import build_bridge_policy
from arvyx_control.control import (
    acknowledge_thread,
    list_pending_threads,
    list_thread_inbox,
    post_thread,
    read_events,
)
from arvyx_control.execution import claim_execution, project_executions, reconcile_executions
from arvyx_control.mcp import (
    CONTROL_THREAD_READ_TOOL_NAMES,
    CONTROL_THREAD_WRITE_TOOL_NAMES,
    handle_request,
    tools_for_profile,
)

REPO_ROOT = Path(__file__).resolve().parents[3]

THREAD_TOOLS = CONTROL_THREAD_READ_TOOL_NAMES + CONTROL_THREAD_WRITE_TOOL_NAMES


class ThreadApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.enterContext(authority_context(self.vault, self.state))

    def _api(self, method: str, path: str, body: dict | None = None):
        if method == "POST" and path == "/threads":
            body = {"actor": "demobot", **(body or {})}
        return handle_api_request(
            method=method,
            path=path,
            body=body,
            vault=self.vault,
            state=self.state,
            allow_unauthenticated_demo=True,
        )

    def test_api_returns_same_projection_as_cli(self) -> None:
        post_thread(state=self.state, title="Ask for vesper", thread_type="ask", target="vesper", actor="demobot")
        post_thread(state=self.state, title="Status for vesper", thread_type="status", target="vesper", actor="demobot")
        post_thread(state=self.state, title="Ask for demobot", thread_type="ask", target="demobot", actor="demobot")

        inbox = self._api("GET", "/threads?agent=vesper")
        self.assertEqual(inbox.status, 200)
        self.assertEqual(inbox.body, list_thread_inbox(state=self.state, target="vesper").to_dict())

        pending = self._api("GET", "/threads/pending?agent=vesper")
        self.assertEqual(pending.status, 200)
        self.assertEqual(pending.body, list_pending_threads(state=self.state, target="vesper").to_dict())

        # no agent filter lists every thread
        all_threads = self._api("GET", "/threads")
        self.assertEqual(len(all_threads.body["threads"]), 3)

    def test_api_thread_lifecycle(self) -> None:
        created = self._api(
            "POST",
            "/threads",
            {"title": "Daily health check", "body": "Run synthetic checks.", "type": "ask", "target": "vesper", "channel": "demo-agent"},
        )
        self.assertEqual(created.status, 201)
        thread_id = created.body["thread"]["id"]
        self.assertTrue(created.body["thread"]["pending"])

        acked = self._api("POST", f"/threads/{thread_id}/ack", {"actor": "vesper", "text": "Taking this."})
        self.assertEqual(acked.status, 200)
        self.assertEqual(acked.body["thread"]["status"], "acked")
        self.assertTrue(acked.body["thread"]["pending"])

        done = self._api("POST", f"/threads/{thread_id}/done", {"actor": "vesper", "text": "Done with receipts."})
        self.assertEqual(done.status, 200)
        self.assertEqual(done.body["thread"]["status"], "done")
        self.assertFalse(done.body["thread"]["pending"])

        pending = self._api("GET", "/threads/pending?agent=vesper")
        self.assertEqual(pending.body["threads"], [])

        marked = self._api("POST", "/threads/read-all", {"agent": "vesper"})
        self.assertEqual(marked.status, 200)
        self.assertEqual([thread["id"] for thread in marked.body["threads"]], [thread_id])

    def test_unbound_api_rejects_exact_continuation_parent(self) -> None:
        parent = self._api(
            "POST",
            "/threads",
            {"title": "Parent", "actor": "odin", "target": "amir"},
        )
        parent_id = parent.body["thread"]["id"]
        acked = self._api("POST", f"/threads/{parent_id}/ack", {"actor": "amir"})
        self.assertEqual(acked.status, 200)

        child = self._api(
            "POST",
            "/threads",
            {
                "title": "Child",
                "actor": "amir",
                "target": "kiran",
                "continuation_thread_id": parent_id,
            },
        )
        self.assertEqual(child.status, 400)
        self.assertIn("identity-bound", child.body["error"])

    def test_api_completion_contract_fails_closed_without_exact_evidence(self) -> None:
        artifact = "/home/vesper/.hermes/memories/USER.md"
        created = self._api(
            "POST",
            "/threads",
            {
                "title": "Update canonical user memory",
                "type": "ask",
                "target": "vesper",
                "completion_artifact": artifact,
                "completion_anchor": "0bserverx",
            },
        )
        self.assertEqual(created.status, 201)
        thread_id = created.body["thread"]["id"]
        rejected = self._api("POST", f"/threads/{thread_id}/done", {"actor": "vesper"})
        self.assertEqual(rejected.status, 400)
        self.assertIn("completion evidence is required", rejected.body["error"])
        done = self._api(
            "POST",
            f"/threads/{thread_id}/done",
            {
                "actor": "vesper",
                "evidence_artifact": artifact,
                "evidence_anchor": "0bserverx",
                "evidence_method": "direct-read",
            },
        )
        self.assertEqual(done.status, 200)
        self.assertEqual(done.body["thread"]["evidence_method"], "direct-read")

    def test_api_null_contract_and_evidence_fields_normalize_to_empty(self) -> None:
        created = self._api(
            "POST",
            "/threads",
            {
                "title": "Nullable client",
                "type": "ask",
                "target": "vesper",
                "completion_artifact": None,
                "completion_anchor": None,
            },
        )
        self.assertEqual(created.status, 201)
        self.assertEqual(created.body["thread"]["completion_artifact"], "")
        done = self._api(
            "POST",
            f"/threads/{created.body['thread']['id']}/done",
            {"evidence_artifact": None, "evidence_anchor": None, "evidence_method": None},
        )
        self.assertEqual(done.status, 200)
        self.assertEqual(done.body["thread"]["evidence_artifact"], "")

    def test_api_rejects_invalid_thread_writes(self) -> None:
        secret = self._api("POST", "/threads", {"title": "leak", "body": "password = hunter2hunter2"})
        self.assertEqual(secret.status, 400)
        self.assertIn("secret-shaped", secret.body["error"])
        unknown = self._api("POST", "/threads/thread_missing/ack", {})
        self.assertEqual(unknown.status, 400)
        bad_type = self._api("POST", "/threads", {"title": "x", "type": "carrier-pigeon"})
        self.assertEqual(bad_type.status, 400)

    def test_summary_includes_thread_counts_and_recent(self) -> None:
        created = post_thread(state=self.state, title="Summary ask", thread_type="ask", target="vesper", actor="demobot")
        acknowledge_thread(state=self.state, thread_id=created.thread.id, actor="vesper")
        post_thread(state=self.state, title="Summary status", thread_type="status", target="demobot", actor="demobot")

        summary = handle_api_request(
            "GET", "/summary", {}, vault=self.vault, state=self.state,
            bearer_secret="summary-fixture-secret",
            authorization="Bearer summary-fixture-secret",
        )
        self.assertEqual(summary.status, 200)
        counts = summary.body["counts"]["threads"]
        self.assertEqual(counts["total"], 2)
        self.assertEqual(counts["pending"], 1)
        self.assertEqual(counts["unread"], 2)
        self.assertEqual(counts["acked"], 1)
        recent = summary.body["recent"]["threads"]
        self.assertEqual(len(recent), 2)
        self.assertIn("pending", recent[0])

    def test_dashboard_mutations_send_retry_stable_idempotency_keys(self) -> None:
        html = self._api("GET", "/dashboard").body
        self.assertIn("Idempotency-Key", html)
        self.assertIn("pendingOperationKeys", html)
        self.assertIn("crypto.randomUUID", html)

    def test_dashboard_renders_thread_panel_without_private_defaults(self) -> None:
        response = self._api("GET", "/dashboard")
        self.assertEqual(response.status, 200)
        html = response.body
        self.assertIsInstance(html, str)
        self.assertIn("War Room", html)
        self.assertIn('id="threads"', html)
        self.assertIn('id="thread-pending"', html)
        self.assertIn('id="thread-unread"', html)
        self.assertIn("renderThreads", html)
        # no private agent names as defaults; fixtures only
        for non_default_name in ("internal-reviewer", "internal-assignee", "internal-release"):
            self.assertNotIn(non_default_name, html.lower())


class ThreadApiIdentityTests(unittest.TestCase):
    """Identity-bound agents over HTTP: own inbox only, no cross-agent mutation."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.enterContext(authority_context(self.vault, self.state))
        init_vault(self.vault)
        self.demobot_token = issue_token(self.vault, "demobot", scopes=["control.read", "control.write"]).token
        self.operator_secret = "operator-shared-secret-for-tests"

    def _api(self, method: str, path: str, body: dict | None = None, token: str | None = None):
        return handle_api_request(
            method=method,
            path=path,
            body=body,
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {token or self.demobot_token}",
            idempotency_key=(f"thread-test-{uuid.uuid4().hex}" if method not in {"GET", "HEAD", "OPTIONS"} else None),
        )

    def _operator(self, method: str, path: str, body: dict | None = None):
        return self._api(method, path, body, token=self.operator_secret)

    def test_identity_bound_rest_assignment_carries_execution_provenance(self) -> None:
        bound = self._api(
            "POST",
            "/threads",
            {"title": "Bound assignment", "type": "ask", "target": "vesper"},
        )
        self.assertEqual(bound.status, 201)
        self.assertIs(bound.body["event"]["payload"]["actor_identity_bound"], True)

        unbound = self._operator(
            "POST",
            "/threads",
            {"title": "Operator assignment", "type": "ask", "target": "vesper", "actor": "operator"},
        )
        self.assertEqual(unbound.status, 201)
        self.assertIs(unbound.body["event"]["payload"]["actor_identity_bound"], False)

    def test_identity_bound_reads_default_to_own_inbox(self) -> None:
        post_thread(state=self.state, title="For demobot", thread_type="ask", target="demobot", actor="demobot")
        post_thread(state=self.state, title="For vesper", thread_type="ask", target="vesper", actor="demobot")
        inbox = self._api("GET", "/threads")
        self.assertEqual(inbox.status, 200)
        self.assertEqual([thread["target"] for thread in inbox.body["threads"]], ["demobot"])
        pending = self._api("GET", "/threads/pending")
        self.assertEqual([thread["target"] for thread in pending.body["threads"]], ["demobot"])
        # the operator identity still sees everything
        all_threads = self._operator("GET", "/threads")
        self.assertEqual(len(all_threads.body["threads"]), 2)

    def test_identity_bound_reads_reject_foreign_target(self) -> None:
        post_thread(state=self.state, title="For vesper", thread_type="ask", target="vesper", actor="demobot")
        for path in ("/threads?target=vesper", "/threads?agent=vesper", "/threads/pending?target=vesper"):
            response = self._api("GET", path)
            self.assertEqual(response.status, 403, path)
            self.assertIn("may only access its own threads", response.body["error"], path)

    def test_cross_agent_ack_done_blocked_over_http(self) -> None:
        created = post_thread(state=self.state, title="For vesper", thread_type="ask", target="vesper", actor="demobot")
        thread_id = created.thread.id
        for action in ("ack", "done"):
            response = self._api("POST", f"/threads/{thread_id}/{action}", {})
            self.assertEqual(response.status, 403, action)
            self.assertIn("may only ack/done its own threads", response.body["error"], action)
        # operator may ack/done any thread
        acked = self._operator("POST", f"/threads/{thread_id}/ack", {})
        self.assertEqual(acked.status, 200)
        done = self._operator("POST", f"/threads/{thread_id}/done", {})
        self.assertEqual(done.status, 200)

    def test_own_target_ack_done_allowed(self) -> None:
        created = post_thread(state=self.state, title="For demobot", thread_type="ask", target="demobot", actor="demobot")
        acked = self._api("POST", f"/threads/{created.thread.id}/ack", {"text": "Taking this."})
        self.assertEqual(acked.status, 200)
        self.assertEqual(acked.body["thread"]["acked_by"], "demobot")
        done = self._api("POST", f"/threads/{created.thread.id}/done", {})
        self.assertEqual(done.status, 200)
        self.assertEqual(done.body["thread"]["done_by"], "demobot")

    def test_http_mcp_binds_execution_session_and_heartbeat_to_token_identity(self) -> None:
        created = post_thread(
            state=self.state, title="HTTP durable continuation", thread_type="ask",
            actor="vesper", target="demobot", actor_identity_bound=True,
        )
        acknowledge_thread(
            state=self.state, thread_id=created.thread.id, actor="demobot",
            actor_identity_bound=True,
        )
        execution = claim_execution(
            self.state, worker="http-execution-worker", execution_capable_targets={"demobot"},
            now=datetime.now(timezone.utc), lease_seconds=120,
        )
        self.assertIsNotNone(execution)

        def call(token: str, name: str, arguments: dict) -> dict:
            response = handle_api_request(
                method="POST",
                path="/mcp",
                body={
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                },
                vault=self.vault,
                state=self.state,
                bearer_secret=self.operator_secret,
                authorization=f"Bearer {token}",
                mcp_profile="agent",
                idempotency_key=str(arguments.get("idempotency_key") or f"execution-http-{uuid.uuid4().hex}"),
            )
            self.assertEqual(response.status, 200)
            return json.loads(response.body)

        arguments = {"execution_id": execution.id, "attempt_id": execution.attempt_id}
        session_response = handle_api_request(
            method="POST",
            path="/mcp",
            body={
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {
                    "name": "control.execution_session_get",
                    "arguments": arguments,
                },
            },
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {self.demobot_token}",
            mcp_profile="agent",
            idempotency_key=None,
        )
        self.assertEqual(session_response.status, 200)
        session = json.loads(session_response.body)
        self.assertEqual(
            session["result"]["structuredContent"]["execution"]["id"], execution.id,
        )

        vesper_token = issue_token(
            self.vault, "vesper", scopes=["control.read", "control.write"],
        ).token
        denied = call(vesper_token, "control.execution_session_get", arguments)
        self.assertIn("identity-bound target", denied["error"]["message"])

        heartbeat = call(
            self.demobot_token,
            "control.execution_heartbeat",
            {**arguments, "lease_seconds": 120, "idempotency_key": "runtime-heartbeat-http-0001"},
        )
        self.assertEqual(
            heartbeat["result"]["structuredContent"]["execution"]["attempt_id"],
            execution.attempt_id,
        )
        event = read_events(self.state)[-1]
        self.assertEqual(event.payload["heartbeat_by"], "demobot")
        self.assertIs(event.payload["actor_identity_bound"], True)

    def test_operator_http_cannot_forge_execution_authoritative_target_terminal(self) -> None:
        created = post_thread(
            state=self.state, title="HTTP execution authority", thread_type="ask",
            actor="vesper", target="demobot", actor_identity_bound=True,
        )
        acked = self._api("POST", f"/threads/{created.thread.id}/ack", {})
        self.assertEqual(acked.status, 200)
        execution = claim_execution(
            self.state, worker="http-authority", execution_capable_targets={"demobot"},
        )
        self.assertIsNotNone(execution)

        forged = self._operator(
            "POST", f"/threads/{created.thread.id}/done", {"actor": "demobot"},
        )
        self.assertEqual(forged.status, 200)
        terminal = read_events(self.state)[-1]
        self.assertEqual(terminal.payload["done_by"], "demobot")
        self.assertIs(terminal.payload["actor_identity_bound"], False)
        self.assertEqual(reconcile_executions(self.state), [])
        self.assertEqual(project_executions(self.state)[execution.id].status, "leased")

        target_done = self._api(
            "POST",
            f"/threads/{created.thread.id}/done",
            {"text": "Identity-bound completion supersedes the unbound terminal."},
        )
        self.assertEqual(target_done.status, 200)
        self.assertEqual(target_done.body["thread"]["done_by"], "demobot")
        reconciled = reconcile_executions(self.state)
        self.assertEqual([item.id for item in reconciled], [execution.id])
        self.assertEqual(project_executions(self.state)[execution.id].status, "completed")

    def test_read_all_accepts_canonical_target_and_legacy_agent(self) -> None:
        post_thread(state=self.state, title="One", thread_type="status", target="vesper", actor="demobot")
        post_thread(state=self.state, title="Two", thread_type="status", target="vesper", actor="demobot")
        via_target = self._operator("POST", "/threads/read-all", {"target": "vesper"})
        self.assertEqual(via_target.status, 200)
        self.assertEqual(len(via_target.body["threads"]), 2)
        post_thread(state=self.state, title="Three", thread_type="status", target="vesper", actor="demobot")
        via_legacy_agent = self._operator("POST", "/threads/read-all", {"agent": "vesper"})
        self.assertEqual(via_legacy_agent.status, 200)
        self.assertEqual([thread["title"] for thread in via_legacy_agent.body["threads"]], ["Three"])

    def test_identity_bound_read_all_scoped_to_own_inbox(self) -> None:
        post_thread(state=self.state, title="For demobot", thread_type="status", target="demobot", actor="demobot")
        post_thread(state=self.state, title="For vesper", thread_type="status", target="vesper", actor="demobot")
        # omitted target defaults to the caller's identity
        marked = self._api("POST", "/threads/read-all", {})
        self.assertEqual(marked.status, 200)
        self.assertEqual([thread["target"] for thread in marked.body["threads"]], ["demobot"])
        # foreign target is rejected, via canonical and legacy keys alike
        for key in ("target", "agent"):
            response = self._api("POST", "/threads/read-all", {key: "vesper"})
            self.assertEqual(response.status, 403, key)


class ThreadMcpTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state = Path(self._tmp.name) / "events.jsonl"
        self.vault = Path(self._tmp.name) / "vault"
        self.enterContext(authority_context(self.vault, self.state))

    def _request(self, method: str, params: dict, profile: str, actor: str | None = None) -> dict:
        return handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            vault=self.vault,
            state=self.state,
            allowed_tools=set(tools_for_profile(profile)),
            actor=actor,
        )

    def _call(self, name: str, arguments: dict, profile: str = "operator", actor: str | None = None) -> dict:
        if name == "control.thread_post":
            arguments = {"actor": "demobot", **arguments}
        if name in {"control.thread_ack", "control.thread_done", "control.thread_reply"}:
            arguments = {"actor": "operator", **arguments}
        if name in CONTROL_THREAD_WRITE_TOOL_NAMES:
            arguments = {"idempotency_key": f"thread-mcp-{uuid.uuid4().hex}", **arguments}
        return self._request("tools/call", {"name": name, "arguments": arguments}, profile, actor=actor)

    def _result(self, response: dict) -> dict:
        self.assertIn("result", response, response.get("error"))
        return response["result"]["structuredContent"]

    def test_tools_list_includes_thread_tools(self) -> None:
        response = self._request("tools/list", {}, "operator")
        tools = {tool["name"]: tool for tool in response["result"]["tools"]}
        for tool in THREAD_TOOLS:
            self.assertIn(tool, tools)
        done_method = tools["control.thread_done"]["inputSchema"]["properties"]["evidence_method"]
        self.assertEqual(
            set(done_method["enum"]),
            {"direct-read", "checksum", "test-output", "api-readback"},
        )
        self.assertIn(
            "contract",
            tools["control.thread_done"]["inputSchema"]["properties"]["evidence_artifact"]["description"],
        )
        continuation = tools["control.thread_post"]["inputSchema"]["properties"]["continuation_thread_id"]
        self.assertIn("parent", continuation["description"])

    def test_identity_bound_mcp_can_create_exact_child_continuation(self) -> None:
        parent = self._result(
            self._call(
                "control.thread_post",
                {"title": "Parent", "target": "amir"},
                actor="odin",
            )
        )
        parent_id = parent["thread"]["id"]
        self._result(self._call("control.thread_ack", {"thread_id": parent_id}, actor="amir"))

        child = self._result(
            self._call(
                "control.thread_post",
                {
                    "title": "Child",
                    "target": "kiran",
                    "continuation_thread_id": parent_id,
                },
                actor="amir",
            )
        )
        self.assertEqual(child["thread"]["continuation_thread_id"], parent_id)

    def test_mcp_null_contract_and_evidence_fields_normalize_to_empty(self) -> None:
        created = self._result(
            self._call(
                "control.thread_post",
                {
                    "title": "Nullable MCP client",
                    "target": "vesper",
                    "completion_artifact": None,
                    "completion_anchor": None,
                },
            )
        )
        self.assertEqual(created["thread"]["completion_artifact"], "")
        done = self._result(
            self._call(
                "control.thread_done",
                {
                    "thread_id": created["thread"]["id"],
                    "evidence_artifact": None,
                    "evidence_anchor": None,
                    "evidence_method": None,
                },
            )
        )
        self.assertEqual(done["thread"]["evidence_method"], "")

    def test_read_only_profile_lists_but_blocks_mutations(self) -> None:
        read_only = set(tools_for_profile("read-only"))
        self.assertIn("control.thread_inbox", read_only)
        self.assertIn("control.thread_pending", read_only)
        for tool in CONTROL_THREAD_WRITE_TOOL_NAMES:
            self.assertNotIn(tool, read_only)

        post_thread(state=self.state, title="Visible to read-only", thread_type="ask", target="vesper", actor="demobot")
        inbox = self._call("control.thread_inbox", {"target": "vesper"}, profile="read-only")
        self.assertEqual(len(self._result(inbox)["threads"]), 1)

        for tool in CONTROL_THREAD_WRITE_TOOL_NAMES:
            response = self._call(tool, {"title": "x", "thread_id": "x", "target": "vesper"}, profile="read-only")
            self.assertIn("error", response, tool)
            self.assertEqual(response["error"]["code"], -32000, tool)
            self.assertIn("not allowlisted", response["error"]["message"], tool)

    def test_operator_profile_allows_thread_lifecycle(self) -> None:
        posted = self._result(
            self._call(
                "control.thread_post",
                {"title": "Daily health check", "body": "Run synthetic checks.", "type": "ask", "target": "vesper", "channel": "demo-agent"},
            )
        )
        thread_id = posted["thread"]["id"]
        self.assertTrue(posted["thread"]["pending"])

        pending = self._result(self._call("control.thread_pending", {"target": "vesper"}))
        self.assertEqual([thread["id"] for thread in pending["threads"]], [thread_id])

        acked = self._result(self._call("control.thread_ack", {"thread_id": thread_id, "actor": "vesper", "text": "Taking this."}))
        self.assertEqual(acked["thread"]["status"], "acked")
        self.assertTrue(acked["thread"]["pending"])

        done = self._result(self._call("control.thread_done", {"thread_id": thread_id, "actor": "vesper"}))
        self.assertFalse(done["thread"]["pending"])

        marked = self._result(self._call("control.thread_read_all", {"target": "vesper"}))
        self.assertEqual([thread["id"] for thread in marked["threads"]], [thread_id])

    def test_identity_bound_actor_cannot_be_spoofed(self) -> None:
        posted = self._result(
            self._call(
                "control.thread_post",
                {"title": "Bound actor", "actor": "mallory", "target": "vesper"},
                actor="demobot",
            )
        )
        self.assertEqual(posted["thread"]["actor"], "demobot")

    def test_identity_bound_target_fetches_exact_execution_session(self) -> None:
        created = post_thread(
            state=self.state, title="Durable continuation", thread_type="ask",
            actor="odin", target="amir", actor_identity_bound=True,
        )
        acknowledge_thread(
            state=self.state, thread_id=created.thread.id, actor="amir",
            actor_identity_bound=True,
        )
        execution = claim_execution(
            self.state, worker="execution-worker", execution_capable_targets={"amir"},
            now=datetime.now(timezone.utc), lease_seconds=120,
        )
        self.assertIsNotNone(execution)

        session = self._result(
            self._call(
                "control.execution_session_get",
                {"execution_id": execution.id, "attempt_id": execution.attempt_id},
                actor="amir",
            )
        )

        self.assertEqual(session["execution"]["id"], execution.id)
        self.assertEqual(session["execution"]["attempt_id"], execution.attempt_id)
        self.assertEqual(session["execution"]["target"], "amir")
        self.assertEqual(session["subject"]["thread"]["id"], created.thread.id)

    def test_identity_bound_target_requests_and_reads_fixed_session_return(self) -> None:
        created = post_thread(
            state=self.state, title="Tell Elin", thread_type="ask",
            actor="odin", target="amir", actor_identity_bound=True,
        )
        acknowledge_thread(
            state=self.state, thread_id=created.thread.id, actor="amir",
            actor_identity_bound=True,
        )
        execution = claim_execution(
            self.state, worker="execution-worker", execution_capable_targets={"amir"},
            now=datetime.now(timezone.utc), lease_seconds=120,
        )
        requested = self._result(
            self._call(
                "control.execution_session_return_request",
                {
                    "execution_id": execution.id,
                    "attempt_id": execution.attempt_id,
                    "message": "bir iki üç",
                    "expected_word_count": 3,
                    "idempotency_key": "session-return-mcp-0001",
                },
                actor="amir",
            )
        )["session_return"]
        self.assertEqual(requested["target"], "amir")
        readback = self._result(
            self._call(
                "control.execution_session_return_get",
                {"request_id": requested["request_id"]},
                actor="amir",
            )
        )["session_return"]
        self.assertEqual(readback["message_sha256"], requested["message_sha256"])
        denied = self._call(
            "control.execution_session_return_get",
            {"request_id": requested["request_id"]},
            actor="esme",
        )
        self.assertIn("unknown session return", denied["error"]["message"])

    def test_execution_session_rejects_foreign_or_unbound_actor(self) -> None:
        created = post_thread(
            state=self.state, title="Private continuation", thread_type="ask",
            actor="odin", target="amir", actor_identity_bound=True,
        )
        acknowledge_thread(
            state=self.state, thread_id=created.thread.id, actor="amir",
            actor_identity_bound=True,
        )
        execution = claim_execution(
            self.state, worker="execution-worker", execution_capable_targets={"amir"},
            now=datetime.now(timezone.utc), lease_seconds=120,
        )
        self.assertIsNotNone(execution)
        arguments = {"execution_id": execution.id, "attempt_id": execution.attempt_id}

        for actor in ("esme", None):
            response = self._call("control.execution_session_get", arguments, actor=actor)
            self.assertIn("error", response)
            self.assertIn("identity-bound target", response["error"]["message"])

    def test_identity_bound_target_heartbeats_its_current_attempt(self) -> None:
        created = post_thread(
            state=self.state, title="Long routine work", thread_type="ask",
            actor="odin", target="amir", actor_identity_bound=True,
        )
        acknowledge_thread(
            state=self.state, thread_id=created.thread.id, actor="amir",
            actor_identity_bound=True,
        )
        execution = claim_execution(
            self.state, worker="execution-worker", execution_capable_targets={"amir"},
            now=datetime.now(timezone.utc), lease_seconds=120,
        )
        self.assertIsNotNone(execution)

        result = self._result(
            self._call(
                "control.execution_heartbeat",
                {
                    "execution_id": execution.id,
                    "attempt_id": execution.attempt_id,
                    "lease_seconds": 120,
                    "detail": "working through scoped tools",
                    "idempotency_key": "heartbeat-amir-attempt-0001",
                },
                actor="amir",
            )
        )

        self.assertEqual(result["execution"]["status"], "leased")
        self.assertEqual(result["execution"]["attempt_id"], execution.attempt_id)
        heartbeat = read_events(self.state)[-1]
        self.assertEqual(heartbeat.type, "execution.heartbeat")
        self.assertEqual(heartbeat.payload["heartbeat_by"], "amir")
        self.assertIs(heartbeat.payload["actor_identity_bound"], True)

    def test_execution_heartbeat_rejects_foreign_and_stale_attempts(self) -> None:
        created = post_thread(
            state=self.state, title="Fenced continuation", thread_type="ask",
            actor="odin", target="amir", actor_identity_bound=True,
        )
        acknowledge_thread(
            state=self.state, thread_id=created.thread.id, actor="amir",
            actor_identity_bound=True,
        )
        execution = claim_execution(
            self.state, worker="execution-worker", execution_capable_targets={"amir"},
            now=datetime.now(timezone.utc), lease_seconds=120,
        )
        self.assertIsNotNone(execution)

        base = {
            "execution_id": execution.id,
            "attempt_id": execution.attempt_id,
            "lease_seconds": 120,
            "idempotency_key": "heartbeat-fence-0001",
        }
        foreign = self._call("control.execution_heartbeat", base, actor="esme")
        self.assertIn("identity-bound target", foreign["error"]["message"])
        stale = self._call(
            "control.execution_heartbeat",
            {**base, "attempt_id": "attempt_stale", "idempotency_key": "heartbeat-fence-0002"},
            actor="amir",
        )
        self.assertIn("stale", stale["error"]["message"])

    def test_execution_heartbeat_rejects_unbounded_lease_extension(self) -> None:
        created = post_thread(
            state=self.state, title="Bounded lease", thread_type="ask",
            actor="odin", target="amir", actor_identity_bound=True,
        )
        acknowledge_thread(
            state=self.state, thread_id=created.thread.id, actor="amir",
            actor_identity_bound=True,
        )
        execution = claim_execution(
            self.state, worker="execution-worker", execution_capable_targets={"amir"},
            now=datetime.now(timezone.utc), lease_seconds=120,
        )
        self.assertIsNotNone(execution)
        operation_id = "-".join(("heartbeat", "unbounded", "0001"))
        response = self._call(
            "control.execution_heartbeat",
            {
                "execution_id": execution.id,
                "attempt_id": execution.attempt_id,
                "lease_seconds": 3601,
                "idempotency_key": operation_id,
            },
            actor="amir",
        )
        self.assertIn("error", response)
        self.assertIn("at most 3600", response["error"]["message"])

    def test_unbound_mcp_assignment_cannot_forge_execution_authority(self) -> None:
        posted = self._result(
            self._call(
                "control.thread_post",
                {
                    "title": "Unbound execution authority",
                    "type": "ask",
                    "target": "amir",
                    "actor": "esme",
                },
            )
        )
        self.assertIs(posted["event"]["payload"]["actor_identity_bound"], False)
        self.assertIsNone(
            claim_execution(
                self.state,
                worker="mcp-authority",
                execution_capable_targets={"amir"},
            )
        )

    def test_operator_mcp_cannot_forge_execution_authoritative_target_terminal(self) -> None:
        posted = self._result(
            self._call(
                "control.thread_post",
                {"title": "Execution authority", "type": "ask", "target": "amir"},
                actor="esme",
            )
        )
        thread_id = posted["thread"]["id"]
        self.assertIs(posted["event"]["payload"]["actor_identity_bound"], True)
        self._result(
            self._call("control.thread_ack", {"thread_id": thread_id}, actor="amir")
        )
        execution = claim_execution(
            self.state, worker="mcp-authority", execution_capable_targets={"amir"},
        )
        self.assertIsNotNone(execution)

        self._result(
            self._call(
                "control.thread_done",
                {"thread_id": thread_id, "actor": "amir"},
                actor=None,
            )
        )
        terminal = read_events(self.state)[-1]
        self.assertEqual(terminal.type, "thread.done")
        self.assertEqual(terminal.payload["done_by"], "amir")
        self.assertIs(terminal.payload["actor_identity_bound"], False)
        self.assertEqual(reconcile_executions(self.state), [])
        self.assertEqual(project_executions(self.state)[execution.id].status, "leased")

    def test_mcp_completion_contract_requires_structured_evidence(self) -> None:
        artifact = "/home/demobot/.hermes/memories/USER.md"
        posted = self._result(
            self._call(
                "control.thread_post",
                {
                    "title": "Update canonical user memory",
                    "type": "ask",
                    "target": "demobot",
                    "completion_artifact": artifact,
                    "completion_anchor": "0bserverx",
                },
                actor="operator",
            )
        )
        thread_id = posted["thread"]["id"]
        rejected = self._call("control.thread_done", {"thread_id": thread_id}, actor="demobot")
        self.assertIn("error", rejected)
        self.assertIn("completion evidence is required", rejected["error"]["message"])
        done = self._result(
            self._call(
                "control.thread_done",
                {
                    "thread_id": thread_id,
                    "evidence_artifact": artifact,
                    "evidence_anchor": "0bserverx",
                    "evidence_method": "direct-read",
                },
                actor="demobot",
            )
        )
        self.assertEqual(done["thread"]["evidence_artifact"], artifact)
        self.assertEqual(done["thread"]["evidence_method"], "direct-read")

    def test_identity_bound_agents_auto_reply_to_broadcast_without_closing_parent(self) -> None:
        created = post_thread(
            state=self.state,
            title="Fleet status",
            thread_type="status",
            actor="odin",
            target="all",
        )
        for agent in ("amir", "esme", "kiran"):
            result = self._result(
                self._call(
                    "control.thread_reply",
                    {
                        "thread_id": created.thread.id,
                        "actor": "mallory",
                        "text": f"{agent} received.",
                        "idempotency_key": f"broadcast-reply-{agent}-0001",
                    },
                    actor=agent,
                )
            )
            self.assertEqual(result["thread"]["messages"][-1]["actor"], agent)
        projected = self._result(self._call("control.thread_inbox", {}))
        thread = next(item for item in projected["threads"] if item["id"] == created.thread.id)
        self.assertEqual(thread["status"], "open")
        self.assertFalse(thread["pending"])
        self.assertEqual([message["actor"] for message in thread["messages"]], ["amir", "esme", "kiran"])
        exact = self._result(
            self._call("control.thread_get", {"thread_id": created.thread.id}, actor="esme")
        )
        self.assertEqual(exact["thread"]["id"], created.thread.id)
        self.assertEqual(len(exact["thread"]["messages"]), 3)
        self.assertEqual(exact["thread"]["target"], "all")
        self.assertEqual(exact["thread"]["actor"], "odin")

    def test_thread_get_denies_foreign_direct_thread(self) -> None:
        created = post_thread(
            state=self.state,
            title="Direct-only",
            thread_type="ask",
            actor="amir",
            target="esme",
        )
        response = self._call("control.thread_get", {"thread_id": created.thread.id}, actor="kiran")
        self.assertIn("error", response)
        self.assertIn("not permitted", response["error"]["message"])

    def test_identity_bound_reply_requires_direct_thread_participation(self) -> None:
        created = post_thread(state=self.state, title="Direct", actor="odin", target="esme")
        denied = self._call(
            "control.thread_reply",
            {"thread_id": created.thread.id, "text": "Not my thread"},
            actor="kiran",
        )
        self.assertIn("error", denied)
        self.assertIn("only reply as a participant", denied["error"]["message"])
        for participant in ("odin", "esme"):
            allowed = self._call(
                "control.thread_reply",
                {"thread_id": created.thread.id, "text": "Participant reply"},
                actor=participant,
            )
            self.assertIn("result", allowed)

    def test_identity_bound_reads_default_to_own_inbox(self) -> None:
        post_thread(state=self.state, title="For demobot", thread_type="ask", target="demobot", actor="demobot")
        post_thread(state=self.state, title="For vesper", thread_type="ask", target="vesper", actor="demobot")
        inbox = self._result(self._call("control.thread_inbox", {}, actor="demobot"))
        self.assertEqual([thread["target"] for thread in inbox["threads"]], ["demobot"])
        pending = self._result(self._call("control.thread_pending", {}, actor="demobot"))
        self.assertEqual([thread["target"] for thread in pending["threads"]], ["demobot"])
        marked = self._result(self._call("control.thread_read_all", {"include_pending": True}, actor="demobot"))
        self.assertEqual([thread["target"] for thread in marked["threads"]], ["demobot"])
        # vesper's thread is untouched by demobot's read-all
        vesper = self._result(self._call("control.thread_inbox", {"target": "vesper"}))
        self.assertTrue(vesper["threads"][0]["unread"])

    def test_identity_bound_reads_reject_foreign_target(self) -> None:
        post_thread(state=self.state, title="For vesper", thread_type="ask", target="vesper", actor="demobot")
        for tool in ("control.thread_inbox", "control.thread_pending", "control.thread_read_all"):
            response = self._call(tool, {"target": "vesper"}, actor="demobot")
            self.assertIn("error", response, tool)
            self.assertEqual(response["error"]["code"], -32000, tool)
            self.assertIn("may only access its own inbox", response["error"]["message"], tool)

    def test_cross_agent_ack_done_blocked(self) -> None:
        created = self._result(self._call("control.thread_post", {"title": "For vesper", "type": "ask", "target": "vesper"}))
        thread_id = created["thread"]["id"]
        for tool in ("control.thread_ack", "control.thread_done"):
            response = self._call(tool, {"thread_id": thread_id}, actor="demobot")
            self.assertIn("error", response, tool)
            self.assertEqual(response["error"]["code"], -32000, tool)
            self.assertIn("may only ack/done its own threads", response["error"]["message"], tool)
        # the targeted agent may ack and complete it
        acked = self._result(self._call("control.thread_ack", {"thread_id": thread_id}, actor="vesper"))
        self.assertEqual(acked["thread"]["status"], "acked")
        self.assertEqual(acked["thread"]["acked_by"], "vesper")
        # operator (no bound actor) may complete any thread
        done = self._result(self._call("control.thread_done", {"thread_id": thread_id}))
        self.assertEqual(done["thread"]["status"], "done")


class ThreadPolicySurfaceTests(unittest.TestCase):
    def test_scopes_split_thread_reads_from_writes(self) -> None:
        read_tools = tools_for_scopes(frozenset({SCOPE_CONTROL_READ}))
        write_tools = tools_for_scopes(frozenset({SCOPE_CONTROL_WRITE}))
        for tool in CONTROL_THREAD_READ_TOOL_NAMES:
            self.assertIn(tool, read_tools)
            self.assertNotIn(tool, write_tools)
        for tool in CONTROL_THREAD_WRITE_TOOL_NAMES:
            self.assertIn(tool, write_tools)
            self.assertNotIn(tool, read_tools)

    def test_bridge_policy_profiles_cover_thread_tools(self) -> None:
        read_only = build_bridge_policy(profile="read-only").policy["policy"]["allow_tools"]
        operator = build_bridge_policy(profile="operator").policy["policy"]["allow_tools"]
        for tool in CONTROL_THREAD_READ_TOOL_NAMES:
            self.assertIn(tool, read_only)
            self.assertIn(tool, operator)
        for tool in CONTROL_THREAD_WRITE_TOOL_NAMES:
            self.assertNotIn(tool, read_only)
            self.assertIn(tool, operator)

    def test_bridge_examples_cover_thread_tools(self) -> None:
        read_only = json.loads(
            (REPO_ROOT / "examples/safe-mcp-bridge/read-only.json").read_text(encoding="utf-8")
        )["policy"]["allow_tools"]
        operator = json.loads(
            (REPO_ROOT / "examples/safe-mcp-bridge/operator.json").read_text(encoding="utf-8")
        )["policy"]["allow_tools"]
        for tool in CONTROL_THREAD_READ_TOOL_NAMES:
            self.assertIn(tool, read_only)
            self.assertIn(tool, operator)
        for tool in CONTROL_THREAD_WRITE_TOOL_NAMES:
            self.assertNotIn(tool, read_only)
            self.assertIn(tool, operator)


if __name__ == "__main__":
    unittest.main()
