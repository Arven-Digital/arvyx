from __future__ import annotations
from arvyx_control.replica_authority import authority_context

from datetime import UTC, datetime, timedelta
from pathlib import Path
import tempfile
import unittest

from arvyx_control.control import (
    complete_task,
    create_handoff,
    create_task,
    post_bus_message,
    request_approval,
)
from arvyx_control.digest import build_digest
from arvyx_control.session import set_session
from arvyx_control.vault import init_vault


class DigestTests(unittest.TestCase):
    def test_agent_scoped_brief(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            with authority_context(vault, state):
                create_task(state=state, title="demobot task", owner="demobot")
                create_task(state=state, title="vesper task", owner="vesper")
                create_handoff(state=state, title="for demobot", from_agent="vesper", to_agent="demobot")
                create_handoff(state=state, title="for operator", from_agent="demobot", to_agent="operator")
                set_session(vault=vault, agent="demobot", content="working on the digest wiring")

                digest = build_digest(state=state, vault=vault, agent="demobot")
                # scoped to demobot: only its task and the handoff assigned to it
                self.assertEqual([t["title"] for t in digest.open_tasks], ["demobot task"])
                self.assertEqual([h["title"] for h in digest.assigned_handoffs], ["for demobot"])
                self.assertIsNotNone(digest.session)
                self.assertIn("digest wiring", digest.session["content"])
                self.assertTrue(any("for demobot" in line for line in digest.focus))

    def test_window_bounds_alerts_and_overdue_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            with authority_context(vault, state):
                create_task(state=state, title="old task", owner="demobot")
                post_bus_message(state=state, message="early alert", channel="ops", actor="demobot", severity="alert")

                # pin "now" 50h ahead so the freshly-created events read as old
                future = datetime.now(UTC) + timedelta(hours=50)
                digest = build_digest(state=state, agent="demobot", window_hours=24, task_sla_hours=48, now=future)
                self.assertEqual([t["title"] for t in digest.overdue_tasks], ["old task"])
                # the alert is 50h old and the window is 24h, so it is not "recent"
                self.assertEqual(digest.recent_alerts, [])

    def test_completed_in_window_counted_and_excluded_from_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            with authority_context(vault, state):
                task = create_task(state=state, title="done task", owner="demobot")
                complete_task(state=state, task_id=task.task.id)

                digest = build_digest(state=state, agent="demobot", window_hours=24)
                self.assertEqual(digest.completed["tasks"], 1)
                self.assertEqual(digest.open_tasks, [])

    def test_team_view_surfaces_awaiting_approvals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            with authority_context(vault, state):
                request_approval(state=state, command="arvyx recall demo-agent", requester="demobot")

                digest = build_digest(state=state, agent=None)  # operator-wide view
                self.assertEqual(len(digest.awaiting_approvals), 1)
                self.assertTrue(any("approval" in line for line in digest.focus))

    def test_session_withheld_from_control_read_only_token(self) -> None:
        # the checkpoint portion requires session.read; a control.read-only caller
        # must not receive another agent's working-memory prose via the digest
        from arvyx_control.api import handle_api_request
        from arvyx_control.auth import issue_token

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            set_session(vault=vault, agent="demobot", content="secret working memory prose")
            control_only = issue_token(vault, "backup-1", scopes=["control.read"]).token
            with_memory = issue_token(vault, "vesper", scopes=["control.read", "memory.read", "session.read"]).token
            ordinary_memory = issue_token(vault, "demobot", scopes=["control.read", "memory.read"]).token
            ordinary = handle_api_request("GET", "/digest?agent=demobot", None,
                vault=vault, state=state, authorization=f"Bearer {ordinary_memory}")
            self.assertEqual(ordinary.status, 200)
            self.assertIsNone(ordinary.body["session"])

            control = handle_api_request(
                "GET", "/digest?agent=demobot", None, vault=vault, state=state, authorization=f"Bearer {control_only}"
            )
            self.assertEqual(control.status, 200)
            self.assertIsNone(control.body["session"])

            memory = handle_api_request(
                "GET", "/digest?agent=demobot", None, vault=vault, state=state, authorization=f"Bearer {with_memory}"
            )
            self.assertEqual(memory.status, 200)
            self.assertIsNotNone(memory.body["session"])

            # the same withhold must hold over POST /mcp control.digest
            import json as json_module

            call = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "control.digest", "arguments": {"agent": "demobot"}},
            }
            mcp_control = handle_api_request(
                "POST", "/mcp", call, vault=vault, state=state,
                authorization=f"Bearer {control_only}", mcp_profile="operator",
            )
            self.assertEqual(mcp_control.status, 200)
            self.assertIsNone(json_module.loads(mcp_control.body)["result"]["structuredContent"]["session"])
            mcp_memory = handle_api_request(
                "POST", "/mcp", call, vault=vault, state=state,
                authorization=f"Bearer {with_memory}", mcp_profile="operator",
            )
            self.assertIsNotNone(json_module.loads(mcp_memory.body)["result"]["structuredContent"]["session"])

    def test_recent_alerts_are_newest_first_and_capped(self) -> None:
        from arvyx_control.control import list_bus_messages
        from arvyx_control.digest import _LIST_CAP

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            with authority_context(vault, state):
                for index in range(_LIST_CAP + 3):
                    post_bus_message(state=state, message=f"alert {index}", channel="ops", actor="demobot", severity="alert")

                canonical = [m for m in list_bus_messages(state=state).messages if m.severity == "alert"]
                expected = [m.message for m in reversed(canonical[-_LIST_CAP:])]
                digest = build_digest(state=state, agent=None, window_hours=24)
                got = [alert["message"] for alert in digest.recent_alerts]
                self.assertEqual(got, expected)
                self.assertEqual(len(got), _LIST_CAP)  # the newest cap, not the oldest

    def test_completed_and_window_are_scoped_and_clamped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            with authority_context(vault, state):
                demobot_done = create_task(state=state, title="demobot done", owner="demobot")
                complete_task(state=state, task_id=demobot_done.task.id)
                vesper_done = create_task(state=state, title="vesper done", owner="vesper")
                complete_task(state=state, task_id=vesper_done.task.id)

                scoped = build_digest(state=state, agent="demobot", window_hours=0)  # 0 must clamp to 1
                self.assertEqual(scoped.window_hours, 1)
                self.assertEqual(scoped.completed["tasks"], 1)  # only demobot's, not vesper's
                team = build_digest(state=state, agent=None)
                self.assertEqual(team.completed["tasks"], 2)

    def test_malformed_timestamps_are_out_of_window(self) -> None:
        from datetime import datetime

        from arvyx_control.digest import _within

        now = datetime.now(UTC)
        self.assertFalse(_within("", now, 24))
        self.assertFalse(_within("not-a-date", now, 24))
        self.assertTrue(_within(now.replace(microsecond=0).isoformat().replace("+00:00", "Z"), now, 24))

    def test_digest_over_api_and_mcp_with_scope(self) -> None:
        from arvyx_control.api import handle_api_request
        from arvyx_control.mcp import handle_request, tools_for_profile

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            state = Path(tmp) / "events.jsonl"
            with authority_context(vault, state):
                create_task(state=state, title="a task", owner="demobot")

                allowed = handle_api_request(
                    "GET", "/digest?agent=demobot", None, vault=vault, state=state, allow_unauthenticated_demo=True
                )
                self.assertEqual(allowed.status, 200)
                self.assertEqual(allowed.body["agent"], "demobot")
                # the digest needs control.read; unauthenticated (memory.read only) is refused
                denied = handle_api_request("GET", "/digest", None, vault=vault, state=state)
                self.assertEqual(denied.status, 401)

                response = handle_request(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "control.digest", "arguments": {"agent": "demobot"}},
                    },
                    vault=vault,
                    state=state,
                    allowed_tools=set(tools_for_profile("operator")),
                )
                self.assertEqual(response["result"]["structuredContent"]["agent"], "demobot")


if __name__ == "__main__":
    unittest.main()
