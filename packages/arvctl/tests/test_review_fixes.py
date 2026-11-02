from __future__ import annotations
from arvyx_control.replica_authority import authority_context

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from arvyx_control.control import (
    accept_handoff,
    create_handoff,
    create_task,
    post_bus_message,
    request_approval,
    review_handoff,
)
from arvyx_control.mcp import handle_request, tools_for_profile
from arvyx_control.recall import coerce_int
from arvyx_control.replica import build_manifest
from arvyx_control.store import sync_sqlite
from arvyx_control.vault import init_vault


class CoerceIntTests(unittest.TestCase):
    def test_valid_and_default(self) -> None:
        self.assertEqual(coerce_int(None, 350), 350)
        self.assertEqual(coerce_int(120, 350), 120)
        self.assertEqual(coerce_int("120", 350), 120)

    def test_malformed_raises_valueerror_not_typeerror(self) -> None:
        for bad in ({}, [], True, False, "abc", 3.5):
            with self.assertRaises(ValueError):
                coerce_int(bad, 350)

    def _recall(self, vault: Path, arguments: dict) -> dict:
        return handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "memory.recall", "arguments": arguments},
            },
            vault=vault,
            allowed_tools=set(tools_for_profile("read-only")),
        )

    def test_null_max_tokens_falls_back_to_default_without_crashing(self) -> None:
        # JSON .get() cannot tell absent from explicit null, so null uses the
        # default. The point is no unhandled TypeError.
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            response = self._recall(vault, {"question": "safe mcp bridge", "project": "demo-agent", "max_tokens": None})
            self.assertIn("result", response)

    def test_malformed_numeric_returns_structured_error_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            for bad in ([1, 2, 3], {"x": 1}, "not-a-number", True):
                response = self._recall(vault, {"question": "anything", "limit": bad})
                self.assertIn("error", response, repr(bad))
                self.assertEqual(response["error"]["code"], -32000, repr(bad))


class ReplicaSymlinkTests(unittest.TestCase):
    def test_manifest_excludes_symlink_escaping_vault(self) -> None:
        if not hasattr(os, "symlink"):
            self.skipTest("symlinks unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            outside = Path(tmp) / "outside.md"
            outside.write_text("secret://private/leak\n", encoding="utf-8")
            link = vault / "projects" / "demo-agent" / "LINK.md"
            try:
                os.symlink(outside, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation not permitted")

            manifest = build_manifest(vault)
            self.assertNotIn("projects/demo-agent/LINK.md", manifest["files"])
            # a normal file is still present
            self.assertTrue(any(p.endswith("DECISIONS.md") for p in manifest["files"]))


class BridgeMethodAllowlistTests(unittest.TestCase):
    def test_resources_and_prompts_methods_are_blocked(self) -> None:
        from safe_mcp_bridge.cli import BLOCKED_METHOD_CODE, _handle_line

        config = {
            "target": {"url": "http://127.0.0.1:1/mcp"},
            "policy": {"mode": "allowlist", "allow_tools": ["memory.recall"]},
        }
        # Regression scenario: an upstream that exposes resources/* must not be
        # reachable through the read-only bridge.
        for method in ("resources/list", "resources/read", "prompts/list", "prompts/get", "completion/complete"):
            response = _handle_line(config, json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}))
            self.assertEqual(response["error"]["code"], BLOCKED_METHOD_CODE, method)

    def test_notifications_are_forwarded_without_json_rpc_response(self) -> None:
        from safe_mcp_bridge import cli as bridge_cli

        config = {
            "target": {"url": "http://127.0.0.1:1/mcp"},
            "policy": {"mode": "allowlist", "allow_tools": ["memory.recall"]},
        }
        payload = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        with mock.patch.object(bridge_cli, "_post_json", return_value={"ok": True}) as post_json:
            response = bridge_cli._handle_line(config, payload)
        self.assertIsNone(response)
        post_json.assert_called_once()

    def test_response_suppression_depends_on_missing_id_not_method_prefix(self) -> None:
        from safe_mcp_bridge import cli as bridge_cli

        config = {
            "target": {"url": "http://127.0.0.1:1/mcp"},
            "policy": {"mode": "allowlist", "allow_tools": ["memory.recall"]},
        }
        with mock.patch.object(bridge_cli, "_post_json", return_value={"jsonrpc": "2.0", "id": 7, "result": {}}):
            response = bridge_cli._handle_line(
                config,
                json.dumps({"jsonrpc": "2.0", "id": 7, "method": "notifications/initialized", "params": {}}),
            )
        self.assertEqual(response, {"jsonrpc": "2.0", "id": 7, "result": {}})

        with mock.patch.object(bridge_cli, "_post_json", return_value={"jsonrpc": "2.0", "result": {"tools": []}}) as post_json:
            response = bridge_cli._handle_line(config, json.dumps({"jsonrpc": "2.0", "method": "tools/list", "params": {}}))
        self.assertIsNone(response)
        post_json.assert_called_once()

    def test_no_id_tools_call_still_enforces_tool_allowlist(self) -> None:
        from safe_mcp_bridge import cli as bridge_cli

        config = {
            "target": {"url": "http://127.0.0.1:1/mcp"},
            "policy": {"mode": "allowlist", "allow_tools": ["memory.recall"]},
        }
        blocked_payload = json.dumps(
            {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "memory.promote", "arguments": {}}}
        )
        with mock.patch.object(bridge_cli, "_post_json", return_value={"should": "not forward"}) as post_json:
            response = bridge_cli._handle_line(config, blocked_payload)
        self.assertIsNone(response)
        post_json.assert_not_called()

        allowed_payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "memory.recall", "arguments": {"question": "safe bridge"}},
            }
        )
        with mock.patch.object(bridge_cli, "_post_json", return_value={"jsonrpc": "2.0", "result": {}}) as post_json:
            response = bridge_cli._handle_line(config, allowed_payload)
        self.assertIsNone(response)
        post_json.assert_called_once()

    def test_mutation_idempotency_key_survives_bridge_forwarding(self) -> None:
        from safe_mcp_bridge import cli as bridge_cli

        operation_key = "bridge-retry-key-0001"
        config = {
            "target": {"url": "http://127.0.0.1:1/mcp"},
            "policy": {"mode": "allowlist", "allow_tools": ["memory.promote"]},
        }
        payload = {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "memory.promote",
                "arguments": {"suggestion_id": "s-1", "idempotency_key": operation_key},
            },
        }
        captured: list[dict[str, object]] = []

        def forward(_config, forwarded):
            captured.append(forwarded)
            return {"jsonrpc": "2.0", "id": 9, "result": {}}

        with mock.patch.object(bridge_cli, "_post_json", side_effect=forward):
            response = bridge_cli._handle_line(config, json.dumps(payload))
        self.assertEqual(response["id"], 9)
        arguments = captured[0]["params"]["arguments"]
        self.assertEqual(arguments["idempotency_key"], operation_key)


class HandoffProjectionTests(unittest.TestCase):
    def test_handoff_author_cannot_review_own_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                handoff = create_handoff(state=state, title="Ship it", from_agent="demobot", to_agent="operator")
                accept_handoff(state=state, handoff_id=handoff.handoff.id)
                with self.assertRaises(ValueError):
                    review_handoff(state=state, handoff_id=handoff.handoff.id, reviewer="DemoBot")

    def test_all_control_free_text_rejects_literal_secrets(self) -> None:
        secret = "password = hunter2hunter2"
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                calls = (
                    lambda: create_task(state=state, title=secret, owner="demobot"),
                    lambda: request_approval(state=state, command="safe", reason=secret, requester="demobot"),
                    lambda: create_handoff(state=state, title="safe", summary=secret, from_agent="demobot"),
                    lambda: post_bus_message(state=state, message=secret, actor="demobot"),
                )
                for call in calls:
                    with self.assertRaises(ValueError):
                        call()
                self.assertFalse(state.exists())

    def test_sqlite_keeps_review_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "authority-vault"
            vault.mkdir(exist_ok=True)
            with authority_context(vault, state):
                db = Path(tmp) / "control.sqlite"
                handoff = create_handoff(state=state, title="Ship it", from_agent="demobot", to_agent="operator")
                accept_handoff(state=state, handoff_id=handoff.handoff.id)
                review_handoff(
                    state=state,
                    handoff_id=handoff.handoff.id,
                    reviewer="operator",
                    decision="changes_requested",
                    notes="tighten the error handling",
                )
                sync_sqlite(state=state, db=db)
                with closing(sqlite3.connect(db)) as conn:
                    row = conn.execute(
                        "SELECT reviewer, review_decision, review_notes FROM handoffs WHERE id = ?",
                        (handoff.handoff.id,),
                    ).fetchone()
        self.assertEqual(row[0], "operator")
        self.assertEqual(row[1], "changes_requested")
        self.assertEqual(row[2], "tighten the error handling")


if __name__ == "__main__":
    unittest.main()
