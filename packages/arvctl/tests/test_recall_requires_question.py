"""A recall with no question is a malformed request, not an empty vault.

`POST /memory/recall` with no `question` answered HTTP 200 with "No matching memory found
in the curated vault.". A caller that forgot the field reads that as a fact about the
vault — "the memory is not there" — rather than about its own request, which is a much
more expensive conclusion. The MCP schema already marked `question` required, but the
domain function defaulted it to `""`, so REST, MCP and the CLI all accepted it. `recall`
now refuses a blank question at the boundary all four callers share.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from arvyx_control.replica_authority import authority_context
from arvyx_control.api import handle_api_request
from arvyx_control.recall import recall


class RecallRequiresQuestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.vault = root / "vault"
        self.vault.mkdir()
        self.state = root / "events.jsonl"
        self.enterContext(authority_context(self.vault, self.state))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _api(self, route: str, body: dict):
        return handle_api_request(
            "POST", route, body, vault=self.vault, state=self.state, allow_unauthenticated_demo=True
        )

    def test_domain_refuses_a_blank_question(self) -> None:
        for blank in ("", "   ", "\n"):
            with self.subTest(blank=repr(blank)):
                with self.assertRaises(ValueError) as caught:
                    recall(blank, vault=self.vault)
                self.assertIn("question is required", str(caught.exception))

    def test_rest_route_answers_400_not_an_empty_answer(self) -> None:
        for body in ({}, {"question": ""}, {"question": "  "}):
            with self.subTest(body=body):
                response = self._api("/memory/recall", body)
                self.assertEqual(response.status, 400, response.body)
                self.assertEqual(response.body["error"], "question is required")
                self.assertNotIn("answer", response.body)

    def test_rest_route_still_answers_a_real_question(self) -> None:
        response = self._api("/memory/recall", {"question": "which guardrail protects credentials"})
        self.assertEqual(response.status, 200, response.body)
        self.assertIn("answer", response.body)

    def test_mcp_tool_call_reports_an_error(self) -> None:
        response = self._api(
            "/mcp",
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "memory.recall", "arguments": {}},
            },
        )
        payload = response.body
        if isinstance(payload, str):
            payload = json.loads(payload)
        self.assertEqual(payload["error"]["message"], "question is required")
        self.assertNotIn("result", payload)


if __name__ == "__main__":
    unittest.main()
