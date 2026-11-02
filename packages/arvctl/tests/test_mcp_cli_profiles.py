from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
PYTHONPATH = os.pathsep.join(
    [
        str(ROOT / "packages" / "arvctl" / "src"),
        str(ROOT / "packages" / "safe-mcp-bridge" / "src"),
    ]
)
FORBIDDEN_DEFAULT_TOOLS = {
    "control.approval_approve",
    "control.approval_consume",
    "control.task_create",
    "memory.promote",
    "secret.resolve",
}
EXPECTED_OPERATOR_TOOLS = {
    "control.approval_consume",
    "control.task_create",
    "memory.promote",
    "secret.resolve",
}


class McpCliProfileTests(unittest.TestCase):
    def _run_mcp(self, *profile_args: str) -> dict[str, object]:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "arvyx_control.cli",
                "mcp",
                "--vault",
                str(ROOT / "fixtures" / "synthetic-vault"),
                *profile_args,
            ],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": PYTHONPATH},
            input='{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n',
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(completed.stdout)

    @staticmethod
    def _tool_names(response: dict[str, object]) -> set[str]:
        result = response["result"]
        assert isinstance(result, dict)
        tools = result["tools"]
        assert isinstance(tools, list)
        return {tool["name"] for tool in tools if isinstance(tool, dict)}

    def test_default_tools_list_is_read_only(self) -> None:
        names = self._tool_names(self._run_mcp())
        self.assertIn("memory.recall", names)
        self.assertFalse(names & FORBIDDEN_DEFAULT_TOOLS, names & FORBIDDEN_DEFAULT_TOOLS)

    def test_operator_tools_require_explicit_profile(self) -> None:
        names = self._tool_names(self._run_mcp("--profile", "operator"))
        self.assertTrue(EXPECTED_OPERATOR_TOOLS <= names, EXPECTED_OPERATOR_TOOLS - names)

    def test_legacy_mcp_profile_flag_remains_compatible(self) -> None:
        names = self._tool_names(self._run_mcp("--mcp-profile", "operator"))
        self.assertTrue(EXPECTED_OPERATOR_TOOLS <= names, EXPECTED_OPERATOR_TOOLS - names)

    def test_help_and_docs_describe_safe_default_and_operator_trust_boundary(self) -> None:
        completed = subprocess.run(
            [sys.executable, "-m", "arvyx_control.cli", "mcp", "--help"],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": PYTHONPATH},
            capture_output=True,
            text=True,
            check=True,
        )
        help_text = completed.stdout
        docs = (ROOT / "examples" / "mcp-clients" / "README.md").read_text(encoding="utf-8")
        self.assertIn("--profile {read-only,agent,operator}", help_text)
        self.assertIn("default: read-only", help_text)
        self.assertIn("--profile operator", docs)
        self.assertIn("trusted", docs.lower())
        self.assertIn("mutation", docs.lower())

    def test_read_only_client_examples_set_the_claimed_profile_explicitly(self) -> None:
        examples = ROOT / "examples" / "mcp-clients"
        for filename in (
            "claude-desktop.json",
            "codex.toml",
            "cursor.json",
            "openhands.toml",
            "langgraph_client.py",
            "crewai_client.py",
        ):
            with self.subTest(filename=filename):
                text = (examples / filename).read_text(encoding="utf-8")
                self.assertIn("--profile", text)
                self.assertIn("read-only", text)


if __name__ == "__main__":
    unittest.main()
