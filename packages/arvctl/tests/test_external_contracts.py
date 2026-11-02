from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "docs" / "contracts" / "external-contracts.json"
GENERATOR = ROOT / "scripts" / "generate_external_contracts.py"


class ExternalContractTests(unittest.TestCase):
    def test_committed_contract_matches_executable_sources(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(GENERATOR), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)

    def test_check_mode_rejects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            stale = Path(temp) / "contract.json"
            stale.write_text("{}\n", encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(GENERATOR), "--check", "--output", str(stale)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("contract drift", completed.stderr)

    def test_priority_memory_and_checkpoint_surfaces_are_exported(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        paths = contract["http"]["paths"]
        self.assertEqual(paths["/memory/suggest-batch"]["post"]["auth"]["required_scope"], "memory.suggest")
        self.assertEqual(paths["/memory/forget"]["post"]["auth"]["required_scope"], "memory.curate")
        self.assertIn("/schemas/memory-suggest-batch", paths)
        # The operator authority gate is part of the contract: a scope alone
        # does not tell a consumer that the route refuses non-operator tokens.
        self.assertTrue(paths["/executions/{id}/close"]["post"]["auth"]["operator_only"])
        self.assertTrue(paths["/executions/{id}/hold"]["post"]["auth"]["operator_only"])

        tools = {tool["name"]: tool for tool in contract["mcp"]["tools"]}
        batch_schema = tools["memory.suggest_batch"]["inputSchema"]
        item = batch_schema["properties"]["memories"]["items"]
        self.assertTrue({"content_class", "memory_class", "future_job", "assistant_suggestion_accepted"} <= set(item["required"]))
        self.assertEqual(item["properties"]["relations"]["maxItems"], 20)
        self.assertIn("memory.forget", tools)
        self.assertIn("operator", tools["memory.forget"]["profiles"])

        commands = {entry["command"] for entry in contract["cli"]["arvyx"]["commands"]}
        self.assertIn("arvyx index rebuild", commands)
        self.assertIn("arvyx index status", commands)
        self.assertIn("arvyx memory forget", commands)


if __name__ == "__main__":
    unittest.main()
