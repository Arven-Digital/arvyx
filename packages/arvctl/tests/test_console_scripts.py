from __future__ import annotations

from importlib import import_module
from pathlib import Path
import tomllib
import unittest

REPO_ROOT = Path(__file__).resolve().parents[3]


class ConsoleScriptTests(unittest.TestCase):
    def test_declared_entry_points_resolve_to_callables(self) -> None:
        pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        scripts = pyproject["project"]["scripts"]
        self.assertIn("arvyx", scripts)
        self.assertIn("safe-mcp-bridge", scripts)
        for name, target in scripts.items():
            module_name, _, attribute = target.partition(":")
            self.assertTrue(attribute, f"{name}: entry point {target!r} has no attribute")
            module = import_module(module_name)
            entry = getattr(module, attribute, None)
            self.assertIsNotNone(entry, f"{name}: {module_name} does not export {attribute!r}")
            self.assertTrue(callable(entry), f"{name}: {target} is not callable")

    def test_stale_app_console_shim_still_resolves(self) -> None:
        # Regression: an earlier packaging revision generated console shims
        # that run `from safe_mcp_bridge.cli import app; app()`. Installed
        # environments keep that shim until reinstalled, so the module must
        # keep exporting app (make bridge-dogfood-smoke discovers the shim
        # via PATH and died on the ImportError when app disappeared).
        from safe_mcp_bridge import cli

        self.assertTrue(callable(cli.app))
        self.assertIs(cli.app, cli.main)


if __name__ == "__main__":
    unittest.main()
