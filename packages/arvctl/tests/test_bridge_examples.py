from __future__ import annotations

import json
from pathlib import Path
import unittest

from arvyx_control.bridge import build_bridge_policy


REPO_ROOT = Path(__file__).resolve().parents[3]
EXAMPLES = REPO_ROOT / "examples" / "safe-mcp-bridge"


class BridgeExampleTests(unittest.TestCase):
    def test_committed_bridge_examples_match_generator(self) -> None:
        for profile, filename in (
            ("read-only", "read-only.json"),
            ("agent", "agent.json"),
            ("operator", "operator.json"),
        ):
            with self.subTest(profile=profile):
                committed = json.loads((EXAMPLES / filename).read_text(encoding="utf-8"))
                generated = build_bridge_policy(profile=profile).policy
                self.assertEqual(committed, generated)


if __name__ == "__main__":
    unittest.main()
