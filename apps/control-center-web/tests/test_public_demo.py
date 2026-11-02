from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "public-safe-synthetic"


class PublicSyntheticDemoTests(unittest.TestCase):
    def test_fixture_is_deterministic_and_covers_control_center_story(self) -> None:
        fixture = json.loads((APP / "fixtures" / "replay.json").read_text(encoding="utf-8"))
        self.assertEqual(fixture["schema"], "amc.synthetic.replay.v1")
        self.assertEqual(fixture["build_id"], "synthetic-replay-v1")
        self.assertEqual(fixture["clock"], "2026-09-09T09:00:00Z")
        self.assertEqual(set(fixture["states"]), {"full", "empty", "loading", "error"})
        full = fixture["states"]["full"]
        for key in ("memory", "tools", "approval", "handoff", "execution", "citations", "receipt"):
            self.assertIn(key, full)
        self.assertEqual(full["memory"]["current"]["status"], "current truth")
        self.assertEqual(full["memory"]["suggestion"]["status"], "pending suggestion")
        self.assertTrue(all(tool["scope"] for tool in full["tools"]))
        self.assertEqual(full["approval"]["status"], "awaiting human")
        self.assertRegex(full["approval"]["command_hash"], r"^sha256:[0-9a-f]{16}$")
        self.assertTrue(full["citations"])
        self.assertEqual(full["receipt"]["kind"], "audit receipt")

    def test_app_has_accessible_state_and_reduced_motion_contracts(self) -> None:
        html = (APP / "index.html").read_text(encoding="utf-8")
        css = (APP / "styles.css").read_text(encoding="utf-8")
        js = (APP / "app.js").read_text(encoding="utf-8")
        self.assertIn('href="#main"', html)
        self.assertIn('aria-label="Replay state"', html)
        self.assertIn('aria-live="polite"', html)
        self.assertIn('rel="icon" href="data:,"', html)
        self.assertIn('id="main"', html)
        self.assertIn(":focus-visible", css)
        self.assertIn("prefers-reduced-motion: reduce", css)
        self.assertIn("min-height: 44px", css)
        self.assertIn("URLSearchParams", js)
        self.assertIn("full", js)
        self.assertIn("empty", js)
        self.assertIn("loading", js)
        self.assertIn("error", js)

    def test_public_demo_contains_no_private_topology_or_live_credentials(self) -> None:
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in APP.rglob("*")
            if path.is_file()
        )
        forbidden = [
            r"https?://(?!example\.test)",
            r"(?:token|password|secret)\s*[:=]\s*[\"'][^\"']+",
            r"(?:token|password|secret)\s*[:=]\s*[A-Za-z0-9_\-./+]{8,}",
            r"(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d+\.\d+",
            r"/home/|/Users/|tailnet|bastion|production",
        ]
        for pattern in forbidden:
            self.assertIsNone(re.search(pattern, text, re.IGNORECASE), pattern)

    def test_capture_matrix_names_every_required_viewport_and_state(self) -> None:
        script = (ROOT / "scripts" / "capture.mjs").read_text(encoding="utf-8")
        for width in (390, 768, 1440):
            self.assertIn(str(width), script)
        for state in ("full", "empty", "loading", "error"):
            self.assertIn(f'"{state}"', script)
        self.assertIn("BUILD_ID", script)
        self.assertIn("COMMIT_ID", script)
        self.assertIn("newPage({ viewport,", script)
        self.assertNotIn("viewportSize", script)


if __name__ == "__main__":
    unittest.main()
