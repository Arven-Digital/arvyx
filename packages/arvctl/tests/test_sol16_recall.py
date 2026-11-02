"""Candidate15 findings 5–7: bounded content and source association."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from arvyx_control.recall import recall, excerpt, context_pack


def cost(text):
    return max(len(text.split()), (len(text.encode("utf-8")) + 15) // 16)


class Sol16RecallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.vault = Path(self.temp.name)

    def source(self, name, text):
        path = self.vault / "projects" / "sample" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path.relative_to(self.vault).as_posix()

    def test_unbroken_content_is_bounded(self):
        for token in ("z" * 200000, "界" * 70000):
            with self.subTest(unicode=token[0]):
                path = self.source("LONG.md", "Needle " + token)
                result = recall("Needle", self.vault, max_tokens=40)
                self.assertTrue(result.cards)
                self.assertLessEqual(sum(cost(s) for s in result.answer), 40)
                self.assertLessEqual(cost(excerpt(self.vault, path, "1", max_tokens=40).text), 40)

    def test_context_pack_uses_one_aggregate_budget(self):
        for i in range(8):
            self.source(f"S{i}.md", "Current truth " + "ordinary content " * 100)
        for budget in (80, 81, 120, 350):
            with self.subTest(budget=budget):
                result = context_pack("current truth", self.vault, max_tokens=budget, limit=20)
                texts = result.answer + [e.text for e in result.excerpts]
                self.assertLessEqual(sum(cost(s) for s in texts), budget)
                self.assertTrue(result.answer)

    def test_skipped_match_does_not_shift_citation(self):
        self.source("A.md", "---\ntags: [needle, needle, needle]\n---\nUnrelated body.")
        self.source("B.md", "Needle is in project Beta.")
        from unittest.mock import patch
        from arvyx_control.index import IndexedChunk
        matches = [
            (IndexedChunk("projects/sample/A.md", 1, 4, "A", {"needle": 3}, 3), 3.0),
            (IndexedChunk("projects/sample/B.md", 1, 1, "B", {"needle": 1}, 6), 2.0),
        ]
        with patch("arvyx_control.recall._score_chunks", return_value=matches):
            result = recall("needle", self.vault)
        self.assertTrue(result.cards)
        for card in result.cards:
            if "Beta" in card.claim:
                self.assertEqual(card.source.path, "projects/sample/B.md")
                self.assertIn("Needle is in project Beta.", excerpt(self.vault, card.source.path, card.source.lines).text)
        self.assertTrue(any("Beta" in c.claim for c in result.cards))


if __name__ == "__main__":
    unittest.main()
