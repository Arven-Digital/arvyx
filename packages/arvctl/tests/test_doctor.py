from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from arvyx_control.doctor import doctor
from arvyx_control.vault import init_vault

GRAPH_CODES = {"dangling_wikilink", "duplicate_title", "orphan_note"}


class DoctorGraphHealthTests(unittest.TestCase):
    def test_synthetic_vault_has_no_graph_findings(self) -> None:
        root = Path(__file__).resolve().parents[3]
        result = doctor(root / "fixtures" / "synthetic-vault")
        graph = [finding.to_dict() for finding in result.findings if finding.code in GRAPH_CODES]
        self.assertEqual(graph, [], f"shipped fixture should stay graph-clean, got {graph}")

    def test_dangling_duplicate_and_orphan_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            notes = vault / "projects" / "demo-agent" / "notes"
            notes.mkdir(parents=True, exist_ok=True)
            (notes / "a.md").write_text("# Note A\n\nSee [[Note B]] and [[Ghost Note]].\n", encoding="utf-8")
            (notes / "b.md").write_text("# Note B\n\nBack to [[Note A]].\n", encoding="utf-8")
            (notes / "lonely.md").write_text("# Lonely Note\n\nno links here\n", encoding="utf-8")
            (notes / "dup1.md").write_text("# Same Title\n\none\n", encoding="utf-8")
            (notes / "dup2.md").write_text("# Same Title\n\ntwo\n", encoding="utf-8")

            result = doctor(vault)
            codes = {(finding.code, finding.path) for finding in result.findings}
            self.assertIn(("dangling_wikilink", "projects/demo-agent/notes/a.md"), codes)
            self.assertTrue(any(code == "duplicate_title" for code, _ in codes))
            self.assertIn(("orphan_note", "projects/demo-agent/notes/lonely.md"), codes)
            # cross-linked notes are not orphans, and a resolvable link is not dangling
            self.assertNotIn(("orphan_note", "projects/demo-agent/notes/a.md"), codes)
            self.assertNotIn(("orphan_note", "projects/demo-agent/notes/b.md"), codes)
            # graph findings are advisory: they never fail the vault
            self.assertTrue(result.ok)

    def test_fenced_links_and_headings_are_ignored(self) -> None:
        # a [[link]] or "# heading" inside a code fence is documentation, not
        # a real link/title, and must not be flagged
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            notes = vault / "projects" / "demo-agent" / "notes"
            notes.mkdir(parents=True, exist_ok=True)
            (notes / "doc.md").write_text(
                '---\ntitle: Link Syntax\n---\n\n# Link Syntax\n\nExample:\n```\n[[Fenced Ghost]]\n# fake heading\n```\n',
                encoding="utf-8",
            )
            result = doctor(vault)
            dangling = [f.path for f in result.findings if f.code == "dangling_wikilink"]
            self.assertNotIn("projects/demo-agent/notes/doc.md", dangling)

    def test_quoted_frontmatter_title_resolves_a_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            notes = vault / "projects" / "demo-agent" / "notes"
            notes.mkdir(parents=True, exist_ok=True)
            # target has only a quoted frontmatter title (no H1); the link is unquoted
            (notes / "target.md").write_text('---\ntitle: "Recall Tuning"\n---\n\nbody\n', encoding="utf-8")
            (notes / "src.md").write_text("# Source\n\nsee [[Recall Tuning]]\n", encoding="utf-8")
            result = doctor(vault)
            dangling = [f.path for f in result.findings if f.code == "dangling_wikilink"]
            self.assertEqual(dangling, [])

    def test_untitled_same_stem_notes_not_flagged_as_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            notes = vault / "projects" / "demo-agent" / "notes"
            (notes / "a").mkdir(parents=True, exist_ok=True)
            (notes / "b").mkdir(parents=True, exist_ok=True)
            # no heading, no frontmatter title -> title falls back to stem "index"
            (notes / "a" / "index.md").write_text("body only\n", encoding="utf-8")
            (notes / "b" / "index.md").write_text("body only\n", encoding="utf-8")
            result = doctor(vault)
            duplicates = [f.path for f in result.findings if f.code == "duplicate_title"]
            self.assertEqual(duplicates, [])

    def test_tolerates_a_file_vanishing_mid_scan(self) -> None:
        # a concurrent promote/refine can move an imported-lane file between
        # rglob and read_text; doctor must skip it, not crash
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            imported = vault / "projects" / "demo-agent" / "imported"
            imported.mkdir(parents=True, exist_ok=True)
            (imported / "ghost.md").write_text("# Ghost\n\nbody\n", encoding="utf-8")

            real_read = Path.read_text

            def flaky_read(self, *args, **kwargs):
                if self.name == "ghost.md":
                    raise FileNotFoundError(self)
                return real_read(self, *args, **kwargs)

            with mock.patch.object(Path, "read_text", flaky_read):
                result = doctor(vault)  # must not raise
            self.assertTrue(result.ok)
            self.assertFalse(any("ghost.md" in (f.path or "") for f in result.findings))

    def test_structural_docs_are_not_orphan_checked(self) -> None:
        # project docs / agent MEMORY are scaffolding; only the notes/ lane orphan-checks
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp) / "vault"
            init_vault(vault)
            result = doctor(vault)
            orphans = [finding.path for finding in result.findings if finding.code == "orphan_note"]
            self.assertEqual(orphans, [])


if __name__ == "__main__":
    unittest.main()
