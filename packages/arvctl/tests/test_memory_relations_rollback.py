from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from arvyx_control.vault import init_vault


QUALITY = {
    "content_class": "durable_fact",
    "memory_class": "dynamic",
    "future_job": "Preserve curated relation behavior during memory review.",
    "assistant_suggestion_accepted": False,
}


def _write_note(path: Path, stem: str, body: str, status: str = "promoted") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"---\nid: {stem}\nstatus: {status}\n---\n\n# {stem}\n\n{body}\n",
        encoding="utf-8",
    )


class PromoteRollbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.vault = Path(self._tmp.name) / "vault"
        init_vault(self.vault)
        self.project = "demo-agent"
        self.notes = self.vault / "projects" / self.project / "notes"
        self.notes.mkdir(parents=True, exist_ok=True)
        self.parent_a_relative = f"projects/{self.project}/notes/parent-a.md"
        self.parent_b_relative = f"projects/{self.project}/notes/parent-b.md"
        self.parent_a = self.vault / self.parent_a_relative
        self.parent_b = self.vault / self.parent_b_relative
        _write_note(self.parent_a, "parent-a", "Parent A original body.")
        _write_note(self.parent_b, "parent-b", "Parent B original body.")
        self.parent_a_original = self.parent_a.read_text(encoding="utf-8")
        self.parent_b_original = self.parent_b.read_text(encoding="utf-8")

    def _suggest_updates_both(self):
        from arvyx_control.writes import suggest_memory_batch

        return suggest_memory_batch(
            vault=self.vault,
            project=self.project,
            author="demobot",
            payload={
                "memories": [
                    {
                        "title": "Dual update",
                        "content": "Replaces both parents.",
                        **QUALITY,
                        "relations": [
                            {"type": "updates", "parent_source_path": self.parent_a_relative},
                            {"type": "updates", "parent_source_path": self.parent_b_relative},
                        ],
                    }
                ]
            },
        ).suggestions[0]

    def test_mid_loop_parent_write_failure_rolls_back_source_parents_and_target(self) -> None:
        from arvyx_control.writes import promote_memory

        suggestion = self._suggest_updates_both()
        source = self.vault / suggestion.path
        real_replace = Path.replace
        before = set(self.notes.glob("*.md"))

        def failing_replace(self_path, target):
            if Path(target) == self.parent_b:
                raise OSError("simulated disk failure on parent B")
            return real_replace(self_path, target)

        with mock.patch.object(Path, "replace", failing_replace):
            with self.assertRaises(OSError):
                promote_memory(self.vault, self.project, suggestion.path, "operator")

        self.assertTrue(source.is_file(), "pending source must survive a failed promotion")
        self.assertEqual(self.parent_a.read_text(encoding="utf-8"), self.parent_a_original)
        self.assertEqual(self.parent_b.read_text(encoding="utf-8"), self.parent_b_original)
        self.assertEqual(set(self.notes.glob("*.md")), before, "no promoted target may remain")
        self.assertEqual([p.name for p in self.notes.glob(".*.tmp")], [])

    def test_rollback_does_not_delete_concurrently_replaced_target(self) -> None:
        from arvyx_control.writes import promote_memory

        suggestion = self._suggest_updates_both()
        source = self.vault / suggestion.path
        real_replace = Path.replace
        notes_root = self.notes

        def failing_replace(self_path, target):
            if Path(target) == self.parent_b:
                # Simulate a concurrent writer replacing the freshly promoted
                # target between our write and the parent supersede loop.
                published = sorted(
                    p for p in notes_root.glob("dual-update*.md")
                )
                self.assertEqual(len(published), 1)
                published[0].write_text("external curated content\n", encoding="utf-8")
                raise OSError("simulated disk failure on parent B")
            return real_replace(self_path, target)

        with mock.patch.object(Path, "replace", failing_replace):
            with self.assertRaises(OSError):
                promote_memory(self.vault, self.project, suggestion.path, "operator")

        survivor = notes_root / "dual-update.md"
        self.assertTrue(survivor.is_file(), "concurrently replaced target must not be unlinked")
        self.assertEqual(survivor.read_text(encoding="utf-8"), "external curated content\n")
        self.assertTrue(source.is_file())
        self.assertEqual(self.parent_a.read_text(encoding="utf-8"), self.parent_a_original)
        self.assertEqual(self.parent_b.read_text(encoding="utf-8"), self.parent_b_original)

    def test_written_target_content_matches_expected_hash(self) -> None:
        # Sanity receipt: a successful dual-update promotion supersedes both
        # parents and the promoted target carries the promoted status.
        from arvyx_control.writes import promote_memory

        suggestion = self._suggest_updates_both()
        promoted = promote_memory(self.vault, self.project, suggestion.path, "operator")
        target = self.vault / promoted.target
        self.assertIn("status: promoted", target.read_text(encoding="utf-8"))
        self.assertIn("status: superseded", self.parent_a.read_text(encoding="utf-8"))
        self.assertIn("status: superseded", self.parent_b.read_text(encoding="utf-8"))
        self.assertFalse((self.vault / suggestion.path).exists())
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        self.assertEqual(len(digest), 64)


class QuotedStatusIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.vault = Path(self._tmp.name) / "vault"
        init_vault(self.vault)
        self.project = "demo-agent"
        self.notes = self.vault / "projects" / self.project / "notes"

    def test_quoted_superseded_status_is_excluded_from_index(self) -> None:
        from arvyx_control.index import load_index

        quoted = self.notes / "quoted-superseded.md"
        _write_note(quoted, "quoted-superseded", "Old truth.", status='"superseded"')
        single_quoted = self.notes / "single-quoted-superseded.md"
        _write_note(single_quoted, "single-quoted-superseded", "Old truth.", status="'superseded'")
        current = self.notes / "current.md"
        _write_note(current, "current", "Current truth.")

        indexed = {chunk.relative_path for chunk in load_index(self.vault)}
        self.assertNotIn(f"projects/{self.project}/notes/quoted-superseded.md", indexed)
        self.assertNotIn(f"projects/{self.project}/notes/single-quoted-superseded.md", indexed)
        self.assertIn(f"projects/{self.project}/notes/current.md", indexed)

    def test_quoted_superseded_parent_is_rejected_at_suggestion_time(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        quoted_relative = f"projects/{self.project}/notes/quoted-superseded.md"
        _write_note(self.notes / "quoted-superseded.md", "quoted-superseded", "Old.", status='"superseded"')
        with self.assertRaisesRegex(ValueError, "current curated truth"):
            suggest_memory_batch(
                vault=self.vault,
                project=self.project,
                author="demobot",
                payload={
                    "memories": [
                        {
                            "title": "Child of quoted superseded",
                            "content": "Body.",
                            **QUALITY,
                            "relations": [{"type": "extends", "parent_source_path": quoted_relative}],
                        }
                    ]
                },
            )


class MixedRelationBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.vault = Path(self._tmp.name) / "vault"
        init_vault(self.vault)
        self.project = "demo-agent"
        self.notes = self.vault / "projects" / self.project / "notes"
        self.notes.mkdir(parents=True, exist_ok=True)
        self.parent_a_relative = f"projects/{self.project}/notes/parent-a.md"
        self.parent_b_relative = f"projects/{self.project}/notes/parent-b.md"
        _write_note(self.vault / self.parent_a_relative, "parent-a", "Parent A body.")
        _write_note(self.vault / self.parent_b_relative, "parent-b", "Parent B body.")

    def test_extends_and_updates_mixed_batch_promotes_independently(self) -> None:
        from arvyx_control.index import load_index
        from arvyx_control.writes import promote_memory, suggest_memory_batch

        batch = suggest_memory_batch(
            vault=self.vault,
            project=self.project,
            author="demobot",
            payload={
                "memories": [
                    {
                        "title": "Update of A",
                        "content": "Supersedes parent A.",
                        **QUALITY,
                        "relations": [{"type": "updates", "parent_source_path": self.parent_a_relative}],
                    },
                    {
                        "title": "Extension of B",
                        "content": "Extends parent B.",
                        **QUALITY,
                        "relations": [{"type": "extends", "parent_source_path": self.parent_b_relative}],
                    },
                ]
            },
        )
        self.assertEqual(batch.count if hasattr(batch, "count") else len(batch.suggestions), 2)
        update_suggestion, extend_suggestion = batch.suggestions

        promoted_update = promote_memory(self.vault, self.project, update_suggestion.path, "operator")
        promoted_extend = promote_memory(self.vault, self.project, extend_suggestion.path, "operator")

        indexed = {chunk.relative_path for chunk in load_index(self.vault)}
        self.assertNotIn(self.parent_a_relative, indexed)
        self.assertIn(self.parent_b_relative, indexed)
        self.assertIn(promoted_update.target, indexed)
        self.assertIn(promoted_extend.target, indexed)
        self.assertIn("status: superseded", (self.vault / self.parent_a_relative).read_text(encoding="utf-8"))
        self.assertNotIn("status: superseded", (self.vault / self.parent_b_relative).read_text(encoding="utf-8"))


class DerivesRefinePromoteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.vault = Path(self._tmp.name) / "vault"
        init_vault(self.vault)
        self.project = "demo-agent"
        self.notes = self.vault / "projects" / self.project / "notes"
        self.notes.mkdir(parents=True, exist_ok=True)
        self.parent_relative = f"projects/{self.project}/notes/relay-policy.md"
        _write_note(self.vault / self.parent_relative, "relay-policy", "The relay quorum is two nodes.")

    def test_inferred_derives_survives_refine_then_promote(self) -> None:
        from arvyx_control.index import load_index
        from arvyx_control.writes import promote_memory, refine_memory, suggest_memory_batch

        suggestion = suggest_memory_batch(
            vault=self.vault,
            project=self.project,
            author="demobot",
            payload={
                "memories": [
                    {
                        "title": "Derived relay conclusion",
                        "content": "The quorum implies three nodes.",
                        **QUALITY,
                        "content_class": "inferred",
                        "inferred": True,
                        "relations": [{"type": "derives", "parent_source_path": self.parent_relative}],
                    }
                ]
            },
        ).suggestions[0]

        refined = refine_memory(self.vault, self.project, suggestion.path, "refiner", content="Polished derivation.")
        promoted = promote_memory(self.vault, self.project, refined.target, "operator")

        target_text = (self.vault / promoted.target).read_text(encoding="utf-8")
        self.assertIn("status: promoted", target_text)
        self.assertIn("inferred: true", target_text)
        self.assertIn('"derives"', target_text)
        self.assertIn("Polished derivation.", target_text)
        # derives never supersedes its parent
        parent_text = (self.vault / self.parent_relative).read_text(encoding="utf-8")
        self.assertNotIn("status: superseded", parent_text)
        indexed = {chunk.relative_path for chunk in load_index(self.vault)}
        self.assertIn(promoted.target, indexed)
        self.assertIn(self.parent_relative, indexed)
        self.assertFalse((self.vault / suggestion.path).exists())


class ParentPathDedupTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.vault = Path(self._tmp.name) / "vault"
        init_vault(self.vault)
        self.project = "demo-agent"
        self.notes = self.vault / "projects" / self.project / "notes"
        self.notes.mkdir(parents=True, exist_ok=True)
        self.parent_relative = f"projects/{self.project}/notes/parent-a.md"
        _write_note(self.vault / self.parent_relative, "parent-a", "Parent A body.")

    def test_same_parent_via_noncanonical_paths_is_deduplicated(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        variant = f"projects/{self.project}/notes/./parent-a.md"
        with self.assertRaisesRegex(ValueError, "duplicates an earlier parent"):
            suggest_memory_batch(
                vault=self.vault,
                project=self.project,
                author="demobot",
                payload={
                    "memories": [
                        {
                            "title": "Dedup check",
                            "content": "Body.",
                            **QUALITY,
                            "relations": [
                                {"type": "updates", "parent_source_path": self.parent_relative},
                                {"type": "extends", "parent_source_path": variant},
                            ],
                        }
                    ]
                },
            )
        self.assertEqual(list((self.notes.parent / "pending").glob("*.md")), [])

    def test_persisted_parent_path_is_canonical(self) -> None:
        from arvyx_control.writes import suggest_memory_batch

        variant = f"projects/{self.project}/notes/./parent-a.md"
        suggestion = suggest_memory_batch(
            vault=self.vault,
            project=self.project,
            author="demobot",
            payload={
                "memories": [
                    {
                        "title": "Canonical check",
                        "content": "Body.",
                        **QUALITY,
                        "relations": [{"type": "updates", "parent_source_path": variant}],
                    }
                ]
            },
        ).suggestions[0]
        text = (self.vault / suggestion.path).read_text(encoding="utf-8")
        self.assertIn(self.parent_relative, text)
        self.assertNotIn("/./", text)


if __name__ == "__main__":
    unittest.main()
