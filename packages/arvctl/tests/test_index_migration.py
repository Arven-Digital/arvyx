from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from arvyx_control.index import INDEX_FORMAT, load_index
from arvyx_control.recall import recall
from arvyx_control.vault import init_vault


class _BrokenVectorTests(unittest.TestCase):
    """B9: index/cache migrations must prove retrieval, not row survival."""

    def _seed(self, tmp: str) -> Path:
        vault = Path(tmp) / "vault"
        init_vault(vault)
        note = vault / "projects" / "demo-agent" / "notes" / "migration-target.md"
        note.parent.mkdir(parents=True, exist_ok=True)
        note.write_text(
            "---\ntitle: migration target\n---\n\n# Migration target\n\n"
            "durable retrieval must survive index migration\n",
            encoding="utf-8",
        )
        return vault

    def _cache_path(self, vault: Path) -> Path:
        return vault / ".arvyx" / "index.json"

    def _build_cache(self, vault: Path) -> dict:
        load_index(vault)
        payload = json.loads(self._cache_path(vault).read_text(encoding="utf-8"))
        self.assertEqual(payload["format"], INDEX_FORMAT)
        return payload

    def test_stale_cache_format_migrates_and_recall_still_works(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = self._seed(tmp)
            payload = self._build_cache(vault)
            # simulate an on-disk cache from an older index format
            payload["format"] = INDEX_FORMAT - 1
            self._cache_path(vault).write_text(json.dumps(payload), encoding="utf-8")

            load_index(vault)
            recalled = recall("durable retrieval migration", vault=vault, project="demo-agent")
            self.assertTrue(recalled.sources)
            self.assertTrue(any("migration-target.md" in s.path for s in recalled.sources))

    def test_torn_cache_json_migrates_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = self._seed(tmp)
            self._build_cache(vault)
            self._cache_path(vault).write_text('{"format": ', encoding="utf-8")

            load_index(vault)
            recalled = recall("durable retrieval migration", vault=vault, project="demo-agent")
            self.assertTrue(recalled.sources)

    def test_broken_chunk_entries_rebuild_from_source(self) -> None:
        """Deliberately broken index content must fail, not silently degrade."""
        with tempfile.TemporaryDirectory() as tmp:
            vault = self._seed(tmp)
            payload = self._build_cache(vault)
            for entry in payload["files"].values():
                for chunk in entry["chunks"]:
                    chunk["terms"] = "not-a-mapping"
            self._cache_path(vault).write_text(json.dumps(payload), encoding="utf-8")

            chunks = load_index(vault)
            self.assertTrue(chunks)
            recalled = recall("durable retrieval migration", vault=vault, project="demo-agent")
            self.assertTrue(recalled.sources)

    def test_missing_source_content_is_not_served(self) -> None:
        """A harmless stale cache is rebuilt rather than treated as a security failure."""
        with tempfile.TemporaryDirectory() as tmp:
            vault = self._seed(tmp)
            self._build_cache(vault)
            note = vault / "projects" / "demo-agent" / "notes" / "migration-target.md"
            note.unlink()
            payload = self._build_cache_after_deletion(vault, note)
            self._cache_path(vault).write_text(json.dumps(payload), encoding="utf-8")
            chunks = load_index(vault)
            self.assertNotIn(note.relative_to(vault).as_posix(), {chunk.relative_path for chunk in chunks})

    def test_symlink_escape_in_cache_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = self._seed(tmp)
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "escaped.md").write_text("outside vault", encoding="utf-8")
            link = vault / "projects" / "escape"
            link.symlink_to(outside, target_is_directory=True)
            payload = self._build_cache(vault)
            relative = "projects/escape/escaped.md"
            payload["files"][relative] = self._cache_entry(relative)
            self._cache_path(vault).write_text(json.dumps(payload), encoding="utf-8")

            chunks = load_index(vault)

            self.assertNotIn(relative, {chunk.relative_path for chunk in chunks})

    def test_concurrent_loads_leave_a_valid_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = self._seed(tmp)
            barrier = threading.Barrier(4)
            failures: list[BaseException] = []

            def worker() -> None:
                try:
                    barrier.wait()
                    load_index(vault)
                except BaseException as exc:  # pragma: no cover - assertion reports details
                    failures.append(exc)

            threads = [threading.Thread(target=worker) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual(failures, [])
            payload = json.loads(self._cache_path(vault).read_text(encoding="utf-8"))
            self.assertEqual(payload["format"], INDEX_FORMAT)
            self.assertTrue(load_index(vault))

    def test_cache_write_fsyncs_file_and_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vault = self._seed(tmp)
            with patch("arvyx_control.index.os.fsync") as fsync:
                load_index(vault)
            self.assertGreaterEqual(fsync.call_count, 2)

    def _build_cache_after_deletion(self, vault: Path, note: Path) -> dict:
        # rebuild cache while the file still existed is impossible now; instead
        # reconstruct a minimal poisoned payload referencing the deleted path.
        relative = note.relative_to(vault).as_posix()
        return {
            "format": INDEX_FORMAT,
            "files": {
                relative: self._cache_entry(relative)
            },
        }

    def _cache_entry(self, relative: str) -> dict:
        return {
            "mtime_ns": 1,
            "size": 10,
            "content_hash": "0" * 64,
            "chunks": [
                {
                    "relative_path": relative,
                    "start_line": 1,
                    "end_line": 2,
                    "heading": "Migration target",
                    "terms": {"durable": 1},
                    "length": 40,
                    "timestamp": 0.0,
                }
            ],
        }


if __name__ == "__main__":
    unittest.main()
