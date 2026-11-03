from arvyx_control.replica_authority import authority_context
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from contextlib import closing
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.checkpoint_jobs import _journal_path, rebuild_index_checkpointed
from arvyx_control.index import INDEX_RELATIVE, _read_cache


class CompletedCheckpointArtifactTests(unittest.TestCase):
    def test_completed_artifact_repair_reuses_checkpoints_and_reclaims_generation(self):
        for damage in ("missing", "json", "encoding", "format", "files", "entry", "extra"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "projects").mkdir()
                (root / "projects" / "note.md").write_text("# Note\nunchanged\n", encoding="utf-8")
                now = datetime(2026, 1, 1, tzinfo=timezone.utc)
                with authority_context(root):
                    rebuild_index_checkpointed(root, owner="worker", now=now, max_attempts=1)
                expected = _read_cache(root)
                artifact = root / INDEX_RELATIVE
                with closing(sqlite3.connect(_journal_path(root))) as connection, connection:
                    previous = connection.execute("SELECT generation FROM jobs").fetchone()[0]
                payload = json.loads(artifact.read_text(encoding="utf-8"))
                if damage == "missing":
                    artifact.unlink()
                elif damage == "json":
                    artifact.write_text("{", encoding="utf-8")
                elif damage == "encoding":
                    artifact.write_bytes(b"\xff")
                else:
                    if damage == "format":
                        payload["format"] = "obsolete"
                    elif damage == "files":
                        payload["files"] = {}
                    elif damage == "entry":
                        payload["files"]["projects/note.md"]["content_hash"] = "bad"
                    else:
                        payload["files"]["../escape.md"] = {}
                    artifact.write_text(json.dumps(payload), encoding="utf-8")
                with patch("arvyx_control.checkpoint_jobs._index_file", side_effect=AssertionError("retokenized")):
                    with authority_context(root):
                        result = rebuild_index_checkpointed(root, owner="worker", now=now, max_attempts=1)
                self.assertEqual(result.status, "completed")
                self.assertEqual(_read_cache(root), expected)
                with closing(sqlite3.connect(_journal_path(root))) as connection, connection:
                    generation = connection.execute("SELECT generation FROM jobs").fetchone()[0]
                self.assertNotEqual(generation, previous)
                with patch("arvyx_control.checkpoint_jobs._write_cache", side_effect=AssertionError("republished valid cache")):
                    with authority_context(root):
                        rebuild_index_checkpointed(root, owner="worker", now=now, max_attempts=1)

    def test_empty_vault_requires_real_valid_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            now = datetime(2026, 1, 1, tzinfo=timezone.utc)
            with authority_context(root):
                rebuild_index_checkpointed(root, owner="worker", now=now)
            artifact = root / INDEX_RELATIVE
            for damage in (None, "{", '{"format":"obsolete","files":{}}'):
                if damage is None:
                    artifact.unlink()
                else:
                    artifact.write_text(damage, encoding="utf-8")
                with authority_context(root):
                    rebuild_index_checkpointed(root, owner="worker", now=now)
                self.assertEqual(json.loads(artifact.read_text(encoding="utf-8"))["files"], {})

    def test_corrupt_checkpoint_is_recomputed_without_retokenizing_valid_peers(self):
        from arvyx_control.index import _index_file

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "projects").mkdir()
            for name in ("good", "bad"):
                (root / "projects" / f"{name}.md").write_text(name, encoding="utf-8")
            now = datetime(2026, 1, 1, tzinfo=timezone.utc)
            with authority_context(root):
                rebuild_index_checkpointed(root, owner="worker", now=now)
            expected = _read_cache(root)
            (root / INDEX_RELATIVE).unlink()
            with closing(sqlite3.connect(_journal_path(root))) as connection, connection:
                connection.execute("UPDATE checkpoints SET entry_json='{' WHERE relative_path='projects/bad.md'")
            with patch("arvyx_control.checkpoint_jobs._index_file", wraps=_index_file) as tokenize:
                with authority_context(root):
                    rebuild_index_checkpointed(root, owner="worker", now=now)
            self.assertEqual([call.args[1] for call in tokenize.call_args_list], ["projects/bad.md"])
            self.assertEqual(_read_cache(root), expected)
