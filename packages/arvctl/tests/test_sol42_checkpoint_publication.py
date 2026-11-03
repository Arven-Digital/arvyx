from arvyx_control.replica_authority import authority_context
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from contextlib import closing
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.checkpoint_jobs import (
    _audit_path,
    _journal_path,
    index_rebuild_status,
    rebuild_index_checkpointed,
)
from arvyx_control.index import INDEX_FORMAT, INDEX_RELATIVE, _write_cache


class CheckpointPublicationTests(unittest.TestCase):
    def test_invalid_published_artifacts_fail_without_completion(self):
        for populated in (False, True):
            for damage in ("missing", "directory", "unreadable", "obsolete", "utf8", "json", "files", "empty"):
                with self.subTest(populated=populated, damage=damage), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    if populated:
                        (root / "projects").mkdir()
                        (root / "projects/note.md").write_text("# Note\nbody\n", encoding="utf-8")
                    artifact = root / INDEX_RELATIVE
                    original_read = Path.read_text

                    def publish(vault, files):
                        artifact.parent.mkdir(parents=True, exist_ok=True)
                        if damage == "missing":
                            return
                        if damage == "directory":
                            artifact.mkdir()
                            # The strict publisher propagates replacement failure.
                            _write_cache(vault, files)
                        elif damage == "unreadable":
                            _write_cache(vault, files)
                        elif damage == "obsolete":
                            artifact.write_text(json.dumps({"format": "obsolete", "files": files}), encoding="utf-8")
                        elif damage == "utf8":
                            artifact.write_bytes(b"\xff")
                        elif damage == "json":
                            artifact.write_text("{", encoding="utf-8")
                        elif damage == "files":
                            artifact.write_text(json.dumps({"format": INDEX_FORMAT, "files": []}), encoding="utf-8")
                        else:
                            artifact.write_bytes(b"")

                    def read(path, *args, **kwargs):
                        if damage == "unreadable" and path == artifact:
                            raise PermissionError("artifact is unreadable")
                        return original_read(path, *args, **kwargs)

                    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
                    with patch("arvyx_control.checkpoint_jobs._write_cache", side_effect=publish), patch.object(Path, "read_text", read):
                        error = OSError if damage == "directory" else RuntimeError
                        message = ".*" if damage == "directory" else "index cache could not be persisted"
                        with self.assertRaisesRegex(error, message):
                            with authority_context(root):
                                rebuild_index_checkpointed(root, owner="worker", now=now)
                    self.assertEqual(index_rebuild_status(root).status, "failed")
                    with closing(sqlite3.connect(_journal_path(root))) as connection, connection:
                        status, expiry, updated = connection.execute(
                            "SELECT status, lease_expires_at, updated_at FROM jobs"
                        ).fetchone()
                    self.assertEqual(status, "failed")
                    self.assertEqual(expiry, updated)
                    events = [json.loads(line)["event"] for line in _audit_path(root).read_text(encoding="utf-8").splitlines()]
                    self.assertIn("index_rebuild_failed", events)
                    self.assertNotIn("index_rebuild_completed", events)

    def test_valid_empty_artifact_completes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with authority_context(root):
                result = rebuild_index_checkpointed(
                    root, owner="worker", now=datetime(2026, 1, 1, tzinfo=timezone.utc)
                )
            self.assertEqual(result.status, "completed")
            self.assertEqual(json.loads((root / INDEX_RELATIVE).read_text(encoding="utf-8")), {"format": INDEX_FORMAT, "files": {}})
