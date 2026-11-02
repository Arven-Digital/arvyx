from arvyx_control.replica_authority import authority_context
"""Scoped cache boundary regressions; execution requires separate authorization."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.checkpoint_jobs import _journal_path, rebuild_index_checkpointed
from arvyx_control.index import INDEX_RELATIVE, _index_file, _read_cache, load_index
from arvyx_control.recall import recall
from arvyx_control.vault import init_vault


DAMAGES = (
    ("heading", None), ("heading", {}), ("relative_path", "../escape.md"),
    ("terms", {"durable": "invalid"}), ("terms", {"durable": True}),
    ("terms", []), ("start_line", 1.5), ("end_line", 0),
    ("length", True), ("length", -1), ("timestamp", {}),
    ("timestamp", float("nan")), ("timestamp", float("inf")),
    ("vector", ["bad"]), ("vector", [float("inf")]),
)


def damage_entry(entry, field, value):
    if value is None:
        del entry["chunks"][0][field]
    else:
        entry["chunks"][0][field] = value


class CacheDecoderTests(unittest.TestCase):
    def seed(self, root):
        init_vault(root)
        note = root / "projects/demo/notes/decoder.md"
        note.parent.mkdir(parents=True, exist_ok=True)
        note.write_text("# Decoder\ndurable retrieval\n", encoding="utf-8")
        return note.relative_to(root).as_posix()

    def assert_retrieval(self, root):
        self.assertTrue(load_index(root))
        self.assertTrue(recall("durable retrieval", vault=root, project="demo").sources)

    def test_load_repairs_every_malformed_consumed_field(self):
        for field, value in DAMAGES:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                relative = self.seed(root)
                load_index(root)
                artifact = root / INDEX_RELATIVE
                payload = json.loads(artifact.read_text(encoding="utf-8"))
                damage_entry(payload["files"][relative], field, value)
                artifact.write_text(json.dumps(payload), encoding="utf-8")
                self.assert_retrieval(root)

    def test_invalid_utf8_is_a_cache_miss(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed(root)
            load_index(root)
            (root / INDEX_RELATIVE).write_bytes(b"\xff")
            self.assert_retrieval(root)

    def test_completed_artifact_and_checkpoint_repair(self):
        for corrupt_checkpoint in (False, True):
            for field, value in DAMAGES:
                with self.subTest(checkpoint=corrupt_checkpoint, field=field, value=value), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    relative = self.seed(root)
                    peer = root / "projects/demo/notes/peer.md"
                    peer.write_text("# Peer\nunchanged\n", encoding="utf-8")
                    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
                    with authority_context(root):
                        rebuild_index_checkpointed(root, owner="worker", now=now)
                    expected = _read_cache(root)
                    artifact = root / INDEX_RELATIVE
                    payload = json.loads(artifact.read_text(encoding="utf-8"))
                    damaged = deepcopy(payload["files"][relative])
                    damage_entry(damaged, field, value)
                    payload["files"][relative] = damaged
                    artifact.write_text(json.dumps(payload), encoding="utf-8")
                    if corrupt_checkpoint:
                        with sqlite3.connect(_journal_path(root)) as connection:
                            connection.execute("UPDATE checkpoints SET entry_json=? WHERE relative_path=?", (json.dumps(damaged), relative))
                    with patch("arvyx_control.checkpoint_jobs._index_file", wraps=_index_file) as tokenize:
                        with authority_context(root):
                            result = rebuild_index_checkpointed(root, owner="worker", now=now)
                    self.assertEqual(result.status, "completed")
                    self.assertEqual([call.args[1] for call in tokenize.call_args_list], [relative] if corrupt_checkpoint else [])
                    self.assertEqual(_read_cache(root), expected)
                    self.assert_retrieval(root)

    def test_source_errors_are_not_hidden_as_cache_misses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.seed(root)
            with patch("arvyx_control.index._index_file", side_effect=RuntimeError("source failure")):
                with self.assertRaisesRegex(RuntimeError, "source failure"):
                    load_index(root)
