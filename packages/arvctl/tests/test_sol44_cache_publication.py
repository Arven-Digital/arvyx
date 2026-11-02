from arvyx_control.replica_authority import authority_context
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control import index
from arvyx_control.checkpoint_jobs import (
    _audit_path, _journal_path, index_rebuild_status, rebuild_index_checkpointed,
)


class CacheDurabilityTests(unittest.TestCase):
    def test_ancestor_sync_failure_precedes_publication_and_retry_preserves_old_cache(self):
        # Separate negative control from the post-replace barrier selections.
        # All bytes are synthetic; executed in wave1 lane 1 with mutation checks.
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);destination=root/index.INDEX_RELATIVE
                if existing:index._write_cache(root,{'old':{}})
                before=destination.read_bytes() if existing else None
                real_fsync=os.fsync;reached=[]
                error=OSError('injected ancestor directory barrier failure')
                def sync(fd):
                    if stat.S_ISDIR(os.fstat(fd).st_mode):
                        reached.append(True);raise error
                    return real_fsync(fd)
                with patch.object(index.os,'fsync',side_effect=sync), \
                     patch.object(index.tempfile,'mkstemp') as temporary, \
                     patch.object(index.os,'replace') as replace:
                    with self.assertRaises(OSError) as raised:index._write_cache(root,{})
                    self.assertIs(raised.exception,error)
                    self.assertTrue(reached)
                    temporary.assert_not_called();replace.assert_not_called()
                if existing:self.assertEqual(destination.read_bytes(),before)
                else:self.assertFalse(destination.exists())
                index._write_cache(root,{})
                self.assertEqual(json.loads(destination.read_text()),{'format':index.INDEX_FORMAT,'files':{}})

    def test_directory_sync_failure_propagates_after_visible_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_fsync = os.fsync
            real_replace = os.replace
            published = []
            def replace(source,target):
                result=real_replace(source,target)
                if Path(target)==root/index.INDEX_RELATIVE:published.append(True)
                return result
            error = OSError("injected directory sync failure")

            def sync(fd):
                if published and stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise error
                real_fsync(fd)

            with patch.object(index.os,"replace",side_effect=replace), patch.object(index.os, "fsync", side_effect=sync):
                with self.assertRaises(OSError) as raised:
                    index._write_cache(root, {})
            self.assertTrue(published,"fault must follow the actual replacement")
            self.assertIs(raised.exception, error)
            self.assertEqual(json.loads((root / index.INDEX_RELATIVE).read_text()),
                             {"format": index.INDEX_FORMAT, "files": {}})
            self.assertEqual(list((root / index.INDEX_RELATIVE).parent.glob("*.tmp")), [])

    def test_load_index_alone_tolerates_persistence_oserror(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "projects").mkdir()
            (root / "projects/note.md").write_text("# Note\nsearchable body\n")
            with patch.object(index, "_write_cache", side_effect=OSError("read only")):
                chunks = index.load_index(root)
            self.assertTrue(chunks)
            self.assertEqual(chunks[0].relative_path, "projects/note.md")
            with patch.object(index, "_write_cache", side_effect=RuntimeError("not an IO failure")):
                with self.assertRaisesRegex(RuntimeError, "not an IO failure"):
                    index.load_index(root)

    def test_checkpoint_sync_failure_is_failed_and_retry_reuses_checkpoints(self):
        for populated in (False, True):
            for barrier in ("file", "directory"):
                with self.subTest(populated=populated, barrier=barrier), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    if populated:
                        (root / "projects").mkdir()
                        (root / "projects/note.md").write_text("# Note\nbody\n")
                    real_fsync = os.fsync
                    real_replace = os.replace;published=[];reached=[]
                    real_mkstemp = index.tempfile.mkstemp
                    cache_temporary = []
                    def mkstemp(*args, **kwargs):
                        fd, name = real_mkstemp(*args, **kwargs)
                        if Path(kwargs.get('dir', '')) == root / '.arvyx' and kwargs.get('suffix') == '.tmp':
                            info = os.fstat(fd)
                            cache_temporary.append((info.st_dev, info.st_ino))
                        return fd, name
                    def replace(source,target):
                        result=real_replace(source,target)
                        if Path(target)==root/index.INDEX_RELATIVE:published.append(True)
                        return result
                    error = OSError("injected publication sync failure")
                    now = datetime(2026, 1, 1, tzinfo=timezone.utc)

                    def sync(fd):
                        directory = stat.S_ISDIR(os.fstat(fd).st_mode)
                        target=Path(os.readlink('/proc/self/fd/'+str(fd)))
                        info = os.fstat(fd)
                        if ((barrier=='directory' and directory and published and target==root/'.arvyx') or
                                (barrier=='file' and not directory and (info.st_dev, info.st_ino) in cache_temporary)):
                            reached.append(barrier);raise error
                        real_fsync(fd)

                    # Isolate audit appends from the fsync injection; inspect
                    # attempted event names rather than mocking publication.
                    with patch("arvyx_control.checkpoint_jobs._audit_event") as audit:
                        with patch.object(index.tempfile, 'mkstemp', side_effect=mkstemp), patch.object(index.os,"replace",side_effect=replace), patch.object(index.os, "fsync", side_effect=sync):
                            with self.assertRaises(OSError) as raised:
                                with authority_context(root):
                                    rebuild_index_checkpointed(root, owner="worker", now=now)
                        self.assertTrue(reached,"must reach the selected cache publication barrier")
                        self.assertIs(raised.exception, error)
                        events = [call.args[1] for call in audit.call_args_list]
                    self.assertIn("index_rebuild_failed", events)
                    self.assertNotIn("index_rebuild_completed", events)
                    status = index_rebuild_status(root)
                    self.assertEqual(status.status, "failed")
                    self.assertEqual(status.checkpoint, status.total)
                    with sqlite3.connect(_journal_path(root)) as connection:
                        state, expiry, updated = connection.execute(
                            "SELECT status, lease_expires_at, updated_at FROM jobs"
                        ).fetchone()
                    self.assertEqual(state, "failed")
                    self.assertEqual(expiry, updated)
                    if barrier == "directory":
                        self.assertTrue(published)
                        self.assertTrue((root / index.INDEX_RELATIVE).is_file())
                    else:
                        self.assertTrue(cache_temporary)
                        self.assertFalse(published)
                        self.assertFalse((root / index.INDEX_RELATIVE).exists())
                    with patch("arvyx_control.checkpoint_jobs._index_file", side_effect=AssertionError("checkpoint not reused")):
                        with authority_context(root):
                            result = rebuild_index_checkpointed(root, owner="worker", now=now)
                    self.assertEqual(result.status, "completed")
                    self.assertEqual(result.attempt, 2)
                    events = [json.loads(line)["event"] for line in _audit_path(root).read_text().splitlines()]
                    self.assertEqual(events.count("index_rebuild_completed"), 1)
