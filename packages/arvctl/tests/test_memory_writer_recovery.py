"""Static-added recovery regressions; execution requires separate authorization."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control import promotion_transaction as transaction
from arvyx_control.importers import import_markdown
from arvyx_control.vault import init_vault
from arvyx_control.writes import suggest_memory, suggest_memory_batch, refine_memory, reject_memory


class MemoryWriterRecoveryTests(unittest.TestCase):
    def test_writers_recover_missing_source_before_reserving_its_name(self):
        for writer in ("single", "batch", "import"):
            with self.subTest(writer=writer), tempfile.TemporaryDirectory() as temporary:
                vault = Path(temporary) / "vault"
                init_vault(vault)
                lane = "imported" if writer == "import" else "pending"
                source = vault / "projects/demo-agent" / lane / "same.md"
                source.parent.mkdir(parents=True, exist_ok=True)
                original = b"# Same\r\n\r\nOriginal bytes\r\n"
                source.write_bytes(original)
                target = vault / "projects/demo-agent/notes/interrupted.md"
                target.parent.mkdir(parents=True, exist_ok=True)
                stage = transaction.stage

                def fail_commit(path, data, mode=0o600):
                    if path.name == "committed.stage":
                        raise OSError("interrupted after source removal")
                    return stage(path, data, mode)

                with patch.object(transaction, "stage", side_effect=fail_commit), patch.object(transaction, "rollback", return_value=False):
                    with self.assertRaises(OSError):
                        transaction.publish(vault, source, target, b"replacement", {}, source_bytes=original)
                self.assertFalse(source.exists())
                if writer == "single":
                    result = suggest_memory(vault, "demo-agent", "Same", "New suggestion", "operator").path
                elif writer == "batch":
                    result = suggest_memory_batch(vault, "demo-agent", "operator", {"memories": [{
                        "title": "Same", "content": "New suggestion", "content_class": "durable_fact",
                        "memory_class": "dynamic", "future_job": "Answer future status questions",
                        "assistant_suggestion_accepted": False,
                    }]}).suggestions[0].path
                else:
                    incoming = Path(temporary) / "same.md"
                    incoming.write_text("Imported content", encoding="utf-8")
                    result = import_markdown(incoming, vault, "demo-agent").imported[0]
                self.assertEqual(source.read_bytes(), original)
                self.assertEqual(Path(result).name, "same-2.md")
                self.assertFalse(target.exists())
                self.assertEqual(list((vault / ".arvyx/promotions").iterdir()), [])

    def test_refine_and_reject_restore_byte_exact_source_on_unlink_failure(self):
        for operation in (refine_memory, reject_memory):
            with self.subTest(operation=operation.__name__), tempfile.TemporaryDirectory() as temporary:
                vault = Path(temporary) / "vault"
                init_vault(vault)
                source = vault / "projects/demo-agent/pending/same.md"
                source.parent.mkdir(parents=True, exist_ok=True)
                original = b"# Same\r\n\r\nOriginal bytes\r\n"
                source.write_bytes(original)
                lane = "refining" if operation is refine_memory else "archive"
                before={p:p.read_bytes() for p in (source.parent.parent/lane).glob("*.md")}
                unlink = Path.unlink

                def fail_source(path, *args, **kwargs):
                    if path == source:
                        raise OSError("source unlink failed")
                    return unlink(path, *args, **kwargs)

                with patch.object(Path, "unlink", fail_source), self.assertRaises(OSError):
                    operation(vault, "demo-agent", source.relative_to(vault).as_posix(), "operator")
                self.assertEqual(source.read_bytes(), original)
                lane = "refining" if operation is refine_memory else "archive"
                self.assertEqual({p:p.read_bytes() for p in (source.parent.parent/lane).glob("*.md")}, before)
