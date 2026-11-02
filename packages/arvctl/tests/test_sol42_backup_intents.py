"""Static-authored regressions. NOT_EXECUTED in the Sol42 fix round."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control import forget
from arvyx_control.snapshot_guard import snapshot_preparation
from arvyx_control.vault import init_vault

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("sol42_backup", ROOT / "scripts/backup_restore.py")
assert SPEC is not None and SPEC.loader is not None
BACKUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BACKUP)


def normalize(raw):
    output = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="r:") as source, tarfile.open(fileobj=output, mode="w") as target:
        BACKUP._normalize_container_archive(source, target)
    output.seek(0)
    return output


class BackupIntentTests(unittest.TestCase):
    def test_completed_forget_restore_materializes_and_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            vault = base / "data/vault"
            init_vault(vault)
            args = (vault, "demo-agent", "projects/demo-agent/STATUS.md", "superseded",
                    "batch-sol42", "operator", "forget-operation-sol42")
            forgotten = forget.soft_forget(*args)
            restored = forget.restore_forgotten(vault, forgotten.tombstone_path, "operator", "restore-operation-sol42")
            raw = io.BytesIO()
            with snapshot_preparation(vault), tarfile.open(fileobj=raw, mode="w") as archive:
                archive.add(base / "data", arcname=".")
            raw.seek(0)
            cooked = normalize(raw)
            with tarfile.open(fileobj=cooked, mode="r:") as archive:
                self.assertTrue(all(m.isfile() or m.isdir() for m in archive.getmembers()))
            copied = base / "copy"
            copied.mkdir()
            archive_path = base / "backup.tar.gz"
            cooked.seek(0)
            with tarfile.open(fileobj=cooked, mode="r:") as source, tarfile.open(archive_path, "w:gz") as target:
                for member in source.getmembers():
                    target.addfile(member, source.extractfile(member) if member.isfile() else None)
            BACKUP._safe_extract(archive_path, copied)
            copy_vault = copied / "data/vault"
            self.assertEqual(forget.soft_forget(copy_vault, *args[1:]), forgotten)
            self.assertEqual(forget.restore_forgotten(copy_vault, forgotten.tombstone_path, "operator", "restore-operation-sol42"), restored)

    def test_unfinished_forget_and_restore_refused_until_original_retry(self):
        for operation in ("forget", "restore"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                vault = Path(directory) / "vault"
                init_vault(vault)
                args = (vault, "demo-agent", "projects/demo-agent/STATUS.md", "superseded",
                        "batch-sol42", "operator", "forget-operation-sol42")
                if operation == "restore":
                    forgotten = forget.soft_forget(*args)
                original = forget._atomic_json

                def interrupt(path, value):
                    if ((operation == "forget" and path.name.endswith(".tombstone.json"))
                            or (operation == "restore" and "request_hash" in value and "stage_path" not in value)):
                        raise OSError("injected interruption")
                    return original(path, value)

                def invoke():
                    if operation == "forget":
                        return forget.soft_forget(*args)
                    return forget.restore_forgotten(vault, forgotten.tombstone_path, "operator", "restore-operation-sol42")

                with patch.object(forget, "_atomic_json", side_effect=interrupt):
                    with self.assertRaises(OSError):
                        invoke()
                with self.assertRaisesRegex(RuntimeError, "original filesystem"):
                    with snapshot_preparation(vault):
                        self.fail("unfinished operation reached copy")
                invoke()
                with snapshot_preparation(vault):
                    pass

    def test_unsafe_links_rejected(self):
        for target, kind in (("../escape", tarfile.LNKTYPE), ("/escape", tarfile.LNKTYPE),
                             (".arvyx-control-secret", tarfile.LNKTYPE), ("missing", tarfile.LNKTYPE),
                             ("chain", tarfile.LNKTYPE), ("regular", tarfile.SYMTYPE)):
            with self.subTest(target=target, kind=kind):
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode="w") as archive:
                    for name in ("regular", ".arvyx-control-secret"):
                        member = tarfile.TarInfo(name); member.size = 1
                        archive.addfile(member, io.BytesIO(b"x"))
                    chain = tarfile.TarInfo("chain"); chain.type = tarfile.LNKTYPE; chain.linkname = "regular"
                    archive.addfile(chain)
                    link = tarfile.TarInfo("alias"); link.type = kind; link.linkname = target
                    archive.addfile(link)
                raw.seek(0)
                with self.assertRaises(RuntimeError):
                    normalize(raw)
