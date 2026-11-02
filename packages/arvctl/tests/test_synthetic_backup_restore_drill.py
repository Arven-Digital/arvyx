from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "synthetic_backup_restore_drill.py"
SPEC = importlib.util.spec_from_file_location("synthetic_backup_restore_drill", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
drill = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(drill)


class SyntheticBackupRestoreDrillTests(unittest.TestCase):
    def test_backup_loss_offline_restore_integrity_and_restart(self) -> None:
        result = drill.run()
        self.assertTrue(result["ok"])
        self.assertTrue(result["backup_created"])
        self.assertTrue(result["primary_loss_simulated"])
        self.assertTrue(result["offline_restore_verified"])
        self.assertTrue(result["restart_acceptance_verified"])
        self.assertGreaterEqual(result["rpo_like_seconds"], 0)
        self.assertGreaterEqual(result["rto_like_seconds"], 0)
        self.assertIn("not a production", result["metric_scope"])

    def test_two_file_receipt_cannot_claim_product_recovery(self) -> None:
        result = drill.run()
        self.assertEqual(result["manifest_entries"], 2)
        self.assertIn("two-file", result["acceptance_scope"])
        for field in ("product_composition_restore_verified",
                      "product_restart_acceptance_verified",
                      "authority_reprovisioning_verified"):
            self.assertIs(result[field], False)

    def test_corruption_fails_closed_before_restore_acceptance(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
            drill.run(corrupt_backup=True)

    def test_extract_rejects_unsafe_entries(self) -> None:
        import tarfile
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # absolute path entry
            evil_abs = root / "evil-abs.tar.gz"
            with tarfile.open(evil_abs, "w:gz") as bundle:
                info = tarfile.TarInfo("/tmp/arvyx-drill-evil-abs")
                payload = b"x"
                import io
                bundle.addfile(info, io.BytesIO(payload))
            with self.assertRaisesRegex(RuntimeError, "unsafe entry"):
                drill._extract(evil_abs, root / "dest1")

            # traversal entry
            evil_trav = root / "evil-trav.tar.gz"
            with tarfile.open(evil_trav, "w:gz") as bundle:
                info = tarfile.TarInfo("data/../../arvyx-drill-evil-trav")
                import io
                bundle.addfile(info, io.BytesIO(b"x"))
            with self.assertRaisesRegex(RuntimeError, "unsafe entry"):
                drill._extract(evil_trav, root / "dest2")

            # fifo entry
            evil_fifo = root / "evil-fifo.tar.gz"
            with tarfile.open(evil_fifo, "w:gz") as bundle:
                info = tarfile.TarInfo("data/fifo")
                info.type = tarfile.FIFOTYPE
                bundle.addfile(info)
            with self.assertRaisesRegex(RuntimeError, "unsafe entry"):
                drill._extract(evil_fifo, root / "dest3")

            # empty archive
            evil_empty = root / "evil-empty.tar.gz"
            with tarfile.open(evil_empty, "w:gz"):
                pass
            with self.assertRaisesRegex(RuntimeError, "empty"):
                drill._extract(evil_empty, root / "dest4")

    def test_extract_rejects_corrupted_archive_bytes(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "primary"
            source.mkdir()
            (source / "vault").mkdir()
            (source / "vault" / "current.md").write_text("truth\n", encoding="utf-8")
            archive = root / "snapshot.tar.gz"
            import tarfile
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(source, arcname="data")
            # flip bytes in the compressed stream: gzip/tar decode must fail closed
            raw = bytearray(archive.read_bytes())
            mid = len(raw) // 2
            for i in range(mid, min(mid + 64, len(raw))):
                raw[i] ^= 0xFF
            archive.write_bytes(bytes(raw))
            with self.assertRaises(Exception):
                drill._extract(archive, root / "restore")

    def test_executable_json_receipt(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=True,
        )
        receipt = json.loads(completed.stdout)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["schema"], "arvyx-synthetic-restore-drill/v1")


if __name__ == "__main__":
    unittest.main()