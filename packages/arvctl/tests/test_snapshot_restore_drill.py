from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile
import unittest
from unittest import mock

try:
    import grp
    import pwd
except ImportError:  # Windows has no POSIX user/group database
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[3]
if not (ROOT / 'deploy').is_dir():
    raise unittest.SkipTest('deployment tree is not part of this checkout (public candidate)')
SNAPSHOT = ROOT / "deploy" / "systemd" / "arvyx-v2-snapshot.py"
DRILL = ROOT / "scripts" / "arvyx_v2_snapshot_restore_drill.py"
DOCTOR = ROOT / "scripts" / "systemd_effective_exec_doctor.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


restore_drill = load(DRILL, "arvyx_v2_snapshot_restore_drill")
runtime_doctor = load(DOCTOR, "systemd_effective_exec_doctor")


@unittest.skipUnless(os.name == 'posix', 'deployment kit tests use pwd and POSIX ownership')
class SnapshotRestoreDrillTests(unittest.TestCase):
    def make_snapshot(self, root: Path) -> Path:
        data = root / "data"
        out = root / "snapshots"
        locks = root / "locks"
        for name in ("vault", "state", "audit", "mirror", "authority"):
            (data / name).mkdir(parents=True, exist_ok=True)
        (data / "vault" / "note.md").write_text("governed current truth\n", encoding="utf-8")
        for path in (
            data / "state" / "control-events.jsonl",
            data / "audit" / "audit-log.jsonl",
            data / "mirror" / "receipts.jsonl",
            data / "mirror" / "quarantine-receipts.jsonl",
        ):
            path.write_text('{"ok":true}\n', encoding="utf-8")
        (data / "authority" / "state.json").write_text('{"authority":"V2_PRIMARY"}\n', encoding="utf-8")
        (data / "authority" / "activated").write_text("evidence only\n", encoding="utf-8")
        (data / "migration-redactions.json").write_text("{}\n", encoding="utf-8")
        env = os.environ | {
            "ARVYX_V2_ROOT": str(root),
            "ARVYX_V2_VAULT_UID": str((data / "vault").stat().st_uid),
            "ARVYX_V2_VAULT_GID": str((data / "vault").stat().st_gid),
            "ARVYX_V2_SNAPSHOT_OUTDIR": str(out),
            "ARVYX_V2_LOCKDIR": str(locks),
            "ARVYX_V2_SNAPSHOT_OWNER": pwd.getpwuid(os.getuid()).pw_name,
            "ARVYX_V2_SNAPSHOT_GROUP": grp.getgrgid(os.getgid()).gr_name,
            "ARVYX_V2_SNAPSHOT_LOCK_HOLD": "30",
            "ARVYX_V2_SNAPSHOT_MAX_ATTEMPTS": "2",
        }
        completed = subprocess.run([sys.executable, str(SNAPSHOT)], env=env, text=True, capture_output=True, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return (out / "current").resolve(strict=True)

    @unittest.skipIf(pwd is None or grp is None, "requires the POSIX pwd/grp user database")
    def test_offline_restore_drill_is_complete_and_non_promoting(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = self.make_snapshot(Path(tmp) / "root")
            with mock.patch.object(restore_drill.os, "geteuid", return_value=0), mock.patch.object(restore_drill.os, "chown"):
                result = restore_drill.run(snapshot)
            self.assertTrue(result["ok"])
            self.assertTrue(result["restore_proven"])
            self.assertTrue(result["ownership_verified"])
            self.assertTrue(result["authority_evidence_verified"])
            self.assertFalse(result["authority_present_in_restorable_data"])
            with tarfile.open(snapshot / "archive.tar.gz", "r:gz") as bundle:
                self.assertFalse(any(name == "authority" or name.startswith("authority/") for name in bundle.getnames()))
            with tarfile.open(snapshot / "authority-evidence.tar.gz", "r:gz") as bundle:
                self.assertIn("authority/state.json", bundle.getnames())

    @unittest.skipIf(pwd is None or grp is None, "requires the POSIX pwd/grp user database")
    def test_restore_drill_requires_root_for_ownership_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = self.make_snapshot(Path(tmp) / "root")
            with mock.patch.object(restore_drill.os, "geteuid", return_value=1000):
                with self.assertRaisesRegex(PermissionError, "requires root"):
                    restore_drill.run(snapshot)

    @unittest.skipIf(pwd is None or grp is None, "requires the POSIX pwd/grp user database")
    def test_restore_drill_accepts_v1_bundle_without_authority_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = self.make_snapshot(Path(tmp) / "root")
            manifest_path = snapshot / "manifest.json"
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
            document["schema"] = "arvyx-v2-snapshot-manifest/v1"
            document.pop("authority_policy", None)
            document["files"] = {
                path: meta for path, meta in document["files"].items()
                if not (path == "authority" or path.startswith("authority/"))
            }
            manifest_path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")
            (snapshot / "authority-evidence.tar.gz").unlink()
            (snapshot / "bundle.sha256").write_text(
                f"{restore_drill.digest(snapshot / 'archive.tar.gz')}  archive.tar.gz\n"
                f"{restore_drill.digest(manifest_path)}  manifest.json\n",
                encoding="utf-8",
            )
            with mock.patch.object(restore_drill.os, "geteuid", return_value=0), mock.patch.object(restore_drill.os, "chown"):
                result = restore_drill.run(snapshot)
            self.assertTrue(result["restore_proven"])
            self.assertFalse(result["authority_evidence_verified"])

    def test_restore_drill_rejects_existing_or_production_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            existing = Path(tmp)
            with self.assertRaisesRegex(RuntimeError, "must not already exist"):
                restore_drill.validate_destination(existing)
        with self.assertRaisesRegex(RuntimeError, "outside the production root"):
            restore_drill.validate_destination(Path("/srv/arvyx-v2/data"))

    @unittest.skipIf(pwd is None or grp is None, "requires the POSIX pwd/grp user database")
    def test_restore_drill_rejects_bundle_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = self.make_snapshot(Path(tmp) / "root")
            with (snapshot / "manifest.json").open("a", encoding="utf-8") as handle:
                handle.write("tamper")
            with mock.patch.object(restore_drill.os, "geteuid", return_value=0):
                with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                    restore_drill.run(snapshot)

    def test_runtime_doctor_passes_exact_release_exec_and_reports_dropins(self) -> None:
        expected = "/usr/bin/python3 /srv/arvyx-v2/current/deploy/systemd/arvyx-v2-snapshot.py"
        with (
            mock.patch.object(runtime_doctor, "effective_paths", return_value=["/usr/bin/python3"]),
            mock.patch.object(runtime_doctor, "effective_argv", return_value=[expected.split()]),
            mock.patch.object(runtime_doctor, "environment_keys", return_value=set()),
            mock.patch.object(runtime_doctor, "systemctl_show", return_value=""),
        ):
            result = runtime_doctor.inspect("arvyx-v2-snapshot.service", expected, set())
        self.assertTrue(result["ok"])
        self.assertEqual(result["dropin_count"], 0)

    def test_runtime_doctor_fails_closed_on_effective_exec_drift(self) -> None:
        expected = "/usr/bin/python3 /srv/arvyx-v2/current/deploy/systemd/arvyx-v2-snapshot.py"
        with (
            mock.patch.object(runtime_doctor, "effective_argv", return_value=[["/usr/bin/python3", "/srv/arvyx-v2/bin/stale.py"]]),
            mock.patch.object(runtime_doctor, "environment_keys", return_value=set()),
            mock.patch.object(runtime_doctor, "systemctl_show", return_value="/etc/systemd/system/example.d/90-stale.conf"),
        ):
            result = runtime_doctor.inspect("arvyx-v2-snapshot.service", expected, set())
        self.assertFalse(result["ok"])
        self.assertEqual(result["findings"][0]["code"], "effective_exec_drift")

    def test_runtime_doctor_blocks_dropins_and_environment_overrides(self) -> None:
        expected = "/bin/sh /srv/arvyx-v2/current/deploy/systemd/arvyx-v2-api-supervisor.sh"
        with (
            mock.patch.object(runtime_doctor, "effective_paths", return_value=["/bin/sh"]),
            mock.patch.object(runtime_doctor, "effective_argv", return_value=[expected.split()]),
            mock.patch.object(runtime_doctor, "environment_keys", return_value={"ARVYX_V2_LAUNCHER"}),
            mock.patch.object(runtime_doctor, "systemctl_show", return_value="/etc/systemd/system/example.d/90-stale.conf"),
        ):
            result = runtime_doctor.inspect("arvyx-v2-api.service", expected, {"ARVYX_V2_LAUNCHER"})
        self.assertFalse(result["ok"])
        self.assertEqual([finding["code"] for finding in result["findings"]], ["unexpected_dropins", "forbidden_environment_override"])

    def test_runtime_doctor_parses_recorded_systemctl_execstart_shape(self) -> None:
        recorded = "{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /srv/arvyx-v2/current/deploy/systemd/arvyx-v2-snapshot.py ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        with mock.patch.object(runtime_doctor, "systemctl_show", return_value=recorded):
            self.assertEqual(
                runtime_doctor.effective_argv("arvyx-v2-snapshot.service"),
                [["/usr/bin/python3", "/srv/arvyx-v2/current/deploy/systemd/arvyx-v2-snapshot.py"]],
            )

    def test_runtime_doctor_allows_only_vendor_generic_dropins(self) -> None:
        expected = "/usr/bin/python3 /srv/arvyx-v2/current/deploy/systemd/arvyx-v2-snapshot.py"
        vendor = "/usr/lib/systemd/system/service.d/10-timeout-abort.conf"
        with (
            mock.patch.object(runtime_doctor, "effective_paths", return_value=["/usr/bin/python3"]),
            mock.patch.object(runtime_doctor, "effective_argv", return_value=[expected.split()]),
            mock.patch.object(runtime_doctor, "environment_keys", return_value=set()),
            mock.patch.object(runtime_doctor, "systemctl_show", return_value=vendor),
        ):
            result = runtime_doctor.inspect(
                "arvyx-v2-snapshot.service", expected, set(), ("/usr/lib/systemd/system/service.d/",)
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["unexpected_dropins"], [])

    def test_runtime_doctor_refuses_at_prefix_executable_substitution(self) -> None:
        expected = "/bin/sh /srv/arvyx-v2/current/deploy/systemd/arvyx-v2-api-supervisor.sh"
        recorded = "{ path=/usr/bin/false ; argv[]=" + expected + " ; ignore_errors=no ; pid=0 }"
        with mock.patch.object(runtime_doctor, "systemctl_show", side_effect=lambda unit, prop: recorded if prop == "ExecStart" else ""), mock.patch.object(runtime_doctor, "environment_keys", return_value=set()):
            result = runtime_doctor.inspect("example.service", expected, set())
        self.assertFalse(result["ok"])
        self.assertFalse(result["effective_exec_matches"])

    def test_runtime_doctor_includes_manager_and_pass_environment_without_values(self) -> None:
        with mock.patch.object(runtime_doctor.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "ARVYX_V2_LAUNCHER=synthetic-private-value\n")), mock.patch.object(runtime_doctor, "systemctl_show", side_effect=lambda unit, prop: 'OTHER_OVERRIDE' if prop == 'PassEnvironment' else ''):
            keys = runtime_doctor.environment_keys("example.service")
        self.assertEqual(keys, {"ARVYX_V2_LAUNCHER", "OTHER_OVERRIDE"})
        self.assertNotIn("synthetic-private-value", repr(keys))

    def test_runtime_doctor_rejects_empty_root_and_parent_dropin_prefixes(self) -> None:
        for prefix in ('', '/', '/usr/lib/../', 'relative/'):
            with self.subTest(prefix=prefix), mock.patch.object(runtime_doctor, "effective_argv", return_value=[['/bin/sh']]), mock.patch.object(runtime_doctor, "effective_paths", return_value=['/bin/sh']), mock.patch.object(runtime_doctor, "environment_keys", return_value=set()), mock.patch.object(runtime_doctor, "systemctl_show", return_value='/etc/evil.conf'):
                result = runtime_doctor.inspect('example.service', '/bin/sh', set(), (prefix,))
                self.assertFalse(result['ok'])
                self.assertIn('invalid_dropin_prefix', [item['code'] for item in result['findings']])

    @unittest.skipIf(pwd is None, "the snapshot script is POSIX-only")
    def test_tick_liveness_telemetry_is_outside_the_snapshot_cut(self) -> None:
        # Tick records under state/liveness/ are rewritten every few seconds;
        # inside the cut they would never hold still across the a/b/c manifests.
        snapshot = load(SNAPSHOT, "arvyx_v2_snapshot_exclusion")
        self.assertTrue(snapshot.excluded("state/liveness"))
        self.assertTrue(snapshot.excluded("state/liveness/execution-worker.json"))
        self.assertTrue(snapshot.excluded("state/liveness/.dispatcher.json.x1y2.tmp"))
        self.assertFalse(snapshot.excluded("state/control-events.jsonl"))
        self.assertFalse(snapshot.excluded("state/liveness-notes.json"))


if __name__ == "__main__":
    unittest.main()
