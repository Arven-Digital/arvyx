"""Lane 06 runbook regressions; Docker and application boundaries are mocked."""
from contextlib import ExitStack, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("deep10fix_06_backup", ROOT / "scripts/backup_restore.py")
assert SPEC is not None and SPEC.loader is not None
BACKUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BACKUP)
GUIDE = ROOT / "docs/vps-deployment.md"


@unittest.skipUnless(os.name == 'posix', 'the deployment scripts take POSIX locks and fail closed elsewhere')
class DeploymentRunbookTests(unittest.TestCase):
    def test_restore_documents_networkless_staging(self):
        drill = GUIDE.read_text().split("### Restore drill", 1)[1].split("## Upgrade", 1)[0]
        self.assertIn("`network_mode: none`", drill)
        self.assertIn("`docker exec`", drill)
        self.assertNotIn("ephemeral loopback port", drill)
        self.assertIn("reseed", drill)

    def test_restore_documents_authority_and_phase_specific_recovery(self):
        drill = " ".join(GUIDE.read_text().split("### Restore drill", 1)[1].split())
        for contract in (
            "Before pointer commit", "After pointer commit",
            "candidate pointer remains authoritative", "retain both volumes",
            "automatic rollback", "forbidden", "acknowledged writes",
            "admission fence", "isolate the service immediately",
            "Do not repoint", "delete or reseed", "crash",
            "`VolumePointerReconciliationRequired`", "`candidate_volume`",
            "`cleanup_failures`", "`restart_failed`",
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, drill)
        self.assertNotIn("previous pointer and volume are restored before the candidate is deleted", drill)

    def _example(self, operation):
        blocks = re.findall(r"```bash\n(.*?)```", GUIDE.read_text(), flags=re.S)
        return next(block for block in blocks if "scripts/backup_restore.py" in block
                    and re.search(rf"\b{operation}\s*\\", block))

    def _check_example(self, operation):
        # Execute only this maintenance block, with python3 replaced by a shell
        # recorder. No Python application, Docker, secret read or network runs.
        with tempfile.TemporaryDirectory(prefix="deep10fix-06-example-") as temporary:
            root = Path(temporary)
            volume = "amcprod_prod-0001_arvyx-data"
            (root / ".env").write_text(
                "COMPOSE_PROJECT_NAME=amcprod\nARVYX_DEPLOYMENT_ID=prod-0001\n"
                f"ARVYX_DATA_VOLUME={volume}\nARVYX_CONTROL_SECRET_FILE=unused-secret\n"
            )
            recorder = r'''python3() {
  printf '%s\0' "$COMPOSE_PROJECT_NAME" "$ARVYX_DEPLOYMENT_ID" "$ARVYX_DATA_VOLUME" "$@"
}
'''
            completed = subprocess.run(
                ["/bin/bash", "--noprofile", "--norc", "-eu", "-c", recorder + self._example(operation)],
                cwd=root, env={"PATH": "/usr/bin:/bin", "HOME": str(root),
                               "ARVYX_BACKUP_DIR": str(root / "backups"),
                               "ARVYX_BACKUP_OFF_HOST": str(root / "off-host")},
                capture_output=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            project, deployment, actual_volume, *argv = completed.stdout.decode().split("\0")[:-1]
            self.assertEqual((project, deployment, actual_volume), ("amcprod", "prod-0001", volume))
            environment = {"COMPOSE_PROJECT_NAME": project, "ARVYX_DEPLOYMENT_ID": deployment,
                           "ARVYX_DATA_VOLUME": actual_volume}
            def selected(**kwargs):
                self.assertEqual(kwargs["project"], "amcprod")
                self.assertEqual(BACKUP._expected_data_volume(environment, kwargs["project"]), volume)
                self.assertTrue(kwargs["enforce_binding"])
                return {"ok": True}
            with mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(BACKUP, operation, side_effect=selected) as entry, \
                    redirect_stdout(io.StringIO()), \
                    mock.patch.object(BACKUP, "_run", side_effect=AssertionError("no Docker")):
                self.assertEqual(BACKUP.main(), 0)
            entry.assert_called_once()

    def test_backup_example_preserves_configured_project(self):
        self._check_example("backup")

    def test_restore_example_preserves_configured_project(self):
        self._check_example("restore")

    def test_wrong_project_still_fails_closed(self):
        environment = {"ARVYX_DEPLOYMENT_ID": "prod-0001",
                       "ARVYX_DATA_VOLUME": "amcprod_prod-0001_arvyx-data"}
        self.assertEqual(BACKUP._expected_data_volume(environment, "amcprod"), environment["ARVYX_DATA_VOLUME"])
        with self.assertRaisesRegex(RuntimeError, "scoped to COMPOSE_PROJECT_NAME"):
            BACKUP._expected_data_volume(environment, "arvyx")


@unittest.skipUnless(os.name == 'posix', 'the deployment scripts take POSIX locks and fail closed elsewhere')
class RestoreBoundaryTests(unittest.TestCase):
    def _failure_case(self, phase, fence="stopped"):
        with tempfile.TemporaryDirectory(prefix="deep10fix-06-restore-") as temporary, ExitStack() as stack:
            root = Path(temporary)
            original = "amcprod_prod-0001_arvyx-data"
            env_file = root / ".env"
            env_file.write_text(f"COMPOSE_PROJECT_NAME=amcprod\nARVYX_DATA_VOLUME={original}\n")
            data = root / "data"
            (data / "vault").mkdir(parents=True)
            (data / "vault/.arvyx-vault").write_text(BACKUP.MARKER_TEXT)
            archive = root / "fixture.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(data, arcname="data")
            checksum = root / "fixture.tar.gz.sha256"
            BACKUP._write_checksum(archive, checksum)
            environment = {"COMPOSE_PROJECT_NAME": "amcprod", "ARVYX_DEPLOYMENT_ID": "prod-0001",
                           "ARVYX_DATA_VOLUME": original, "ARVYX_CONTROL_SECRET_FILE": "unused-secret"}
            volumes = {original: {"Labels": {}, "payload": "original"}}
            commands = []
            admitted = False
            admission_index = None
            candidate = None

            def run(command, *, env, check=True):
                nonlocal admitted, admission_index, candidate
                commands.append((list(command), env["ARVYX_DATA_VOLUME"]))
                output, code = "", 0
                if command[:3] == ["docker", "volume", "inspect"]:
                    output = json.dumps([volumes[command[-1]]])
                elif command[:3] == ["docker", "volume", "create"]:
                    candidate = command[-1]
                    labels = dict(command[i + 1].split("=", 1) for i, arg in enumerate(command) if arg == "--label")
                    volumes[candidate] = {"Labels": labels, "payload": "pristine"}
                elif command[:3] == ["docker", "volume", "rm"]:
                    del volumes[command[-1]]
                elif command[:2] == ["docker", "run"]:
                    self.assertIn("none", command)  # Candidate durability helper is mocked.
                elif command[:2] == ["docker", "inspect"]:
                    output = "true" if fence == "unverified" else "false"
                elif command[:2] == ["docker", "compose"]:
                    staging = command[3].startswith("amcprod-restore-")
                    if staging:
                        self.assertIn(str(root / "scripts/restore-candidate.private.yml"), command)
                        self.assertNotIn(str(root / "docker-compose.yml"), command)
                    if "ps" in command:
                        output = "fixture-container"
                    elif "up" in command:
                        if not staging and env["ARVYX_DATA_VOLUME"] != original:
                            self.assertEqual(BACKUP._read_active_volume_pointer(env_file), candidate)
                            admitted = True
                            admission_index = len(commands) - 1
                            volumes[candidate]["payload"] = "acknowledged-write"
                            if phase == "startup":
                                raise RuntimeError("injected production startup failure")
                    elif "stop" in command:
                        code = 1 if fence == "stop-failed" else 0
                    elif "down" not in command:
                        raise AssertionError(f"unexpected mocked Compose command: {command}")
                else:
                    raise AssertionError(f"unexpected external command: {command}")
                return subprocess.CompletedProcess(command, code, stdout=output, stderr="")

            def healthy(compose, env, *, phase):
                if phase == "staging restore" and failure_phase == "staging":
                    raise RuntimeError("injected staging failure")
                if phase == "candidate cutover" and failure_phase == "health":
                    raise RuntimeError("injected production health failure")
                return "fixture-container"

            def mount(container, volume, project, env):
                if admitted and phase == "mount":
                    raise RuntimeError("injected production mount failure")

            failure_phase = phase
            stack.enter_context(mock.patch.dict(os.environ, environment, clear=True))
            stack.enter_context(mock.patch.object(BACKUP, "ROOT", root))
            stack.enter_context(mock.patch.object(BACKUP, "_run", side_effect=run))
            stack.enter_context(mock.patch.object(BACKUP, "_wait_healthy", side_effect=healthy))
            stack.enter_context(mock.patch.object(BACKUP, "_assert_data_volume", side_effect=mount))
            stack.enter_context(mock.patch.object(BACKUP, "_materialize_candidate_volume"))
            stack.enter_context(mock.patch.object(BACKUP, "_acceptance_probe"))
            stack.enter_context(mock.patch.object(BACKUP.subprocess, "run", side_effect=AssertionError("unmocked process")))
            error_type = RuntimeError if phase == "staging" else BACKUP.VolumePointerReconciliationRequired
            with self.assertRaises(error_type) as raised:
                BACKUP.restore(project="amcprod", archive=archive, checksum=checksum,
                               confirm_destroy_volume=True, env_file=env_file)
            self.assertIsNotNone(candidate)
            if phase == "staging":
                self.assertFalse(admitted)
                self.assertEqual(BACKUP._read_active_volume_pointer(env_file), original)
                self.assertEqual(set(volumes), {original})
                self.assertFalse(any("up" in cmd and volume == original for cmd, volume in commands))
                return
            error = raised.exception
            self.assertEqual(error.candidate_volume, candidate)
            self.assertFalse(error.restart_failed)
            self.assertEqual(BACKUP._read_active_volume_pointer(env_file), candidate)
            self.assertEqual(set(volumes), {original, candidate})
            self.assertEqual(volumes[candidate]["payload"], "acknowledged-write")
            self.assertEqual(volumes[original]["payload"], "original")
            self.assertFalse(any("up" in cmd and volume == original for cmd, volume in commands))
            self.assertIsNotNone(admission_index)
            after_admission = commands[admission_index + 1:]
            self.assertTrue(any("stop" in cmd for cmd, _ in after_admission))
            self.assertFalse(any("rm" in cmd or "down" in cmd for cmd, _ in after_admission))
            if fence == "stopped":
                self.assertEqual(error.cleanup_failures, ())
            else:
                self.assertTrue(any("admission fence" in item for item in error.cleanup_failures))
                self.assertIn("isolate the service immediately", " ".join(error.__notes__))
            # Verify the sanitized CLI recovery fields without replaying restore.
            stream = io.StringIO()
            with mock.patch.object(sys, "argv", ["backup_restore.py", "restore", str(archive), "--confirm-cutover"]), \
                    mock.patch.object(BACKUP, "restore", side_effect=error), redirect_stdout(stream):
                self.assertEqual(BACKUP.main(), 1)
            payload = json.loads(stream.getvalue())
            self.assertEqual(payload["error"], "VolumePointerReconciliationRequired")
            self.assertEqual(payload["candidate_volume"], candidate)
            self.assertEqual(payload["cleanup_failures"], list(error.cleanup_failures))
            self.assertFalse(payload["restart_failed"])

    def test_precommit_staging_failure_keeps_previous_authority(self):
        self._failure_case("staging")

    def test_postcommit_failures_retain_candidate_authority_and_report_fence(self):
        for phase in ("startup", "health", "mount"):
            for fence in ("stopped", "stop-failed", "unverified"):
                with self.subTest(phase=phase, fence=fence):
                    self._failure_case(phase, fence)


if __name__ == "__main__":
    unittest.main()
