from __future__ import annotations

from pathlib import Path
import os
import json
import signal
import subprocess
import sys
import tempfile
import time
import unittest

try:
    import pwd
    import grp
except ImportError:  # Windows has no POSIX user/group database
    pwd = None  # type: ignore[assignment]
    grp = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[3]
if not (ROOT / 'deploy').is_dir():
    raise unittest.SkipTest('deployment tree is not part of this checkout (public candidate)')
LAUNCHER = ROOT / "deploy" / "systemd" / "launch-v2-api.sh"
SUPERVISOR = ROOT / "deploy" / "systemd" / "arvyx-v2-api-supervisor.sh"
API_CLEANUP = ROOT / "deploy" / "systemd" / "arvyx-v2-api-cleanup.sh"
UNIT = ROOT / "deploy" / "systemd" / "arvyx-v2-api.service"
DELIVERY_SERVICE = ROOT / "deploy" / "systemd" / "arvyx-agent-delivery.service"
EXECUTION_SERVICE = ROOT / "deploy" / "systemd" / "arvyx-execution-worker.service"
EXECUTION_TIMER = ROOT / "deploy" / "systemd" / "arvyx-execution-worker.timer"
SNAPSHOT = ROOT / "deploy" / "systemd" / "arvyx-v2-snapshot.py"
SNAPSHOT_SERVICE = ROOT / "deploy" / "systemd" / "arvyx-v2-snapshot.service"
SNAPSHOT_TIMER = ROOT / "deploy" / "systemd" / "arvyx-v2-snapshot.timer"


class ProductionLauncherContractTests(unittest.TestCase):
    def test_launcher_is_valid_shell_and_overrides_image_readiness_contract(self) -> None:
        self.assertTrue(os.access(LAUNCHER, os.X_OK), "launcher must be executable")
        completed = subprocess.run(["sh", "-n", str(LAUNCHER)], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        source = LAUNCHER.read_text(encoding="utf-8")
        for fragment in (
            "--health-cmd",
            "--vault /data/vault",
            "--state /data/state/control-events.jsonl",
            "--audit-log /data/audit/audit-log.jsonl",
            "--health-url http://127.0.0.1:8766/health",
            "--read-only",
            "--user 10001:10001",
            "--tmpfs /tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop ALL",
            "--security-opt no-new-privileges:true",
            "--pids-limit 256",
            "--network host",
            "--host 127.0.0.1 --port 8766",
            "--health-interval 5s",
            "--health-timeout 5s",
            "--health-start-period 45s",
            "--health-retries 18",
            "ARVYX_AUTHORITY_STATE=/data/authority/state.json",
            "ARVYX_CUTOVER_ACTIVATION_MARKER=/data/authority/activated",
            "-v /srv/arvyx-v2/data/authority:/data/authority:rw",
            "--mount type=bind,src=/etc/arvyx-v2/routes.d,dst=/data/config,readonly",
            "--delivery-routes /data/config/agent-delivery-routes.json",
        ):
            self.assertIn(fragment, source)
        unit = UNIT.read_text(encoding="utf-8")
        self.assertIn("ExecStart=/bin/sh /srv/arvyx-v2/current/deploy/systemd/arvyx-v2-api-supervisor.sh", unit)
        self.assertIn("systemd_effective_exec_doctor.py --unit arvyx-v2-api.service", unit)

    def test_api_unit_uses_supervisor_for_clean_container_shutdown_and_stale_cleanup(self) -> None:
        unit = UNIT.read_text(encoding="utf-8")
        supervisor = SUPERVISOR.read_text(encoding="utf-8")
        self.assertIn("ExecStart=/bin/sh /srv/arvyx-v2/current/deploy/systemd/arvyx-v2-api-supervisor.sh", unit)
        self.assertIn("KillMode=process", unit)
        self.assertIn("ExecStartPre=-/usr/bin/docker rm -f arvyx-v2-api", unit)
        self.assertLess(unit.index("systemd_effective_exec_doctor.py"), unit.index("docker rm -f arvyx-v2-api"))
        self.assertIn("ExecStopPost=-/bin/sh /srv/arvyx-v2/current/deploy/systemd/arvyx-v2-api-cleanup.sh", unit)
        self.assertNotIn("ExecStop=/usr/bin/docker stop", unit)
        self.assertIn('"$docker_bin" stop --timeout 30 arvyx-v2-api', supervisor)
        self.assertIn('if [ "$stopping" -eq 1 ]', supervisor)
        completed = subprocess.run(["sh", "-n", str(SUPERVISOR)], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipIf(os.name != "posix", "executes chmod +x stub binaries through a POSIX shell")
    def test_api_cleanup_preserves_container_when_composition_gate_never_passed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "composition-ok"
            docker = root / "docker"
            log = root / "docker.log"
            docker.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\n", encoding="utf-8")
            docker.chmod(0o755)
            env = os.environ | {"ARVYX_V2_API_COMPOSITION_MARKER": str(marker), "ARVYX_DOCKER_BIN": str(docker)}
            first = subprocess.run(["sh", str(API_CLEANUP)], env=env, text=True, capture_output=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertFalse(log.exists())
            marker.touch()
            second = subprocess.run(["sh", str(API_CLEANUP)], env=env, text=True, capture_output=True)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("rm -f arvyx-v2-api", log.read_text(encoding="utf-8"))
            self.assertFalse(marker.exists())

    def test_snapshot_contract_has_bounded_contention_retries_and_atomic_publication(self) -> None:
        source = SNAPSHOT.read_text(encoding="utf-8")
        service = SNAPSHOT_SERVICE.read_text(encoding="utf-8")
        timer = SNAPSHOT_TIMER.read_text(encoding="utf-8")
        self.assertIn("ARVYX_V2_SNAPSHOT_MAX_ATTEMPTS", source)
        self.assertNotIn("ARVYX_V2_SNAPSHOT_LOCK_WAIT", source)
        self.assertIn("ARVYX_V2_SNAPSHOT_LOCK_HOLD", source)
        self.assertIn("os.replace(current_tmp,OUT/'current')", source)
        self.assertIn("ARVYX_V2_SNAPSHOT_MAX_ATTEMPTS=12", service)
        self.assertIn("TimeoutStartSec=30m", service)
        self.assertNotIn("SuccessExitStatus=75", service)
        self.assertIn("OnCalendar=*-*-* *:05/15:00 UTC", timer)
        completed = subprocess.run([sys.executable, "-m", "py_compile", str(SNAPSHOT)], cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    @unittest.skipIf(os.name != "posix", "requires POSIX SIGTERM delivery and shell trap semantics")
    def test_supervisor_forwards_term_and_exits_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docker = root / "docker"
            launcher = root / "launcher"
            log = root / "docker.log"
            docker.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\n", encoding="utf-8")
            launcher.write_text("#!/bin/sh\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n", encoding="utf-8")
            docker.chmod(0o755); launcher.chmod(0o755)
            env = os.environ | {"ARVYX_DOCKER_BIN": str(docker), "ARVYX_V2_LAUNCHER": str(launcher)}
            proc = subprocess.Popen(["sh", str(SUPERVISOR)], env=env, start_new_session=True)
            try:
                time.sleep(0.2); proc.send_signal(signal.SIGTERM)
                self.assertEqual(proc.wait(timeout=5), 0)
                self.assertIn("stop --timeout 30 arvyx-v2-api", log.read_text(encoding="utf-8"))
            finally:
                # The Docker stub cannot stop the fake launcher. Own its session.
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=5)
                finally:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait(timeout=5)

    @unittest.skipIf(pwd is None or grp is None, "requires the POSIX pwd/grp user database")
    def test_snapshot_round_trip_preserves_content_mode_and_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"; data = root / "data"; out = root / "snapshots"; locks = root / "locks"
            for name in ("vault", "state", "audit", "mirror", "authority"):
                (data / name).mkdir(parents=True, exist_ok=True)
            (data / "vault" / "note.md").write_text("governed\n", encoding="utf-8")
            (data / "state" / "control-events.jsonl").write_text('{"ok":true}\n', encoding="utf-8")
            (data / "audit" / "audit-log.jsonl").write_text('{"ok":true}\n', encoding="utf-8")
            (data / "mirror" / "receipts.jsonl").write_text('{"ok":true}\n', encoding="utf-8")
            (data / "mirror" / "quarantine-receipts.jsonl").write_text('{"ok":true}\n', encoding="utf-8")
            (data / "authority" / "state.json").write_text('{"authority":"V2_PRIMARY"}\n', encoding="utf-8")
            (data / "authority" / "activated").write_text('activation evidence only\n', encoding="utf-8")
            (data / "migration-redactions.json").write_text('{}\n', encoding="utf-8")
            os.chmod(data / "vault" / "note.md", 0o640)
            env = os.environ | {
                "ARVYX_V2_VAULT_UID": str((data / "vault").stat().st_uid),
                "ARVYX_V2_VAULT_GID": str((data / "vault").stat().st_gid),
                "ARVYX_V2_ROOT": str(root), "ARVYX_V2_SNAPSHOT_OUTDIR": str(out),
                "ARVYX_V2_LOCKDIR": str(locks), "ARVYX_V2_SNAPSHOT_OWNER": pwd.getpwuid(os.getuid()).pw_name,
                "ARVYX_V2_SNAPSHOT_GROUP": grp.getgrgid(os.getgid()).gr_name,
                "ARVYX_V2_SNAPSHOT_LOCK_HOLD": "30", "ARVYX_V2_SNAPSHOT_MAX_ATTEMPTS": "2",
            }
            completed = subprocess.run([sys.executable, str(SNAPSHOT)], env=env, text=True, capture_output=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertEqual(payload["archive_test"], "PASS")
            current = (out / "current").resolve(strict=True)
            manifest = json.loads((current / "manifest.json").read_text(encoding="utf-8"))["files"]
            source = (data / "vault" / "note.md").stat()
            self.assertEqual(manifest["vault/note.md"]["uid"], source.st_uid)
            self.assertEqual(manifest["vault/note.md"]["gid"], source.st_gid)
            self.assertEqual(manifest["vault/note.md"]["mode"], 0o640)
            self.assertIn("authority/state.json", manifest)

    def test_snapshot_unit_provisions_output_before_strict_namespace(self) -> None:
        service = SNAPSHOT_SERVICE.read_text(encoding="utf-8")
        self.assertIn("ExecStartPre=+/usr/bin/install -d -m 0750 -o root -g root /srv/arvyx-v2/snapshot-commits", service)
        writable = [token for line in service.splitlines() if line.startswith("ReadWritePaths=")
                    for token in line.split("=", 1)[1].split()]
        # Optional (-) output path. Within the read-only data tree only the vault
        # is writable, for the canonical lock held across the copy.
        self.assertIn("-/srv/arvyx-v2/snapshot-commits", writable)
        self.assertNotIn("/srv/arvyx-v2/data", writable)
        self.assertNotIn("-/srv/arvyx-v2/data", writable)
        self.assertIn("ReadOnlyPaths=/srv/arvyx-v2/data", service.splitlines())
        self.assertIn("systemd_effective_exec_doctor.py --unit arvyx-v2-snapshot.service", service)

    def test_liveness_units_provision_only_the_dedupe_directory(self) -> None:
        for name in ('arvyx-delivery-probe.service', 'arvyx-delivery-canary.service'):
            source=(ROOT/'deploy/systemd'/name).read_text()
            self.assertIn('ExecStartPre=+/usr/bin/install -d -m 0700 -o 10001 -g 10001 /srv/arvyx-v2/data/state/liveness',source)
            self.assertIn('ReadWritePaths=-/srv/arvyx-v2/data/state/liveness',source)
            self.assertNotIn('ReadWritePaths=/srv/arvyx-v2/data/state\n',source)

    def test_dispatcher_service_shares_the_api_state_and_environment_contract(self) -> None:
        launcher = LAUNCHER.read_text(encoding="utf-8")
        service = DELIVERY_SERVICE.read_text(encoding="utf-8")

        self.assertIn("-v /srv/arvyx-v2/data/state:/data/state:rw", launcher)
        self.assertIn("--state /data/state/control-events.jsonl", launcher)
        self.assertIn("EnvironmentFile=/etc/arvyx-v2/agent-delivery.env", service)
        self.assertNotIn("EnvironmentFile=/etc/arvyx-v2/control.env", service)
        self.assertIn("User=10001", service)
        self.assertIn("Group=10001", service)
        self.assertIn("--state /srv/arvyx-v2/data/state/control-events.jsonl", service)
        self.assertIn("--routes /etc/arvyx-v2/routes.d/agent-delivery-routes.json", service)
        self.assertIn("ReadWritePaths=/srv/arvyx-v2/data/state", service)

    def test_execution_worker_is_route_bound_and_timer_driven(self) -> None:
        service = EXECUTION_SERVICE.read_text(encoding="utf-8")
        timer = EXECUTION_TIMER.read_text(encoding="utf-8")
        for fragment in (
            "After=docker.service arvyx-v2-api.service",
            "Requires=docker.service arvyx-v2-api.service",
            "EnvironmentFile=/etc/arvyx-v2/agent-delivery.env",
            "docker exec --env-file /etc/arvyx-v2/agent-delivery.env arvyx-v2-api",
            "execution worker",
            "--state /data/state/control-events.jsonl",
            "--worker arvyx-production",
            "--routes /data/config/agent-delivery-routes.json",
            "--lease-seconds 120",
            "--max-attempts 8",
            "ReadWritePaths=/srv/arvyx-v2/data/state",
        ):
            self.assertIn(fragment, service)
        self.assertNotIn("provider-command", service)
        self.assertNotIn("capable-target", service)
        self.assertIn("OnUnitActiveSec=5s", timer)
        self.assertIn("Unit=arvyx-execution-worker.service", timer)
        self.assertIn("Persistent=true", timer)

    def test_api_route_mount_tracks_atomic_file_replacement(self) -> None:
        launcher = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("src=/etc/arvyx-v2/routes.d,dst=/data/config,readonly", launcher)
        self.assertNotIn("src=/etc/arvyx-v2/agent-delivery-routes.json", launcher)
        self.assertNotIn("src=/etc/arvyx-v2,dst=/data/config", launcher)
        self.assertNotIn("agent-delivery.env", next(line for line in launcher.splitlines() if "dst=/data/config" in line))
        self.assertNotIn("control.env", next(line for line in launcher.splitlines() if "dst=/data/config" in line))
        self.assertIn("--delivery-routes /data/config/agent-delivery-routes.json", launcher)


if __name__ == "__main__":
    unittest.main()
