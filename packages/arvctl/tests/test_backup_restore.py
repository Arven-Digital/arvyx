from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "backup_restore.py"
SPEC = importlib.util.spec_from_file_location("backup_restore", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
backup_restore = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup_restore)

SECRET_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "create_secret_file.py"
SECRET_SPEC = importlib.util.spec_from_file_location("create_secret_file", SECRET_SCRIPT)
assert SECRET_SPEC is not None and SECRET_SPEC.loader is not None
create_secret_file = importlib.util.module_from_spec(SECRET_SPEC)
SECRET_SPEC.loader.exec_module(create_secret_file)

PREFLIGHT_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "docker_preflight.py"
PREFLIGHT_SPEC = importlib.util.spec_from_file_location("docker_preflight", PREFLIGHT_SCRIPT)
assert PREFLIGHT_SPEC is not None and PREFLIGHT_SPEC.loader is not None
docker_preflight = importlib.util.module_from_spec(PREFLIGHT_SPEC)
PREFLIGHT_SPEC.loader.exec_module(docker_preflight)


@unittest.skipUnless(os.name == 'posix', 'the Docker deployment script takes a POSIX flock and fails closed elsewhere')
class BackupRestoreTests(unittest.TestCase):
    def test_public_entrypoints_share_stable_lock_before_validation(self) -> None:
        import fcntl

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock_path = root / ".backup-restore.deployment.lock"
            inode = None
            with mock.patch.object(backup_restore, "ROOT", root):
                for operation, kwargs in (
                    (backup_restore.backup, dict(project="synthetic", backup_dir=root,
                     off_host_dir=None, local_only=False, retention=1)),
                    (backup_restore.restore, dict(project="synthetic", archive=root / "a",
                     checksum=root / "c", confirm_destroy_volume=False)),
                ):
                    with mock.patch.object(fcntl, "flock") as flock:
                        with self.assertRaises(RuntimeError):
                            operation(**kwargs)
                        self.assertEqual([call.args[1] for call in flock.call_args_list],
                                         [fcntl.LOCK_EX, fcntl.LOCK_UN])
                    self.assertTrue(lock_path.is_file())
                    if inode is None:
                        inode = lock_path.stat().st_ino
                    self.assertEqual(lock_path.stat().st_ino, inode)

    def test_local_publication_barrier_failure_prevents_retention(self) -> None:
        for failed_barrier in (1, 2):
            with self.subTest(barrier=failed_barrier), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                destination = root / "backups"
                destination.mkdir()
                events = []

                def capture(container, archive, env):
                    archive.write_bytes(b"synthetic backup")

                def barrier(path):
                    events.append("barrier")
                    if len(events) == failed_barrier:
                        raise OSError("local durability failure")

                with (
                    mock.patch.object(backup_restore, "ROOT", root),
                    mock.patch.object(backup_restore, "_run") as run,
                    mock.patch.object(backup_restore, "_expected_data_volume", return_value="volume"),
                    mock.patch.object(backup_restore, "_assert_data_volume"),
                    mock.patch.object(backup_restore, "_capture_container_data", side_effect=capture),
                    mock.patch.object(backup_restore, "_safe_extract"),
                    mock.patch.object(backup_restore, "_wait_healthy") as healthy,
                    mock.patch.object(backup_restore, "_fsync_parent_directory", side_effect=barrier),
                    mock.patch.object(backup_restore, "_enforce_retention") as retention,
                ):
                    run.side_effect = lambda command, **kwargs: mock.Mock(
                        stdout="true" if "{{.State.Running}}" in command else "synthetic-container",
                        returncode=0,
                    )
                    healthy.return_value = "synthetic-container"
                    with self.assertRaisesRegex(OSError, "local durability failure"):
                        backup_restore.backup(project="synthetic", backup_dir=destination,
                                              off_host_dir=None, local_only=True, retention=1)
                    retention.assert_not_called()
                    healthy.assert_called_once()
                self.assertEqual(list(destination.glob(".*.tmp")), [])

    def test_restore_binding_rejects_wrong_authority_before_restore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "arvyx-backup-test.tar.gz"
            archive.write_bytes(b"synthetic backup")
            key = root / "binding-key"
            key.write_bytes(b"synthetic-test-binding-key-32bytes!!")
            os.chmod(key, 0o600)
            manifest = archive.with_name(f"{archive.name}.binding.json")

            backup_restore._write_restore_binding(
                archive=archive,
                manifest=manifest,
                authority_id="authority-primary",
                deployment_id="primary-0001",
                key_file=key,
            )

            with self.assertRaisesRegex(RuntimeError, "restore binding target mismatch"):
                backup_restore._verify_restore_binding(
                    archive=archive,
                    manifest=manifest,
                    authority_id="authority-unrelated",
                    key_file=key,
                )

    def test_restore_binding_allows_failover_deployment_in_same_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "arvyx-backup-test.tar.gz"
            archive.write_bytes(b"synthetic backup")
            key = root / "binding-key"
            key.write_bytes(b"synthetic-test-binding-key-32bytes!!")
            os.chmod(key, 0o600)
            manifest = archive.with_name(f"{archive.name}.binding.json")

            backup_restore._write_restore_binding(
                archive=archive,
                manifest=manifest,
                authority_id="authority-cluster-a",
                deployment_id="primary-0001",
                key_file=key,
            )
            verified = backup_restore._verify_restore_binding(
                archive=archive,
                manifest=manifest,
                authority_id="authority-cluster-a",
                key_file=key,
            )

            self.assertEqual(verified["schema"], "arvyx-restore-binding/v1")
            self.assertEqual(verified["source_deployment_id"], "primary-0001")

    def test_off_host_publish_crash_between_copies_leaves_no_visible_unbound_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "arvyx-backup-test.tar.gz"
            archive.write_bytes(b"synthetic backup payload")
            checksum = root / f"{archive.name}.sha256"
            backup_restore._write_checksum(archive, checksum)
            binding = root / f"{archive.name}.binding.json"
            binding.write_text(json.dumps({"schema": "arvyx-restore-binding/v1"}), encoding="utf-8")
            off_host = root / "off-host"

            # Crash while copying the binding (third staged file): the archive
            # copy already succeeded as a hidden temp file, but nothing visible
            # may exist — especially not an unbound archive.
            original_copy2 = backup_restore.shutil.copy2

            def crashing_copy2(src, dst, **kwargs):
                if str(src).endswith(".binding.json"):
                    raise OSError("synthetic crash during binding copy")
                return original_copy2(src, dst, **kwargs)

            with (
                mock.patch.object(backup_restore.shutil, "copy2", side_effect=crashing_copy2),
                self.assertRaisesRegex(OSError, "synthetic crash"),
            ):
                backup_restore._publish_off_host_atomic(archive, checksum, binding, off_host)

            visible = [path for path in off_host.iterdir() if not path.name.startswith(".")]
            self.assertEqual(visible, [])
            self.assertFalse((off_host / archive.name).exists())
            # Hidden temp staging files must also be cleaned up by the finally path.
            self.assertEqual(list(off_host.iterdir()), [])

    def test_off_host_publish_crash_during_commit_leaves_no_partially_visible_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "arvyx-backup-test.tar.gz"
            archive.write_bytes(b"synthetic backup payload")
            checksum = root / f"{archive.name}.sha256"
            backup_restore._write_checksum(archive, checksum)
            binding = root / f"{archive.name}.binding.json"
            binding.write_text(json.dumps({"schema": "arvyx-restore-binding/v1"}), encoding="utf-8")
            off_host = root / "off-host"

            # Crash on the very first os.replace commit: no visible file at all.
            with (
                mock.patch.object(backup_restore.os, "replace", side_effect=OSError("synthetic crash")),
                self.assertRaisesRegex(OSError, "synthetic crash"),
            ):
                backup_restore._publish_off_host_atomic(archive, checksum, binding, off_host)

            self.assertEqual(list(off_host.iterdir()), [])

    def test_off_host_publish_commits_archive_checksum_and_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "arvyx-backup-test.tar.gz"
            archive.write_bytes(b"synthetic backup payload")
            checksum = root / f"{archive.name}.sha256"
            backup_restore._write_checksum(archive, checksum)
            binding = root / f"{archive.name}.binding.json"
            binding.write_text(json.dumps({"schema": "arvyx-restore-binding/v1"}), encoding="utf-8")
            off_host = root / "off-host"

            backup_restore._publish_off_host_atomic(archive, checksum, binding, off_host)

            self.assertEqual(
                sorted(path.name for path in off_host.iterdir()),
                sorted([archive.name, checksum.name, binding.name]),
            )
            backup_restore._verify_checksum(off_host / archive.name, off_host / checksum.name)
            if os.name != "nt":
                for path in off_host.iterdir():
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_binding_key_exactly_32_bytes_accepted_and_31_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key32 = root / "key-32"
            key32.write_bytes(b"k" * 32)
            os.chmod(key32, 0o600)
            key31 = root / "key-31"
            key31.write_bytes(b"k" * 31)
            os.chmod(key31, 0o600)

            self.assertEqual(backup_restore._restore_binding_key(key32), b"k" * 32)
            with self.assertRaisesRegex(RuntimeError, "at least 32 bytes"):
                backup_restore._restore_binding_key(key31)

    def test_binding_key_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "real-key"
            target.write_bytes(b"k" * 32)
            os.chmod(target, 0o600)
            link = root / "linked-key"
            link.symlink_to(target)

            with self.assertRaisesRegex(RuntimeError, "regular file"):
                backup_restore._restore_binding_key(link)

    def test_tampered_archive_sha256_fails_authentication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "arvyx-backup-test.tar.gz"
            archive.write_bytes(b"synthetic backup payload")
            key = root / "binding-key"
            key.write_bytes(b"synthetic-test-binding-key-32bytes!!")
            os.chmod(key, 0o600)
            manifest = archive.with_name(f"{archive.name}.binding.json")
            backup_restore._write_restore_binding(
                archive=archive,
                manifest=manifest,
                authority_id="authority-cluster-a",
                deployment_id="primary-0001",
                key_file=key,
            )

            # An attacker without the key can flip archive_sha256 but cannot
            # recompute the MAC over the tampered canonical payload.
            document = json.loads(manifest.read_text(encoding="utf-8"))
            document["archive_sha256"] = "0" * 64
            manifest.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "authentication failed"):
                backup_restore._verify_restore_binding(
                    archive=archive,
                    manifest=manifest,
                    authority_id="authority-cluster-a",
                    key_file=key,
                )

    def test_backup_enforce_binding_without_env_fails_loudly_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch.object(backup_restore, "_run") as run,
                self.assertRaisesRegex(RuntimeError, "restore binding requires"),
            ):
                backup_restore.backup(
                    project="arvyx",
                    backup_dir=Path(tmp) / "backups",
                    off_host_dir=None,
                    local_only=True,
                    retention=1,
                    enforce_binding=True,
                )
            run.assert_not_called()

    def test_restore_wrong_target_fails_before_docker_inspection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = self._data(root)
            archive = root / "arvyx-backup-test.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(data, arcname="data")
            checksum = archive.with_name(f"{archive.name}.sha256")
            backup_restore._write_checksum(archive, checksum)
            key = root / "binding-key"
            key.write_bytes(b"synthetic-test-binding-key-32bytes!!")
            os.chmod(key, 0o600)
            backup_restore._write_restore_binding(
                archive=archive,
                manifest=archive.with_name(f"{archive.name}.binding.json"),
                authority_id="authority-cluster-a",
                deployment_id="primary-0001",
                key_file=key,
            )
            environment = {
                "ARVYX_BACKUP_AUTHORITY_ID": "authority-cluster-b",
                "ARVYX_BACKUP_BINDING_KEY_FILE": str(key),
            }
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(backup_restore, "_run") as run,
                self.assertRaisesRegex(RuntimeError, "restore binding target mismatch"),
            ):
                backup_restore.restore(
                    project="arvyx",
                    archive=archive,
                    checksum=checksum,
                    confirm_destroy_volume=True,
                    enforce_binding=True,
                )
            run.assert_not_called()

    def _data(self, root: Path) -> Path:
        data = root / "data"
        vault = data / "vault"
        vault.mkdir(parents=True)
        (vault / ".arvyx-vault").write_text("arvyx-vault-format: 1\n", encoding="utf-8")
        return data

    def _owned_candidate_inspection(self, command):
        if (
            command[:3] == ["docker", "volume", "inspect"]
            and "-restore-" in command[-1]
        ):
            return mock.Mock(
                stdout=json.dumps(
                    [
                        {
                            "Labels": {
                                "com.docker.compose.project": "arvyx",
                                "com.docker.compose.volume": "arvyx-data",
                                "com.arvyx.restore.operation": "abcdef123456",
                            }
                        }
                    ]
                )
            )
        return None

    def _exercise_post_publication_failure(
        self,
        *,
        rollback_fsync_fails: bool,
        rollback_restart_fails: bool = False,
        pointer_decode_fails: bool = False,
    ) -> tuple[Path, list[str], Exception, tempfile.TemporaryDirectory[str]]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        data = self._data(root)
        archive = root / "arvyx-backup-test.tar.gz"
        checksum = root / f"{archive.name}.sha256"
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(data, arcname="data")
        backup_restore._write_checksum(archive, checksum)
        previous = "arvyx_prod-0001_arvyx-data"
        candidate = f"{previous}-restore-abcdef123456"
        env_file = root / ".env"
        env_file.write_text(f"ARVYX_DATA_VOLUME={previous}\n", encoding="utf-8")
        events: list[str] = []

        def fake_run(command, *, env, check=True):
            owned_inspection = self._owned_candidate_inspection(command)
            if owned_inspection is not None:
                return owned_inspection
            if command[:3] == ["docker", "volume", "rm"]:
                events.append(f"volume-rm:{command[-1]}")
            if "up" in command and "-d" in command and "-p" in command:
                project = command[command.index("-p") + 1]
                if project == "arvyx":
                    events.append(f"production-up:{env.get('ARVYX_DATA_VOLUME')}")
            if "ps" in command and "-aq" in command:
                project = command[command.index("-p") + 1]
                return mock.Mock(stdout="" if project == "arvyx" else "staging-container\n")
            return mock.Mock(stdout="")

        def faulting_pointer_update(path: Path, *, previous: str, candidate: str) -> None:
            if candidate.endswith("restore-abcdef123456") and pointer_decode_fails:
                path.write_bytes(b"\xff")
            else:
                text = path.read_text(encoding="utf-8")
                path.write_text(
                    text.replace(
                        f"ARVYX_DATA_VOLUME={previous}",
                        f"ARVYX_DATA_VOLUME={candidate}",
                    ),
                    encoding="utf-8",
                )
            events.append(f"pointer:{candidate}")
            if candidate.endswith("restore-abcdef123456"):
                raise OSError("post-replace directory fsync failed")
            if rollback_fsync_fails:
                raise OSError("rollback directory fsync failed")

        environment = {
            "ARVYX_DATA_VOLUME": previous,
            "ARVYX_CONTROL_SECRET_FILE": "secrets/control-secret",
            "COMPOSE_PROJECT_NAME": "arvyx",
            "ARVYX_DEPLOYMENT_ID": "prod-0001",
        }
        caught: Exception | None = None
        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(backup_restore.secrets, "token_hex", return_value="abcdef123456"),
            mock.patch.object(backup_restore, "_run", side_effect=fake_run),
            mock.patch.object(backup_restore, "_assert_data_volume"),
            mock.patch.object(backup_restore, "_stage_current_control_secret"),
            mock.patch.object(backup_restore, "_acceptance_probe"),
            mock.patch.object(
                backup_restore,
                "_wait_healthy",
                side_effect=[
                    "staging-container",
                    "pristine-container",
                    "candidate-container",
                    RuntimeError("rollback restart failed")
                    if rollback_restart_fails
                    else "rollback-container",
                ],
            ),
            mock.patch.object(
                backup_restore, "_atomic_update_active_volume", side_effect=faulting_pointer_update
            ),
            mock.patch.object(backup_restore.subprocess, "run", return_value=mock.Mock(returncode=0)),
        ):
            try:
                backup_restore.restore(
                    project="arvyx",
                    archive=archive,
                    checksum=checksum,
                    confirm_destroy_volume=True,
                    env_file=env_file,
                )
            except Exception as exc:  # expected fault injection
                caught = exc
        assert caught is not None
        return env_file, events, caught, temporary

    def test_post_publication_failure_restores_pointer_before_candidate_delete(self) -> None:
        env_file, events, caught, temporary = self._exercise_post_publication_failure(
            rollback_fsync_fails=False
        )
        try:
            self.assertIn("post-replace directory fsync failed", str(caught))
            self.assertEqual(
                env_file.read_text(encoding="utf-8"),
                "ARVYX_DATA_VOLUME=arvyx_prod-0001_arvyx-data\n",
            )
            rollback_event = "pointer:arvyx_prod-0001_arvyx-data"
            final_delete = "volume-rm:arvyx_prod-0001_arvyx-data-restore-abcdef123456"
            self.assertIn(rollback_event, events)
            self.assertLess(events.index(rollback_event), len(events) - 1 - events[::-1].index(final_delete))
            self.assertEqual(events.count(final_delete), 2)
        finally:
            temporary.cleanup()

    def test_rollback_durability_ambiguity_retains_candidate_for_reconciliation(self) -> None:
        env_file, events, caught, temporary = self._exercise_post_publication_failure(
            rollback_fsync_fails=True
        )
        try:
            self.assertIn("reconciliation required", str(caught).lower())
            self.assertEqual(
                env_file.read_text(encoding="utf-8"),
                "ARVYX_DATA_VOLUME=arvyx_prod-0001_arvyx-data\n",
            )
            # Only the expected pristine-reseed delete may occur; exception cleanup must retain candidate.
            actual_candidate = "volume-rm:arvyx_prod-0001_arvyx-data-restore-abcdef123456"
            self.assertEqual(events.count(actual_candidate), 1)
            retained_candidate = actual_candidate.removeprefix("volume-rm:")
            notes = getattr(caught, "__notes__", [])
            self.assertTrue(any(retained_candidate in note for note in notes), notes)
        finally:
            temporary.cleanup()

    def test_rollback_restart_failure_does_not_mask_pointer_reconciliation(self) -> None:
        _env_file, events, caught, temporary = self._exercise_post_publication_failure(
            rollback_fsync_fails=True,
            rollback_restart_fails=True,
        )
        try:
            self.assertIn("reconciliation required", str(caught).lower())
            actual_candidate = "volume-rm:arvyx_prod-0001_arvyx-data-restore-abcdef123456"
            self.assertEqual(events.count(actual_candidate), 1)
        finally:
            temporary.cleanup()

    def test_non_utf8_pointer_keeps_typed_reconciliation_and_blocks_restart(self) -> None:
        _env_file, events, caught, temporary = self._exercise_post_publication_failure(
            rollback_fsync_fails=False,
            rollback_restart_fails=True,
            pointer_decode_fails=True,
        )
        try:
            self.assertIn("reconciliation required", str(caught).lower())
            self.assertNotIn("production-up:arvyx_prod-0001_arvyx-data", events)
            assert isinstance(caught, backup_restore.VolumePointerReconciliationRequired)
            self.assertTrue(caught.restart_blocked)
            self.assertFalse(caught.restart_failed)
            self.assertEqual(caught.previous_volume,'arvyx_prod-0001_arvyx-data')
            self.assertEqual(caught.candidate_volume,'arvyx_prod-0001_arvyx-data-restore-abcdef123456')
            actual_candidate = "volume-rm:arvyx_prod-0001_arvyx-data-restore-abcdef123456"
            self.assertEqual(events.count(actual_candidate), 1)
        finally:
            temporary.cleanup()

    def test_safe_archive_round_trip_and_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = self._data(root)
            archive = root / "arvyx-backup-test.tar.gz"
            checksum = root / f"{archive.name}.sha256"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(data, arcname="data")
            digest = backup_restore._write_checksum(archive, checksum)
            self.assertEqual(backup_restore._verify_checksum(archive, checksum), digest)
            extracted = root / "extracted"
            extracted.mkdir()
            backup_restore._safe_extract(archive, extracted)

    def test_capture_excludes_staged_control_secret_from_backup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w") as bundle:
                for name, payload in (
                    ("vault/.arvyx-vault", b"arvyx-vault-format: 1\n"),
                    (".arvyx-control-secret", b"revoked-bearer\n"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    bundle.addfile(info, io.BytesIO(payload))
            raw_bytes = raw.getvalue()

            def fake_cp(command, **kwargs):
                if command == ['docker', 'inspect', '--format', '{{.Image}}', 'container']:
                    self.assertTrue(kwargs['capture_output'])
                    return mock.Mock(returncode=0, stdout='sha256:' + 'a' * 64 + '\n')
                self.assertEqual(command[:2], ['docker', 'run'])
                kwargs["stdout"].write(raw_bytes)
                return mock.Mock(returncode=0)

            archive = root / "backup.tar.gz"
            with mock.patch.object(backup_restore.subprocess, "run", side_effect=fake_cp):
                backup_restore._capture_container_data("container", archive, {})

            with tarfile.open(archive, "r:gz") as bundle:
                names = bundle.getnames()
            self.assertIn("data/vault/.arvyx-vault", names)
            self.assertNotIn("data/.arvyx-control-secret", names)

    def test_materialized_candidate_stages_current_host_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "container.tar"
            archive.write_bytes(b"candidate")
            secret = root / "current-secret"
            secret.write_text("current-bearer" + "x" * 24 + "\n", encoding="ascii")
            environment = {
                "COMPOSE_PROJECT_NAME": "arvyx-prod",
                "ARVYX_DEPLOYMENT_ID": "prod-0001",
                "ARVYX_CONTROL_SECRET_FILE": str(secret),
                "ARVYX_IMAGE": "arvyx:test",
            }

            def fake_run(command, *, env, check=True):
                owned_inspection = self._owned_candidate_inspection(command)
                if owned_inspection is not None:
                    return owned_inspection
                if "ps" in command and "-aq" in command:
                    return mock.Mock(stdout="staging-container\n")
                return mock.Mock(stdout="")

            with (
                mock.patch.object(backup_restore, "_run", side_effect=fake_run),
                mock.patch.object(backup_restore, "_assert_data_volume"),
                mock.patch.object(backup_restore.subprocess, "run", return_value=mock.Mock(returncode=0)),
                mock.patch.object(backup_restore, "_stage_current_control_secret", create=True) as stage,
            ):
                backup_restore._materialize_candidate_volume(
                    staging_compose=["docker", "compose"],
                    staging_env=environment,
                    production_env=environment,
                    project="arvyx-prod",
                    candidate_volume="arvyx-prod_prod-0001_arvyx-data-restore-abc",
                    container_archive=archive,
                )

            stage.assert_called_once_with(
                secret_file=secret,
                volume="arvyx-prod_prod-0001_arvyx-data-restore-abc",
                image="arvyx:test",
                env=environment,
            )

    def test_backup_data_rejects_corrupt_or_invalid_operation_journal(self) -> None:
        from arvyx_control.operation_journal import claim_operation

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = self._data(root)
            journal = data / "audit-log.jsonl.operations.sqlite3"
            claim_operation(
                journal,
                vault=data / "vault",
                principal_scope="test:operator",
                action="POST:/tasks",
                idempotency_key="backup-integrity-key-0001",
                request_hash="a" * 64,
            )
            backup_restore._verify_data(data)
            journal.write_bytes(b"not-a-sqlite-database")
            with self.assertRaisesRegex(RuntimeError, "corrupt"):
                backup_restore._verify_data(data)

    def test_safe_extract_rejects_traversal_and_symlink(self) -> None:
        for kind in ("traversal", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                archive = root / "bad.tar.gz"
                with tarfile.open(archive, "w:gz") as bundle:
                    if kind == "traversal":
                        info = tarfile.TarInfo("data/../../escape")
                        payload = b"bad"
                        info.size = len(payload)
                        bundle.addfile(info, io.BytesIO(payload))
                    else:
                        info = tarfile.TarInfo("data/link")
                        info.type = tarfile.SYMTYPE
                        info.linkname = "/etc/passwd"
                        bundle.addfile(info)
                destination = root / "out"
                destination.mkdir()
                with self.assertRaises(RuntimeError):
                    backup_restore._safe_extract(archive, destination)

    def test_checksum_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "arvyx-backup-test.tar.gz"
            archive.write_bytes(b"before")
            checksum = root / f"{archive.name}.sha256"
            backup_restore._write_checksum(archive, checksum)
            archive.write_bytes(b"after")
            with self.assertRaises(RuntimeError):
                backup_restore._verify_checksum(archive, checksum)

    def test_backup_requires_off_host_or_explicit_local_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RuntimeError):
                backup_restore.backup(
                    project="synthetic",
                    backup_dir=Path(tmp),
                    off_host_dir=None,
                    local_only=False,
                    retention=7,
                )

    def test_retention_counts_only_verified_complete_pairs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            complete: list[Path] = []
            for index in range(2):
                archive = root / f"arvyx-backup-2026010{index + 1}T000000Z.tar.gz"
                archive.write_bytes(f"complete-{index}".encode("ascii"))
                backup_restore._write_checksum(archive, archive.with_name(f"{archive.name}.sha256"))
                complete.append(archive)
            orphan = root / "arvyx-backup-20260103T000000Z.tar.gz"
            orphan.write_bytes(b"orphan")
            backup_restore._enforce_retention(root, keep=2)
            self.assertTrue(all(path.exists() for path in complete))
            self.assertFalse(orphan.exists())
            self.assertEqual(len(list(root.glob("*.tar.gz.sha256"))), 2)

    def test_secret_file_is_exclusive_and_mode_private(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "secrets" / "control-secret"
            create_secret_file.create_secret_file(path)
            self.assertTrue(path.is_file())
            raw = path.read_bytes()
            self.assertTrue(raw[:-1])
            self.assertTrue(raw.endswith(b"\n"))
            self.assertEqual(raw.count(b"\n"), 1)
            self.assertNotIn(b"\r", raw)
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                create_secret_file.create_secret_file(path)

    def test_secret_file_refuses_symlink_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.write_text("unchanged", encoding="utf-8")
            link = root / "control-secret"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlinks unavailable")
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                create_secret_file.create_secret_file(link)
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")

    def test_secret_file_refuses_dangling_symlink_without_chmod(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            other = root / "other"
            other.mkdir(mode=0o755)
            target = other / "absent-secret"
            link = root / "control-secret"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlinks unavailable")
            original_mode = other.stat().st_mode
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                create_secret_file.create_secret_file(link)
            self.assertFalse(target.exists())
            self.assertEqual(other.stat().st_mode, original_mode)

    def test_secret_file_refuses_symlink_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            other = root / "other"
            other.mkdir(mode=0o755)
            link = root / "alias"
            try:
                link.symlink_to(other, target_is_directory=True)
            except OSError:
                self.skipTest("symlinks unavailable")
            original_mode = other.stat().st_mode
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                create_secret_file.create_secret_file(link / "nested" / "control-secret")
            self.assertFalse((other / "nested").exists())
            self.assertEqual(other.stat().st_mode, original_mode)

    def test_docker_version_parser_and_floor_contract(self) -> None:
        self.assertEqual(docker_preflight._version("v24.0.7"), (24, 0, 7))
        self.assertEqual(docker_preflight._version("2.20"), (2, 20, 0))
        with self.assertRaisesRegex(RuntimeError, "unrecognized"):
            docker_preflight._version("unknown")

    def test_deployment_identity_prevents_copied_checkout_volume_collision(self) -> None:
        valid = {
            "COMPOSE_PROJECT_NAME": "arvyx-prod",
            "ARVYX_DEPLOYMENT_ID": "prod-0001",
            "ARVYX_DATA_VOLUME": "arvyx-prod_prod-0001_arvyx-data",
        }
        self.assertEqual(
            docker_preflight._deployment_contract(valid),
            ("arvyx-prod", "prod-0001", "arvyx-prod_prod-0001_arvyx-data"),
        )
        with self.assertRaisesRegex(RuntimeError, "deployment-specific"):
            docker_preflight._deployment_contract(
                {
                    "COMPOSE_PROJECT_NAME": "change-me-project",
                    "ARVYX_DEPLOYMENT_ID": "prod-0001",
                    "ARVYX_DATA_VOLUME": "change-me-project_prod-0001_arvyx-data",
                }
            )
        with self.assertRaisesRegex(RuntimeError, "scoped"):
            docker_preflight._deployment_contract(
                {**valid, "ARVYX_DATA_VOLUME": "arvyx-prod_other_arvyx-data"}
            )

    def test_active_pointer_read_failure_requires_reconciliation(self) -> None:
        failures = (
            OSError("read failed"),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as tmp:
                env_file = Path(tmp) / ".env"
                env_file.write_text("ARVYX_DATA_VOLUME=arvyx_old\n", encoding="utf-8")
                with mock.patch.object(Path, "read_text", side_effect=failure):
                    with self.assertRaisesRegex(
                        backup_restore.VolumePointerReconciliationRequired,
                        "reconciliation required",
                    ):
                        backup_restore._read_active_volume_pointer(env_file)

    def test_atomic_volume_pointer_update_surfaces_post_replace_durability_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("ARVYX_DATA_VOLUME=arvyx_old\n", encoding="utf-8")
            with mock.patch.object(
                backup_restore,
                "_fsync_parent_directory",
                side_effect=OSError("directory fsync failed"),
            ):
                with self.assertRaisesRegex(
                    backup_restore.VolumePointerPublicationDurabilityError,
                    "publication durability failed after replace",
                ):
                    backup_restore._atomic_update_active_volume(
                        env_file,
                        previous="arvyx_old",
                        candidate="arvyx_candidate",
                    )
            self.assertEqual(
                env_file.read_text(encoding="utf-8"),
                "ARVYX_DATA_VOLUME=arvyx_candidate\n",
            )

    def test_atomic_volume_pointer_update_is_exact_and_preserves_other_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / ".env"
            env_file.write_text("COMPOSE_PROJECT_NAME=arvyx\nARVYX_DATA_VOLUME=arvyx_old\nOTHER=value\n", encoding="utf-8")
            backup_restore._atomic_update_active_volume(
                env_file,
                previous="arvyx_old",
                candidate="arvyx_candidate",
            )
            self.assertEqual(
                env_file.read_text(encoding="utf-8"),
                "COMPOSE_PROJECT_NAME=arvyx\nARVYX_DATA_VOLUME=arvyx_candidate\nOTHER=value\n",
            )
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                backup_restore._atomic_update_active_volume(
                    env_file,
                    previous="arvyx_old",
                    candidate="arvyx_other",
                )

    def test_partial_materialization_failures_clean_container_before_candidate_volume(self) -> None:
        for boundary in (
            "container-create",
            "archive-copy",
            "secret-stage",
            "secret-stage-cleanup-fails",
            "secret-stage-volume-rm-fails",
            "secret-stage-foreign-replaced",
        ):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                data = self._data(root)
                archive = root / "arvyx-backup-test.tar.gz"
                checksum = root / f"{archive.name}.sha256"
                with tarfile.open(archive, "w:gz") as bundle:
                    bundle.add(data, arcname="data")
                backup_restore._write_checksum(archive, checksum)
                previous = "arvyx_prod-0001_arvyx-data"
                candidate = f"{previous}-restore-abcdef123456"
                env_file = root / ".env"
                env_file.write_text(f"ARVYX_DATA_VOLUME={previous}\n", encoding="utf-8")
                events: list[str] = []
                candidate_inspections = 0

                def fake_run(command, *, env, check=True):
                    nonlocal candidate_inspections
                    if (
                        command[:3] == ["docker", "volume", "inspect"]
                        and "-restore-" in command[-1]
                    ):
                        candidate_inspections += 1
                        if (
                            boundary == "secret-stage-foreign-replaced"
                            and candidate_inspections > 1
                        ):
                            return mock.Mock(
                                stdout=json.dumps(
                                    [
                                        {
                                            "Labels": {
                                                "com.docker.compose.project": "arvyx",
                                                "com.docker.compose.volume": "arvyx-data",
                                                "com.arvyx.restore.operation": "foreign-operation",
                                            }
                                        }
                                    ]
                                )
                            )
                    owned_inspection = self._owned_candidate_inspection(command)
                    if owned_inspection is not None:
                        return owned_inspection
                    if command[:3] == ["docker", "volume", "create"]:
                        events.append(f"volume-create:{command[-1]}")
                    if "create" in command and "arvyx-server" in command:
                        events.append("staging-container-create")
                        if boundary == "container-create":
                            raise RuntimeError("container creation failed")
                    if "down" in command:
                        events.append("staging-down")
                        if boundary == "secret-stage-cleanup-fails":
                            return mock.Mock(stdout="", returncode=1)
                    if command[:3] == ["docker", "volume", "rm"]:
                        events.append(f"volume-rm:{command[-1]}")
                        if boundary == "secret-stage-volume-rm-fails":
                            return mock.Mock(stdout="", returncode=1)
                    if "ps" in command and "-aq" in command:
                        project = command[command.index("-p") + 1]
                        return mock.Mock(stdout="" if project == "arvyx" else "staging-container\n")
                    return mock.Mock(stdout="")

                def fake_cp(*_args, **_kwargs):
                    if boundary == "archive-copy":
                        raise RuntimeError("archive copy failed")
                    return mock.Mock(returncode=0)

                def fake_stage(**_kwargs):
                    if boundary.startswith("secret-stage"):
                        raise RuntimeError("secret stage failed")

                environment = {
                    "ARVYX_DATA_VOLUME": previous,
                    "ARVYX_CONTROL_SECRET_FILE": "secrets/control-secret",
                    "COMPOSE_PROJECT_NAME": "arvyx",
                    "ARVYX_DEPLOYMENT_ID": "prod-0001",
                }
                with (
                    mock.patch.dict(os.environ, environment, clear=True),
                    mock.patch.object(
                        backup_restore.secrets, "token_hex", return_value="abcdef123456"
                    ),
                    mock.patch.object(backup_restore, "_run", side_effect=fake_run),
                    mock.patch.object(backup_restore, "_assert_data_volume"),
                    mock.patch.object(
                        backup_restore,
                        "_stage_current_control_secret",
                        side_effect=fake_stage,
                    ),
                    mock.patch.object(backup_restore.subprocess, "run", side_effect=fake_cp),
                ):
                    expected_error = (
                        f"cleanup required.*{candidate}"
                        if boundary
                        in (
                            "secret-stage-cleanup-fails",
                            "secret-stage-volume-rm-fails",
                            "secret-stage-foreign-replaced",
                        )
                        else "failed"
                    )
                    with self.assertRaisesRegex(RuntimeError, expected_error):
                        backup_restore.restore(
                            project="arvyx",
                            archive=archive,
                            checksum=checksum,
                            confirm_destroy_volume=True,
                            env_file=env_file,
                        )
                remove_event = f"volume-rm:{candidate}"
                self.assertIn("staging-down", events)
                if boundary in (
                    "secret-stage-cleanup-fails",
                    "secret-stage-foreign-replaced",
                ):
                    self.assertNotIn(remove_event, events)
                else:
                    self.assertIn(remove_event, events)
                    self.assertLess(events.index("staging-down"), events.index(remove_event))
                self.assertEqual(
                    env_file.read_text(encoding="utf-8"),
                    f"ARVYX_DATA_VOLUME={previous}\n",
                )

    def test_staging_restore_failure_does_not_stop_or_delete_production_volume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = self._data(root)
            archive = root / "arvyx-backup-test.tar.gz"
            checksum = root / f"{archive.name}.sha256"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(data, arcname="data")
            backup_restore._write_checksum(archive, checksum)
            env_file = root / ".env"
            env_file.write_text("ARVYX_DATA_VOLUME=arvyx_prod-0001_arvyx-data\n", encoding="utf-8")
            calls: list[tuple[list[str], str | None]] = []

            def fake_run(command, *, env, check=True):
                owned_inspection = self._owned_candidate_inspection(command)
                if owned_inspection is not None:
                    return owned_inspection
                calls.append((command, env.get("ARVYX_DATA_VOLUME")))
                if "ps" in command and "-aq" in command:
                    project = command[command.index("-p") + 1]
                    return mock.Mock(stdout="" if project == "arvyx" else "staging-container\n")
                return mock.Mock(stdout="")

            environment = {
                "ARVYX_DATA_VOLUME": "arvyx_prod-0001_arvyx-data",
                "ARVYX_CONTROL_SECRET_FILE": "secrets/control-secret",
                "COMPOSE_PROJECT_NAME": "arvyx",
                "ARVYX_DEPLOYMENT_ID": "prod-0001",
            }
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(backup_restore.secrets, "token_hex", return_value="abcdef123456"),
                mock.patch.object(backup_restore, "_run", side_effect=fake_run),
                mock.patch.object(backup_restore, "_assert_data_volume"),
                mock.patch.object(backup_restore, "_stage_current_control_secret"),
                mock.patch.object(backup_restore, "_wait_healthy", side_effect=RuntimeError("staging unhealthy")),
                mock.patch.object(backup_restore.subprocess, "run", return_value=mock.Mock(returncode=0)),
            ):
                with self.assertRaisesRegex(RuntimeError, "staging unhealthy"):
                    backup_restore.restore(
                        project="arvyx",
                        archive=archive,
                        checksum=checksum,
                        confirm_destroy_volume=True,
                        env_file=env_file,
                    )
            production_down = [
                command for command, _volume in calls
                if "-p" in command and command[command.index("-p") + 1] == "arvyx" and "down" in command
            ]
            self.assertEqual(production_down, [])
            self.assertNotIn("--volumes", " ".join(part for command, _ in calls for part in command))
            self.assertEqual(env_file.read_text(encoding="utf-8"), "ARVYX_DATA_VOLUME=arvyx_prod-0001_arvyx-data\n")

    def test_postcommit_health_failure_retains_candidate_and_fences_admission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = self._data(root)
            archive = root / "arvyx-backup-test.tar.gz"
            checksum = root / f"{archive.name}.sha256"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(data, arcname="data")
            backup_restore._write_checksum(archive, checksum)
            env_file = root / ".env"
            env_file.write_text("ARVYX_DATA_VOLUME=arvyx_prod-0001_arvyx-data\n", encoding="utf-8")
            calls: list[tuple[list[str], str | None]] = []

            def fake_run(command, *, env, check=True):
                owned_inspection = self._owned_candidate_inspection(command)
                if owned_inspection is not None:
                    return owned_inspection
                calls.append((command, env.get("ARVYX_DATA_VOLUME")))
                if "ps" in command and "-aq" in command:
                    project = command[command.index("-p") + 1]
                    return mock.Mock(stdout="" if project == "arvyx" else "staging-container\n")
                return mock.Mock(stdout="")

            environment = {
                "ARVYX_DATA_VOLUME": "arvyx_prod-0001_arvyx-data",
                "ARVYX_CONTROL_SECRET_FILE": "secrets/control-secret",
                "COMPOSE_PROJECT_NAME": "arvyx",
                "ARVYX_DEPLOYMENT_ID": "prod-0001",
            }
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(backup_restore.secrets, "token_hex", return_value="abcdef123456"),
                mock.patch.object(backup_restore, "_run", side_effect=fake_run),
                mock.patch.object(backup_restore, "_assert_data_volume"),
                mock.patch.object(backup_restore, "_stage_current_control_secret"),
                mock.patch.object(backup_restore, "_acceptance_probe"),
                mock.patch.object(
                    backup_restore,
                    "_wait_healthy",
                    side_effect=[
                        "staging-container",
                        "pristine-container",
                        RuntimeError("candidate unhealthy"),
                        "rollback-container",
                    ],
                ),
                mock.patch.object(backup_restore.subprocess, "run", return_value=mock.Mock(returncode=0)),
            ):
                with self.assertRaisesRegex(backup_restore.VolumePointerReconciliationRequired, "automatic rollback forbidden") as caught:
                    backup_restore.restore(
                        project="arvyx",
                        archive=archive,
                        checksum=checksum,
                        confirm_destroy_volume=True,
                        env_file=env_file,
                    )
            production_ups = [
                volume for command, volume in calls
                if "-p" in command and command[command.index("-p") + 1] == "arvyx" and "up" in command
            ]
            candidate = "arvyx_prod-0001_arvyx-data-restore-abcdef123456"
            self.assertEqual(production_ups, [candidate])
            self.assertTrue(caught.exception.restart_blocked)
            self.assertEqual(env_file.read_text(encoding="utf-8"), f"ARVYX_DATA_VOLUME={candidate}\n")
            self.assertTrue(any("stop" in command for command, _ in calls))
            # One pristine-reseed removal is allowed; postcommit cleanup must retain it.
            removals = [command for command, _ in calls if command[:3] == ["docker", "volume", "rm"] and command[-1] == candidate]
            self.assertEqual(len(removals), 1)

    def test_successful_cutover_updates_pointer_and_retains_previous_volume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = self._data(root)
            archive = root / "arvyx-backup-test.tar.gz"
            checksum = root / f"{archive.name}.sha256"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(data, arcname="data")
            backup_restore._write_checksum(archive, checksum)
            env_file = root / ".env"
            env_file.write_text("ARVYX_DATA_VOLUME=arvyx_prod-0001_arvyx-data\n", encoding="utf-8")
            calls: list[list[str]] = []

            def fake_run(command, *, env, check=True):
                owned_inspection = self._owned_candidate_inspection(command)
                if owned_inspection is not None:
                    return owned_inspection
                calls.append(command)
                if "ps" in command and "-aq" in command:
                    project = command[command.index("-p") + 1]
                    return mock.Mock(stdout="" if project == "arvyx" else "staging-container\n")
                return mock.Mock(stdout="")

            environment = {
                "ARVYX_DATA_VOLUME": "arvyx_prod-0001_arvyx-data",
                "ARVYX_CONTROL_SECRET_FILE": "secrets/control-secret",
                "COMPOSE_PROJECT_NAME": "arvyx",
                "ARVYX_DEPLOYMENT_ID": "prod-0001",
            }
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(backup_restore.secrets, "token_hex", return_value="abcdef123456"),
                mock.patch.object(backup_restore, "_run", side_effect=fake_run),
                mock.patch.object(backup_restore, "_assert_data_volume"),
                mock.patch.object(backup_restore, "_stage_current_control_secret"),
                mock.patch.object(backup_restore, "_acceptance_probe"),
                mock.patch.object(
                    backup_restore,
                    "_wait_healthy",
                    side_effect=["staging-container", "pristine-container", "candidate-container"],
                ),
                mock.patch.object(backup_restore.subprocess, "run", return_value=mock.Mock(returncode=0)),
            ):
                result = backup_restore.restore(
                    project="arvyx",
                    archive=archive,
                    checksum=checksum,
                    confirm_destroy_volume=True,
                    env_file=env_file,
                )
            self.assertTrue(result["rollback_volume_retained"])
            self.assertEqual(result["rollback_volume"], "arvyx_prod-0001_arvyx-data")
            self.assertIn("ARVYX_DATA_VOLUME=arvyx_prod-0001_arvyx-data-restore-abcdef123456", env_file.read_text(encoding="utf-8"))
            # Candidate may be reseeded via volume rm; production rollback volume must remain.
            removed = [command[-1] for command in calls if command[:3] == ["docker", "volume", "rm"]]
            self.assertNotIn("arvyx_prod-0001_arvyx-data", removed)

    def test_reseed_ownership_rejection_does_not_delete_foreign_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = self._data(root)
            archive = root / "arvyx-backup-test.tar.gz"
            checksum = root / f"{archive.name}.sha256"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(data, arcname="data")
            backup_restore._write_checksum(archive, checksum)
            previous = "arvyx_prod-0001_arvyx-data"
            candidate = f"{previous}-restore-abcdef123456"
            env_file = root / ".env"
            env_file.write_text(f"ARVYX_DATA_VOLUME={previous}\n", encoding="utf-8")
            removed: list[str] = []

            def fake_run(command, *, env, check=True):
                owned_inspection = self._owned_candidate_inspection(command)
                if owned_inspection is not None:
                    return owned_inspection
                if command[:3] == ["docker", "volume", "rm"]:
                    removed.append(command[-1])
                if "ps" in command and "-aq" in command:
                    project = command[command.index("-p") + 1]
                    return mock.Mock(stdout="" if project == "arvyx" else "staging-container\n")
                return mock.Mock(stdout="")

            environment = {
                "ARVYX_DATA_VOLUME": previous,
                "ARVYX_CONTROL_SECRET_FILE": "secrets/control-secret",
                "COMPOSE_PROJECT_NAME": "arvyx",
                "ARVYX_DEPLOYMENT_ID": "prod-0001",
            }
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(
                    backup_restore.secrets, "token_hex", return_value="abcdef123456"
                ),
                mock.patch.object(backup_restore, "_run", side_effect=fake_run),
                mock.patch.object(
                    backup_restore,
                    "_create_candidate_volume",
                    side_effect=[None, RuntimeError("candidate volume ownership labels do not match")],
                ),
                mock.patch.object(backup_restore, "_materialize_candidate_volume"),
                mock.patch.object(backup_restore, "_wait_healthy", return_value="staging-container"),
                mock.patch.object(backup_restore, "_acceptance_probe"),
            ):
                with self.assertRaisesRegex(RuntimeError, "ownership"):
                    backup_restore.restore(
                        project="arvyx",
                        archive=archive,
                        checksum=checksum,
                        confirm_destroy_volume=True,
                        env_file=env_file,
                    )
            self.assertEqual(removed.count(candidate), 1)
            self.assertEqual(
                env_file.read_text(encoding="utf-8"),
                f"ARVYX_DATA_VOLUME={previous}\n",
            )

    def test_reseed_remove_failure_revokes_cleanup_ownership(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = self._data(root)
            archive = root / "arvyx-backup-test.tar.gz"
            checksum = root / f"{archive.name}.sha256"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(data, arcname="data")
            backup_restore._write_checksum(archive, checksum)
            previous = "arvyx_prod-0001_arvyx-data"
            candidate = f"{previous}-restore-abcdef123456"
            env_file = root / ".env"
            env_file.write_text(f"ARVYX_DATA_VOLUME={previous}\n", encoding="utf-8")
            removed: list[str] = []

            def fake_run(command, *, env, check=True):
                owned_inspection = self._owned_candidate_inspection(command)
                if owned_inspection is not None:
                    return owned_inspection
                if command[:3] == ["docker", "volume", "rm"]:
                    removed.append(command[-1])
                    if len(removed) == 1:
                        raise RuntimeError("reseed volume removal failed")
                if "ps" in command and "-aq" in command:
                    project = command[command.index("-p") + 1]
                    return mock.Mock(stdout="" if project == "arvyx" else "staging-container\n")
                return mock.Mock(stdout="", returncode=0)

            environment = {
                "ARVYX_DATA_VOLUME": previous,
                "ARVYX_CONTROL_SECRET_FILE": "secrets/control-secret",
                "COMPOSE_PROJECT_NAME": "arvyx",
                "ARVYX_DEPLOYMENT_ID": "prod-0001",
            }
            with (
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(
                    backup_restore.secrets, "token_hex", return_value="abcdef123456"
                ),
                mock.patch.object(backup_restore, "_run", side_effect=fake_run),
                mock.patch.object(
                    backup_restore, "_create_candidate_volume", return_value=None
                ),
                mock.patch.object(backup_restore, "_materialize_candidate_volume"),
                mock.patch.object(
                    backup_restore, "_wait_healthy", return_value="staging-container"
                ),
                mock.patch.object(backup_restore, "_acceptance_probe"),
            ):
                with self.assertRaisesRegex(
                    backup_restore.RestoreCleanupRequired,
                    f"cleanup required.*{candidate}",
                ):
                    backup_restore.restore(
                        project="arvyx",
                        archive=archive,
                        checksum=checksum,
                        confirm_destroy_volume=True,
                        env_file=env_file,
                    )
            self.assertEqual(removed.count(candidate), 1)

    def test_failed_reseed_staging_teardown_blocks_candidate_deletion(self) -> None:
        for failure_mode in ("nonzero", "exception"):
            with self.subTest(failure_mode=failure_mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                data = self._data(root)
                archive = root / "arvyx-backup-test.tar.gz"
                checksum = root / f"{archive.name}.sha256"
                with tarfile.open(archive, "w:gz") as bundle:
                    bundle.add(data, arcname="data")
                backup_restore._write_checksum(archive, checksum)
                previous = "arvyx_prod-0001_arvyx-data"
                candidate = f"{previous}-restore-abcdef123456"
                env_file = root / ".env"
                env_file.write_text(
                    f"ARVYX_DATA_VOLUME={previous}\n", encoding="utf-8"
                )
                removed: list[str] = []

                def fake_run(command, *, env, check=True):
                    owned_inspection = self._owned_candidate_inspection(command)
                    if owned_inspection is not None:
                        return owned_inspection
                    if "down" in command:
                        if failure_mode == "exception":
                            raise RuntimeError("staging teardown transport failed")
                        return mock.Mock(stdout="", returncode=9)
                    if command[:3] == ["docker", "volume", "rm"]:
                        removed.append(command[-1])
                    if "ps" in command and "-aq" in command:
                        project = command[command.index("-p") + 1]
                        return mock.Mock(
                            stdout="" if project == "arvyx" else "staging-container\n"
                        )
                    return mock.Mock(stdout="", returncode=0)

                environment = {
                    "ARVYX_DATA_VOLUME": previous,
                    "ARVYX_CONTROL_SECRET_FILE": "secrets/control-secret",
                    "COMPOSE_PROJECT_NAME": "arvyx",
                    "ARVYX_DEPLOYMENT_ID": "prod-0001",
                }
                with (
                    mock.patch.dict(os.environ, environment, clear=True),
                    mock.patch.object(
                        backup_restore.secrets,
                        "token_hex",
                        return_value="abcdef123456",
                    ),
                    mock.patch.object(backup_restore, "_run", side_effect=fake_run),
                    mock.patch.object(
                        backup_restore, "_create_candidate_volume", return_value=None
                    ),
                    mock.patch.object(backup_restore, "_materialize_candidate_volume"),
                    mock.patch.object(
                        backup_restore,
                        "_wait_healthy",
                        return_value="staging-container",
                    ),
                    mock.patch.object(backup_restore, "_acceptance_probe"),
                ):
                    with self.assertRaisesRegex(
                        backup_restore.RestoreCleanupRequired,
                        f"cleanup required.*{candidate}",
                    ):
                        backup_restore.restore(
                            project="arvyx",
                            archive=archive,
                            checksum=checksum,
                            confirm_destroy_volume=True,
                            env_file=env_file,
                        )
                self.assertEqual(removed.count(candidate), 0)

    def test_candidate_volume_creation_requires_exact_restore_ownership_label(self) -> None:
        foreign = json.dumps(
            [
                {
                    "Labels": {
                        "com.docker.compose.project": "arvyx",
                        "com.docker.compose.volume": "arvyx-data",
                        "com.arvyx.restore.operation": "other-operation",
                    }
                }
            ]
        )
        with mock.patch.object(
            backup_restore,
            "_run",
            side_effect=[mock.Mock(stdout="candidate\n"), mock.Mock(stdout=foreign)],
        ):
            with self.assertRaisesRegex(RuntimeError, "ownership"):
                backup_restore._create_candidate_volume(
                    candidate_volume="arvyx_prod-0001_arvyx-data-restore-candidate",
                    project="arvyx",
                    ownership_token="expected-operation",
                    production_env={},
                )

    def test_main_serializes_structured_reconciliation_details(self) -> None:
        error = backup_restore.VolumePointerReconciliationRequired(
            "volume pointer reconciliation required"
        )
        error.candidate_volume = "arvyx_prod-0001_arvyx-data-restore-candidate"
        error.cleanup_failures = ("candidate service cleanup exited 4",)
        error.restart_failed = True
        with (
            mock.patch.object(
                sys,
                "argv",
                [
                    "backup_restore.py",
                    "--project",
                    "arvyx",
                    "restore",
                    "backup.tar.gz",
                    "--confirm-cutover",
                ],
            ),
            mock.patch.object(backup_restore, "restore", side_effect=error),
            mock.patch("builtins.print") as printed,
        ):
            self.assertEqual(backup_restore.main(), 1)
        payload = json.loads(printed.call_args.args[0])
        self.assertEqual(payload["candidate_volume"], error.candidate_volume)
        self.assertEqual(payload["cleanup_failures"], list(error.cleanup_failures))
        self.assertTrue(payload["restart_failed"])
        self.assertNotIn("secret", json.dumps(payload).lower())

    def test_data_volume_identity_is_fail_closed(self) -> None:
        container = json.dumps(
            [{"Mounts": [{"Type": "volume", "Name": "arvyx-data", "Destination": "/data"}]}]
        )
        volume = json.dumps(
            [{"Labels": {"com.docker.compose.project": "arvyx", "com.docker.compose.volume": "arvyx-data"}}]
        )
        with mock.patch.object(
            backup_restore,
            "_run",
            side_effect=[mock.Mock(stdout=container), mock.Mock(stdout=volume)],
        ):
            backup_restore._assert_data_volume("container", "arvyx-data", "arvyx", {})
        with mock.patch.object(backup_restore, "_run", return_value=mock.Mock(stdout=container)):
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                backup_restore._assert_data_volume("container", "wrong-volume", "arvyx", {})
        bad_labels = json.dumps(
            [{"Labels": {"com.docker.compose.project": "other", "com.docker.compose.volume": "arvyx-data"}}]
        )
        with mock.patch.object(
            backup_restore,
            "_run",
            side_effect=[mock.Mock(stdout=container), mock.Mock(stdout=bad_labels)],
        ):
            with self.assertRaisesRegex(RuntimeError, "project label"):
                backup_restore._assert_data_volume("container", "arvyx-data", "arvyx", {})

    def test_volume_name_must_be_explicit_and_project_scoped(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "DEPLOYMENT_ID"):
            backup_restore._expected_data_volume({}, "arvyx")
        with self.assertRaisesRegex(RuntimeError, "scoped"):
            backup_restore._expected_data_volume(
                {"ARVYX_DEPLOYMENT_ID": "prod-0001", "ARVYX_DATA_VOLUME": "other_data"},
                "arvyx",
            )
        self.assertEqual(
            backup_restore._expected_data_volume(
                {
                    "ARVYX_DEPLOYMENT_ID": "prod-0001",
                    "ARVYX_DATA_VOLUME": "arvyx_prod-0001_arvyx-data",
                },
                "arvyx",
            ),
            "arvyx_prod-0001_arvyx-data",
        )

    def test_restore_input_failures_remove_private_stage_before_docker(self) -> None:
        """NOT_EXECUTED: source shape, limits, copy and auth fail closed."""
        for failure in ("archive-link", "checksum-link", "binding-link", "hardlink",
                        "fifo", "archive-limit", "sidecar-limit", "copy-error", "mac", "checksum"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                archive = root / "signed.tar.gz"
                archive.write_bytes(b"synthetic backup")
                checksum = root / "custom-checksum"
                backup_restore._write_checksum(archive, checksum)
                key = root / "key"
                key.write_bytes(b"k" * 32)
                os.chmod(key, 0o600)
                binding = root / f"{archive.name}.binding.json"
                backup_restore._write_restore_binding(
                    archive=archive, manifest=binding, authority_id="authority-primary",
                    deployment_id="primary-0001", key_file=key,
                )
                if failure.endswith("-link"):
                    source = {"archive-link": archive, "checksum-link": checksum,
                              "binding-link": binding}[failure]
                    target = root / "link-target"
                    source.rename(target)
                    source.symlink_to(target)
                elif failure == "hardlink":
                    os.link(archive, root / "alias")
                elif failure == "fifo":
                    archive.unlink()
                    os.mkfifo(archive)
                elif failure == "mac":
                    document = json.loads(binding.read_text())
                    document["mac"] = "0" * 64
                    binding.write_text(json.dumps(document))
                elif failure == "checksum":
                    checksum.write_text(f"{'0' * 64}  {archive.name}\n")
                stages = []
                original_copy = backup_restore._copy_restore_input

                def copy_input(source, destination, *, limit):
                    stages.append(destination.parent)
                    if failure == "copy-error":
                        destination.write_bytes(b"partial")
                        raise OSError("injected copy error")
                    original_copy(source, destination, limit=limit)

                with (
                    mock.patch.object(backup_restore, "ROOT", root),
                    mock.patch.object(backup_restore, "_copy_restore_input", side_effect=copy_input),
                    mock.patch.object(backup_restore, "RESTORE_ARCHIVE_MAX_BYTES",
                                      1 if failure == "archive-limit" else 1024),
                    mock.patch.object(backup_restore, "RESTORE_SIDECAR_MAX_BYTES",
                                      1 if failure == "sidecar-limit" else 65536),
                    mock.patch.dict(os.environ, {
                        "ARVYX_BACKUP_AUTHORITY_ID": "authority-primary",
                        "ARVYX_BACKUP_BINDING_KEY_FILE": str(key),
                    }, clear=True),
                    mock.patch.object(backup_restore, "_run") as run,
                ):
                    with self.assertRaises((OSError, RuntimeError)):
                        backup_restore.restore(project="arvyx", archive=archive, checksum=checksum,
                                               confirm_destroy_volume=True, enforce_binding=True)
                    run.assert_not_called()
                self.assertTrue(stages)
                self.assertTrue(all(not stage.exists() for stage in stages))

    def test_restore_reseeds_pristine_candidate_after_acceptance_probe(self) -> None:
        """Mutating acceptance must not ride into the promoted volume."""
        self._restore_reseed_case(swap_external=False)

    def test_restore_uses_signed_private_bytes_despite_external_swaps(self) -> None:
        """NOT_EXECUTED: swap after auth and again after extraction; check both feeds."""
        self._restore_reseed_case(swap_external=True)

    def _restore_reseed_case(self, *, swap_external: bool) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = self._data(root)
            (data / "payload.txt").write_bytes(b"authenticated payload")
            archive = root / "arvyx-backup-test.tar.gz"
            checksum = root / f"{archive.name}.sha256"
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(data, arcname="data")
            backup_restore._write_checksum(archive, checksum)
            env_file = root / ".env"
            env_file.write_text("ARVYX_DATA_VOLUME=arvyx_prod-0001_arvyx-data\n", encoding="utf-8")
            events: list[str] = []

            def fake_run(command, *, env, check=True):
                owned_inspection = self._owned_candidate_inspection(command)
                if owned_inspection is not None:
                    return owned_inspection
                joined = " ".join(command)
                if command[:3] == ["docker", "volume", "create"]:
                    events.append(f"volume-create:{command[-1]}")
                elif command[:3] == ["docker", "volume", "rm"]:
                    events.append(f"volume-rm:{command[-1]}")
                elif "up" in command and "-d" in command:
                    events.append(f"up:{env.get('ARVYX_DATA_VOLUME')}:{command[command.index('-p') + 1]}")
                elif "down" in command:
                    events.append(f"down:{command[command.index('-p') + 1]}")
                elif "create" in command and "arvyx-server" in command:
                    events.append(f"compose-create:{env.get('ARVYX_DATA_VOLUME')}")
                if "ps" in command and "-aq" in command:
                    project = command[command.index("-p") + 1]
                    return mock.Mock(stdout="" if project == "arvyx" else "staging-container\n")
                return mock.Mock(stdout="")

            key = root / "binding-key"
            key.write_bytes(b"k" * 32)
            os.chmod(key, 0o600)
            backup_restore._write_restore_binding(
                archive=archive, manifest=archive.with_name(f"{archive.name}.binding.json"),
                authority_id="authority-cluster-a", deployment_id="prod-0001", key_file=key,
            )
            staged_paths = []
            original_binding = backup_restore._verify_restore_binding
            original_extract = backup_restore._safe_extract

            def replace_external(payload):
                (data / "payload.txt").write_bytes(payload)
                replacement = root / "replacement.tar.gz"
                with tarfile.open(replacement, "w:gz") as bundle:
                    bundle.add(data, arcname="data")
                os.replace(replacement, archive)

            def verify_binding(**kwargs):
                staged = kwargs["archive"]
                self.assertNotEqual(staged, archive)
                self.assertEqual(staged.name, archive.name)
                self.assertEqual(staged.parent.stat().st_mode & 0o777, 0o700)
                self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
                staged_paths.append(staged)
                result = original_binding(**kwargs)
                if swap_external:
                    replace_external(b"substituted after authentication")
                return result

            def extract_private(source, destination):
                self.assertEqual(source, staged_paths[0])
                result = original_extract(source, destination)
                if swap_external:
                    replace_external(b"substituted after validation")
                return result

            def fake_probe(*_args, **_kwargs):
                events.append("acceptance-probe")

            def fake_subprocess_run(command, **kwargs):
                if command[:2] == ["docker", "cp"]:
                    events.append("docker-cp-data")
                    with tarfile.open(fileobj=kwargs["stdin"], mode="r:") as bundle:
                        payload = bundle.extractfile("payload.txt")
                        assert payload is not None
                        with payload:
                            self.assertEqual(payload.read(), b"authenticated payload")
                return mock.Mock(returncode=0, stdout="", stderr="")

            environment = {
                "ARVYX_DATA_VOLUME": "arvyx_prod-0001_arvyx-data",
                "ARVYX_CONTROL_SECRET_FILE": "secrets/control-secret",
                "COMPOSE_PROJECT_NAME": "arvyx",
                "ARVYX_DEPLOYMENT_ID": "prod-0001",
            }
            environment.update({
                "ARVYX_BACKUP_AUTHORITY_ID": "authority-cluster-a",
                "ARVYX_BACKUP_BINDING_KEY_FILE": str(key),
            })
            candidate = "arvyx_prod-0001_arvyx-data-restore-abcdef123456"
            with (
                mock.patch.object(backup_restore, "_verify_restore_binding", side_effect=verify_binding),
                mock.patch.object(backup_restore, "_safe_extract", side_effect=extract_private),
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch.object(backup_restore.secrets, "token_hex", return_value="abcdef123456"),
                mock.patch.object(backup_restore, "_run", side_effect=fake_run),
                mock.patch.object(backup_restore, "_assert_data_volume"),
                mock.patch.object(backup_restore, "_stage_current_control_secret"),
                mock.patch.object(backup_restore, "_acceptance_probe", side_effect=fake_probe),
                mock.patch.object(
                    backup_restore,
                    "_wait_healthy",
                    side_effect=["staging-container", "pristine-container", "candidate-container"],
                ),
                mock.patch.object(backup_restore.subprocess, "run", side_effect=fake_subprocess_run),
            ):
                result = backup_restore.restore(
                    project="arvyx",
                    archive=archive,
                    checksum=checksum,
                    confirm_destroy_volume=True,
                    env_file=env_file,
                    enforce_binding=True,
                )

            self.assertTrue(result["ok"])
            self.assertEqual(events.count("docker-cp-data"), 2)
            self.assertFalse(staged_paths[0].parent.exists())
            self.assertIn("acceptance-probe", events)
            probe_at = events.index("acceptance-probe")
            post_probe = events[probe_at + 1 :]
            self.assertIn(f"volume-rm:{candidate}", post_probe)
            self.assertIn(f"volume-create:{candidate}", post_probe)
            self.assertGreaterEqual(post_probe.count("docker-cp-data"), 1)
            removed_volumes = [
                event.split(":", 1)[1]
                for event in post_probe
                if event.startswith("volume-rm:")
            ]
            self.assertEqual(removed_volumes, [candidate])
            # Production cutover must happen only after the pristine reseed path.
            cutover_ups = [
                event for event in post_probe
                if event.startswith(f"up:{candidate}:arvyx")
            ]
            self.assertTrue(cutover_ups)
            last_seed_cp = max(i for i, event in enumerate(post_probe) if event == "docker-cp-data")
            first_cutover = post_probe.index(cutover_ups[0])
            self.assertLess(last_seed_cp, first_cutover)
            self.assertNotIn("acceptance-probe", post_probe)


if __name__ == "__main__":
    unittest.main()
