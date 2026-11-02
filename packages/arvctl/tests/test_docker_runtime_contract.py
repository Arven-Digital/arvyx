from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "docker_runtime_smoke.py"
SPEC = importlib.util.spec_from_file_location("docker_runtime_smoke", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
docker_runtime_smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(docker_runtime_smoke)

DRILL_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "release_restore_drill.py"
DRILL_SPEC = importlib.util.spec_from_file_location("release_restore_drill", DRILL_SCRIPT)
assert DRILL_SPEC is not None and DRILL_SPEC.loader is not None
release_restore_drill = importlib.util.module_from_spec(DRILL_SPEC)
DRILL_SPEC.loader.exec_module(release_restore_drill)


class DockerRuntimeContractTests(unittest.TestCase):
    def test_upgrade_requires_previous_immutable_image(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "previous image"):
            docker_runtime_smoke._validate_release_mode("upgrade", None)

    def test_first_release_rejects_previous_image(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "must not"):
            docker_runtime_smoke._validate_release_mode("first", "previous:image")

    def test_explicit_release_modes_accept_valid_contracts(self) -> None:
        docker_runtime_smoke._validate_release_mode("first", None)
        docker_runtime_smoke._validate_release_mode("upgrade", "previous:image")

    def test_restore_drill_requires_revoked_old_and_accepted_current_bearer(self) -> None:
        validator = getattr(release_restore_drill, "_require_rotated_auth", None)
        self.assertTrue(callable(validator))
        validator(401, 200)
        with self.assertRaisesRegex(RuntimeError, "revoked|current"):
            validator(200, 200)
        with self.assertRaisesRegex(RuntimeError, "revoked|current"):
            validator(401, 401)

    def test_authenticated_mutation_headers_include_idempotency_key(self) -> None:
        headers = docker_runtime_smoke._request_headers("synthetic-secret", mutation=True)
        self.assertEqual(headers["Authorization"].split(" ", 1), ["Bearer", "synthetic-secret"])
        self.assertGreaterEqual(len(headers["Idempotency-Key"]), 16)
        self.assertNotIn("synthetic-secret", headers["Idempotency-Key"])

    def test_restore_probe_uses_the_staged_compose_secret_path(self) -> None:
        root = Path(__file__).resolve().parents[3]
        if not (root / "scripts" / "restore_acceptance_probe.py").is_file():
            self.skipTest("restore acceptance probe is not part of this checkout")
        staged_path = "/data/.arvyx-control-secret"
        compose = (root / "docker-compose.yml").read_text(encoding="utf-8")
        probe = (root / "scripts" / "restore_acceptance_probe.py").read_text(encoding="utf-8")
        stage_helper = (root / "scripts" / "stage_control_secret.py").read_text(encoding="utf-8")

        self.assertIn(staged_path, compose)
        self.assertIn(staged_path, stage_helper)
        self.assertIn(staged_path, probe)
        self.assertNotIn("/run/secrets/arvyx-control-secret", probe)

    def test_secret_stager_creates_compose_owned_data_volume(self) -> None:
        stage = docker_runtime_smoke.stage_control_secret_mod
        expected_inspection = json.dumps(
            [
                {
                    "Labels": {
                        "com.docker.compose.project": "arvyx-prod",
                        "com.docker.compose.volume": "arvyx-data",
                    }
                }
            ]
        )
        responses = [
            Mock(returncode=1, stdout="", stderr="not found"),
            Mock(returncode=0, stdout="volume", stderr=""),
            Mock(returncode=0, stdout=expected_inspection, stderr=""),
            Mock(returncode=0, stdout="", stderr=""),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            secret = Path(temporary) / "secret"
            secret.write_text("x" * 32 + "\n", encoding="ascii")
            with patch.object(stage.subprocess, "run", side_effect=responses) as run:
                stage.stage_control_secret(
                    secret_file=secret,
                    volume="arvyx-prod_deploy-id_arvyx-data",
                    image="arvyx:test",
                    env={
                        "COMPOSE_PROJECT_NAME": "arvyx-prod",
                        "ARVYX_DEPLOYMENT_ID": "deploy-id",
                    },
                )

        create_command = run.call_args_list[1].args[0]
        self.assertIn("com.docker.compose.project=arvyx-prod", create_command)
        self.assertIn("com.docker.compose.volume=arvyx-data", create_command)

    def test_secret_stager_rejects_foreign_existing_volume_before_root_mount(self) -> None:
        stage = docker_runtime_smoke.stage_control_secret_mod
        foreign_inspection = json.dumps(
            [
                {
                    "Labels": {
                        "com.docker.compose.project": "foreign-project",
                        "com.docker.compose.volume": "foreign-data",
                    }
                }
            ]
        )

        def fake_run(command, **kwargs):
            if command[:3] == ["docker", "volume", "inspect"]:
                return Mock(returncode=0, stdout=foreign_inspection, stderr="")
            return Mock(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as temporary:
            secret = Path(temporary) / "secret"
            secret.write_text("x" * 32 + "\n", encoding="ascii")
            with patch.object(stage.subprocess, "run", side_effect=fake_run) as run:
                with self.assertRaisesRegex(RuntimeError, "foreign|label|ownership"):
                    stage.stage_control_secret(
                        secret_file=secret,
                        volume="arvyx-prod_prod-0001_arvyx-data",
                        image="arvyx:test",
                        env={
                            "COMPOSE_PROJECT_NAME": "arvyx-prod",
                            "ARVYX_DEPLOYMENT_ID": "prod-0001",
                        },
                    )

        self.assertFalse(any(call.args[0][:2] == ["docker", "run"] for call in run.call_args_list))


if __name__ == "__main__":
    unittest.main()
