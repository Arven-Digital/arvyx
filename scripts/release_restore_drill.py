from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import tempfile
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
STAGE_SPEC = importlib.util.spec_from_file_location(
    "stage_control_secret", ROOT / "scripts" / "stage_control_secret.py"
)
assert STAGE_SPEC is not None and STAGE_SPEC.loader is not None
stage_control_secret_mod = importlib.util.module_from_spec(STAGE_SPEC)
STAGE_SPEC.loader.exec_module(stage_control_secret_mod)
BACKUP_SPEC = importlib.util.spec_from_file_location("backup_restore", ROOT / "scripts" / "backup_restore.py")
assert BACKUP_SPEC is not None and BACKUP_SPEC.loader is not None
backup_restore = importlib.util.module_from_spec(BACKUP_SPEC)
BACKUP_SPEC.loader.exec_module(backup_restore)


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _request(
    base_url: str,
    path: str,
    *,
    credential: str,
    body: dict[str, object] | None = None,
    key: str | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {
        "Authorization": " ".join(("Bearer", credential)),
        "Content-Type": "application/json",
    }
    if key is not None:
        headers["Idempotency-Key"] = key
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = Request(
        base_url + path,
        headers=headers,
        data=data,
        method="POST" if data is not None else "GET",
    )
    try:
        with urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _task_titles(base_url: str, credential: str) -> set[str]:
    status, payload = _request(base_url, "/tasks", credential=credential)
    if status != 200:
        raise RuntimeError("task readback failed")
    body = payload.get("body", payload)
    tasks = body.get("tasks", []) if isinstance(body, dict) else []
    return {str(task.get("title")) for task in tasks if isinstance(task, dict)}


def _require_rotated_auth(revoked_status: int, current_status: int) -> None:
    if revoked_status != 401:
        raise RuntimeError("revoked bearer was accepted")
    if current_status != 200:
        raise RuntimeError("current bearer was rejected")


def run(image: str) -> dict[str, object]:
    suffix = secrets.token_hex(6)
    project = f"arvyx-release-drill-{suffix}"
    deployment_id = f"drill-{suffix}"
    original_volume = f"{project}_{deployment_id}_arvyx-data"
    port = _free_port()
    compose = ["docker", "compose", "-p", project]
    original_environment = os.environ.copy()
    active_volume: str | None = None

    with tempfile.TemporaryDirectory(prefix="arvyx-release-restore-") as temporary:
        root = Path(temporary)
        secret_file = root / "control-secret"
        credential = secrets.token_urlsafe(32)
        revoked_credential = credential
        current_credential = credential
        secret_file.write_bytes(credential.encode("ascii") + b"\n")
        os.chmod(secret_file, stat.S_IRUSR | stat.S_IWUSR)
        env_file = root / ".env"
        env_file.write_text(
            "\n".join(
                (
                    f"COMPOSE_PROJECT_NAME={project}",
                    f"ARVYX_DEPLOYMENT_ID={deployment_id}",
                    f"ARVYX_DATA_VOLUME={original_volume}",
                    f"ARVYX_CONTROL_SECRET_FILE={secret_file}",
                    f"ARVYX_PORT={port}",
                    f"ARVYX_IMAGE={image}",
                    "ARVYX_MEMORY_LIMIT=512m",
                    "ARVYX_CPU_LIMIT=1.0",
                    "",
                )
            ),
            encoding="utf-8",
        )
        environment = original_environment.copy()
        environment.update(
            {
                "COMPOSE_PROJECT_NAME": project,
                "ARVYX_DEPLOYMENT_ID": deployment_id,
                "ARVYX_DATA_VOLUME": original_volume,
                "ARVYX_CONTROL_SECRET_FILE": str(secret_file),
                "ARVYX_PORT": str(port),
                "ARVYX_IMAGE": image,
                "ARVYX_MEMORY_LIMIT": "512m",
                "ARVYX_CPU_LIMIT": "1.0",
            }
        )
        os.environ.clear()
        os.environ.update(environment)
        base_url = f"http://127.0.0.1:{port}"
        try:
            backup_restore._run(["docker", "image", "inspect", image], env=environment)
            stage_control_secret_mod.stage_control_secret(
                secret_file=secret_file,
                volume=original_volume,
                image=image,
                env=environment,
            )
            backup_restore._run(
                [*compose, "run", "--rm", "--no-deps", "arvyx-server", "arvyx", "init", "/data/vault"],
                env=environment,
            )
            stage_control_secret_mod.stage_control_secret(
                secret_file=secret_file,
                volume=original_volume,
                image=image,
                env=environment,
            )
            backup_restore._run([*compose, "up", "-d", "--no-build", "arvyx-server"], env=environment)
            backup_restore._wait_healthy(compose, environment, phase="initial drill server")
            status, _ = _request(
                base_url,
                "/tasks",
                credential=credential,
                key=f"release-drill-a-{suffix}",
                body={"title": "restore state A", "owner": "release-drill"},
            )
            if status != 201:
                raise RuntimeError("state A mutation failed")

            backup_dir = root / "backups"
            backup_result = backup_restore.backup(
                project=project,
                backup_dir=backup_dir,
                off_host_dir=None,
                local_only=True,
                retention=2,
            )

            # Rotate after backup. Restore must never revive the archived bearer.
            current_credential = secrets.token_urlsafe(32)
            secret_file.write_bytes(current_credential.encode("ascii") + b"\n")
            os.chmod(secret_file, stat.S_IRUSR | stat.S_IWUSR)
            stage_control_secret_mod.stage_control_secret(
                secret_file=secret_file,
                volume=original_volume,
                image=image,
                env=environment,
            )
            backup_restore._run([*compose, "restart", "arvyx-server"], env=environment)
            backup_restore._wait_healthy(compose, environment, phase="rotated credential server")
            revoked_status, _ = _request(base_url, "/summary", credential=revoked_credential)
            current_status, _ = _request(base_url, "/summary", credential=current_credential)
            _require_rotated_auth(revoked_status, current_status)
            credential = current_credential

            status, _ = _request(
                base_url,
                "/tasks",
                credential=credential,
                key=f"release-drill-b-{suffix}",
                body={"title": "restore state B", "owner": "release-drill"},
            )
            if status != 201:
                raise RuntimeError("state B mutation failed")

            restore_result = backup_restore.restore(
                project=project,
                archive=Path(str(backup_result["archive"])),
                checksum=Path(str(backup_result["checksum"])),
                confirm_destroy_volume=True,
                env_file=env_file,
            )
            active_volume = str(restore_result["active_volume"])
            active_environment = dict(environment)
            active_environment["ARVYX_DATA_VOLUME"] = active_volume
            revoked_status, _ = _request(base_url, "/summary", credential=revoked_credential)
            current_status, _ = _request(base_url, "/summary", credential=current_credential)
            _require_rotated_auth(revoked_status, current_status)
            titles = _task_titles(base_url, current_credential)
            if "restore acceptance probe" in titles:
                raise RuntimeError("restore validation polluted the promoted candidate volume")
            if "restore state A" not in titles or "restore state B" in titles:
                raise RuntimeError("restored candidate did not return exactly to state A")

            backup_restore._run([*compose, "down", "--remove-orphans"], env=active_environment)
            stage_control_secret_mod.stage_control_secret(
                secret_file=secret_file,
                volume=str(environment["ARVYX_DATA_VOLUME"]),
                image=image,
                env=environment,
            )
            backup_restore._run([*compose, "up", "-d", "--no-build", "arvyx-server"], env=environment)
            backup_restore._wait_healthy(compose, environment, phase="retained rollback server")
            revoked_status, _ = _request(base_url, "/summary", credential=revoked_credential)
            current_status, _ = _request(base_url, "/summary", credential=current_credential)
            _require_rotated_auth(revoked_status, current_status)
            rollback_titles = _task_titles(base_url, current_credential)
            if not {"restore state A", "restore state B"}.issubset(rollback_titles):
                raise RuntimeError("retained rollback volume did not preserve pre-cutover state")
            return {
                "ok": True,
                "staged_restore": True,
                "state_a_restored": True,
                "state_b_excluded": True,
                "rollback_volume_retained": True,
                "rollback_state_verified": True,
                "revoked_credential_rejected": True,
                "current_credential_preserved": True,
            }
        except Exception as exc:
            ps = backup_restore._run(
                [*compose, "ps", "-a", "--format", "json"], env=environment, check=False
            )
            logs = backup_restore._run(
                [*compose, "logs", "--no-color", "--tail", "80", "arvyx-server"],
                env=environment,
                check=False,
            )
            detail = " ".join((ps.stdout, ps.stderr, logs.stdout, logs.stderr))
            for sensitive in {credential, revoked_credential, current_credential}:
                detail = detail.replace(sensitive, "[REDACTED]")
            raise RuntimeError(f"{exc}; diagnostics={detail[:2000]}") from exc
        finally:
            candidate_environment = dict(environment)
            if active_volume is not None:
                candidate_environment["ARVYX_DATA_VOLUME"] = active_volume
                backup_restore._run([*compose, "down", "--remove-orphans"], env=candidate_environment, check=False)
            backup_restore._run([*compose, "down", "--remove-orphans"], env=environment, check=False)
            for volume in (active_volume, original_volume):
                if volume:
                    backup_restore._run(["docker", "volume", "rm", volume], env=environment, check=False)
            os.environ.clear()
            os.environ.update(original_environment)


def main() -> int:
    parser = argparse.ArgumentParser(description="Disposable real-Docker backup, staged restore, cutover, and rollback drill.")
    parser.add_argument("--image", required=True)
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()
    try:
        result = run(args.image)
    except Exception as exc:
        payload = {"ok": False, "error": type(exc).__name__, "message": str(exc)}
        print(json.dumps(payload, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True) if args.json_output else "restore-drill-ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
