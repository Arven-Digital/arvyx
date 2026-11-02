from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


SERVER_SERVICE = "arvyx-server"
DEMO_SERVICE = "arvyx-demo"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate hardened Docker server and synthetic demo wiring without requiring a Docker daemon."
    )
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()

    result = check(args.repo)
    if args.json_output:
        print(json.dumps(result, sort_keys=True))
    else:
        print(f"ok={str(result['ok']).lower()}")
        for error in result["errors"]:
            print(f"error={error}")
    return 0 if result["ok"] else 1


def check(repo: Path) -> dict[str, object]:
    repo = repo.resolve()
    dockerfile = repo / "Dockerfile"
    compose = repo / "docker-compose.yml"
    dockerignore = repo / ".dockerignore"
    vps_guide = repo / "docs" / "vps-deployment.md"
    errors: list[str] = []

    dockerfile_text = _read(dockerfile, errors)
    compose_text = _read(compose, errors)
    dockerignore_text = _read(dockerignore, errors)
    vps_text = _read(vps_guide, errors)

    _require("FROM python:3.11-slim@sha256:", dockerfile_text, "digest-pinned Dockerfile base image", errors)
    _require("COPY pyproject.toml README.md LICENSE NOTICE ./", dockerfile_text, "license-aware package copy", errors)
    # The image installs the build backend from a hash-pinned lock and then the package
    # without build isolation, so no unpinned bytes enter the image build.
    _require("python -m pip install --no-cache-dir --require-hashes -r requirements/build.lock", dockerfile_text, "hash-pinned build backend", errors)
    _require("python -m pip install --no-cache-dir --no-build-isolation --no-deps .", dockerfile_text, "installed console scripts", errors)
    _require("USER arvyx", dockerfile_text, "unprivileged runtime user", errors)
    _require('VOLUME ["/data"]', dockerfile_text, "persistent data volume", errors)
    _require("HEALTHCHECK", dockerfile_text, "container healthcheck", errors)
    _require("arvyx_control.container_readiness", dockerfile_text, "data-aware readiness check", errors)
    _require('["arvyx", "demo"', dockerfile_text, "safe synthetic default", errors)

    _require(f"{SERVER_SERVICE}:", compose_text, "authenticated server service", errors)
    _require(f"{DEMO_SERVICE}:", compose_text, "synthetic demo service", errors)
    _require("ARVYX_CONTROL_SECRET_FILE", compose_text, "file-backed bearer secret", errors)
    _require("/data/.arvyx-control-secret", compose_text, "staged data-volume secret path", errors)
    _require('--auth-file "$$secret_file"', compose_text, "server auth-file boundary", errors)
    _require("scripts/stage_control_secret.py", vps_text, "secret staging helper", errors)
    if "ARVYX_CONTROL_SECRET:" in compose_text or "--auth-env ARVYX_CONTROL_SECRET" in compose_text:
        errors.append("production bearer secret must not be exposed through container environment")
    _require('"127.0.0.1:${ARVYX_PORT:-8765}:8765"', compose_text, "loopback-only port mapping", errors)
    _require("arvyx-data:/data", compose_text, "persistent server data", errors)
    _require(
        "name: ${ARVYX_DATA_VOLUME:?ARVYX_DATA_VOLUME must be explicitly project-scoped}",
        compose_text,
        "required project-scoped production volume identity",
        errors,
    )
    _require("restart: unless-stopped", compose_text, "restart policy", errors)
    _require("read_only: true", compose_text, "read-only root filesystem", errors)
    _require("no-new-privileges:true", compose_text, "no-new-privileges", errors)
    _require("cap_drop:", compose_text, "capability drop", errors)
    _require("pids_limit: 128", compose_text, "PID limit", errors)
    _require("mem_limit:", compose_text, "memory limit", errors)
    _require("cpus:", compose_text, "CPU quota", errors)
    _require("ARVYX_IMAGE", compose_text, "digest-selectable release image", errors)
    _require('profiles: ["demo"]', compose_text, "opt-in demo profile", errors)

    for ignored in [".git", ".arvyx", ".env", "secrets", "__pycache__", "*.py[cod]", "build", "dist", "*.egg-info"]:
        _require(ignored, dockerignore_text, f"Docker context exclusion for {ignored}", errors)

    _require("docker compose build --pull arvyx-server", vps_text, "VPS build command", errors)
    _require("arvyx init /data/vault --json", vps_text, "VPS initialization", errors)
    _require("127.0.0.1", vps_text, "loopback boundary documentation", errors)
    _require("Backup", vps_text, "backup procedure", errors)
    _require("Restore", vps_text, "restore procedure", errors)
    _require("scripts/create_secret_file.py", vps_text, "exclusive secret provisioning", errors)
    _require("scripts/docker_preflight.py", vps_text, "Docker/VPS preflight", errors)
    _check_backup_restore_examples(vps_text, errors)
    _require("--off-host-dir", vps_text, "off-host backup requirement", errors)
    _require("--confirm-cutover", vps_text, "explicit staged restore cutover confirmation", errors)
    _require("/summary", vps_text, "protected-route authentication checks", errors)
    _require("deliberately-wrong", vps_text, "wrong-bearer rejection check", errors)
    _require("EnvironmentFile=/etc/caddy/arvyx.env", vps_text, "Caddy systemd environment", errors)
    _require("Upgrade and rollback", vps_text, "upgrade and rollback procedure", errors)
    _require("@sha256:", vps_text, "digest-pinned upgrade image", errors)

    return {
        "ok": not errors,
        "dockerfile": dockerfile.name,
        "compose": compose.name,
        "dockerignore": dockerignore.name,
        "vps_guide": "docs/vps-deployment.md",
        "services": [SERVER_SERVICE, DEMO_SERVICE],
        "errors": errors,
    }


def _check_backup_restore_examples(text: str, errors: list[str]) -> None:
    """Each copyable example must export .env and use its configured project."""
    blocks = re.findall(r"```(?:bash|sh)\n(.*?)```", text, re.DOTALL)
    for operation in ("backup", "restore"):
        command = f'python3 scripts/backup_restore.py --project "$COMPOSE_PROJECT_NAME" {operation}'
        if not any(command in block and 'set -a; . ./.env; set +a' in block.split(command, 1)[0]
                   for block in blocks):
            errors.append(f"missing exported configured-project {operation} procedure: {command}")


def _read(path: Path, errors: list[str]) -> str:
    if not path.exists():
        errors.append(f"missing required file: {path}")
        return ""
    return path.read_text(encoding="utf-8")


def _require(needle: str, haystack: str, label: str, errors: list[str]) -> None:
    if needle not in haystack:
        errors.append(f"missing {label}: {needle}")


if __name__ == "__main__":
    raise SystemExit(main())
