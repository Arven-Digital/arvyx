from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MIN_ENGINE = (25, 0, 0)
MIN_COMPOSE = (2, 20, 0)
MIN_FREE_BYTES = 2 * 1024 * 1024 * 1024
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")


def _version(text: str) -> tuple[int, int, int]:
    match = _VERSION_RE.match(text.strip().lstrip("v"))
    if not match:
        raise RuntimeError("unrecognized Docker version")
    return tuple(int(part or 0) for part in match.groups())


def _run(command: list[str]) -> str:
    return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=True).stdout.strip()


def _deployment_contract(env: dict[str, str]) -> tuple[str, str, str]:
    project = env.get("COMPOSE_PROJECT_NAME", "").strip()
    deployment_id = env.get("ARVYX_DEPLOYMENT_ID", "").strip()
    volume = env.get("ARVYX_DATA_VOLUME", "").strip()
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{2,31}", project) is None or project.startswith("change-me"):
        raise RuntimeError("COMPOSE_PROJECT_NAME must be an explicit deployment-specific name")
    if (
        re.fullmatch(r"[a-z0-9][a-z0-9-]{7,31}", deployment_id) is None
        or deployment_id.startswith("change-me")
    ):
        raise RuntimeError("ARVYX_DEPLOYMENT_ID must be a unique 8-32 character identifier")
    if not volume.startswith(f"{project}_{deployment_id}_"):
        raise RuntimeError("ARVYX_DATA_VOLUME must be scoped to project and deployment ID")
    return project, deployment_id, volume


def check(secret_file: Path) -> dict[str, Any]:
    project, deployment_id, volume = _deployment_contract(os.environ)
    engine_raw = _run(["docker", "version", "--format", "{{.Server.Version}}"])
    compose_raw = _run(["docker", "compose", "version", "--short"])
    engine = _version(engine_raw)
    compose = _version(compose_raw)
    if engine < MIN_ENGINE:
        raise RuntimeError("Docker Engine is below the supported minimum 25.0.0")
    if compose < MIN_COMPOSE:
        raise RuntimeError("Docker Compose is below the supported minimum 2.20.0")
    _run(["docker", "compose", "config", "--quiet"])

    if not secret_file.is_file() or secret_file.is_symlink():
        raise RuntimeError("file-backed bearer secret is missing or unsafe")
    raw_secret = secret_file.read_bytes()
    if len(raw_secret) > 4097:
        raise RuntimeError("file-backed bearer secret is too large")
    try:
        secret = raw_secret.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeError("file-backed bearer secret must be ASCII") from exc
    encoded_secret = secret.encode("ascii")
    canonical_encodings = {encoded_secret, encoded_secret + b"\n"}
    if not re.fullmatch(r"[!-~]{32,4096}", secret) or raw_secret not in canonical_encodings:
        raise RuntimeError("file-backed bearer secret must be one 32-4096 character printable ASCII token")
    mode = stat.S_IMODE(secret_file.stat().st_mode)
    if os.name != "nt" and mode & 0o077:
        raise RuntimeError("file-backed bearer secret permissions are too broad")

    free = shutil.disk_usage(ROOT).free
    if free < MIN_FREE_BYTES:
        raise RuntimeError("less than 2 GiB free disk remains")
    return {
        "ok": True,
        "engine": ".".join(map(str, engine)),
        "compose": ".".join(map(str, compose)),
        "compose_config": True,
        "project_scoped": bool(project),
        "deployment_scoped": bool(deployment_id),
        "volume_scoped": bool(volume),
        "secret_file": True,
        "secret_mode_private": os.name == "nt" or not bool(mode & 0o077),
        "free_bytes": free,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate supported Docker/VPS prerequisites without printing secrets.")
    parser.add_argument(
        "--secret-file",
        type=Path,
        default=Path(os.environ.get("ARVYX_CONTROL_SECRET_FILE", "secrets/arvyx-control-secret")),
    )
    args = parser.parse_args()
    try:
        result = check(args.secret_file)
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__, "message": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
