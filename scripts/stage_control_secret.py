#!/usr/bin/env python3
"""Stage a host-private control secret into the data volume for uid 10001.

Host secret stays operator-private (typically 0600). A one-shot root helper
copies it onto the project data volume as /data/.arvyx-control-secret owned by
10001:10001 mode 0400 so the hardened runtime (USER arvyx, cap_drop ALL) can
read it without world-readable bind mounts.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
STAGED_SECRET_PATH = "/data/.arvyx-control-secret"
STAGED_SECRET_BASENAME = ".arvyx-control-secret"


def _inspect_volume_labels(volume: str, env: dict[str, str]) -> dict[str, str] | None:
    inspected = subprocess.run(
        ["docker", "volume", "inspect", volume],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if inspected.returncode != 0:
        return None
    try:
        payload = json.loads(inspected.stdout)
        labels = payload[0].get("Labels") if len(payload) == 1 else None
    except (json.JSONDecodeError, IndexError, AttributeError, TypeError) as exc:
        raise RuntimeError("Docker returned invalid volume inspection data") from exc
    return {str(key): str(value) for key, value in (labels or {}).items()}


def _ensure_compose_owned_volume(
    *, volume: str, project: str, deployment_id: str, env: dict[str, str]
) -> None:
    expected_prefix = f"{project}_{deployment_id}_"
    if not project or not deployment_id or not volume.startswith(expected_prefix):
        raise RuntimeError("data volume is not scoped to COMPOSE_PROJECT_NAME and ARVYX_DEPLOYMENT_ID")

    labels = _inspect_volume_labels(volume, env)
    if labels is None:
        created = subprocess.run(
            [
                "docker",
                "volume",
                "create",
                "--label",
                f"com.docker.compose.project={project}",
                "--label",
                "com.docker.compose.volume=arvyx-data",
                volume,
            ],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if created.returncode != 0:
            raise RuntimeError(f"failed to create data volume: {created.stderr[-1000:]}")
        # Re-inspection closes the missing→foreign-create race before root mount.
        labels = _inspect_volume_labels(volume, env)

    if labels is None or labels.get("com.docker.compose.project") != project:
        raise RuntimeError("data volume has foreign or missing Compose project ownership label")
    if labels.get("com.docker.compose.volume") != "arvyx-data":
        raise RuntimeError("data volume has foreign or missing Compose logical-volume label")


def stage_control_secret(
    *,
    secret_file: Path,
    volume: str,
    image: str,
    env: dict[str, str] | None = None,
) -> None:
    secret_file = secret_file.resolve()
    if not secret_file.is_file() or secret_file.is_symlink():
        raise RuntimeError("host control secret must be a regular non-symlink file")
    if not secret_file.stat().st_size:
        raise RuntimeError("host control secret must be non-empty")
    if not volume.strip():
        raise RuntimeError("data volume name is required")
    if not image.strip():
        raise RuntimeError("image is required")

    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    project = run_env.get("COMPOSE_PROJECT_NAME", "").strip()
    deployment_id = run_env.get("ARVYX_DEPLOYMENT_ID", "").strip()
    if not project:
        raise RuntimeError("COMPOSE_PROJECT_NAME is required to stage the control secret")
    if not deployment_id:
        raise RuntimeError("ARVYX_DEPLOYMENT_ID is required to stage the control secret")

    _ensure_compose_owned_volume(
        volume=volume,
        project=project,
        deployment_id=deployment_id,
        env=run_env,
    )
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "0:0",
            "-v",
            f"{secret_file}:/in/secret:ro",
            "-v",
            f"{volume}:/data",
            image,
            "sh",
            "-ec",
            f"""
set -eu
test -s /in/secret
install -d -o 10001 -g 10001 -m 0750 /data
install -m 0400 -o 10001 -g 10001 /in/secret {STAGED_SECRET_PATH}
# Keep vault/state writable by the runtime user after root staging.
chown -R 10001:10001 /data
# Refuse group/other bits on the staged secret.
mode=$(stat -c '%a' {STAGED_SECRET_PATH} 2>/dev/null || stat -f '%OLp' {STAGED_SECRET_PATH})
case "$mode" in
  400|0400) ;;
  *) echo "staged secret mode must be 0400, got $mode" >&2; exit 65 ;;
esac
""",
        ],
        cwd=ROOT,
        env=run_env,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "failed to stage control secret into data volume\n"
            f"stdout={completed.stdout[-2000:]}\n"
            f"stderr={completed.stderr[-2000:]}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--secret-file",
        type=Path,
        default=Path(os.environ.get("ARVYX_CONTROL_SECRET_FILE", "secrets/arvyx-control-secret")),
    )
    parser.add_argument(
        "--volume",
        default=os.environ.get("ARVYX_DATA_VOLUME", ""),
        help="Docker volume name (ARVYX_DATA_VOLUME)",
    )
    parser.add_argument(
        "--image",
        default=os.environ.get("ARVYX_IMAGE", "arvyx:local"),
    )
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()
    try:
        if os.name != "nt":
            mode = stat.S_IMODE(args.secret_file.stat().st_mode)
            if mode & 0o077:
                raise RuntimeError("host control secret permissions are too broad (want 0600)")
        stage_control_secret(secret_file=args.secret_file, volume=args.volume, image=args.image)
    except (OSError, RuntimeError) as exc:
        if args.json_output:
            import json

            print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.json_output:
        import json

        print(
            json.dumps(
                {
                    "ok": True,
                    "staged_path": STAGED_SECRET_PATH,
                    "volume": args.volume,
                    "image": args.image,
                },
                sort_keys=True,
            )
        )
    else:
        print(f"staged {STAGED_SECRET_PATH} on volume {args.volume}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
