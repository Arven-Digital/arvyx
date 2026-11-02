from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PYTHONPATH = os.pathsep.join(
    [
        str(ROOT / "packages" / "arvctl" / "src"),
        str(ROOT / "packages" / "safe-mcp-bridge" / "src"),
    ]
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the release-candidate operator path end to end.")
    parser.add_argument("--vault", type=Path, default=ROOT / "fixtures" / "synthetic-vault")
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--run-docker", action="store_true")
    parser.add_argument("--run-bridge", action="store_true")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()

    try:
        result = run_check(repo=args.repo, vault=args.vault, run_docker=args.run_docker, run_bridge=args.run_bridge)
    except Exception as exc:  # pragma: no cover - CLI safety net
        result = {"ok": False, "errors": [str(exc)]}

    if args.json_output:
        print(json.dumps(result, sort_keys=True))
    elif result["ok"]:
        print("ok=true")
        for check in result["checks"]:
            print(f"check={check}")
    else:
        for error in result["errors"]:
            print(error, file=sys.stderr)
    return 0 if result["ok"] else 1


def run_check(repo: Path, vault: Path, run_docker: bool = False, run_bridge: bool = False) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        mcp_evidence = tmp_path / "mcp-client-evidence.json"
        evidence_bundle = tmp_path / "evidence.json"

        docker_args = ["--run-docker"] if run_docker else []
        bridge_args = ["--run-bridge"] if run_bridge else []
        mcp_result = _run_json(
            [
                sys.executable,
                "-m",
                "arvyx_control.cli",
                "evidence",
                "mcp-client",
                "--vault",
                str(vault),
                "--output",
                str(mcp_evidence),
                "--json",
            ]
        )
        evidence_result = _run_json(
            [
                sys.executable,
                "-m",
                "arvyx_control.cli",
                "evidence",
                "export",
                "--repo",
                str(repo),
                "--vault",
                str(vault),
                "--output",
                str(evidence_bundle),
                "--mcp-client-evidence",
                str(mcp_evidence),
                *docker_args,
                *bridge_args,
                "--json",
            ]
        )
        dogfood_result = _run_json(
            [
                sys.executable,
                "-m",
                "arvyx_control.cli",
                "dogfood",
                "self",
                "--repo",
                str(repo),
                "--mcp-client-evidence",
                str(mcp_evidence),
                *docker_args,
                *bridge_args,
                "--json",
            ]
        )
        release_host_result = _run_json(
            [
                sys.executable,
                "-m",
                "arvyx_control.cli",
                "release-host",
                "--repo",
                str(repo),
                "--mcp-client-evidence",
                str(mcp_evidence),
                *docker_args,
                *bridge_args,
                "--json",
            ],
            # release-host exits 1 while host checks remain blocked; that is
            # the honest posture for self-attested evidence, not a failure.
            allowed_exit_codes=(0, 1),
        )
        release_result = _run_json(
            [
                sys.executable,
                "-m",
                "arvyx_control.cli",
                "release-candidate",
                "--repo",
                str(repo),
                "--vault",
                str(vault),
                "--mcp-client-evidence",
                str(mcp_evidence),
                *docker_args,
                *bridge_args,
                "--json",
            ]
        )

        errors = _validate(
            mcp_result=mcp_result,
            evidence_result=evidence_result,
            dogfood_result=dogfood_result,
            release_host_result=release_host_result,
            release_result=release_result,
            mcp_evidence=mcp_evidence,
            evidence_bundle=evidence_bundle,
            run_docker=run_docker,
            run_bridge=run_bridge,
        )
        checks = [
            "mcp evidence generated",
            "evidence bundle exported",
            "self dogfood passed",
            "release-host classified self-attested MCP evidence as blocked",
            "release-candidate allows private preview",
            "release blockers are classified",
        ]
        if run_docker:
            checks.append("release-host consumed Docker evidence")
        if run_bridge:
            checks.append("release-host consumed safe-mcp-bridge E2E evidence")
        return {
            "ok": not errors,
            "checks": checks,
            "errors": errors,
            "private_preview_allowed": release_result.get("private_preview_allowed"),
            "public_release_allowed": release_result.get("public_release_allowed"),
            "internal_evidence_blockers": release_result.get("internal_evidence_blockers"),
            "public_release_blockers": release_result.get("public_release_blockers"),
        }


def _run_json(command: list[str], allowed_exit_codes: tuple[int, ...] = (0,)) -> dict[str, Any]:
    env = os.environ.copy()
    env["PYTHONPATH"] = PYTHONPATH
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode not in allowed_exit_codes:
        raise RuntimeError(
            f"command failed: {' '.join(command)}\nstdout={completed.stdout}\nstderr={completed.stderr}"
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"command did not return JSON: {' '.join(command)}\nstdout={completed.stdout}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"command returned non-object JSON: {' '.join(command)}")
    return payload


def _validate(
    mcp_result: dict[str, Any],
    evidence_result: dict[str, Any],
    dogfood_result: dict[str, Any],
    release_host_result: dict[str, Any],
    release_result: dict[str, Any],
    mcp_evidence: Path,
    evidence_bundle: Path,
    run_docker: bool,
    run_bridge: bool,
) -> list[str]:
    errors: list[str] = []
    if not mcp_result.get("ok"):
        errors.append("MCP client evidence generation failed")
    if not mcp_evidence.exists():
        errors.append("MCP client evidence file was not written")
    if not evidence_bundle.exists():
        errors.append("evidence bundle file was not written")
    if "release_host" not in evidence_result:
        errors.append("evidence bundle does not include release-host posture")
    if not dogfood_result.get("ok"):
        errors.append("self dogfood did not pass")
    release_host_checks = _checks_by_id(release_host_result)
    mcp_check = release_host_checks.get("mcp_client_real", {})
    if (mcp_check.get("status") != "blocked"
            or "client is arvyx's own self client; external evidence is required"
            not in mcp_check.get("evidence", [])):
        errors.append("release-host must classify self-generated MCP evidence as self-attested and blocked")
    if run_docker and release_host_checks.get("docker_runtime", {}).get("status") != "complete":
        errors.append("release-host did not accept Docker runtime evidence")
    if run_bridge and release_host_checks.get("safe_mcp_bridge_e2e", {}).get("status") != "complete":
        errors.append("release-host did not accept safe-mcp-bridge E2E evidence")
    if release_result.get("private_preview_allowed") is not True:
        errors.append("release-candidate did not allow private preview")
    if release_result.get("internal_evidence_blockers") != []:
        errors.append("release-candidate has internal evidence blockers")
    public_blockers = release_result.get("public_release_blockers")
    combined_blockers = release_result.get("blockers")
    if not isinstance(public_blockers, list) or not public_blockers:
        errors.append("release-candidate did not preserve public release blockers")
        public_blockers = []
    if combined_blockers != [*release_result.get("internal_evidence_blockers", []), *public_blockers]:
        errors.append("release-candidate combined blockers are not classified consistently")
    if not any("mcp_client_real" in blocker for blocker in public_blockers):
        errors.append("release-candidate must keep self-attested MCP client evidence as a public blocker")
    if run_docker and any("docker_runtime" in blocker for blocker in public_blockers):
        errors.append("release-candidate still reports Docker runtime evidence as blocked")
    if run_bridge and any("safe_mcp_bridge_e2e" in blocker for blocker in public_blockers):
        errors.append("release-candidate still reports safe-mcp-bridge E2E evidence as blocked")
    return errors


def _checks_by_id(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    checks = report.get("checks", [])
    if not isinstance(checks, list):
        return {}
    return {check["id"]: check for check in checks if isinstance(check, dict) and isinstance(check.get("id"), str)}


if __name__ == "__main__":
    raise SystemExit(main())
