from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

from .attestation import NS_RUN_PROVENANCE, allowed_signers_path, git_tree_sha, release_grade_principals, verify_payload, worktree_dirty_paths
from .mcp_client_evidence import validate_release_mcp_client_evidence


# Without `--require-provenance` the docker and bridge smokes run in place on
# whatever machine invokes the command and are marked complete on exit 0. The
# status is honest; the evidence line says out loud that nothing signed it, so a
# reader cannot mistake an in-place run for host attestation.
UNATTESTED_RUN_NOTE = "unattested: ran in place on this host; no signed run-provenance"


@dataclass(frozen=True)
class ReleaseHostCheck:
    id: str
    label: str
    status: str
    evidence: list[str]
    next_step: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "status": self.status,
            "evidence": self.evidence,
            "next_step": self.next_step,
        }


@dataclass(frozen=True)
class ReleaseHostReport:
    ok: bool
    public_release_ready: bool
    checks: list[ReleaseHostCheck]
    blockers: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "public_release_ready": self.public_release_ready,
            "checks": [check.to_dict() for check in self.checks],
            "blockers": self.blockers,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def release_host_report(
    repo: Path,
    *,
    run_docker: bool = False,
    run_bridge: bool = False,
    mcp_client_evidence: Path | None = None,
    require_provenance: bool = False,
    provenance_dir: Path | None = None,
) -> ReleaseHostReport:
    """Collect release-host checks.

    With `require_provenance`, the docker and bridge smokes are verified from a
    CI-signed run-provenance (namespace ``arvyx-run-provenance``) bound to the
    release tree. This verifies the configured runner identity, result, and tree;
    it is artifact integrity for the run result and tree, not the governance layer.
    """
    repo = repo.resolve()
    if require_provenance:
        checks = [
            _provenance_check(repo, "docker_runtime", "Docker runtime smoke on release host", provenance_dir),
            _mcp_client_check(repo=repo, evidence_path=mcp_client_evidence),
            _provenance_check(repo, "safe_mcp_bridge_e2e", "safe-mcp-bridge end-to-end smoke", provenance_dir),
        ]
    else:
        checks = [
            _docker_runtime_check(repo=repo, run_docker=run_docker),
            _mcp_client_check(repo=repo, evidence_path=mcp_client_evidence),
            _bridge_e2e_check(repo=repo, run_bridge=run_bridge),
        ]
    blockers = [f"{check.id}: {check.next_step}" for check in checks if check.status != "complete"]
    # Host diagnostics remain independently useful on a dirty checkout, but
    # HEAD-bound provenance cannot qualify changed/untracked candidate bytes.
    try:
        dirty = worktree_dirty_paths(repo)
    except (OSError, UnicodeError):
        dirty = None
    if dirty is None:
        blockers.append("release worktree cleanliness is unknown")
    elif dirty:
        blockers.append("release worktree has uncommitted or untracked changes")
    if not require_provenance:
        blockers.append("signed release-grade run-provenance is required for public release")
    return ReleaseHostReport(
        ok=all(check.status == "complete" for check in checks),
        public_release_ready=not blockers,
        checks=checks,
        blockers=blockers,
    )


def _provenance_check(repo: Path, check_id: str, label: str, provenance_dir: Path | None) -> ReleaseHostCheck:
    def blocked(evidence: list[str], next_step: str) -> ReleaseHostCheck:
        return ReleaseHostCheck(id=check_id, label=label, status="blocked", evidence=evidence, next_step=next_step)

    sign_hint = "run the check in CI and sign run-provenance with the pinned CI key"
    if provenance_dir is None:
        return blocked(["no provenance directory provided"], sign_hint)
    path = provenance_dir / f"{check_id}.provenance.json"
    if not path.is_file():
        return blocked([f"missing {path.name}"], sign_hint)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return blocked([f"{path.name} is not valid JSON"], sign_hint)
    if not isinstance(payload, dict):
        return blocked([f"{path.name} must be a JSON object"], sign_hint)
    ok, error = verify_payload(payload, namespace=NS_RUN_PROVENANCE, allowed_signers=allowed_signers_path(repo))
    if not ok:
        return blocked([f"provenance signature: {error}"], sign_hint)
    attestation = payload.get("attestation")
    if not isinstance(attestation, dict) or attestation.get("principal") not in release_grade_principals(repo):
        return blocked(["provenance signer is not release-grade"], sign_hint)
    if payload.get("check_id") != check_id:
        return blocked([f"provenance check_id != {check_id}"], sign_hint)
    tree = git_tree_sha(repo)
    if not tree or payload.get("git_tree") != tree:
        return blocked(["provenance git_tree does not match the release tree"], sign_hint)
    if payload.get("result") != "pass":
        return blocked([f"provenance result is {payload.get('result')!r}, not 'pass'"], "fix the CI run and re-sign provenance")
    return ReleaseHostCheck(
        id=check_id,
        label=label,
        status="complete",
        evidence=[path.name, f"signer={payload.get('attestation', {}).get('principal')}", f"workflow={payload.get('workflow')}"],
        next_step="preserve this CI provenance with the release evidence bundle",
    )


def _docker_runtime_check(repo: Path, run_docker: bool) -> ReleaseHostCheck:
    if not run_docker:
        return ReleaseHostCheck(
            id="docker_runtime",
            label="Docker runtime smoke on release host",
            status="blocked",
            evidence=["not requested"],
            next_step="run arvyx release-host --run-docker on the release host",
        )
    if shutil.which("docker") is None:
        return ReleaseHostCheck(
            id="docker_runtime",
            label="Docker runtime smoke on release host",
            status="blocked",
            evidence=["docker binary missing"],
            next_step="install Docker or record release-host Docker capability as blocked",
        )
    completed = subprocess.run(
        [sys.executable, "scripts/docker_runtime_smoke.py", "--json"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    evidence = [_trim_output(completed.stdout), _trim_output(completed.stderr)]
    evidence = [item for item in evidence if item]
    if completed.returncode == 0:
        return ReleaseHostCheck(
            id="docker_runtime",
            label="Docker runtime smoke on release host",
            status="complete",
            evidence=[*(evidence or ["scripts/docker_runtime_smoke.py passed"]), UNATTESTED_RUN_NOTE],
            next_step="preserve this report with the release evidence bundle",
        )
    return ReleaseHostCheck(
        id="docker_runtime",
        label="Docker runtime smoke on release host",
        status="blocked",
        evidence=evidence or [f"docker runtime smoke exited {completed.returncode}"],
        next_step="fix Docker runtime smoke failure or record the host capability blocker",
    )


def _mcp_client_check(repo: Path, evidence_path: Path | None) -> ReleaseHostCheck:
    fixtures = [
        repo / "examples/mcp-clients/codex.toml",
        repo / "examples/mcp-clients/claude-desktop.json",
        repo / "scripts/mcp_client_examples_check.py",
    ]
    missing = [path.relative_to(repo).as_posix() for path in fixtures if not path.exists()]
    if missing:
        return ReleaseHostCheck(
            id="mcp_client_real",
            label="Real stdio MCP client check",
            status="missing",
            evidence=missing,
            next_step="restore MCP client examples and checker",
        )
    if evidence_path is None:
        return ReleaseHostCheck(
            id="mcp_client_real",
            label="Real stdio MCP client check",
            status="blocked",
            evidence=[path.relative_to(repo).as_posix() for path in fixtures],
            next_step="run at least one real stdio MCP client and pass --mcp-client-evidence",
        )
    evidence_path = evidence_path.resolve()
    if not evidence_path.exists():
        return ReleaseHostCheck(
            id="mcp_client_real",
            label="Real stdio MCP client check",
            status="blocked",
            evidence=[evidence_path.name],
            next_step="write the real MCP client evidence file before release review",
        )
    validation = validate_release_mcp_client_evidence(evidence_path, repo=repo)
    if not validation["ok"]:
        return ReleaseHostCheck(
            id="mcp_client_real",
            label="Real stdio MCP client check",
            status="blocked",
            evidence=[*validation["errors"]],
            next_step="fix the MCP client evidence JSON before release review",
        )
    return ReleaseHostCheck(
        id="mcp_client_real",
        label="Real stdio MCP client check",
        status="complete",
        evidence=[
            _display_path(evidence_path, repo),
            f"client={validation.get('client')}",
            f"signer={validation.get('attestation_principal')}",
            f"git_tree={validation.get('git_tree')}",
        ],
        next_step="preserve this evidence with the release bundle",
    )


def _bridge_e2e_check(repo: Path, run_bridge: bool) -> ReleaseHostCheck:
    script = repo / "scripts/bridge_dogfood_smoke.py"
    if not script.exists():
        return ReleaseHostCheck(
            id="safe_mcp_bridge_e2e",
            label="safe-mcp-bridge end-to-end smoke",
            status="missing",
            evidence=[script.name],
            next_step="restore scripts/bridge_dogfood_smoke.py",
        )
    if not run_bridge:
        return ReleaseHostCheck(
            id="safe_mcp_bridge_e2e",
            label="safe-mcp-bridge end-to-end smoke",
            status="blocked",
            evidence=["not requested"],
            next_step="run arvyx release-host --run-bridge to execute the live bridge smoke",
        )
    completed = subprocess.run(
        [sys.executable, str(script)],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    evidence = [item for item in (_trim_output(completed.stdout), _trim_output(completed.stderr)) if item]
    if completed.returncode == 0:
        return ReleaseHostCheck(
            id="safe_mcp_bridge_e2e",
            label="safe-mcp-bridge end-to-end smoke",
            status="complete",
            evidence=[*(evidence or ["scripts/bridge_dogfood_smoke.py passed"]), UNATTESTED_RUN_NOTE],
            next_step="preserve this report with the release evidence bundle",
        )
    return ReleaseHostCheck(
        id="safe_mcp_bridge_e2e",
        label="safe-mcp-bridge end-to-end smoke",
        status="blocked",
        evidence=evidence or [f"bridge smoke exited {completed.returncode}"],
        next_step="fix the live bridge smoke failure",
    )


def _display_path(path: Path, repo: Path) -> str:
    try:
        return path.relative_to(repo).as_posix()
    except ValueError:
        return path.name


def _git_head(repo: Path) -> str | None:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def _trim_output(text: str) -> str:
    return text.strip().replace("\n", " ")[:500]
