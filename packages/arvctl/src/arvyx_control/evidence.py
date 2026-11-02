from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import os
from datetime import UTC
from datetime import datetime
import json
from pathlib import Path
import subprocess
import time
from typing import Any

from .attestation import worktree_dirty_paths
from .audit import AuditResult, _doctor_check, _demo_check, _failed_check_blockers, run_audit
from .security import iter_source_files, load_private_denylist
from .benchmark import run_recall_benchmark
from .readiness import readiness
from .release_host import release_host_report


class _AuditOperation:
    """Invocation-local repository audit; vault checks are never shared."""
    def __init__(self, repo):
        self.repo = repo.resolve()
        self.active = True
        self.result = None
        self.binding = self._binding()

    def _binding(self):
        deadline=time.monotonic()+60
        consumed=0
        def active():
            if time.monotonic()>=deadline:raise ValueError('audit binding time budget exhausted')
        digest = hashlib.sha256()
        paths=set()
        def include(path):
            active()
            if len(paths)>=50000 and path not in paths:raise ValueError('audit binding file budget exhausted')
            paths.add(path)
        for path in iter_source_files(self.repo):include(path)
        # Release review receipts/reports live in ignored .arvyx directories.
        # Include ignored policy/docs too; scanner inventory alone is insufficient.
        for relative in ('docs', 'config', 'fixtures', '.arvyx/release-reviews', '.arvyx/model-reviews'):
            root = self.repo / relative
            for path in root.rglob('*'):
                active()
                # A vault's own .arvyx runtime state below these roots (index cache,
                # locks) is derived, not source or policy; the operation itself writes
                # it when it audits an in-repository vault. The vault sources and the
                # repository-root review receipts above remain bound.
                if relative in ('docs', 'config', 'fixtures') and '.arvyx' in path.relative_to(root).parts:
                    continue
                if path.is_file():include(path)
        for path in sorted(paths):
            active()
            if path.is_symlink() or any((self.repo/p).is_symlink() for p in path.relative_to(self.repo).parents if p!=Path('.')):
                raise ValueError('audit binding symlink input refused')
            if path.is_file():
                size=path.stat().st_size;consumed+=size
                if size>8*1024*1024 or consumed>256*1024*1024:raise ValueError('audit binding byte budget exhausted')
                digest.update(json.dumps([str(path.relative_to(self.repo)),path.stat().st_mode]).encode())
                digest.update(b'\0')
                digest.update(hashlib.sha256(path.read_bytes()).digest())
        try:
            policy_binding = {"loaded": load_private_denylist(self.repo)}
        except (OSError, UnicodeError, ValueError):
            # An invalid policy must produce blocked audit evidence, not prevent
            # the fail-closed report from being constructed. Never equate this
            # sentinel with a successfully loaded (including empty) policy.
            policy_binding = {"invalid_private_denylist": True}
        digest.update(json.dumps(policy_binding).encode())
        digest.update(json.dumps(sorted(os.environ.items())).encode())
        for args in (("rev-parse", "HEAD^{tree}"), ("status", "--porcelain", "--untracked-files=all")):
            active()
            try:
                result = subprocess.run(["git", *args], cwd=self.repo, capture_output=True, check=False,timeout=max(.001,deadline-time.monotonic()))
            except subprocess.SubprocessError as exc:
                raise ValueError('audit binding git deadline unavailable') from exc
            if result.returncode:
                raise ValueError("cannot bind audit operation to repository tree")
            digest.update(result.stdout)
        return digest.digest()

    def validate(self, repo):
        if not self.active or repo.resolve() != self.repo or self._binding() != self.binding:
            raise ValueError("audit operation source or policy changed; start a fresh operation")

    def audit(self, repo, vault):
        self.validate(repo)
        if self.result is None:
            self.result = deepcopy(run_audit(repo=repo, vault=vault))
            result = deepcopy(self.result)
        else:
            result = deepcopy(self.result)
            checks = [(_doctor_check(vault) if c.id == "vault_doctor" else
                       _demo_check(vault) if c.id == "demo" else c) for c in result.checks]
            # Repository findings are reusable; vault-specific failures are not.
            old_failures = set(_failed_check_blockers(result.checks))
            blockers = [item for item in result.release_blockers if item not in old_failures]
            blockers.extend(_failed_check_blockers(checks))
            result = AuditResult(all(c.ok for c in checks), bool(blockers), checks, blockers)
        self.validate(repo)
        return result


@contextmanager
def _audit_operation(repo):
    operation = _AuditOperation(repo)
    try:
        yield operation
        operation.validate(repo)
    finally:
        operation.active = False
        operation.result = None


@dataclass(frozen=True)
class EvidenceBundle:
    generated_at: str
    repo: str
    vault: str
    git_head: str | None
    worktree: dict[str, Any]
    readiness: dict[str, Any]
    audit: dict[str, Any]
    recall_benchmark: dict[str, Any]
    recall_benchmarks: dict[str, dict[str, Any]]
    release_host: dict[str, Any]
    release_blockers: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "repo": self.repo,
            "vault": self.vault,
            "git_head": self.git_head,
            "worktree": self.worktree,
            "readiness": self.readiness,
            "audit": self.audit,
            "recall_benchmark": self.recall_benchmark,
            "recall_benchmarks": self.recall_benchmarks,
            "release_host": self.release_host,
            "release_blockers": self.release_blockers,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def export_evidence(
    repo: Path,
    vault: Path,
    benchmark_cases: Path,
    output: Path | None = None,
    run_docker: bool = False,
    run_bridge: bool = False,
    mcp_client_evidence: Path | None = None,
    require_provenance: bool = False,
    provenance_dir: Path | None = None,
    *,
    _operation: _AuditOperation | None = None,
) -> EvidenceBundle:
    repo = repo.resolve()
    vault = vault.resolve()
    benchmark_cases = benchmark_cases.resolve()
    readiness_result = readiness(repo=repo)
    audit_result = (_operation.audit(repo, vault) if _operation is not None
                    else run_audit(repo=repo, vault=vault))
    lexical_benchmark = run_recall_benchmark(vault=vault, cases_path=benchmark_cases, retrieval_mode="lexical")
    # Never disclose vault inputs to ambient embedding endpoints during evidence
    # generation. Provenance distinguishes this offline hybrid fallback from
    # a qualification of a configured semantic model.
    hybrid_benchmark = run_recall_benchmark(vault=vault, cases_path=benchmark_cases,
                                          retrieval_mode="hybrid", allow_network_embeddings=False)
    release_host = release_host_report(
        repo=repo,
        run_docker=run_docker,
        run_bridge=run_bridge,
        mcp_client_evidence=mcp_client_evidence,
        require_provenance=require_provenance,
        provenance_dir=provenance_dir,
    )
    benchmark_results = {
        "lexical": lexical_benchmark.to_dict(),
        "hybrid": hybrid_benchmark.to_dict(),
    }
    release_blockers = [*audit_result.release_blockers, *release_host.blockers]
    for mode, benchmark in benchmark_results.items():
        if benchmark.get("ok") is not True:
            release_blockers.append(f"recall benchmark failed: {mode}")
    if readiness_result.score < 90:
        release_blockers.append("readiness score is below private-preview threshold")
    bundle = EvidenceBundle(
        generated_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        repo=_display_path(repo, repo),
        vault=_display_path(vault, repo),
        git_head=_git_head(repo),
        worktree=_worktree_report(repo),
        readiness=readiness_result.to_dict(),
        audit=audit_result.to_dict(),
        recall_benchmark=benchmark_results["lexical"],
        recall_benchmarks=benchmark_results,
        release_host=release_host.to_dict(),
        release_blockers=release_blockers,
    )
    if _operation is not None:
        _operation.validate(repo)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(bundle.to_json() + "\n", encoding="utf-8")
    return bundle


def _worktree_report(repo: Path) -> dict[str, Any]:
    """Worktree cleanliness, reported next to the tree a receipt would bind.

    `clean: null` means git could not answer — the caller must treat that as
    not-clean rather than absent.
    """
    dirty = worktree_dirty_paths(repo)
    if dirty is None:
        return {"clean": None, "dirty_count": None, "dirty_paths": None}
    return {"clean": not dirty, "dirty_count": len(dirty), "dirty_paths": dirty[:20]}


def _display_path(path: Path, repo: Path) -> str:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(repo.resolve())
    except ValueError:
        return resolved.name
    return "." if relative == Path(".") else relative.as_posix()


def _git_head(repo: Path) -> str | None:
    completed = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None
