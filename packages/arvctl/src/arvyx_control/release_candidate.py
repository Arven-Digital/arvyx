from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC
from datetime import datetime
import json
from pathlib import Path
from typing import Any

from .attestation import release_grade_principals
from .dogfood import dogfood_self
from .evidence import export_evidence, _audit_operation


@dataclass(frozen=True)
class ReleaseCandidateReport:
    generated_at: str
    private_preview_allowed: bool
    public_release_allowed: bool
    summary: str
    evidence: dict[str, Any]
    self_dogfood: dict[str, Any]
    internal_evidence_blockers: list[str]
    public_release_blockers: list[str]
    blockers: list[str]
    next_actions: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "private_preview_allowed": self.private_preview_allowed,
            "public_release_allowed": self.public_release_allowed,
            "summary": self.summary,
            "evidence": self.evidence,
            "self_dogfood": self.self_dogfood,
            "internal_evidence_blockers": self.internal_evidence_blockers,
            "public_release_blockers": self.public_release_blockers,
            "blockers": self.blockers,
            "next_actions": self.next_actions,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def release_candidate_report(
    repo: Path,
    vault: Path,
    benchmark_cases: Path,
    run_docker: bool = False,
    run_bridge: bool = False,
    mcp_client_evidence: Path | None = None,
    require_provenance: bool = False,
    provenance_dir: Path | None = None,
) -> ReleaseCandidateReport:
    with _audit_operation(repo) as operation:
        evidence = export_evidence(
            repo=repo,
            vault=vault,
            benchmark_cases=benchmark_cases,
            run_docker=run_docker,
            run_bridge=run_bridge,
            mcp_client_evidence=mcp_client_evidence,
            require_provenance=require_provenance,
            provenance_dir=provenance_dir,
            _operation=operation,
        )
        self_dogfood = dogfood_self(
            repo=repo,
            run_docker=run_docker,
            run_bridge=run_bridge,
            mcp_client_evidence=mcp_client_evidence,
            require_provenance=require_provenance,
            provenance_dir=provenance_dir,
            _operation=operation,
        )
        evidence_dict = evidence.to_dict()
        audit_ok = bool(evidence_dict["audit"]["ok"])
        benchmarks = evidence_dict["recall_benchmarks"]
        benchmark_ok = bool(benchmarks) and all(bool(item["ok"]) for item in benchmarks.values())
        readiness_score = int(evidence_dict["readiness"]["score"])
        internal_evidence_blockers = _internal_evidence_blockers(
            audit_ok=audit_ok,
            benchmark_ok=benchmark_ok,
            readiness_score=readiness_score,
            self_dogfood_ok=self_dogfood.ok,
        )
        public_release_blockers = list(evidence.release_blockers)
        if not require_provenance:
            public_release_blockers.append("signed release-grade run-provenance is required for public release")
        if not _private_denylist_loaded(evidence_dict):
            public_release_blockers.append("private context denylist was not loaded")
        non_release_grade = _non_release_grade_signers(
            repo, mcp_client_evidence=mcp_client_evidence, provenance_dir=provenance_dir
        )
        if non_release_grade:
            public_release_blockers.append(
                "public-release evidence is signed by a principal that is not release-grade: "
                + ", ".join(sorted(non_release_grade))
            )
        public_release_blockers.extend(_worktree_blockers(evidence_dict))
        private_preview_allowed = not internal_evidence_blockers
        public_release_allowed = private_preview_allowed and not public_release_blockers
        blockers = [*internal_evidence_blockers, *public_release_blockers]
        next_actions = _next_actions(
            private_preview_allowed,
            public_release_allowed,
            internal_evidence_blockers,
            public_release_blockers,
        )
        return ReleaseCandidateReport(
            generated_at=datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            private_preview_allowed=private_preview_allowed,
            public_release_allowed=public_release_allowed,
            summary=_summary(private_preview_allowed, public_release_allowed),
            evidence=evidence_dict,
            self_dogfood=self_dogfood.to_dict(),
            internal_evidence_blockers=internal_evidence_blockers,
            public_release_blockers=public_release_blockers,
            blockers=blockers,
            next_actions=next_actions,
        )


def _summary(private_preview_allowed: bool, public_release_allowed: bool) -> str:
    if public_release_allowed:
        return "public release allowed"
    if private_preview_allowed:
        return "private preview allowed; public release blocked"
    return "private preview blocked"


def _worktree_blockers(evidence: dict[str, Any]) -> list[str]:
    """Block a public-release verdict produced over a dirty worktree.

    Receipts bind `HEAD^{tree}`, but every scan reads the working tree, so
    uncommitted bytes can satisfy a receipt issued for the committed tree.
    `clean` is ``None`` when git cannot answer, which fails closed.
    """
    worktree = evidence.get("worktree")
    if not isinstance(worktree, dict):
        return ["worktree cleanliness could not be determined"]
    clean = worktree.get("clean")
    if clean is True:
        return []
    if clean is None:
        return ["worktree cleanliness could not be determined (git status unavailable)"]
    return [
        f"worktree is not clean ({worktree.get('dirty_count')} changed path(s)); "
        "receipts bind the committed tree while scans read the working tree"
    ]


def _private_denylist_loaded(evidence: dict[str, Any]) -> bool:
    checks = evidence.get("audit", {}).get("checks", [])
    for check in checks:
        if check.get("id") != "private_context":
            continue
        return "private_denylist_loaded=true" in check.get("evidence", [])
    return False


def _non_release_grade_signers(
    repo: Path, *, mcp_client_evidence: Path | None, provenance_dir: Path | None
) -> set[str]:
    """Principals that signed supplied evidence but are not release-grade.

    Pinned is not the same as release-grade: a signature that verifies may still
    have been produced by an operator's shell rather than by the release pipeline
    on an exact tagged commit. Only principals named in
    ``docs/release-grade-signers.allowed`` can carry a public release, and an
    absent or comment-only list makes every signer non-release-grade so the public
    verdict fails closed instead of falling back to "any pinned signer".

    Evidence that is missing or unreadable is left to the existing blockers; this
    check only refuses evidence that is present but under-qualified.
    """
    grade = release_grade_principals(repo)
    suspects: set[str] = set()
    candidates: list[Path] = []
    if provenance_dir is not None and provenance_dir.is_dir():
        candidates.extend(sorted(provenance_dir.glob("*.json")))
    if mcp_client_evidence is not None and mcp_client_evidence.is_file():
        candidates.append(mcp_client_evidence)
    for path in candidates:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        attestation = payload.get("attestation")
        if not isinstance(attestation, dict):
            continue
        principal = attestation.get("principal")
        if isinstance(principal, str) and principal.strip() and principal not in grade:
            suspects.add(principal)
    return suspects


def _internal_evidence_blockers(
    audit_ok: bool,
    benchmark_ok: bool,
    readiness_score: int,
    self_dogfood_ok: bool,
) -> list[str]:
    blockers: list[str] = []
    if not audit_ok:
        blockers.append("internal audit evidence checks failed")
    if not benchmark_ok:
        blockers.append("recall benchmark failed")
    if readiness_score < 90:
        blockers.append("readiness score is below private-preview threshold")
    if not self_dogfood_ok:
        blockers.append("self-dogfood failed")
    return blockers


def _next_actions(
    private_preview_allowed: bool,
    public_release_allowed: bool,
    internal_evidence_blockers: list[str],
    public_release_blockers: list[str],
) -> list[str]:
    if public_release_allowed:
        # A green candidate is a readiness fact about this tree. The next step is
        # a decision, not an action: tagging and publishing are separate
        # approvals, and docs/public-release.md says this repository is not a
        # publication source at all. Do not emit an instruction that reads as if
        # this command authorized either.
        return [
            "record this verdict with the tree it was measured on",
            "request an explicit release decision before any tag or publication",
        ]
    if private_preview_allowed:
        return ["continue private dogfood", *public_release_blockers]
    return ["fix failed internal evidence checks", *internal_evidence_blockers, *public_release_blockers]
