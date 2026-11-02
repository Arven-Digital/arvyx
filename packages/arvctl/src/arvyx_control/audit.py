from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from .attestation import (
    AttestationError,
    allowed_signers_path,
    model_review_attestation_path,
    verify_model_review_attestation,
    worktree_dirty_paths,
)
from .bridge import build_bridge_policy
from .doctor import doctor
from .readiness import readiness
from .security import (
    SECRET_RE,
    contains_literal_secret,
    contains_private_name,
    canonical_secret_line_spans,
    iter_source_files,
    SOURCE_SKIP_DIRS,
    is_expected_text,
    is_verified_image,
    is_verified_font,
    load_secret_scan_allowlist,
    multiline_constant_secret_spans,
    private_name_exempt_paths,
    private_name_patterns,
    python_constant_secret_spans,
    read_scannable_text,
    secret_line_fingerprint,
    strip_secret_refs,
)
from .vault import run_demo


SKIP_DIRS = SOURCE_SKIP_DIRS


def reviewed_name_example(path: Path, relative: Path) -> bool:
    """Exempt names only in the exact reviewed example bytes, never secrets."""
    return (
        relative == Path("fixtures/private-denylist.example.txt")
        and hashlib.sha256(path.read_bytes()).hexdigest()
        == "389338c82f4cfc44c8932a3d3ff467a426f4e1d6b26ae589fe105a80c3bf5fd7"
    )


@dataclass(frozen=True)
class AuditCheck:
    id: str
    label: str
    ok: bool
    evidence: list[str]
    findings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "ok": self.ok,
            "evidence": self.evidence,
            "findings": self.findings,
        }


@dataclass(frozen=True)
class AuditResult:
    ok: bool
    public_release_blocked: bool
    checks: list[AuditCheck]
    release_blockers: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "public_release_blocked": self.public_release_blocked,
            "checks": [check.to_dict() for check in self.checks],
            "release_blockers": self.release_blockers,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def run_audit(repo: Path, vault: Path) -> AuditResult:
    repo = repo.resolve()
    vault = vault.resolve()
    checks = [
        _private_context_check(repo),
        _doctor_check(vault),
        _demo_check(vault),
        _readiness_check(repo),
        _bridge_policy_check(),
        _release_docs_check(repo),
    ]
    release_blockers = [*_release_blockers(repo), *_failed_check_blockers(checks)]
    return AuditResult(
        ok=all(check.ok for check in checks),
        public_release_blocked=bool(release_blockers),
        checks=checks,
        release_blockers=release_blockers,
    )


def _failed_check_blockers(checks: list[AuditCheck]) -> list[str]:
    """Internal failures also veto release; doc statuses cannot override them."""
    return [f"audit check failed: {check.id}" for check in checks if not check.ok]


def _private_context_check(repo: Path) -> AuditCheck:
    try:
        hits, exempted, denylist_loaded, fingerprint_count = scan_private_context(repo)
    except (OSError, UnicodeError, ValueError):
        return AuditCheck(
            id="private_context", label="Private context and secret-shaped material scan",
            ok=False, evidence=["private_denylist_loaded=false"],
            findings=["private context scan could not complete"],
        )
    if not denylist_loaded:
        hits.add("private context denylist was not loaded")
    if exempted is None:
        hits.add("release classification manifest is missing or invalid")
    return AuditCheck(
        id="private_context",
        label="Private context and secret-shaped material scan",
        ok=not hits,
        evidence=[
            "repository text scan",
            f"private_denylist_loaded={str(denylist_loaded).lower()}",
            f"private_name_exempt_private_only={exempted or 0}",
            f"release_manifest_loaded={str(exempted is not None).lower()}",
            f"secret_fixture_fingerprints={fingerprint_count}",
        ],
        findings=sorted(hits),
    )


AUDIT_MAX_BYTES=256*1024*1024
AUDIT_MAX_FILES=50000
# Wall-clock bound on one repository scan. It guards against pathological inputs (the
# file and byte budgets above bound the work itself); it is not a performance target.
# Hosted CI runs four audit-based smokes concurrently on a four-core runner, where a
# full private-tree scan with the real denylist can exceed a minute, so the bound is
# generous rather than tight: a scan that stops here still reports "incomplete".
AUDIT_MAX_SECONDS=300


def scan_private_context(repo: Path) -> tuple[set[str], int | None, bool, int]:
    """Shared detector engine; callers must explicitly enforce denylist policy.

    Return findings, exemption count (None for an invalid manifest), whether
    private terms were loaded, and the configured secret fingerprint count.
    No result is cached across calls or operations.
    """
    deadline=time.monotonic()+AUDIT_MAX_SECONDS
    consumed=0
    def active():
        if time.monotonic()>=deadline:raise ValueError('audit time budget exhausted; incomplete scan')
    hits: set[str] = set()
    private_patterns = private_name_patterns(repo, strict=True)
    # Private names are expected in manifest private-only files (never
    # exported, notice-marked, boundary-gated); secret shapes are not, so only
    # the name detector honours this exemption. None means fail closed.
    exempt_paths = private_name_exempt_paths(repo)
    exempted = 0
    secret_allowlist = load_secret_scan_allowlist(repo)
    matched_allowlist: set[str] = set()
    for number,path in enumerate(iter_source_files(repo),1):
        active()
        if number>AUDIT_MAX_FILES:raise ValueError('audit file budget exhausted; incomplete scan')
        if not path.is_file() or _should_skip(repo, path):
            continue
        if path.is_symlink() or any((repo/p).is_symlink() for p in path.relative_to(repo).parents if p!=Path('.')):
            raise ValueError('audit symlink input refused; incomplete scan')
        size=path.stat().st_size
        consumed+=size
        if size>8*1024*1024 or consumed>AUDIT_MAX_BYTES:
            raise ValueError('audit byte budget exhausted; incomplete scan')
        if is_verified_image(path) or is_verified_font(path):
            continue
        try:
            text = read_scannable_text(path)
        except UnicodeDecodeError:
            hits.add(f"{path.relative_to(repo).as_posix()}:decode-error")
            continue
        relative = path.relative_to(repo)
        name_patterns = private_patterns
        if private_patterns and reviewed_name_example(path, relative):
            name_patterns = []
        elif private_patterns and (
            relative != Path("fixtures/private-denylist.example.txt")
            and exempt_paths is not None and relative.as_posix() in exempt_paths
        ):
            name_patterns = []
            exempted += 1
        lines = text.splitlines()
        for start, end in canonical_secret_line_spans(text):
            allowed = False
            if start == end and start <= len(lines):
                fingerprint = secret_line_fingerprint(relative, lines[start - 1])
                allowed = fingerprint in secret_allowlist
                if allowed:
                    matched_allowlist.add(fingerprint)
            if not allowed:
                hits.add(f"{relative.as_posix()}:{start}")
        for line_number, line in enumerate(lines, start=1):
            if line_number%256==0:active()
            scannable = strip_secret_refs(line)
            private_hit = contains_private_name(line, name_patterns)
            secret_hit = contains_literal_secret(scannable)
            if secret_hit:
                fingerprint = secret_line_fingerprint(relative, line)
                if fingerprint in secret_allowlist:
                    matched_allowlist.add(fingerprint)
                    secret_hit = False
            if private_hit or secret_hit:
                hits.add(f"{relative.as_posix()}:{line_number}")
        if path.suffix.casefold() == ".py":
            try:
                constant_spans = python_constant_secret_spans(text)
            except (ValueError, RecursionError) as exc:
                hits.add(f"{relative.as_posix()}:resource-limit:{type(exc).__name__}")
                constant_spans = set()
            for start, end in constant_spans:
                allowed = False
                if start == end and start <= len(lines):
                    fingerprint = secret_line_fingerprint(relative, lines[start - 1])
                    allowed = fingerprint in secret_allowlist
                    if allowed:
                        matched_allowlist.add(fingerprint)
                if not allowed:
                    hits.add(f"{relative.as_posix()}:{start}")
        else:
            for start, _end in multiline_constant_secret_spans(text):
                hits.add(f"{relative.as_posix()}:{start}")
    active()
    for fingerprint in sorted(secret_allowlist - matched_allowlist):
        hits.add(f"fixtures/secret-scan-allowlist.txt:stale:{fingerprint[:12]}")
    return hits, exempted if exempt_paths is not None else None, bool(private_patterns), len(secret_allowlist)


def _doctor_check(vault: Path) -> AuditCheck:
    result = doctor(vault=vault)
    findings = [f"{item.severity}:{item.code}:{item.path or ''}" for item in result.findings]
    return AuditCheck(
        id="vault_doctor",
        label="Vault structure and safety doctor",
        ok=result.ok,
        evidence=[f"checked_files={result.checked_files}", f"indexed_files={result.indexed_files}"],
        findings=findings,
    )


def _demo_check(vault: Path) -> AuditCheck:
    result = run_demo(vault=vault)
    failures = [str(check["name"]) for check in result.checks if not check.get("ok")]
    return AuditCheck(
        id="demo",
        label="End-to-end synthetic demo",
        ok=result.ok,
        evidence=[str(check["name"]) for check in result.checks],
        findings=failures,
    )


def _readiness_check(repo: Path) -> AuditCheck:
    result = readiness(repo=repo)
    incomplete = [f"{item.id}:{item.status}" for item in result.items if item.status != "complete"]
    return AuditCheck(
        id="readiness",
        label="Product readiness gate",
        ok=result.score >= 90,
        evidence=[f"score={result.score}", f"structural_complete={str(result.structural_complete).lower()}"],
        findings=incomplete,
    )


def _bridge_policy_check() -> AuditCheck:
    read_only = build_bridge_policy(profile="read-only", upstream="http://127.0.0.1:8765/mcp", auth_env="TOKEN_ENV")
    operator = build_bridge_policy(profile="operator", upstream="http://127.0.0.1:8765/mcp", auth_env="TOKEN_ENV")
    read_only_tools = read_only.policy["policy"]["allow_tools"]
    operator_tools = operator.policy["policy"]["allow_tools"]
    ok = "memory.recall" in read_only_tools and "control.approval_consume" in operator_tools
    return AuditCheck(
        id="bridge_policy",
        label="safe-mcp-bridge policy profiles",
        ok=ok,
        evidence=[f"read_only_tools={len(read_only_tools)}", f"operator_tools={len(operator_tools)}"],
        findings=[] if ok else ["bridge policy profiles are incomplete"],
    )


def _release_docs_check(repo: Path) -> AuditCheck:
    required = [repo / "docs/security-audit.md", repo / "docs/release-gate.md"]
    missing = [str(path.relative_to(repo)) for path in required if not path.exists()]
    return AuditCheck(
        id="release_docs",
        label="Release-gate and audit documentation",
        ok=not missing,
        evidence=[str(path.relative_to(repo)) for path in required if path.exists()],
        findings=missing,
    )


def _release_blockers(repo: Path) -> list[str]:
    blockers: list[str] = []
    try:
        dirty = worktree_dirty_paths(repo)
    except (OSError, UnicodeError):
        dirty = None
    if dirty is None:
        blockers.append("release worktree cleanliness is unknown")
    elif dirty:
        blockers.append("release worktree has uncommitted or untracked changes")
    security_audit = repo / "docs/security-audit.md"
    release_gate = repo / "docs/release-gate.md"
    if _status_value(security_audit, "audit-status") != "complete":
        blockers.append("security audit multi-model review is not complete")
    elif not _valid_model_review_attestation(model_review_attestation_path(repo, "security-audit"), subject="security-audit", repo=repo):
        blockers.append("security audit multi-model review is missing or invalid")
    if _status_value(release_gate, "release-gate-status") != "complete":
        blockers.append("public release gate is not complete")
    elif not _valid_model_review_attestation(model_review_attestation_path(repo, "release-gate"), subject="release-gate", repo=repo):
        blockers.append("public release gate multi-model review is missing or invalid")
    return blockers


def _status_value(path: Path, key: str) -> str | None:
    if not path.exists():
        return None
    prefix = f"{key}:"
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return line.removeprefix(prefix).strip()
    return None


def _valid_model_review_attestation(path: Path, *, subject: str, repo: Path) -> bool:
    """A release review is valid when distinct model reports are hash-bound to
    the exact reviewed tree and an explicit synthesis approves the release."""
    if not path.is_file():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    try:
        ok, _models, _error = verify_model_review_attestation(payload, repo=repo, subject=subject)
    except AttestationError:
        return False
    return ok

def _should_skip(repo: Path, path: Path) -> bool:
    relative = path.relative_to(repo)
    if relative.name == ".coverage" or relative.name.startswith(".coverage."):
        return True
    return any(part in SKIP_DIRS or part.endswith(".egg-info") for part in relative.parts)
