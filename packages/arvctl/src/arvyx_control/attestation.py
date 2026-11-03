from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from datetime import datetime
from typing import Any


# Asymmetric attestation for machine evidence.
#
# Public-key verification does not require distributing the signer secret to
# every verifier. The signatures bind bytes to a configured identity and give
# tamper-evidence plus tree binding — artifact integrity, not the governance
# layer. Namespaces prevent replay across gate purposes.

NS_MCP_CLIENT = "arvyx-mcp-client-evidence"
# A CI run's provenance: a signed record that a run-check
# (docker/bridge/mcp-client) executed for the bound tree and produced a result.
NS_RUN_PROVENANCE = "arvyx-run-provenance"

# Release governance is model-review diversity (a solo-operator model): at
# least this many distinct provider/model identities must review the same tree.
MIN_MODEL_REVIEWS_ENV = "ARVYX_RELEASE_MIN_MODEL_REVIEWS"
DEFAULT_MIN_MODEL_REVIEWS = 2
MODEL_REVIEW_POLICY = "multi-model-review-v1"
MODEL_REVIEW_VERDICTS = {"approve", "approve-with-findings", "block"}
MODEL_REVIEW_REPORTS_RELATIVE = Path(".arvyx") / "model-reviews"
MODEL_REVIEW_RECEIPTS_RELATIVE = Path(".arvyx") / "release-reviews"
# The receipt records its own custody limit, so a pass cannot be read as
# independent custody. It is a declaration by the operator, not proof — the
# gate requires the field to be present and to name this value, and the docs
# say plainly what it does not prove.
MODEL_REVIEW_CUSTODY = "operator-authored-unsigned"
# Longest first: `approve` must not match inside `approve-with-findings`.
REPORT_VERDICT_RE = re.compile(r"\b(approve-with-findings|approve|block)\b")

# Tracked (NOT under the gitignored .arvyx/), so changing the trust set is a
# reviewable diff. Empty/comment-only means nothing verifies — fail closed.
ALLOWED_SIGNERS_RELATIVE = Path("docs") / "trusted-signers.allowed"
RELEASE_GRADE_SIGNERS_RELATIVE = Path("docs") / "release-grade-signers.allowed"
ATTESTATION_METHOD = "ssh-ed25519"
# A principal name as it appears as the first field of an allowed_signers line.
PRINCIPAL_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


class AttestationError(RuntimeError):
    """Signing failure. Never carries key material in its message."""


def allowed_signers_path(repo: Path) -> Path:
    return repo / ALLOWED_SIGNERS_RELATIVE


def model_review_attestation_path(repo: Path, subject: str) -> Path:
    return repo / MODEL_REVIEW_RECEIPTS_RELATIVE / f"{subject}.attestation.json"


def validate_model_review_receipt_path(repo: Path, path: Path) -> Path:
    repo = repo.resolve()
    receipt_root = (repo / MODEL_REVIEW_RECEIPTS_RELATIVE).resolve()
    if not _is_within(receipt_root, repo):
        raise AttestationError(".arvyx/release-reviews must resolve inside the repository")
    resolved = path.resolve()
    if not _is_within(resolved, receipt_root):
        raise AttestationError("model review receipt must be inside .arvyx/release-reviews")
    return resolved


def canonical_bytes(payload: dict[str, Any], *, exclude: tuple[str, ...] = ("attestation",)) -> bytes:
    """The exact bytes the signer signs and the gate verifies. Excludes the
    attestation envelope itself so the signature covers everything but itself."""
    unsigned = {key: value for key, value in payload.items() if key not in exclude}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def git_head(repo: Path) -> str | None:
    return _git(repo, "rev-parse", "HEAD")


def git_tree_sha(repo: Path) -> str | None:
    """The tree object of HEAD — the content hash of the committed tree. Binds
    an attestation to the exact reviewed source, not a free-text string."""
    return _git(repo, "rev-parse", "HEAD^{tree}")


def _git(repo: Path, *args: str) -> str | None:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def worktree_dirty_paths(repo: Path) -> list[str] | None:
    """Modified tracked files plus untracked, non-ignored files in the worktree.

    Model-review receipts and signed provenance bind ``HEAD^{tree}``, but every
    scan (private context, secret shapes, doc status lines) reads the working
    tree. Without this check an uncommitted edit satisfies a receipt issued for
    the committed tree. Returns ``None`` when git cannot answer, so a caller can
    fail closed instead of treating "unknown" as clean.
    """
    try:
        completed = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
            cwd=repo, text=True, capture_output=True, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    dirty = [entry for entry in completed.stdout.split('\0') if entry]
    # Git status trusts skip-worktree/assume-unchanged flags. Never let those
    # flags authorize scans over bytes other than the receipt's committed tree.
    # Refuse flagged entries, including sparse checkouts, rather than silently
    # claiming committed-byte equivalence. This read does not mutate the index.
    try:
        flags = subprocess.run(
            ["git", "ls-files", "-v", "-z"], cwd=repo, capture_output=True,
            check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if flags.returncode != 0:
        return None
    entries = flags.stdout.split(b'\0')
    if len(entries) > 50001 or len(flags.stdout) > 8 * 1024 * 1024:
        return None
    for entry in entries:
        if not entry:
            continue
        if len(entry) < 3 or entry[1:2] != b' ':
            return None
        tag = chr(entry[0])
        if tag == 'S' or tag.islower():
            dirty.append('index-flags ' + os.fsdecode(entry[2:]))
    return dirty


def pinned_principals(allowed_signers: Path) -> list[str]:
    """Principals that have a public key pinned in an allowed_signers file.

    Comment and blank lines are ignored, so a declaration comment never counts
    as a pinned key.
    """
    if not allowed_signers.is_file():
        return []
    principals: list[str] = []
    for line in allowed_signers.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        principals.append(stripped.split()[0])
    return principals


def sign_payload(
    payload: dict[str, Any],
    *,
    key_path: Path,
    principal: str,
    namespace: str,
    exclude: tuple[str, ...] = ("attestation",),
) -> dict[str, str]:
    """Produce the attestation envelope for `payload`, signing with an SSH
    private key via `ssh-keygen -Y sign`. Run by the trusted signer off the
    release host; the gate never calls this."""
    if not principal.strip():
        raise AttestationError("attestation principal must not be empty")
    signature = _ssh_sign(canonical_bytes(payload, exclude=exclude), key_path=key_path, namespace=namespace)
    return {
        "method": ATTESTATION_METHOD,
        "principal": principal,
        "namespace": namespace,
        "signature": signature,
    }


def verify_payload(
    payload: dict[str, Any],
    *,
    namespace: str,
    allowed_signers: Path | None,
    exclude: tuple[str, ...] = ("attestation",),
) -> tuple[bool, str | None]:
    """Return (verified, error). `verified` is True only when the attestation
    is a well-formed SSH signature by a principal pinned in `allowed_signers`,
    over the canonical payload, under the expected namespace."""
    attestation = payload.get("attestation")
    if not isinstance(attestation, dict):
        return False, "attestation is missing"
    if attestation.get("method") != ATTESTATION_METHOD:
        return False, f"attestation.method must be {ATTESTATION_METHOD}"
    if attestation.get("namespace") != namespace:
        return False, "attestation.namespace does not match this gate"
    principal = attestation.get("principal")
    signature = attestation.get("signature")
    if not isinstance(principal, str) or not principal.strip():
        return False, "attestation.principal is required"
    if not isinstance(signature, str) or "BEGIN SSH SIGNATURE" not in signature:
        return False, "attestation.signature must be an armored SSH signature"
    if allowed_signers is None or not allowed_signers.is_file():
        return False, "no pinned trusted-signers file to verify against"
    ok = _ssh_verify(
        canonical_bytes(payload, exclude=exclude),
        signature=signature,
        principal=principal,
        namespace=namespace,
        allowed_signers=allowed_signers,
    )
    return (True, None) if ok else (False, "attestation signature is not from a pinned trusted signer")


def has_pinned_signers(allowed_signers: Path) -> bool:
    """True if the allowed_signers file pins at least one real key (a
    non-empty, non-comment line). A comment-only file means fail-closed."""
    if not allowed_signers.is_file():
        return False
    for line in allowed_signers.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return True
    return False


def release_grade_signers_path(repo: Path) -> Path:
    return repo / RELEASE_GRADE_SIGNERS_RELATIVE


def release_grade_principals(repo: Path) -> frozenset[str]:
    """Principals whose signature counts for a public release.

    Being pinned is not the same as being release-grade. A pin says "this
    signature verifies"; it does not say "this evidence came from the release
    pipeline". The host drill signer proves an operator ran a check on a working
    copy, which is exactly what a public-release gate must not accept as proof
    that an exact tagged commit produced the artifacts.

    A missing or comment-only list means *nothing* is release-grade, so the
    public path fails closed rather than falling back to "any pinned signer".
    """
    path = release_grade_signers_path(repo)
    if not path.is_file():
        return frozenset()
    principals = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # This file lists bare principal names, one per line — unlike the pinned
        # allowed_signers format, it carries no key material. Accept only a lone
        # token so a stray prose line cannot be read as a release-grade principal.
        fields = stripped.split()
        if len(fields) != 1 or not PRINCIPAL_NAME_RE.fullmatch(fields[0]):
            continue
        principals.add(fields[0])
    return frozenset(principals)


def resolve_min_model_reviews(default: int = DEFAULT_MIN_MODEL_REVIEWS) -> int:
    raw = os.environ.get(MIN_MODEL_REVIEWS_ENV, "").strip()
    minimum = max(DEFAULT_MIN_MODEL_REVIEWS, default)
    if not raw:
        return minimum
    try:
        value = int(raw)
    except ValueError as exc:
        raise AttestationError(f"{MIN_MODEL_REVIEWS_ENV} must be an integer of at least {minimum}") from exc
    if value < minimum:
        raise AttestationError(f"{MIN_MODEL_REVIEWS_ENV} must be at least {minimum}")
    return value


def report_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def model_review_entry(
    *,
    repo: Path,
    provider: str,
    model: str,
    verdict: str,
    reviewed_at: str,
    scope: list[str],
    report_path: Path,
) -> dict[str, Any]:
    """Build one review receipt. It documents which model reviewed what and
    binds the receipt to the report bytes; it does not claim an independent
    human or external key-custody boundary."""
    provider = provider.strip()
    model = model.strip()
    verdict = verdict.strip()
    if not provider or not model:
        raise AttestationError("provider and model must not be empty")
    if verdict not in MODEL_REVIEW_VERDICTS:
        raise AttestationError(f"verdict must be one of {sorted(MODEL_REVIEW_VERDICTS)}")
    if not scope or any(not item.strip() for item in scope):
        raise AttestationError("scope must contain at least one non-empty item")
    _parse_timestamp(reviewed_at)
    repo = repo.resolve()
    report = report_path.resolve()
    report_root = (repo / MODEL_REVIEW_REPORTS_RELATIVE).resolve()
    if not _is_within(report_root, repo):
        raise AttestationError(".arvyx/model-reviews must resolve inside the repository")
    if not _is_within(report, report_root):
        raise AttestationError("model review report must be inside .arvyx/model-reviews")
    if not report.is_file():
        raise AttestationError(f"model review report not found: {report_path}")
    return {
        "reviewer_id": f"{provider}/{model}",
        "provider": provider,
        "model": model,
        "verdict": verdict,
        "reviewed_at": reviewed_at,
        "scope": [item.strip() for item in scope],
        "report_path": report.relative_to(repo).as_posix(),
        "report_sha256": report_sha256(report),
    }


def verify_model_review_attestation(
    payload: dict[str, Any],
    *,
    repo: Path,
    subject: str,
    min_reviews: int | None = None,
) -> tuple[bool, list[str], str | None]:
    """Validate a release review bundle against the current repository tree.

    This proves that documented report files for distinct model identities were
    reviewed and synthesized, that the bundle declares the custody it was
    produced under, and that the bundle names the tree it covers. It does not
    prove a provider invocation actually occurred; the control is model
    diversity, not anti-forgery.
    """
    repo = repo.resolve()
    required = resolve_min_model_reviews()
    if min_reviews is not None:
        # Callers may strengthen policy, never bypass the configured floor.
        required = max(required, min_reviews)
    if payload.get("schema_version") != 1 or payload.get("subject") != subject:
        return False, [], "schema_version or subject is invalid"
    if payload.get("status") != "complete":
        return False, [], "review process is not complete"
    if payload.get("policy_version") != MODEL_REVIEW_POLICY:
        return False, [], f"policy_version must be {MODEL_REVIEW_POLICY}"
    if payload.get("custody") != MODEL_REVIEW_CUSTODY:
        return False, [], f"custody must be {MODEL_REVIEW_CUSTODY}"
    tree = git_tree_sha(repo)
    if tree is None or payload.get("artifact_git_tree") != tree:
        return False, [], "artifact_git_tree does not match the current release tree"
    reviews = payload.get("reviews")
    if not isinstance(reviews, list):
        return False, [], "reviews must be a list"
    identities: list[str] = []
    for entry in reviews:
        error = _model_review_error(entry, repo=repo)
        if error:
            return False, identities, error
        identity = f"{entry['provider'].strip()}/{entry['model'].strip()}"
        if identity in identities:
            return False, identities, f"duplicate model review identity: {identity}"
        identities.append(identity)
        if entry["verdict"] == "block":
            return False, identities, f"blocking verdict from {identity}"
    if len(identities) < required:
        return False, identities, f"need {required} distinct model review(s); {len(identities)} verified"
    synthesis = payload.get("synthesis")
    if not isinstance(synthesis, dict) or synthesis.get("decision") != "approve":
        return False, identities, "synthesis.decision must be approve"
    synthesizer = synthesis.get("synthesizer")
    if not isinstance(synthesizer, str) or not synthesizer.strip():
        return False, identities, "synthesis.synthesizer is required"
    synthesized_at = synthesis.get("synthesized_at")
    if not isinstance(synthesized_at, str):
        return False, identities, "synthesis.synthesized_at is required"
    try:
        _parse_timestamp(synthesized_at)
    except AttestationError as exc:
        return False, identities, str(exc).replace("reviewed_at", "synthesized_at")
    for field in ("agreements", "disagreements"):
        value = synthesis.get(field)
        if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
            return False, identities, f"synthesis.{field} must be a list of non-empty strings"
    resolution = synthesis.get("resolution")
    if not isinstance(resolution, str) or not resolution.strip():
        return False, identities, "synthesis.resolution is required"
    return True, identities, None


def report_verdict(path: Path) -> str | None:
    """The verdict the review report itself states.

    The receipt's `verdict` field is operator JSON; this reads the report body so
    a hash-bound report that says `block` cannot ride in under an `approve`
    envelope. Returns ``None`` when the report states no verdict, which the
    caller fails closed on.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return _report_verdict_bytes(data)


def _report_verdict_bytes(data: bytes) -> str | None:
    text = data.decode("utf-8", errors="replace")
    declarations = list(re.finditer(r"(?im)^[ \t]*(?:#{1,6}[ \t]+verdict[ \t]*\r?$|verdict[ \t]*[:\-][ \t]*([^\r\n]*)\r?$)", text))
    if len(declarations) != 1:
        return None
    declaration = declarations[0]
    value = declaration.group(1)
    if value is None:
        remaining = text[declaration.end():].lstrip('\r\n')
        value = remaining.splitlines()[0] if remaining else ''
    value = value.strip()
    return value if value in MODEL_REVIEW_VERDICTS else None


def _model_review_error(entry: Any, *, repo: Path) -> str | None:
    if not isinstance(entry, dict):
        return "each review must be an object"
    for field in ("reviewer_id", "provider", "model", "verdict", "reviewed_at", "report_path", "report_sha256"):
        if not isinstance(entry.get(field), str) or not entry[field].strip():
            return f"review.{field} is required"
    identity = f"{entry['provider'].strip()}/{entry['model'].strip()}"
    if entry["reviewer_id"] != identity:
        return "reviewer_id must equal provider/model"
    if entry["verdict"] not in MODEL_REVIEW_VERDICTS:
        return "review.verdict is invalid"
    try:
        _parse_timestamp(entry["reviewed_at"])
    except AttestationError as exc:
        return str(exc)
    scope = entry.get("scope")
    if not isinstance(scope, list) or not scope or any(not isinstance(item, str) or not item.strip() for item in scope):
        return "review.scope must contain non-empty strings"
    report = (repo / entry["report_path"]).resolve()
    report_root = (repo / MODEL_REVIEW_REPORTS_RELATIVE).resolve()
    if not _is_within(report_root, repo):
        return ".arvyx/model-reviews must resolve inside the repository"
    if not _is_within(report, report_root) or not report.is_file():
        return "review.report_path must reference a file inside .arvyx/model-reviews"
    try:
        report_bytes = report.read_bytes()
        digest = hashlib.sha256(report_bytes).hexdigest()
    except OSError as exc:
        return f"cannot read model review report {entry['report_path']}: {exc}"
    if digest != entry["report_sha256"]:
        return f"review report hash mismatch for {entry['report_path']}"
    stated = _report_verdict_bytes(report_bytes)
    if stated is None:
        return f"review report {entry['report_path']} does not state a verdict"
    if stated != entry["verdict"]:
        return (
            f"review report {entry['report_path']} states '{stated}' "
            f"but the receipt claims '{entry['verdict']}'"
        )
    return None


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AttestationError("reviewed_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise AttestationError("reviewed_at must include a timezone")
    return parsed


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _ssh_sign(message: bytes, *, key_path: Path, namespace: str) -> str:
    if not key_path.is_file():
        raise AttestationError(f"signing key not found: {key_path}")
    with tempfile.TemporaryDirectory() as tmp:
        msg = Path(tmp) / "message"
        msg.write_bytes(message)
        completed = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(key_path), "-n", namespace, str(msg)],
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            # stderr can echo the key path but never the private key itself.
            raise AttestationError(f"ssh-keygen sign failed: {completed.stderr.strip()[:200]}")
        sig_path = Path(f"{msg}.sig")
        if not sig_path.is_file():
            raise AttestationError("ssh-keygen produced no signature")
        return sig_path.read_text(encoding="utf-8")


def _ssh_verify(
    message: bytes,
    *,
    signature: str,
    principal: str,
    namespace: str,
    allowed_signers: Path,
) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        sig = Path(tmp) / "signature"
        sig.write_text(signature, encoding="utf-8", newline="\n")
        completed = subprocess.run(
            [
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed_signers),
                "-I",
                principal,
                "-n",
                namespace,
                "-s",
                str(sig),
            ],
            input=message,
            capture_output=True,
            check=False,
        )
        return completed.returncode == 0
