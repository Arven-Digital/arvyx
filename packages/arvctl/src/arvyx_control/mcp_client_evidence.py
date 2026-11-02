from __future__ import annotations

from datetime import timedelta
from datetime import UTC
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from .attestation import NS_MCP_CLIENT, git_head, git_tree_sha, sign_payload, verify_payload


# secret://broker/path is a sanctioned valueless reference, not a leak, so
# it is not a private marker.
#
# The markers are a coarse leak tripwire over the captured tool output, not a
# proof of absence: an operator path, a Windows path, an authorization header,
# or credential-shaped text anywhere in the capture fails validation. A capture
# that mentions any of these is treated as leaking rather than trimmed.
PRIVATE_MARKERS = (
    "/home/",
    "/srv/",
    "/root/",
    "/Users/",
    "\\Users\\",
    "C:" + "\\",
    "Authorization:",
    "Bearer" + " ",
    "api" + "_key",
    "apikey",
    "password",
    "PRIVATE" + " KEY",
)
REQUIRED_RESULT_FLAGS = ("tools_list_ok", "recall_ok", "sources_returned", "private_paths_leaked")
# A closed shape on purpose: the file is signed by a release principal and then
# hashed, attested and published, so anything that can travel inside it must be a
# named, bounded field rather than an unknown key carrying arbitrary bytes.
MAX_EVIDENCE_BYTES = 64 * 1024
ALLOWED_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "client",
        "client_version",
        "client_provenance",
        "protocol_version",
        "checked_at",
        "git_head",
        "git_tree",
        "transport",
        "command",
        "result",
        "notes",
        "capture_sha256",
        "capture_bytes",
        "scan_scope",
        "marker_set_sha256",
        "attestation",
    }
)
ALLOWED_RESULT_KEYS = frozenset(REQUIRED_RESULT_FLAGS)
# field name -> maximum length; every text field in the schema is bounded.
MAX_TEXT_FIELD_LENGTHS = {
    "client": 64,
    "client_version": 64,
    "protocol_version": 64,
    "command": 512,
    "notes": 1024,
    "git_head": 128,
    "git_tree": 128,
}
MAX_SCAN_SCOPE_ENTRIES = 8
MAX_SCAN_SCOPE_ENTRY_LENGTH = 64
# `checked_at` is validated as a timestamp, so its length is bounded there rather
# than in MAX_TEXT_FIELD_LENGTHS: an ISO-8601 instant with a timezone needs far
# fewer characters, and a parser will happily accept a timestamp padded with tens
# of thousands of fractional digits.
MAX_CHECKED_AT_LENGTH = 64
# Display client names carry no provenance authority. Legacy files without
# measured provenance remain self evidence, even with an external-looking label.
# Stated here because the prose used to say only "fresh". A file may be reused
# for any re-checkout of the same commit inside this window.
DEFAULT_MAX_AGE_HOURS = 14 * 24


def generate_mcp_client_evidence(
    *,
    vault: Path,
    client: str = "arvyx-cli",
    output: Path | None = None,
) -> dict[str, Any]:
    # Record the interpreter actually used so evidence is honest on any OS.
    command = [Path(sys.executable).name, "-m", "arvyx_control.cli", "mcp", "--profile", "read-only", "--vault", _display_path(vault)]
    tools_response = _call_stdio_mcp(
        command=[
            sys.executable,
            "-m",
            "arvyx_control.cli",
            "mcp",
            "--profile",
            "read-only",
            "--vault",
            vault.as_posix(),
        ],
        request={"jsonrpc": "2.0", "id": "tools", "method": "tools/list"},
    )
    recall_response = _call_stdio_mcp(
        command=[
            sys.executable,
            "-m",
            "arvyx_control.cli",
            "mcp",
            "--profile",
            "read-only",
            "--vault",
            vault.as_posix(),
        ],
        request={
            "jsonrpc": "2.0",
            "id": "recall",
            "method": "tools/call",
            "params": {
                "name": "memory.recall",
                "arguments": {
                    "question": "what did we decide about safe mcp bridge",
                    "project": "demo-agent",
                    "max_tokens": 120,
                },
            },
        },
    )
    text = json.dumps({"tools": tools_response, "recall": recall_response}, sort_keys=True)
    tools = tools_response.get("result", {}).get("tools", [])
    structured = recall_response.get("result", {}).get("structuredContent", {})
    payload = {
        "schema_version": 1,
        "client": client,
        "client_provenance": {"kind": "product-self-client"},
        "checked_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "git_head": git_head(Path.cwd()),
        "git_tree": git_tree_sha(Path.cwd()),
        "transport": "stdio",
        "command": " ".join(command),
        "result": {
            "tools_list_ok": any(isinstance(tool, dict) and tool.get("name") == "memory.recall" for tool in tools),
            "recall_ok": bool(structured.get("answer")),
            "sources_returned": bool(structured.get("sources")),
            "private_paths_leaked": any(marker in text for marker in PRIVATE_MARKERS),
        },
        "notes": "Generated by arvyx evidence mcp-client. Self-attested: does not satisfy the external-client release gate.",
    }
    # Deliberately NOT signed here: generation and signing are separate steps.
    # `arvyx evidence sign` binds the completed evidence to a configured identity.
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def attest_evidence_file(path: Path, *, key_path: Path, principal: str) -> dict[str, Any]:
    """Sign an existing evidence file in place with a pinned signer's SSH key.

    Embeds the SSH-signature attestation so the release-host gate can verify it
    against the pinned trusted-signers file. The signer is CI or release tooling;
    this gives artifact integrity (tamper-evidence + tree binding), not the
    governance layer.
    """
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("evidence must be a JSON object")
    payload["attestation"] = sign_payload(
        payload,
        key_path=key_path,
        principal=principal,
        namespace=NS_MCP_CLIENT,
    )
    path.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def validate_mcp_client_evidence(
    path: Path,
    *,
    expected_git_head: str | None = None,
    expected_git_tree: str | None = None,
    max_age_hours: int | None = None,
    require_attestation: bool = False,
    allowed_signers: Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    try:
        size = path.stat().st_size
    except OSError as exc:
        return {"ok": False, "path": str(path), "errors": [str(exc)]}
    if size > MAX_EVIDENCE_BYTES:
        # Checked before reading: the ceiling must hold even when the file would not
        # fit comfortably in memory.
        return {
            "ok": False,
            "path": str(path),
            "errors": [f"evidence file exceeds {MAX_EVIDENCE_BYTES} bytes ({size})"],
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        return {"ok": False, "path": str(path), "errors": [str(exc)]}
    if not isinstance(payload, dict):
        return {"ok": False, "path": str(path), "errors": ["evidence must be a JSON object"]}

    provenance = payload.get("client_provenance")
    if ("client_provenance" in payload
            and provenance != {"kind": "product-self-client"}
            and not _external_client_provenance(payload)):
        errors.append("client_provenance must contain bounded measured SDK provenance or product-self-client")
    unknown = sorted(set(payload) - ALLOWED_TOP_LEVEL_KEYS)
    if unknown:
        errors.append(f"unknown top-level key(s): {', '.join(unknown)}")
    # Type and length are checked together. A length-only test is skipped entirely
    # for a non-string value, so an object carrying arbitrary nested keys and text
    # would travel inside a file that is then signed, attested and published.
    # `null` is treated as absent: optional bindings such as git_head/git_tree are
    # legitimately missing outside a checkout, and the generator records that as
    # null rather than inventing a string.
    for field, limit in MAX_TEXT_FIELD_LENGTHS.items():
        if field not in payload:
            continue
        value = payload[field]
        if value is None:
            continue
        if not isinstance(value, str):
            errors.append(f"{field} must be a string")
        elif len(value) > limit:
            errors.append(f"{field} must be at most {limit} characters")
    if "capture_sha256" in payload:
        digest = payload.get("capture_sha256")
        if not isinstance(digest, str) or not _is_sha256_hex(digest):
            errors.append("capture_sha256 must be a sha256 hex digest")
    if "marker_set_sha256" in payload:
        digest = payload.get("marker_set_sha256")
        if not isinstance(digest, str) or not _is_sha256_hex(digest):
            errors.append("marker_set_sha256 must be a sha256 hex digest")
    if "capture_bytes" in payload:
        capture_bytes = payload.get("capture_bytes")
        if not isinstance(capture_bytes, int) or isinstance(capture_bytes, bool) or capture_bytes < 0:
            errors.append("capture_bytes must be a non-negative integer")
    if "scan_scope" in payload:
        scope = payload.get("scan_scope")
        if not isinstance(scope, list) or not scope or len(scope) > MAX_SCAN_SCOPE_ENTRIES:
            errors.append(f"scan_scope must be a list of 1 to {MAX_SCAN_SCOPE_ENTRIES} entries")
        elif any(
            not isinstance(entry, str) or not entry or len(entry) > MAX_SCAN_SCOPE_ENTRY_LENGTH
            for entry in scope
        ):
            errors.append("scan_scope entries must be bounded non-empty strings")

    if payload.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if payload.get("transport") != "stdio":
        errors.append("transport must be stdio")
    _require_text(payload, "client", errors)
    _require_text(payload, "checked_at", errors)
    _validate_checked_at(payload.get("checked_at"), max_age_hours=max_age_hours, errors=errors)
    if expected_git_head is not None:
        if payload.get("git_head") != expected_git_head:
            errors.append("git_head must match the release commit")
    if expected_git_tree is not None:
        # Tree, not commit: the signature covers these bytes, and a checkout can
        # be modified without changing HEAD. Evidence that names no tree cannot
        # be bound to the reviewed source.
        tree = payload.get("git_tree")
        if not isinstance(tree, str) or not tree.strip():
            errors.append("git_tree is required and must match the release tree")
        elif tree != expected_git_tree:
            errors.append("git_tree must match the release tree")
    _require_text(payload, "command", errors)
    if "arvyx_control.cli" not in str(payload.get("command", "")):
        errors.append("command must reference arvyx_control.cli")

    result = payload.get("result")
    if not isinstance(result, dict):
        errors.append("result must be an object")
    else:
        unknown_result = sorted(set(result) - ALLOWED_RESULT_KEYS)
        if unknown_result:
            errors.append(f"unknown result key(s): {', '.join(unknown_result)}")
        for flag in REQUIRED_RESULT_FLAGS:
            if flag not in result:
                errors.append(f"result.{flag} is required")
            elif not isinstance(result[flag], bool):
                errors.append(f"result.{flag} must be boolean")
        if result.get("private_paths_leaked") is True:
            errors.append("result.private_paths_leaked must be false")
        if any(result.get(flag) is False for flag in ("tools_list_ok", "recall_ok", "sources_returned")):
            errors.append("tools_list_ok, recall_ok, and sources_returned must be true")

    text = json.dumps(payload, sort_keys=True)
    for marker in PRIVATE_MARKERS:
        if marker in text:
            errors.append(f"private marker found: {marker}")
    attested = _validate_attestation(
        payload,
        require_attestation=require_attestation,
        allowed_signers=allowed_signers,
        errors=errors,
    )

    attestation = payload.get("attestation")
    principal = attestation.get("principal") if isinstance(attestation, dict) else None
    return {
        "ok": not errors,
        "path": path.name,
        "client": payload.get("client"),
        "transport": payload.get("transport"),
        "self_attested": not _external_client_provenance(payload),
        "git_head": payload.get("git_head"),
        "git_tree": payload.get("git_tree"),
        "attested": attested,
        "attestation_principal": principal,
        "errors": errors,
    }


def validate_release_mcp_client_evidence(path: Path, *, repo: Path) -> dict[str, Any]:
    """Authoritative release policy for every MCP evidence consumer.

    Structural validation is intentionally weaker. Release validation always binds
    a known commit/tree, limits age (including future skew), requires an external
    client and verifies a pinned, release-grade signer. Missing git metadata must
    not silently disable binding by passing None to the structural validator.
    """
    from .attestation import allowed_signers_path, release_grade_principals

    head = git_head(repo)
    tree = git_tree_sha(repo)
    validation = validate_mcp_client_evidence(
        path,
        expected_git_head=head or "",
        expected_git_tree=tree or "",
        max_age_hours=DEFAULT_MAX_AGE_HOURS,
        require_attestation=True,
        allowed_signers=allowed_signers_path(repo),
    )
    errors = list(validation.get("errors", []))
    if not head or not tree:
        errors.append("cannot read release git HEAD/tree binding")
    if validation.get("self_attested"):
        errors.append("client is arvyx's own self client; external evidence is required")
    if not validation.get("attested"):
        errors.append("verified attestation is required in release mode")
    principal = validation.get("attestation_principal")
    if not isinstance(principal, str) or not principal.strip():
        errors.append("a signed principal is required in release mode")
    elif principal not in release_grade_principals(repo):
        errors.append(f"principal {principal!r} is not release-grade")
    return {**validation, "ok": not errors, "errors": errors}


def _external_client_provenance(payload: dict[str, Any]) -> bool:
    """Recognize measured implementation provenance, never a display name.

    These measurements are claims until a pinned release-grade signer attests
    them. Digests bind observed code; they do not independently prove execution.
    Legacy evidence without provenance cannot open the external-client gate.
    """
    provenance = payload.get("client_provenance")
    if not isinstance(provenance, dict) or set(provenance) != {
        "kind", "distribution", "version", "implementation_sha256"
    }:
        return False
    return (
        provenance.get("kind") == "third-party-sdk"
        and provenance.get("distribution") == "mcp"
        and isinstance(provenance.get("version"), str)
        and bool(provenance["version"].strip())
        and len(provenance["version"]) <= 64
        and provenance["version"] == payload.get("client_version")
        and isinstance(provenance.get("implementation_sha256"), str)
        and _is_sha256_hex(provenance["implementation_sha256"])
        and isinstance(payload.get("capture_sha256"), str)
        and _is_sha256_hex(payload["capture_sha256"])
        and type(payload.get("capture_bytes")) is int
        and payload["capture_bytes"] > 0
        and payload.get("scan_scope") == ["initialize", "tools/list", "memory.recall"]
    )


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _require_text(payload: dict[str, Any], key: str, errors: list[str]) -> None:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{key} is required")


def _validate_checked_at(value: Any, *, max_age_hours: int | None, errors: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        return
    if len(value) > MAX_CHECKED_AT_LENGTH:
        errors.append(f"checked_at must be at most {MAX_CHECKED_AT_LENGTH} characters")
        return
    try:
        checked_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append("checked_at must be an ISO timestamp")
        return
    if checked_at.tzinfo is None:
        errors.append("checked_at must include a timezone")
        return
    if max_age_hours is None:
        return
    now = datetime.now(UTC)
    if checked_at > now + timedelta(minutes=5):
        errors.append("checked_at is in the future")
    if now - checked_at > timedelta(hours=max_age_hours):
        errors.append("checked_at is stale")


def _validate_attestation(
    payload: dict[str, Any],
    *,
    require_attestation: bool,
    allowed_signers: Path | None,
    errors: list[str],
) -> bool:
    """Verify the asymmetric SSH-signature attestation, if present.

    A missing attestation is not itself an error unless `require_attestation`
    is set — the release-host gate blocks on `attested` explicitly, so a
    self-attested (`arvyx-cli`) file is still reported as self-attested rather
    than masked by an attestation error. A present-but-invalid attestation is
    always an error.
    """
    if not isinstance(payload.get("attestation"), dict):
        if require_attestation:
            errors.append("attestation is required")
        return False
    ok, error = verify_payload(payload, namespace=NS_MCP_CLIENT, allowed_signers=allowed_signers)
    if not ok:
        errors.append(f"attestation invalid: {error}")
    return ok


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.name


def _call_stdio_mcp(command: list[str], request: dict[str, Any]) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        input=json.dumps(request),
        text=True,
        capture_output=True,
        env=_subprocess_env(),
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError(completed.stderr.strip() or f"MCP client command exited {completed.returncode}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"MCP client returned invalid JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("MCP client returned non-object JSON")
    return payload


def _subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    paths = [item for item in sys.path if item]
    existing = env.get("PYTHONPATH")
    if existing:
        paths.append(existing)
    env["PYTHONPATH"] = os.pathsep.join(dict.fromkeys(paths))
    return env
