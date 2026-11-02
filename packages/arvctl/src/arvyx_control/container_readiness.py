from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from urllib.error import URLError
from urllib.request import Request

from .http_bounds import BoundedOpener

from .audit_log import pending_operations, verify_chain_tail
from .replica_authority import bound_entry
from .security import is_http_url
from .vault import VAULT_MARKER


EXPECTED_VAULT_MARKER = "arvyx-vault-format: 1"
_STATE_READINESS_TAIL_BYTES = 1024 * 1024
_HEALTH_MAX_BYTES = 64 * 1024


def _verify_state_tail(path: Path, max_bytes: int = _STATE_READINESS_TAIL_BYTES) -> bool:
    """Check record shapes in the last 1 MiB, not historical integrity.

    The first partial record is skipped. Success says nothing about records
    preceding this window, projection correctness, or authenticated history.
    Keep polling bounded; full replay/restore verification is a separate gate.
    """
    size = path.stat().st_size
    if size == 0:
        return True
    offset = max(0, size - max_bytes)
    with path.open("rb") as handle:
        handle.seek(offset)
        payload = handle.read(max_bytes)
    if not payload.endswith(b"\n"):
        return False
    if offset:
        newline = payload.find(b"\n")
        if newline < 0:
            return False
        payload = payload[newline + 1 :]
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return False
    records = [line for line in lines if line.strip()]
    if not records:
        return not bool(offset)
    for line in records:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return False
        if not isinstance(event, dict):
            return False
        if not all(isinstance(event.get(field), str) for field in ("id", "type", "task_id", "timestamp")):
            return False
        if not isinstance(event.get("payload"), dict):
            return False
    return True


@bound_entry
def check_readiness(
    *,
    vault: Path,
    state: Path,
    audit_log: Path,
    health_url: str,
) -> dict[str, object]:
    """Poll local access, bounded log tails/pending outcomes and HTTP liveness.

    This is not full control-history validation or release/restore approval.
    """
    errors: list[str] = []
    marker = vault / VAULT_MARKER
    if not marker.is_file():
        errors.append("vault marker is missing")
    else:
        try:
            if marker.read_text(encoding="utf-8").strip() != EXPECTED_VAULT_MARKER:
                errors.append("vault marker format is invalid")
        except (OSError, UnicodeError):
            errors.append("vault marker is unreadable")
    if not vault.is_dir() or not os.access(vault, os.R_OK | os.W_OK | os.X_OK):
        errors.append("vault is not readable and writable")
    elif not errors:
        try:
            with tempfile.NamedTemporaryFile(prefix=".readiness-", dir=vault, delete=True):
                pass
        except OSError:
            errors.append("vault write probe failed")

    for label, path in (("state", state), ("audit", audit_log)):
        parent = path.parent
        lock_path = path.with_suffix(path.suffix + ".lock")
        if not parent.is_dir() or not os.access(parent, os.W_OK | os.X_OK):
            errors.append(f"{label} path is not writable")
        if path.exists() and not path.is_file():
            errors.append(f"{label} path is not a regular file")
            continue
        if path.exists() and not os.access(path, os.R_OK | os.W_OK):
            errors.append(f"{label} file is not readable and writable")
        if lock_path.exists() and (not lock_path.is_file() or not os.access(lock_path, os.W_OK)):
            errors.append(f"{label} lock path is not writable")

    if state.is_file():
        try:
            if not _verify_state_tail(state):
                errors.append("state event log is invalid")
        except (OSError, UnicodeError, ValueError, KeyError, TypeError):
            errors.append("state event log is invalid")
    if audit_log.is_file():
        try:
            if not verify_chain_tail(audit_log).ok:
                errors.append("audit hash-chain tail is invalid")
            elif pending_operations(audit_log):
                errors.append("audit has pending mutation outcomes")
        except (OSError, UnicodeError, RuntimeError, ValueError, json.JSONDecodeError, sqlite3.Error):
            errors.append("audit log is unreadable")

    if not is_http_url(health_url):
        errors.append("HTTP health URL must use http or https")
        return {"ok": False, "errors": errors}

    try:
        # One total DNS/connect/TLS/body deadline; no redirects or proxies.
        with BoundedOpener().open(Request(health_url, method="GET"), timeout=2) as response:
            raw = response.read(_HEALTH_MAX_BYTES + 1)
            if len(raw) > _HEALTH_MAX_BYTES:
                raise ValueError("HTTP health body too large")
            if response.status != 200:
                errors.append(f"HTTP health returned {response.status}")
            else:
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("HTTP health object required")
                body = payload.get("body")
                ready = payload.get("ok") is True or (
                    isinstance(body, dict) and body.get("ok") is True
                )
                if not ready:
                    errors.append("HTTP health payload was not ready")
    except (OSError, URLError, ValueError) as exc:
        errors.append(f"HTTP health failed: {type(exc).__name__}")

    return {"ok": not errors, "errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser(description="Check container data and HTTP readiness.")
    parser.add_argument("--vault", type=Path, default=Path("/data/vault"))
    parser.add_argument("--state", type=Path, default=Path("/data/control-events.jsonl"))
    parser.add_argument("--audit-log", type=Path, default=Path("/data/audit-log.jsonl"))
    parser.add_argument("--health-url", default="http://127.0.0.1:8765/health")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()
    result = check_readiness(
        vault=args.vault,
        state=args.state,
        audit_log=args.audit_log,
        health_url=args.health_url,
    )
    if args.json_output:
        print(json.dumps(result, sort_keys=True))
    elif not result["ok"]:
        for error in result["errors"]:
            print(error)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
