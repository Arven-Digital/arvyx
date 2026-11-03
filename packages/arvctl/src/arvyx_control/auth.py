from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
from secrets import token_hex
import tempfile
from typing import Iterator

from . import private_paths
from . import safe_open
from .locks import exclusive_lock

from .mcp import (
    CONTROL_DELIVERY_READ_TOOL_NAMES,
    CONTROL_DELIVERY_WRITE_TOOL_NAMES,
    CONTROL_EXECUTION_READ_TOOL_NAMES,
    CONTROL_TOOL_NAMES,
    MEMORY_CURATION_TOOL_NAMES,
    MEMORY_REFINE_TOOL_NAMES,
    MEMORY_TOOL_NAMES,
    SECRET_INSPECTION_TOOL_NAMES,
    SESSION_READ_TOOL_NAMES,
    MEMORY_WRITE_TOOL_NAMES,
    SESSION_WRITE_TOOL_NAMES,
)


AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TOKEN_SLOT_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$")
TOKENS_DIR = Path("registry") / "tokens"

SCOPE_MEMORY_READ = "memory.read"
SCOPE_MEMORY_SUGGEST = "memory.suggest"
# Move raw suggestions into the refining lane and rewrite them; distinct
# from curate so a refiner role need not also hold promote/reject authority.
SCOPE_MEMORY_REFINE = "memory.refine"
SCOPE_MEMORY_CURATE = "memory.curate"
SCOPE_CONTROL_READ = "control.read"
SCOPE_CONTROL_WRITE = "control.write"
SCOPE_CONTROL_DELIVERY = "control.delivery"
# Full-vault read for backup hosts, including lanes recall excludes.
# Grant it only to the replica agent.
SCOPE_REPLICA_READ = "replica.read"
# Resolve secret://broker/path references to real values through the
# broker. Grant sparingly; every resolution is audited (without the value).
SCOPE_SECRET_RESOLVE = "secret.resolve"
# Inspect provider and pointer metadata without resolving any secret value.
SCOPE_SECRET_INSPECT = "secret.inspect"
# Read hot agent session state. Kept separate from curated memory.read so the
# intentionally anonymous recall surface cannot expose in-flight work context.
SCOPE_SESSION_READ = "session.read"
# Write the agent's own hot session state (SESSION-STATE.md). Direct write,
# identity-bound to the agent; reading is covered by session.read.
SCOPE_SESSION_WRITE = "session.write"

ALL_SCOPES = frozenset(
    {
        SCOPE_MEMORY_READ,
        SCOPE_MEMORY_SUGGEST,
        SCOPE_MEMORY_REFINE,
        SCOPE_MEMORY_CURATE,
        SCOPE_CONTROL_READ,
        SCOPE_CONTROL_WRITE,
        SCOPE_CONTROL_DELIVERY,
        SCOPE_REPLICA_READ,
        SCOPE_SECRET_RESOLVE,
        SCOPE_SECRET_INSPECT,
        SCOPE_SESSION_READ,
        SCOPE_SESSION_WRITE,
    }
)

CONTROL_READ_TOOLS = (
    "control.task_list",
    "control.approval_list",
    "control.handoff_list",
    "control.bus_list",
    "control.digest",
    "control.thread_get",
    "control.thread_inbox",
    "control.thread_pending",
) + CONTROL_EXECUTION_READ_TOOL_NAMES

DELIVERY_TOOLS = CONTROL_DELIVERY_READ_TOOL_NAMES + CONTROL_DELIVERY_WRITE_TOOL_NAMES

SCOPE_TOOLS = {
    SCOPE_MEMORY_READ: MEMORY_TOOL_NAMES,
    SCOPE_MEMORY_SUGGEST: MEMORY_WRITE_TOOL_NAMES,
    SCOPE_MEMORY_REFINE: MEMORY_REFINE_TOOL_NAMES,
    SCOPE_MEMORY_CURATE: MEMORY_CURATION_TOOL_NAMES,
    SCOPE_CONTROL_READ: CONTROL_READ_TOOLS,
    SCOPE_CONTROL_WRITE: tuple(
        name for name in CONTROL_TOOL_NAMES if name not in CONTROL_READ_TOOLS and name not in DELIVERY_TOOLS
    ),
    SCOPE_CONTROL_DELIVERY: DELIVERY_TOOLS,
    SCOPE_REPLICA_READ: (),  # replication is HTTP-only, no MCP tools
    SCOPE_SECRET_RESOLVE: ("secret.resolve", "secret.brokers"),
    SCOPE_SECRET_INSPECT: SECRET_INSPECTION_TOOL_NAMES,
    SCOPE_SESSION_READ: SESSION_READ_TOOL_NAMES,
    SCOPE_SESSION_WRITE: SESSION_WRITE_TOOL_NAMES,
}


@dataclass(frozen=True)
class Identity:
    agent_id: str
    scopes: frozenset[str]
    kind: str  # "agent" (per-agent token) or "operator" (shared secret)

    @property
    def binds_actor(self) -> bool:
        return self.kind == "agent"


OPERATOR_IDENTITY = Identity(agent_id="operator", scopes=ALL_SCOPES, kind="operator")


@dataclass(frozen=True)
class IssueResult:
    agent_id: str
    token: str
    scopes: list[str]
    path: str
    slot: str = "default"

    def to_dict(self) -> dict[str, object]:
        return {"agent_id": self.agent_id, "token": self.token, "scopes": self.scopes, "path": self.path, "slot": self.slot}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class TokenRecord:
    agent_id: str
    scopes: list[str]
    issued_at: str
    revoked: bool
    expires_at: str = ""
    slot: str = "default"

    def to_dict(self) -> dict[str, object]:
        return {
            "agent_id": self.agent_id,
            "scopes": self.scopes,
            "issued_at": self.issued_at,
            "revoked": self.revoked,
            "expires_at": self.expires_at,
            "slot": self.slot,
        }


@dataclass(frozen=True)
class TokenListResult:
    tokens: list[TokenRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {"tokens": [record.to_dict() for record in self.tokens]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@contextmanager
def _token_slot_lock(vault_root: Path, agent_id: str, slot: str) -> Iterator[None]:
    """Lock a stable sidecar, never the atomically replaced record inode."""
    from .replica_authority import assert_mutation_authority
    assert_mutation_authority(vault_root)
    path = _token_path(vault_root, agent_id, slot)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with exclusive_lock(path.with_suffix(".lock")):
        assert_mutation_authority(vault_root)
        yield


def issue_token(
    vault: Path,
    agent_id: str,
    scopes: list[str] | None = None,
    ttl_days: int | None = None,
    ttl_seconds: int | None = None,
    slot: str | None = None,
) -> IssueResult:
    """Issue under the same process-shared slot lock as renewal/revocation."""
    vault_root = vault.resolve()
    agent_id = _validate_agent_id(agent_id)
    normalized_slot = _validate_token_slot(slot)
    with _token_slot_lock(vault_root, agent_id, normalized_slot):
        return _issue_token_unlocked(
            vault_root, agent_id, scopes=scopes, ttl_days=ttl_days,
            ttl_seconds=ttl_seconds, slot=normalized_slot,
        )


def _issue_token_unlocked(
    vault: Path,
    agent_id: str,
    scopes: list[str] | None = None,
    ttl_days: int | None = None,
    ttl_seconds: int | None = None,
    slot: str | None = None,
) -> IssueResult:
    """Caller must hold the slot lock. Issue a bearer token for a registry agent; only its sha256 is stored."""
    vault_root = vault.resolve()
    agent_id = _validate_agent_id(agent_id)
    normalized_slot = _validate_token_slot(slot)
    agent_record = _load_agent(vault_root, agent_id)
    granted = _validate_scopes(scopes if scopes is not None else agent_record.get("scopes", []))
    if not granted:
        raise ValueError(f"agent {agent_id} has no scopes; grant scopes in the registry or pass --scope")
    if ttl_seconds is not None and ttl_days is not None:
        raise ValueError("token ttl_days and ttl_seconds are mutually exclusive")
    if ttl_seconds is not None:
        if not 1 <= ttl_seconds <= 365 * 24 * 60 * 60:
            raise ValueError("token ttl_seconds must be between 1 and 31536000")
        ttl = timedelta(seconds=ttl_seconds)
    else:
        effective_days = 30 if ttl_days is None else ttl_days
        if not 1 <= effective_days <= 365:
            raise ValueError("token ttl_days must be between 1 and 365")
        ttl = timedelta(days=effective_days)

    token = f"arv_{agent_id}_{token_hex(20)}"
    issued_at = _now()
    record = {
        "agent_id": agent_id,
        "token_sha256": _hash_token(token),
        "scopes": sorted(granted),
        "issued_at": issued_at,
        "expires_at": (datetime.fromisoformat(issued_at.replace("Z", "+00:00")) + ttl).isoformat().replace("+00:00", "Z"),
        "revoked": False,
        "slot": normalized_slot,
    }
    path = _token_path(vault_root, agent_id, normalized_slot)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _write_record(path, record)
    return IssueResult(
        agent_id=agent_id,
        token=token,
        scopes=sorted(granted),
        path=path.relative_to(vault_root).as_posix(),
        slot=normalized_slot,
    )


def renew_token(vault: Path, agent_id: str, slot: str | None = None, ttl_days: int = 30) -> IssueResult:
    """Re-issue an existing, unrevoked token slot with exactly its current scopes.

    Renewal must not widen or narrow access, and must not revive a slot someone
    revoked on purpose — that is a fresh ``issue`` with an explicit decision.
    The previous token stops working when the new record replaces it.
    """
    vault_root = vault.resolve()
    agent_id = _validate_agent_id(agent_id)
    normalized_slot = _validate_token_slot(slot)
    with _token_slot_lock(vault_root, agent_id, normalized_slot):
        path = _token_path(vault_root, agent_id, normalized_slot)
        try:
            current = _record_from_payload(json.loads(path.read_text(encoding="utf-8")))
        except FileNotFoundError:
            raise ValueError(f"no token slot to renew: {agent_id}/{normalized_slot}") from None
        except json.JSONDecodeError:
            raise ValueError(f"token slot record is unreadable: {agent_id}/{normalized_slot}") from None
        if current.revoked:
            raise ValueError(f"token slot {agent_id}/{normalized_slot} is revoked; issue a new one deliberately")
        if not current.scopes:
            raise ValueError(f"token slot {agent_id}/{normalized_slot} has no scopes to renew")
        return _issue_token_unlocked(vault_root, agent_id, scopes=list(current.scopes), ttl_days=ttl_days, slot=normalized_slot)


def revoke_token(vault: Path, agent_id: str, slot: str | None = None) -> TokenRecord:
    vault_root = vault.resolve()
    agent_id = _validate_agent_id(agent_id)
    normalized_slot = _validate_token_slot(slot)
    with _token_slot_lock(vault_root, agent_id, normalized_slot):
        path = _token_path(vault_root, agent_id, normalized_slot)
        if not path.is_file():
            raise FileNotFoundError(f"no token issued for agent: {agent_id} slot={normalized_slot}")
        record = json.loads(path.read_text(encoding="utf-8"))
        record["revoked"] = True
        record["revoked_at"] = _now()
        record["slot"] = normalized_slot
        _write_record(path, record)
        return _record_from_payload(record)


def list_tokens(vault: Path) -> TokenListResult:
    tokens_dir = vault.resolve() / TOKENS_DIR
    records: list[TokenRecord] = []
    if tokens_dir.exists():
        for path in sorted(tokens_dir.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                # A record that is valid JSON but not an object is exactly as
                # unreadable as a malformed one. Skip it here, like the JSON case,
                # so one stray file cannot raise AttributeError out of every caller
                # (including the watchdog tick).
                continue
            records.append(_record_from_payload(payload))
    return TokenListResult(tokens=records)


TOKEN_EXPIRY_WARN_DAYS = 7


def expiring_tokens(
    vault: Path, *, now: datetime | None = None, within_days: int = TOKEN_EXPIRY_WARN_DAYS
) -> list[dict[str, object]]:
    """Live (unrevoked) tokens already expired or expiring within ``within_days``.

    Metadata only — never the hash. Every agent token so far was issued with the
    30-day default on the same night, so without this the whole fleet loses AMC at
    once with no warning (Keeper's provider slot did, silently, for six days).
    A record without an expiry never expires and is not reported.
    """
    if within_days < 0:
        raise ValueError("within_days must not be negative")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        # Comparing a naive clock against an aware expiry raises TypeError deep in
        # the loop; refuse an ambiguous clock up front instead.
        raise ValueError("now must be timezone-aware")
    horizon = current + timedelta(days=within_days)
    found: list[dict[str, object]] = []
    for record in list_tokens(vault).tokens:
        if record.revoked or not record.expires_at:
            continue
        try:
            expires = datetime.fromisoformat(record.expires_at.replace("Z", "+00:00"))
        except ValueError:
            expires = None
        if expires is None or expires.tzinfo is None:
            # An unparseable *or* timezone-less expiry cannot be compared with an
            # aware "now". Report it as malformed metadata rather than raising: this
            # runs inside the watchdog tick, and one bad record must not abort the
            # whole autonomy sweep with it.
            found.append({"agent_id": record.agent_id, "slot": record.slot, "expires_at": record.expires_at,
                          "expired": True, "malformed": True})
            continue
        if expires <= horizon:
            found.append({"agent_id": record.agent_id, "slot": record.slot, "expires_at": record.expires_at,
                          "expired": expires <= current})
    return sorted(found, key=lambda item: (str(item["expires_at"]), str(item["agent_id"]), str(item["slot"])))


def resolve_identity(
    vault: Path,
    authorization: str | None,
    shared_secret: str | None = None,
) -> Identity | None:
    """Map an Authorization header to an identity, or None."""
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    if shared_secret and hmac.compare_digest(value, shared_secret):
        return OPERATOR_IDENTITY
    return _resolve_agent_token(vault, value)


def tools_for_scopes(scopes: frozenset[str]) -> set[str]:
    tools: set[str] = set()
    for scope in scopes:
        tools.update(SCOPE_TOOLS.get(scope, ()))
    return tools


def _resolve_agent_token(vault: Path, token_value: str) -> Identity | None:
    tokens_dir = vault.resolve() / TOKENS_DIR
    if not tokens_dir.exists():
        return None
    hashed = _hash_token(token_value)
    for path in sorted(tokens_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("revoked"):
            continue
        expires_at = payload.get("expires_at")
        if expires_at is not None:
            try:
                if datetime.fromisoformat(str(expires_at).replace("Z", "+00:00")) <= datetime.now(UTC):
                    continue
            except (TypeError, ValueError):
                continue
        stored = str(payload.get("token_sha256", ""))
        if stored and hmac.compare_digest(stored, hashed):
            agent_id = str(payload.get("agent_id", path.stem))
            # Resolution is lenient (unlike issuance): keep only recognized
            # scopes instead of raising, so a token file carrying a since-
            # renamed/unknown scope cleanly grants less rather than 500-ing
            # the request and locking the agent out entirely.
            raw = payload.get("scopes", [])
            scopes = frozenset(str(scope) for scope in raw if str(scope) in ALL_SCOPES) if isinstance(raw, list) else frozenset()
            return Identity(agent_id=agent_id, scopes=scopes, kind="agent")
    return None


def _load_agent(vault_root: Path, agent_id: str) -> dict[str, object]:
    path = vault_root / "registry" / "agents" / f"{agent_id}.json"
    if not path.is_file():
        raise FileNotFoundError(f"agent is not registered in the vault registry: {agent_id}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"invalid agent registry record: {agent_id}")
    return payload


def _validate_agent_id(agent_id: str) -> str:
    value = agent_id.strip()
    if not AGENT_ID_RE.fullmatch(value):
        raise ValueError(f"invalid agent id: {agent_id!r}")
    return value


def _validate_token_slot(slot: str | None) -> str:
    if slot is None:
        return "default"
    value = slot.strip()
    if not TOKEN_SLOT_RE.fullmatch(value) or "--" in value:
        raise ValueError(f"invalid token slot: {slot!r}")
    return value


def _token_path(vault_root: Path, agent_id: str, slot: str) -> Path:
    filename = f"{agent_id}.json" if slot == "default" else f"{agent_id}.{slot}.json"
    return vault_root / TOKENS_DIR / filename


def _write_record(path: Path, record: dict[str, object]) -> None:
    payload = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        if hasattr(os, "fchmod"):
            private_paths.apply_mode(fd=fd, mode=0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        safe_open.replace_path(tmp_name, path)
        if True:
            directory_fd = safe_open.open_directory(path.parent)
            try:
                safe_open.fsync_directory(directory_fd)
            finally:
                os.close(directory_fd)
    except BaseException:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


def _validate_scopes(raw: object) -> frozenset[str]:
    if not isinstance(raw, list):
        raise ValueError("scopes must be a list of scope names")
    scopes = {str(scope) for scope in raw}
    unknown = scopes - ALL_SCOPES
    if unknown:
        raise ValueError(f"unknown scopes: {', '.join(sorted(unknown))}")
    return frozenset(scopes)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _record_from_payload(payload: dict[str, object]) -> TokenRecord:
    # A null/missing expiry means "never expires" — the resolver already reads it that
    # way, so ``str(None)`` must not turn it into the literal "None" and have the
    # expiry watch report a healthy slot as a malformed, already-expired token.
    expires_raw = payload.get("expires_at")
    scopes_raw = payload.get("scopes", [])
    return TokenRecord(
        agent_id=str(payload.get("agent_id", "")),
        scopes=[str(scope) for scope in scopes_raw if isinstance(scope, str)] if isinstance(scopes_raw, list) else [],
        issued_at=str(payload.get("issued_at", "")),
        revoked=bool(payload.get("revoked", False)),
        expires_at="" if expires_raw is None else str(expires_raw),
        slot=str(payload.get("slot", "default")),
    )


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
