from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC
from datetime import datetime
import json
import os
import tempfile
from pathlib import Path
import re

from .locks import vault_lock
from .paths import resolve_under
from .security import contains_literal_secret, redact_secrets


# Hot working memory, ported from the v1 vault's SESSION-STATE.md: an
# agent's "what am I doing right now" scratch. Unlike curated memory it is
# written directly by the owning agent (no review lane) because it is
# volatile state, not durable truth — but it is still identity-bound,
# secret-linted, and excluded from recall. Explicit checkpoint reads use the
# session.read scope; digest inclusion is governed by that same session scope.
SESSION_FILENAME = "SESSION-STATE.md"
AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
MAX_SESSION_BYTES = 64 * 1024


@dataclass(frozen=True)
class SessionResult:
    agent: str
    path: str
    updated_at: str
    content: str

    def to_dict(self) -> dict[str, object]:
        return {
            "agent": self.agent,
            "path": self.path,
            "updated_at": self.updated_at,
            "content": self.content,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def set_session(vault: Path, agent: str, content: str) -> SessionResult:
    """Replace an agent's hot session state. The agent owns this file."""
    vault_root = vault.resolve()
    agent = _validate_agent(agent)
    content = content.strip()
    if not content:
        raise ValueError("session content must not be empty")
    if len(content.encode("utf-8")) > MAX_SESSION_BYTES:
        raise ValueError("session content exceeds size cap")
    if contains_literal_secret(content):
        raise ValueError(
            "session content contains a secret-shaped string; store a "
            "secret://broker/path reference instead of the literal value"
        )
    with vault_lock(vault_root):
        from .replica_authority import assert_mutation_authority
        assert_mutation_authority(vault_root)
        target = resolve_under(vault_root, "agents", agent, SESSION_FILENAME)
        from .filesystem import durable_mkdir
        durable_mkdir(target.parent)
        updated_at = _now()
        payload = (
            "---\n"
            f"id: {agent}-session\n"
            "type: session-state\n"
            f"agent: {agent}\n"
            f"updated_at: {updated_at}\n"
            "---\n\n"
            f"# {agent} Session State\n\n"
            f"{content}\n"
        )
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent,
                                             prefix=".session-", suffix=".tmp", delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            directory = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return SessionResult(
        agent=agent,
        path=target.relative_to(vault_root).as_posix(),
        updated_at=updated_at,
        content=content,
    )


def get_session(vault: Path, agent: str) -> SessionResult:
    """Read an agent's hot session state for a zero-ramp-up session start."""
    vault_root = vault.resolve()
    agent = _validate_agent(agent)
    target = resolve_under(vault_root, "agents", agent, SESSION_FILENAME)
    if not target.is_file():
        raise FileNotFoundError(f"no session state for agent: {agent}")
    raw = target.read_text(encoding="utf-8")
    updated_at = _frontmatter_value(raw, "updated_at")
    body = _strip_frontmatter(raw).lstrip("\n")
    body = re.sub(r"\A#\s.*\n+", "", body, count=1)  # drop the generated heading
    return SessionResult(
        agent=agent,
        path=target.relative_to(vault_root).as_posix(),
        updated_at=updated_at,
        content=redact_secrets(body.strip()),
    )


def _validate_agent(agent: str) -> str:
    value = agent.strip()
    if not AGENT_ID_RE.fullmatch(value):
        raise ValueError(f"invalid agent id: {agent!r}")
    return value


def _frontmatter_value(text: str, key: str) -> str:
    match = re.match(r"\A---\n(.*?)\n---\n", text, flags=re.DOTALL)
    if not match:
        return ""
    found = re.search(rf"^{key}:\s*(.+)$", match.group(1), flags=re.MULTILINE)
    return found.group(1).strip() if found else ""


def _strip_frontmatter(text: str) -> str:
    return re.sub(r"\A---\n.*?\n---\n", "", text, flags=re.DOTALL)


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
