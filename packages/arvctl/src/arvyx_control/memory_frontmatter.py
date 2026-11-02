"""Shared logical-newline boundary for governed memory metadata.

Callers retaining recovery originals must keep the original bytes separately.
"""
from __future__ import annotations

import json
import re


def split_frontmatter(text: str) -> tuple[str | None, str]:
    """Return a complete leading metadata block and body using LF newlines."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    match = re.match(r"\A---\n(.*?)\n---(?:\n|\Z)", normalized, flags=re.DOTALL)
    if match is None:
        return None, normalized
    return match.group(1), normalized[match.end():]


def frontmatter_values(text: str) -> dict[str, str]:
    head, _ = split_frontmatter(text)
    values: dict[str, str] = {}
    for line in (head or "").splitlines():
        key, separator, value = line.partition(":")
        if separator:
            values[key.strip()] = value.strip()
    return values


def metadata_json(value: object) -> str:
    """Encode metadata without any literal logical line separators.

    ASCII escaping also covers Unicode separators recognized by splitlines();
    scalar_value/json.loads recover the literal value without lossy sanitizing.
    """
    return json.dumps(value, ensure_ascii=True)


def collapse_metadata_lines(value: str) -> str:
    """Collapse every line boundary recognized by the metadata reader."""
    return " ".join(value.splitlines())


def scalar_value(raw: str) -> str:
    value = raw.strip()
    if value.startswith('"'):
        try:
            decoded = json.loads(value)
        except ValueError:
            pass  # Preserve legacy quoted scalar handling for non-JSON metadata.
        else:
            if isinstance(decoded, str):
                return decoded
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1].strip()
    return value


def render_frontmatter(head: str, body: str) -> str:
    """Render one complete LF metadata block, never a second nested block."""
    return f"---\n{head}\n---\n{body}"
