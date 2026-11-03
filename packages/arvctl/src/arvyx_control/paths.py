from __future__ import annotations

import os
from pathlib import Path
import re

from . import safe_open


PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def validate_project_id(project: str) -> str:
    value = project.strip()
    if not PROJECT_ID_RE.fullmatch(value):
        raise ValueError(f"invalid project id: {project!r}")
    return safe_open.component(value)


def resolve_under(root: Path, *parts: str) -> Path:
    """The resolved path of ``parts`` under ``root``, refused unless it stays inside.

    Both sides are resolved (``safe_open.resolve_path``) and compared as normalized text
    with a prefix check, the form path-injection analysis recognizes; the returned path
    is built from the checked text.
    """
    root_resolved = safe_open.resolve_path(root)
    root_text = os.path.normpath(str(root_resolved))
    # Lexical containment first (no filesystem access on an unchecked path), then the
    # resolved path (symlinks) is checked the same way.
    candidate_text = os.path.normpath(os.path.join(root_text, *parts)) if parts else root_text
    if candidate_text == root_text:
        return Path(root_text)
    if not candidate_text.startswith(root_text + os.sep):
        raise ValueError(f"refusing path outside root: {candidate_text}")
    target_text = os.path.normpath(str(safe_open.resolve_path(candidate_text)))
    if target_text == root_text:
        return Path(root_text)
    if not target_text.startswith(root_text + os.sep):
        raise ValueError(f"refusing path outside root: {target_text}")
    return Path(target_text)
