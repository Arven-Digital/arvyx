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


def _comparable(text: str) -> str:
    """Drop the Windows extended-length prefix so both sides of a check match.

    Path.resolve() may add the extended-length prefix while the root text does not.
    Those name the same path. The prefix is not a way out of the root.
    """
    unc = '\\\\?\\UNC\\'
    extended = '\\\\?\\'
    if text.startswith(unc):
        return '\\\\' + text[len(unc):]
    if text.startswith(extended):
        return text[len(extended):]
    return text


def _stays_inside(root_text: str, candidate_text: str) -> bool:
    root_cmp = _comparable(root_text)
    candidate_cmp = _comparable(candidate_text)
    if candidate_cmp == root_cmp:
        return True
    separator = '\\' if '\\' in root_cmp or '\\' in candidate_cmp else os.sep
    return candidate_cmp.startswith(root_cmp + separator)


def resolve_under(root: Path, *parts: str) -> Path:
    """The resolved path of ``parts`` under ``root``, refused unless it stays inside.

    Both sides are resolved (``safe_open.resolve_path``) and compared as normalized text
    with a prefix check, the form path-injection analysis recognizes; the returned path
    is built from the checked text.
    """
    root_resolved = safe_open.resolve_path(root)
    root_text = os.path.normpath(str(root_resolved))
    # Lexical containment first (no filesystem access on an unchecked path), then the
    # resolved path (symlinks) is checked the same way. The Windows \\?\ prefix is
    # ignored on both sides so a resolved name is not refused as outside.
    candidate_text = os.path.normpath(os.path.join(root_text, *parts)) if parts else root_text
    if _stays_inside(root_text, candidate_text) and _comparable(candidate_text) == _comparable(root_text):
        return Path(root_text)
    if not _stays_inside(root_text, candidate_text):
        raise ValueError(f"refusing path outside root: {candidate_text}")
    target_text = os.path.normpath(str(safe_open.resolve_path(candidate_text)))
    if _comparable(target_text) == _comparable(root_text):
        return Path(root_text)
    if not _stays_inside(root_text, target_text):
        raise ValueError(f"refusing path outside root: {target_text}")
    return Path(target_text)
