from __future__ import annotations

from pathlib import Path
import re

from . import safe_open


PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


def validate_project_id(project: str) -> str:
    value = project.strip()
    if not PROJECT_ID_RE.fullmatch(value):
        raise ValueError(f"invalid project id: {project!r}")
    return value


def resolve_under(root: Path, *parts: str) -> Path:
    root_resolved = safe_open.resolve_path(root)
    target = safe_open.resolve_path(root_resolved.joinpath(*parts))
    if target != root_resolved and root_resolved not in target.parents:
        raise ValueError(f"refusing path outside root: {target}")
    return target
