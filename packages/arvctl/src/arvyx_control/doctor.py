from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re

from .index import frontmatter_text, is_forbidden_relative, searchable_text
from .security import contains_literal_secret

# Obsidian wikilink target: everything up to the first ], |, or # (alias and
# heading fragments are stripped so [[Note#heading|alias]] resolves to "Note").
WIKILINK_RE = re.compile(r"\[\[([^\[\]|#\n]+)")

REQUIRED_PROJECT_DOCS = {
    "OVERVIEW.md",
    "STATUS.md",
    "DECISIONS.md",
    "RUNBOOK.md",
    "OPEN_QUESTIONS.md",
}

REGISTRY_REQUIRED_FIELDS = {
    "agents": {"id", "display_name", "machine_id", "runtime_id", "scopes"},
    "machines": {"id", "display_name", "role"},
    "runtimes": {"id", "display_name", "harness"},
    "projects": {"id", "display_name", "owner_agent_id"},
}


@dataclass(frozen=True)
class DoctorFinding:
    severity: str
    code: str
    message: str
    path: str | None = None

    def to_dict(self) -> dict[str, str]:
        payload = {"severity": self.severity, "code": self.code, "message": self.message}
        if self.path:
            payload["path"] = self.path
        return payload


@dataclass(frozen=True)
class DoctorResult:
    ok: bool
    checked_files: int
    indexed_files: int
    registry_files: int
    findings: list[DoctorFinding]

    def to_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "checked_files": self.checked_files,
            "indexed_files": self.indexed_files,
            "registry_files": self.registry_files,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass
class _NoteInfo:
    relative: str
    title: str
    names: set[str]
    links: list[str]
    has_real_title: bool = field(default=False)
    is_note: bool = field(default=False)


def doctor(vault: Path) -> DoctorResult:
    findings: list[DoctorFinding] = []
    notes: list[_NoteInfo] = []
    checked_files = 0
    indexed_files = 0

    if not vault.exists():
        return DoctorResult(
            ok=False,
            checked_files=0,
            indexed_files=0,
            registry_files=0,
            findings=[
                DoctorFinding(
                    severity="error",
                    code="vault_missing",
                    message=f"vault does not exist: {vault}",
                )
            ],
        )

    projects_dir = vault / "projects"
    if not projects_dir.exists():
        findings.append(
            DoctorFinding(
                severity="error",
                code="projects_missing",
                message="vault is missing projects/ directory",
                path="projects",
            )
        )
    else:
        for project_dir in sorted(path for path in projects_dir.iterdir() if path.is_dir()):
            present = {path.name for path in project_dir.glob("*.md")}
            for missing in sorted(REQUIRED_PROJECT_DOCS - present):
                findings.append(
                    DoctorFinding(
                        severity="warning",
                        code="project_doc_missing",
                        message=f"project is missing {missing}",
                        path=(project_dir / missing).relative_to(vault).as_posix(),
                    )
                )

    for path in sorted(vault.rglob("*.md")):
        checked_files += 1
        if is_forbidden_relative(path.relative_to(vault).as_posix()):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            # a concurrent promote/refine can move a source file (e.g. an
            # imported-lane doc) between rglob and read; skip it rather than crash
            checked_files -= 1
            continue
        indexed_files += 1
        notes.append(_note_info(path.relative_to(vault).as_posix(), text))
        if _needs_frontmatter(path, vault) and not _has_frontmatter(text):
            findings.append(
                DoctorFinding(
                    severity="warning",
                    code="frontmatter_missing",
                    message="curated memory file should include Obsidian-friendly frontmatter",
                    path=path.relative_to(vault).as_posix(),
                )
            )
        # Same detector as every write lane: literal secret shapes are findings,
        # sanctioned secret://broker/path references are not (they carry no value).
        if contains_literal_secret(text):
            findings.append(
                DoctorFinding(
                    severity="error",
                    code="secret_shape",
                    message="curated memory file contains a secret-shaped string",
                    path=path.relative_to(vault).as_posix(),
                )
            )

    _check_graph(notes=notes, findings=findings)
    registry_files = _check_registry(vault=vault, findings=findings)
    return DoctorResult(
        ok=not any(finding.severity == "error" for finding in findings),
        checked_files=checked_files,
        indexed_files=indexed_files,
        registry_files=registry_files,
        findings=findings,
    )


def _note_info(relative: str, text: str) -> _NoteInfo:
    # Parse links and the heading from body text with frontmatter and fenced
    # code blocks stripped (same normalization the index uses), so a [[link]]
    # or "# heading" shown inside a code example is not mistaken for a real
    # link or the note's title.
    body = searchable_text(text)
    heading = _first_heading(body)
    stem = relative.rsplit("/", 1)[-1].removesuffix(".md")
    fields = _frontmatter_fields(text)
    real_title = heading or fields.get("title") or fields.get("id")
    title = real_title or stem
    names = {_norm(name) for name in (title, stem, heading, fields.get("id"), fields.get("title")) if name}
    links = [target.strip() for target in WIKILINK_RE.findall(body) if target.strip()]
    return _NoteInfo(
        relative=relative,
        title=title,
        names=names,
        links=links,
        has_real_title=real_title is not None,
        is_note="/notes/" in f"/{relative}",
    )


def _check_graph(notes: list[_NoteInfo], findings: list[DoctorFinding]) -> None:
    """Wikilink/graph health: broken links, duplicate titles, orphan notes."""
    resolvable: set[str] = set()
    all_targets: set[str] = set()
    for note in notes:
        resolvable |= note.names
        all_targets |= {_norm(link) for link in note.links}

    for note in notes:
        for target in sorted({link for link in note.links}):
            if _norm(target) not in resolvable:
                findings.append(
                    DoctorFinding(
                        severity="warning",
                        code="dangling_wikilink",
                        message=f"wikilink [[{target}]] resolves to no note",
                        path=note.relative,
                    )
                )

    # Group only notes with a real (heading/frontmatter) title, so two
    # untitled files that merely share a filename stem in different folders
    # are not flagged as a title clash.
    by_title: dict[str, list[str]] = {}
    for note in notes:
        if not note.has_real_title:
            continue
        by_title.setdefault(_norm(note.title), []).append(note.relative)
    for title, paths in sorted(by_title.items()):
        if len(paths) > 1:
            findings.append(
                DoctorFinding(
                    severity="warning",
                    code="duplicate_title",
                    message=f"{len(paths)} notes share the title '{title}': {', '.join(sorted(paths))}",
                    path=sorted(paths)[0],
                )
            )

    # Orphans matter for curated notes (promoted memory that should connect);
    # structural docs (project docs, READMEs) are expected to be terminal.
    for note in notes:
        if not note.is_note or note.links:
            continue
        if note.names & all_targets:
            continue
        findings.append(
            DoctorFinding(
                severity="info",
                code="orphan_note",
                message="curated note has no inbound or outbound wikilinks",
                path=note.relative,
            )
        )


def _first_heading(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return None


def _frontmatter_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in frontmatter_text(text).splitlines():
        key, _, value = line.partition(":")
        # strip surrounding YAML quotes so `title: "X"` matches a `[[X]]` link
        cleaned = value.strip().strip("'\"")
        if key.strip() in {"id", "title"} and cleaned:
            fields[key.strip()] = cleaned
    return fields


def _norm(value: str) -> str:
    return value.strip().lower()


def _check_registry(vault: Path, findings: list[DoctorFinding]) -> int:
    registry_root = vault / "registry"
    if not registry_root.exists():
        findings.append(
            DoctorFinding(
                severity="error",
                code="registry_missing",
                message="vault is missing registry/ directory",
                path="registry",
            )
        )
        return 0

    count = 0
    for kind, required_fields in REGISTRY_REQUIRED_FIELDS.items():
        kind_dir = registry_root / kind
        if not kind_dir.exists():
            findings.append(
                DoctorFinding(
                    severity="error",
                    code="registry_kind_missing",
                    message=f"registry is missing {kind}/ entries",
                    path=f"registry/{kind}",
                )
            )
            continue
        for path in sorted(kind_dir.glob("*.json")):
            count += 1
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                findings.append(
                    DoctorFinding(
                        severity="error",
                        code="registry_json_invalid",
                        message=f"invalid JSON: {exc.msg}",
                        path=path.relative_to(vault).as_posix(),
                    )
                )
                continue
            missing = sorted(required_fields - set(payload))
            if missing:
                findings.append(
                    DoctorFinding(
                        severity="error",
                        code="registry_fields_missing",
                        message=f"missing required fields: {', '.join(missing)}",
                        path=path.relative_to(vault).as_posix(),
                    )
                )
    return count


def _needs_frontmatter(path: Path, vault: Path) -> bool:
    relative = path.relative_to(vault)
    if len(relative.parts) >= 3 and relative.parts[0] == "projects":
        return path.name in REQUIRED_PROJECT_DOCS
    return len(relative.parts) >= 3 and relative.parts[0] == "agents" and path.name == "MEMORY.md"


def _has_frontmatter(text: str) -> bool:
    return text.startswith("---\n") and "\n---\n" in text[4:]
