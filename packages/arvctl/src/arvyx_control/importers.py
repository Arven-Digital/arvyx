from __future__ import annotations

from contextlib import closing, nullcontext
from dataclasses import dataclass
from datetime import UTC
from datetime import datetime
import json
import os
from pathlib import Path
import re
import stat
import uuid

from . import safe_open
from .filesystem import MAX_MEMORY_DOCUMENT_BYTES, durable_mkdir, fsync_directory, memory_document_bytes
from .memory_frontmatter import render_frontmatter, split_frontmatter

from .promotion_transaction import memory_mutation
from .security import contains_literal_secret
from .paths import resolve_under, validate_project_id

MAX_IMPORT_ENTRIES = 10_000
MAX_IMPORT_FILES = 256
MAX_IMPORT_FILE_BYTES = MAX_MEMORY_DOCUMENT_BYTES
MAX_IMPORT_TOTAL_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class ImportResult:
    imported: list[str]
    skipped: list[str]
    dry_run: bool = False
    manifest_path: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "imported": self.imported,
            "skipped": self.skipped,
            "dry_run": self.dry_run,
            "manifest_path": self.manifest_path,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def import_markdown(source: Path, vault: Path, project: str, dry_run: bool = False) -> ImportResult:
    return _import_markdown(
        source=source,
        vault=vault,
        project=project,
        target_lane="imported",
        source_type="imported-markdown",
        tags=["imported"],
        dry_run=dry_run,
    )


def import_obsidian(source: Path, vault: Path, project: str, dry_run: bool = False) -> ImportResult:
    return _import_markdown(
        source=source,
        vault=vault,
        project=project,
        target_lane="imported/obsidian",
        source_type="imported-obsidian",
        tags=["imported", "obsidian"],
        dry_run=dry_run,
    )


def import_basic_memory(source: Path, vault: Path, project: str, dry_run: bool = False) -> ImportResult:
    return _import_markdown(
        source=source,
        vault=vault,
        project=project,
        target_lane="imported/basic-memory",
        source_type="imported-basic-memory",
        tags=["imported", "basic-memory"],
        dry_run=dry_run,
    )


def _import_markdown(
    source: Path,
    vault: Path,
    project: str,
    target_lane: str,
    source_type: str,
    tags: list[str],
    dry_run: bool,
) -> ImportResult:
    if not source.exists():
        raise FileNotFoundError(source)
    if source.is_symlink():
        raise ValueError(f"refusing symlink import source: {source}")
    vault_root = vault.resolve()
    project = validate_project_id(project)
    # Capture bounded source bytes before taking the mutation lock.
    captured, skipped = _capture_inputs(source)
    # Wrapper/metadata expansion must fit the same stored-byte bound as every
    # lifecycle reader. Validate the whole import, including dry-run, before
    # publishing any member of the batch.
    rendered = [(path, memory_document_bytes(_wrap_import(
        path=path, text=text, project=project, source_type=source_type, tags=tags,
    ))) for path, text in captured]
    with nullcontext() if dry_run else memory_mutation(vault_root):
        target_root = resolve_under(vault_root, "projects", project, *target_lane.split("/"))
        if not dry_run:
            durable_mkdir(target_root)

        imported: list[str] = []
        used = set()
        if target_root.exists():
            with os.scandir(target_root) as entries:
                for number, entry in enumerate(entries, 1):
                    if number > MAX_IMPORT_ENTRIES:
                        raise ValueError('import destination enumeration budget exceeded')
                    used.add(entry.name)
        for path, payload in rendered:
            target = _unique_target(target_root=target_root, stem=_slug(path.stem), used=used)
            _assert_under(target, vault_root)
            used.add(target.name)
            if not dry_run:
                from .import_publication import publish
                publish(vault_root,target,payload)
            imported.append(target.relative_to(vault_root).as_posix())
        manifest_path = _write_manifest(
            vault=vault,
            target_root=target_root,
            project=project,
            source_type=source_type,
            imported=imported,
            skipped=skipped,
            dry_run=dry_run,
        )
        return ImportResult(imported=imported, skipped=skipped, dry_run=dry_run, manifest_path=manifest_path)


def _write_manifest(
    vault: Path,
    target_root: Path,
    project: str,
    source_type: str,
    imported: list[str],
    skipped: list[str],
    dry_run: bool,
) -> str | None:
    if dry_run:
        return None
    manifest = target_root / "import-manifest.jsonl"
    event = {
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "project": project,
        "source_type": source_type,
        "imported": imported,
        "skipped": skipped,
        "imported_count": len(imported),
        "skipped_count": len(skipped),
    }
    with manifest.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    fsync_directory(target_root)
    return manifest.relative_to(vault.resolve()).as_posix()


def _wrap_import(path: Path, text: str, project: str, source_type: str, tags: list[str]) -> str:
    head, normalized = split_frontmatter(text)
    if head is not None:
        body = render_frontmatter(head, normalized)
    else:
        tag_text = ", ".join(tags)
        body = (
            "---\n"
            f"id: imported-{_slug(path.stem)}\n"
            f"type: {source_type}\n"
            f"project: {project}\n"
            f"tags: [{tag_text}]\n"
            "---\n\n"
            f"# {path.stem}\n\n"
            f"{text.strip()}\n"
        )
    return body.rstrip() + "\n"


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    slug = slug or 'note'
    if len(slug.encode()) > 160:
        import hashlib
        slug = slug[:135] + '-' + hashlib.sha256(slug.encode()).hexdigest()[:24]
    return slug


def _unique_target(target_root: Path, stem: str, used: set[str]) -> Path:
    name = f"{stem}.md"
    if name not in used and not (target_root / name).exists():
        return target_root / name
    index = 2
    while index <= 1024:
        candidate = f"{stem}-{index}.md"
        if candidate not in used and not (target_root / candidate).exists():
            return target_root / candidate
        index += 1
    raise ValueError('import filename collision budget exhausted')


def _capture_inputs(source: Path):
    captured, skipped = [], []
    count, total, files = 0, 0, 0

    def capture(parent_fd, name, path):
        nonlocal total, files
        if path.suffix.lower() != '.md':
            return
        files += 1
        if files > MAX_IMPORT_FILES:
            raise ValueError('import file budget exceeded')
        fd = safe_open.open_file_at(parent_fd, name)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError('import requires regular source files')
            data = stream.read(MAX_IMPORT_FILE_BYTES + 1)
        total += len(data)
        if len(data) > MAX_IMPORT_FILE_BYTES or total > MAX_IMPORT_TOTAL_BYTES:
            raise ValueError('import byte budget exceeded')
        text = data.decode('utf-8')
        if contains_literal_secret(text) or contains_literal_secret(path.stem):
            skipped.append(f'input-{files}:rejected')
        else:
            captured.append((path, text))

    def walk(fd, path, depth):
        nonlocal count
        if depth > 32:
            raise ValueError('import depth budget exceeded')
        with closing(safe_open.scandir_names(fd)) as names_iter:
            for name in names_iter:
                count += 1
                if count > MAX_IMPORT_ENTRIES:
                    raise ValueError('import enumeration budget exceeded')
                info = safe_open.stat_at(fd, name)
                child_path = path / name
                if stat.S_ISDIR(info.st_mode):
                    child = safe_open.open_directory_at(fd, name)
                    try:
                        walk(child, child_path, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode):
                    capture(fd, name, child_path)
                elif name.lower().endswith('.md'):
                    skipped.append(f'input-entry-{count}:outside-source')

    if source.is_file():
        fd = safe_open.open_directory(source.parent)
        try:
            capture(fd, source.name, source)
        finally:
            os.close(fd)
    else:
        fd = safe_open.open_directory(source)
        try:
            walk(fd, source, 0)
        finally:
            os.close(fd)
    return sorted(captured, key=lambda item: item[0].as_posix()), skipped


def _within(path: Path, root: Path) -> bool:
    resolved = path.resolve()
    return resolved == root or root in resolved.parents


def _assert_under(path: Path, root: Path) -> None:
    try:
        path.resolve().relative_to(root)
    except ValueError as exc:
        raise ValueError(f"refusing to write outside vault: {path}") from exc
