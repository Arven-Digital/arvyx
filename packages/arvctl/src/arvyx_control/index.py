from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Any, Iterable, Iterator, cast

from .embeddings import EmbeddingConfig, EmbeddingError, embed_texts
from .filesystem import durable_mkdir, fsync_directory
from .locks import exclusive_lock
from .paths import PROJECT_ID_RE, resolve_under
from .memory_frontmatter import frontmatter_values, scalar_value, split_frontmatter


# Format 6 invalidates pre-fence-aware partitions, terms and vectors.
INDEX_FORMAT = 6
INDEX_RELATIVE = Path(".arvyx") / "index.json"
WORD_RE = re.compile(r"[a-z0-9][a-z0-9_.-]*", re.IGNORECASE)
FORBIDDEN_SEGMENTS = {"archive", "raw", "pending", "refining", ".git", ".arvyx"}
INDEXED_ROOTS = ("projects", "agents")
_FRONTMATTER_DATE_KEYS = ("updated_at", "promoted_at", "created_at", "date")
_EMBED_TEXT_CHARS = 2000


@dataclass(frozen=True)
class IndexedChunk:
    relative_path: str
    start_line: int
    end_line: int
    heading: str
    terms: dict[str, int]
    length: int
    timestamp: float = 0.0
    vector: tuple[float, ...] | None = None
    # Request-local redacted snapshot; never serialized into the derived cache.
    snapshot_text: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "relative_path": self.relative_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "heading": self.heading,
            "terms": self.terms,
            "length": self.length,
            "timestamp": self.timestamp,
        }
        if self.vector is not None:
            payload["vector"] = list(self.vector)
        return payload


def is_forbidden_relative(relative_path: str) -> bool:
    parts = relative_path.split("/")
    # A curated project note has an identifier in slot 1, not a lane.
    # Keep legacy projects/archive/*.md and every actual excluded lane hidden.
    if (len(parts) >= 4 and parts[0] == "projects" and parts[2] == "notes"
            and PROJECT_ID_RE.fullmatch(parts[1])):
        checked = parts[:1] + parts[2:]
    else:
        checked = parts
    return (PurePosixPath(relative_path).name == "SESSION-STATE.md"
            or any(part in FORBIDDEN_SEGMENTS for part in checked))


def load_index(vault: Path, embed_config: EmbeddingConfig | None = None,
               *, prefixes: tuple[str, ...] = ("projects/", "agents/")) -> list[IndexedChunk]:
    """Build scoped chunks from one immutable byte snapshot per source.

    Provider I/O holds no vault lock. Concurrent cache writers may lose derived
    work, but cannot mix source generations: every reader validates source bytes.
    Scoped publication preserves unrelated entries from the latest artifact.
    """
    from dataclasses import replace
    from .security import redact_secrets
    vault = vault.resolve()
    cached = _read_cache(vault)
    current = _current_file_stats(vault, prefixes=prefixes)
    fingerprint = embed_config.fingerprint() if embed_config is not None else None
    files: dict[str, dict[str, object]] = {}
    snapshots: dict[str, str] = {}
    for relative, expected in current.items():
        snapshot = _source_snapshot(vault, relative)
        if snapshot is None or snapshot[0] != expected:
            continue
        (mtime_ns, size, content_hash), text = snapshot
        snapshots[relative] = redact_secrets(text)
        entry = cached.get(relative)
        if _valid_cached_entry(relative, entry, content_hash, mtime_ns, size,
                               text=snapshots[relative]):
            # Deep-copy before attaching new vectors to nested cache rows.
            files[relative] = json.loads(json.dumps(entry))
        else:
            files[relative] = {
                "mtime_ns": mtime_ns, "size": size, "content_hash": content_hash,
                "chunks": [c.to_dict() for c in _index_file(
                    vault, relative, mtime_ns, text=snapshots[relative])],
            }
    if embed_config is not None:
        _embed_missing(vault, files, fingerprint, embed_config, snapshots=snapshots)
    # Drop changed/superseded generations, including changes during provider I/O.
    files = {r: e for r, e in files.items()
             if _current_file_stat(vault, r) == current[r]}
    try:
        _write_scoped_cache(vault, files, prefixes)
    except OSError:
        pass
    return [replace(_decode_cached_chunk(
                relative, raw,
                include_vector=entry.get("emb_fingerprint") == fingerprint),
                snapshot_text="\n".join(snapshots[relative].splitlines()[
                    raw["start_line"] - 1:raw["end_line"]]))
            for relative, entry in sorted(files.items()) for raw in cast(list[dict[str, Any]], entry["chunks"])]


def _embed_missing(
    vault: Path,
    files: dict[str, dict[str, object]],
    fingerprint: str | None,
    embed_config: EmbeddingConfig,
    *, snapshots: dict[str, str] | None = None,
) -> bool:
    """Embed chunks whose file changed or whose provider fingerprint is stale."""
    pending: list[tuple[str, int]] = []
    for relative, entry in files.items():
        if entry.get("emb_fingerprint") == fingerprint and all(
            "vector" in chunk for chunk in entry["chunks"]
        ):
            continue
        for index in range(len(entry["chunks"])):
            pending.append((relative, index))
    if not pending:
        return False
    texts = [
        _read_chunk_embed_text(vault, cast(list[dict[str, Any]], files[relative]["chunks"])[index],
                               text=snapshots[relative] if snapshots is not None else None)
        for relative, index in pending
    ]
    try:
        vectors = embed_texts(embed_config, texts)
    except EmbeddingError:
        # Network/config trouble must never break recall: stay lexical and
        # do not poison the cache with a stale fingerprint.
        return False
    for (relative, index), vector in zip(pending, vectors):
        cast(list[dict[str, Any]], files[relative]["chunks"])[index]["vector"] = list(vector)
    for relative, _ in pending:
        files[relative]["emb_fingerprint"] = fingerprint
    return True


def _read_chunk_embed_text(vault: Path, raw: dict[str, object], *, text: str | None = None) -> str:
    relative = raw.get("relative_path")
    if not isinstance(relative, str):
        raise ValueError("invalid cached chunk path")
    chunk = _decode_cached_chunk(relative, raw)
    path = _resolve_indexed_path(vault, chunk.relative_path)
    from .security import redact_secrets
    # Redact in document context before selecting or clipping: a chunk can
    # begin inside a PEM block or after a cross-line credential label.
    lines = redact_secrets(text if text is not None else path.read_text(encoding="utf-8")).splitlines()
    start = chunk.start_line
    body = "\n".join(_prose_lines("\n".join(lines))[start - 1 : chunk.end_line])
    # Never trust a legacy cache heading stripped of its document context.
    heading = redact_secrets(path.name)
    for line in _prose_lines("\n".join(lines))[:start]:
        if line.startswith("#"):
            heading = line.lstrip("#").strip() or redact_secrets(path.name)
    return f"{heading}\n{searchable_text(body)}"[:_EMBED_TEXT_CHARS]


def chunk_text(vault: Path, chunk: IndexedChunk) -> str:
    if chunk.snapshot_text is not None:
        return chunk.snapshot_text
    path = _resolve_indexed_path(vault, chunk.relative_path)
    from .security import redact_secrets
    lines = redact_secrets(path.read_text(encoding="utf-8")).splitlines()
    return "\n".join(lines[chunk.start_line - 1 : chunk.end_line])


def _decode_cached_chunk(
    relative: str, raw: object, *, include_vector: bool = True
) -> IndexedChunk:
    """Decode the complete persisted chunk contract or raise ValueError.

    JSON types are checked before conversion: bools, fractional counts and
    non-finite numbers are corruption, not values to silently coerce.
    Timestamp omission remains compatible with legacy lexical entries.
    """
    if not isinstance(raw, dict) or raw.get("relative_path") != relative:
        raise ValueError("invalid cached chunk path")
    heading = raw.get("heading")
    if not isinstance(heading, str):
        raise ValueError("invalid cached heading")
    start, end, length = (raw.get(key) for key in ("start_line", "end_line", "length"))
    if (
        not isinstance(start, int) or isinstance(start, bool)
        or not isinstance(end, int) or isinstance(end, bool)
        or not isinstance(length, int) or isinstance(length, bool)
    ):
        raise ValueError("invalid cached chunk counts")
    if start < 1 or end < start or length < 0 or max(start, end, length) > 2**53:
        raise ValueError("invalid cached chunk range")
    terms = raw.get("terms")
    if not isinstance(terms, dict) or any(
        not isinstance(key, str) or type(value) is not int or value < 0 or value > 2**53
        for key, value in terms.items()
    ):
        raise ValueError("invalid cached terms")

    def finite_number(value: object) -> float:
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise ValueError("invalid cached numeric value")
        try:
            number = float(value)
        except OverflowError as exc:
            raise ValueError("cached numeric value overflows") from exc
        if not math.isfinite(number):
            raise ValueError("non-finite cached numeric value")
        return number

    timestamp = finite_number(raw.get("timestamp", 0.0))
    vector = raw.get("vector")
    if vector is not None and not isinstance(vector, list):
        raise ValueError("invalid cached vector")
    decoded_vector = tuple(finite_number(value) for value in vector) if vector is not None else None
    return IndexedChunk(
        relative_path=relative, start_line=start, end_line=end, heading=heading,
        terms=dict(terms), length=length, timestamp=timestamp,
        vector=decoded_vector if include_vector else None,
    )


def _valid_cached_entry(
    relative: str, entry: object, content_hash: str, mtime_ns: int, size: int,
    *, text: str,
) -> bool:
    """Accept cache data only when it still describes the scanned source file."""
    if (
        not isinstance(entry, dict)
        or entry.get("content_hash") != content_hash
        or entry.get("mtime_ns") != mtime_ns
        or entry.get("size") != size
    ):
        return False
    chunks = entry.get("chunks")
    if not isinstance(chunks, list) or (size > 0 and not chunks):
        return False
    from .security import redact_secrets
    lines = redact_secrets(text).splitlines()
    # Match the producer's complete heading partition, not just an EOF ceiling:
    # duplicated, missing, overlapping or truncated ranges also need rebuilding.
    starts = _heading_starts(lines)
    ends = [start - 1 for start in starts[1:]] + ([len(lines)] if lines else [])
    if len(chunks) != len(starts):
        return False
    fallback_heading = redact_secrets(PurePosixPath(relative).name)
    heading = fallback_heading
    expected_chunks: list[IndexedChunk] = []
    prose = _prose_lines("\n".join(lines))
    for start, end in zip(starts, ends):
        if prose[start - 1].startswith("#"):
            heading = prose[start - 1].lstrip("#").strip() or fallback_heading
        expected_chunks.append(_make_chunk(relative, start, end, heading, lines[start - 1:end],
                                           _file_timestamp(text, mtime_ns)))
    try:
        for raw, start, end, expected in zip(chunks, starts, ends, expected_chunks):
            chunk = _decode_cached_chunk(relative, raw)
            if (chunk.start_line, chunk.end_line) != (start, end):
                return False
            if (chunk.heading, chunk.terms, chunk.length, chunk.timestamp) != (
                    expected.heading, expected.terms, expected.length, expected.timestamp):
                return False
            # Token production is bounded by redacted source characters. Allow
            # marker expansion, but reject counts incompatible with source size.
            bound = max(1, size * 64)
            if chunk.length > bound or sum(chunk.terms.values()) > bound:
                return False
            if chunk.length != max(1, sum(chunk.terms.values())):
                return False
    except ValueError:
        return False
    return True


def _resolve_indexed_path(vault: Path, relative: str) -> Path:
    """Resolve a cache-provided path without allowing lane or vault escape."""
    candidate = PurePosixPath(relative)
    if (
        candidate.is_absolute()
        or candidate.as_posix() != relative
        or ".." in candidate.parts
        or not candidate.parts
        or candidate.parts[0] not in INDEXED_ROOTS
        or candidate.suffix != ".md"
        or is_forbidden_relative(relative)
    ):
        raise ValueError(f"invalid indexed path: {relative}")
    vault_root = vault.resolve()
    if (vault_root / candidate.parts[0]).is_symlink():
        raise ValueError(f"symlinked indexed root: {relative}")
    resolved = resolve_under(vault_root, *candidate.parts)
    resolved_relative = resolved.relative_to(vault_root).as_posix()
    if (
        is_forbidden_relative(resolved_relative)
        or not resolved_relative.split("/")[0] in INDEXED_ROOTS
        or resolved.suffix != ".md"
    ):
        raise ValueError(f"invalid resolved indexed path: {relative}")
    return resolved


def _current_file_stats(vault: Path, *, prefixes: tuple[str, ...] = ("projects/", "agents/")) -> dict[str, tuple[int, int, str]]:
    vault_root = vault.resolve()
    stats: dict[str, tuple[int, int, str]] = {}
    for root_name in INDEXED_ROOTS:
        root = vault_root / root_name
        if root.is_symlink() or not root.exists():
            continue
        for path in sorted(root.rglob("*.md")):
            relative = path.relative_to(vault_root).as_posix()
            if not relative.startswith(prefixes):
                continue
            current = _current_file_stat(vault_root, relative)
            if current is not None:
                stats[relative] = current
    return stats


def _current_file_stat(vault: Path, relative: str) -> tuple[int, int, str] | None:
    snapshot = _source_snapshot(vault, relative)
    return snapshot[0] if snapshot is not None else None


def _source_snapshot(vault: Path, relative: str) -> tuple[tuple[int, int, str], str] | None:
    """Read eligibility, digest and text from exactly the same source bytes."""
    candidate = PurePosixPath(relative)
    if (
        candidate.is_absolute()
        or candidate.as_posix() != relative
        or ".." in candidate.parts
        or not candidate.parts
        or candidate.parts[0] not in INDEXED_ROOTS
        or candidate.suffix != ".md"
        or is_forbidden_relative(relative)
    ):
        return None
    # Platform capability is not an ineligible document. Surface it before the
    # per-file race/eligibility handler so rebuild cannot commit an empty index.
    import os
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise RuntimeError("secure indexed source reads unavailable on this platform")
    vault_root = vault.resolve()
    path = vault_root / relative
    # Never index a symlink or anything resolving outside the vault:
    # otherwise recall would serve content from arbitrary host files.
    if path.is_symlink():
        return None
    try:
        # Containment and both lane policies must precede reading contents.
        resolved = _resolve_indexed_path(vault_root, relative)
        from .external_workspace import _read
        from .filesystem import MAX_MEMORY_DOCUMENT_BYTES
        data, identity, _ = _read(vault_root, candidate.parts, MAX_MEMORY_DOCUMENT_BYTES)
    except (OSError, ValueError, RuntimeError):
        # A file moved mid-scan must be skipped, not crash all of recall.
        return None

    try:
        text = data.decode("utf-8")
    except UnicodeError:
        return None
    if _frontmatter_status(text) == "superseded":
        return None
    return ((identity[5], len(data), hashlib.sha256(data).hexdigest()), text)


def _frontmatter_status(text: str) -> str:
    return scalar_value(frontmatter_values(text).get("status", ""))


def _index_file(vault: Path, relative: str, mtime_ns: int, *, text: str | None = None) -> Iterable[IndexedChunk]:
    path = _resolve_indexed_path(vault, relative)
    from .security import redact_secrets
    if text is None:
        from .external_workspace import _read
        from .filesystem import MAX_MEMORY_DOCUMENT_BYTES
        data, _, _ = _read(vault.resolve(), tuple(PurePosixPath(relative).parts), MAX_MEMORY_DOCUMENT_BYTES)
        text = data.decode('utf-8')
    text = redact_secrets(text)
    lines = text.splitlines()
    timestamp = _file_timestamp(text, mtime_ns)
    current_heading = redact_secrets(path.name)
    start = 1
    buffer: list[str] = []
    starts = set(_heading_starts(lines))
    prose = _prose_lines(text)
    for index, line in enumerate(lines, start=1):
        if index in starts and buffer:
            yield _make_chunk(relative, start, index - 1, current_heading, buffer, timestamp)
            current_heading = line.lstrip("#").strip() or redact_secrets(path.name)
            start = index
            buffer = [line]
        else:
            if prose[index - 1].startswith("#"):
                current_heading = line.lstrip("#").strip() or redact_secrets(path.name)
                start = index
            buffer.append(line)
    if buffer:
        yield _make_chunk(relative, start, len(lines), current_heading, buffer, timestamp)


def _make_chunk(
    relative: str, start: int, end: int, heading: str, lines: list[str], timestamp: float
) -> IndexedChunk:
    searchable = searchable_text("\n".join(lines))
    terms: dict[str, int] = {}
    for term in WORD_RE.findall(searchable):
        term = term.lower()
        terms[term] = terms.get(term, 0) + 1
    for term in WORD_RE.findall(frontmatter_text("\n".join(lines))):
        term = term.lower()
        terms[term] = terms.get(term, 0) + 1
    return IndexedChunk(
        relative_path=relative,
        start_line=start,
        end_line=end,
        heading=heading,
        terms=terms,
        length=max(1, sum(terms.values())),
        timestamp=timestamp,
    )


def _file_timestamp(text: str, mtime_ns: int) -> float:
    """Prefer a frontmatter date; fall back to the file mtime."""
    frontmatter = frontmatter_text(text)
    for key in _FRONTMATTER_DATE_KEYS:
        match = re.search(rf"^{key}:\s*(.+)$", frontmatter, flags=re.MULTILINE)
        if not match:
            continue
        parsed = _parse_timestamp(match.group(1).strip().strip("'\""))
        if parsed is not None:
            return parsed
    return mtime_ns / 1_000_000_000


def _parse_timestamp(value: str) -> float | None:
    candidate = value.replace("Z", "+00:00")
    for text in (candidate, f"{candidate}T00:00:00+00:00"):
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    return None


def _prose_lines(text: str) -> list[str]:
    """Mask fenced Markdown without changing logical line positions.

    Backtick and tilde fences may be indented up to three spaces. Only a
    matching character run at least as long closes a fence; an unclosed fence
    excludes the remainder. The same mask drives all heading consumers.
    """
    result: list[str] = []
    fence: str | None = None
    width = 0
    for line in text.splitlines():
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if fence is not None:
            result.append("")
            if (marker and marker[1][0] == fence and len(marker[1]) >= width
                    and not marker[2].strip()):
                fence = None
        elif marker and (marker[1][0] != "`" or "`" not in marker[2]):
            fence, width = marker[1][0], len(marker[1])
            result.append("")
        else:
            result.append(line)
    return result


def _heading_starts(lines: list[str]) -> list[int]:
    if not lines:
        return []
    return [1] + [number for number, line in enumerate(_prose_lines("\n".join(lines)), 1)
                  if number > 1 and line.startswith("#")]


def searchable_text(text: str) -> str:
    _, text = split_frontmatter(text)
    return "\n".join(_prose_lines(text))


def frontmatter_text(text: str) -> str:
    head, _ = split_frontmatter(text)
    return head or ""


def _cache_path(vault: Path) -> Path:
    return vault / INDEX_RELATIVE


def _read_cache(vault: Path) -> dict[str, dict[str, object]]:
    path = _cache_path(vault)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError, RecursionError):
        return {}
    if not isinstance(payload, dict) or payload.get("format") != INDEX_FORMAT:
        return {}
    files = payload.get("files")
    return files if isinstance(files, dict) else {}


def _write_cache(vault: Path, files: dict[str, dict[str, object]]) -> None:
    path = _cache_path(vault)
    payload = json.dumps({"format": INDEX_FORMAT, "files": files}, sort_keys=True)
    # Success includes both the file and post-replacement directory barriers.
    # Visible bytes alone do not establish durable publication. The vault
    # metadata directory never grants group/other write, whatever the umask
    # (a common 0002 umask made the packaged default vault fail validation).
    durable_mkdir(path.parent, mode=0o755)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        fsync_directory(path.parent)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


@contextmanager
def _publication_lock(vault: Path) -> Iterator[None]:
    """Share all cache publication windows; acquire before a jobs transaction.

    Recall holds only this lock. Rebuild acquires it before SQLite and keeps
    both through readback, source validation and completion. Provider work
    must finish before acquisition, and no SQLite holder may wait for it.
    """
    path = _cache_path(vault)
    with exclusive_lock(path.parent / "index-publication.lock"):
        yield


def _write_scoped_cache(vault: Path, files: dict[str, dict[str, object]],
                        prefixes: tuple[str, ...]) -> None:
    """Serialize only read/merge/publication, never provider or source I/O."""
    with _publication_lock(vault):
        latest = _read_cache(vault)
        merged = {r: e for r, e in latest.items() if not r.startswith(prefixes)}
        merged.update(files)
        _write_cache(vault, merged)
