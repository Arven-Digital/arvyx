from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC
from datetime import datetime
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import cast

from .memory_frontmatter import (
    collapse_metadata_lines, frontmatter_values, metadata_json,
    render_frontmatter, scalar_value, split_frontmatter,
)
from .filesystem import MAX_MEMORY_DOCUMENT_BYTES, durable_mkdir, fsync_directory, memory_document_bytes
from .promotion_transaction import memory_mutation, publish, stage
from .paths import resolve_under, validate_project_id
from .security import contains_literal_secret, redact_secrets

SECRET_METADATA_ERROR = (
    "contains a secret-shaped string; store a secret://broker/path reference "
    "instead of the literal value"
)

MAX_SUGGESTIONS_PER_BATCH = 100
MAX_TAGS_PER_SUGGESTION = 20
MAX_RELATIONS_PER_SUGGESTION = 20
MAX_SUGGESTION_TITLE_CHARS = 200
MAX_SUGGESTION_CONTENT_CHARS = 100_000
MAX_SUGGESTION_TAG_CHARS = 64
_BATCH_ROOT_FIELDS = frozenset({"memories"})
_RELATION_FIELDS = frozenset({"type", "parent_source_path"})
_RELATION_TYPES = frozenset({"updates", "extends", "derives"})
_QUALITY_FIELDS = frozenset({"content_class", "memory_class", "future_job", "assistant_suggestion_accepted"})
_BATCH_ITEM_FIELDS = frozenset({"title", "content", "tags", "inferred", "relations", *_QUALITY_FIELDS})
MEMORY_CLASSES = frozenset({"static", "dynamic"})
CONTENT_CLASSES = frozenset({
    "durable_identity", "preference", "plan", "state", "inferred",
    "assistant_suggestion", "research_quote", "durable_fact",
    "boilerplate", "greeting", "prompt_injection", "no_future_job",
})
_REJECTED_CONTENT_CLASSES = {
    "boilerplate": "NOISE_BOILERPLATE",
    "greeting": "NOISE_GREETING",
    "prompt_injection": "PROMPT_INJECTION",
    "no_future_job": "NO_FUTURE_JOB",
}


def memory_suggestion_batch_schema(*, include_envelope: bool = False) -> dict[str, object]:
    """Return the canonical closed JSON schema used by HTTP and MCP."""
    item = {
        "type": "object", "additionalProperties": False,
        "required": ["title", "content", "content_class", "memory_class", "future_job", "assistant_suggestion_accepted"],
        "properties": {
            "title": {"type": "string", "minLength": 1, "maxLength": MAX_SUGGESTION_TITLE_CHARS},
            "content": {"type": "string", "minLength": 1, "maxLength": MAX_SUGGESTION_CONTENT_CHARS},
            "tags": {"type": "array", "maxItems": MAX_TAGS_PER_SUGGESTION, "items": {"type": "string", "minLength": 1, "maxLength": MAX_SUGGESTION_TAG_CHARS}},
            "inferred": {"type": "boolean"},
            "relations": {
                "type": "array",
                "maxItems": MAX_RELATIONS_PER_SUGGESTION,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["type", "parent_source_path"],
                    "properties": {
                        "type": {"type": "string", "enum": ["updates", "extends", "derives"]},
                        "parent_source_path": {"type": "string"},
                    },
                },
            },
            "content_class": {"type": "string", "enum": sorted(CONTENT_CLASSES)},
            "memory_class": {"type": "string", "enum": ["static", "dynamic"]},
            "future_job": {"type": "string", "minLength": 1, "description": "Concrete downstream use; classification metadata, not free-text censorship."},
            "assistant_suggestion_accepted": {"type": "boolean"},
        },
    }
    properties: dict[str, object] = {"memories": {"type": "array", "minItems": 1, "maxItems": MAX_SUGGESTIONS_PER_BATCH, "items": item}}
    required = ["memories"]
    if include_envelope:
        properties = {"project": {"type": "string"}, "author": {"type": "string"}, **properties}
        required = ["project", "author", "memories"]
    return {"type": "object", "additionalProperties": False, "required": required, "properties": properties}


PENDING_LANE = "pending"
IMPORTED_LANE = "imported"
REFINING_LANE = "refining"
NOTES_LANE = "notes"
# Lanes a promote/reject may draw from. Refining sits between the raw
# pending/imported lanes and the curated notes lane: a refiner claims and
# rewrites a suggestion, then an operator promotes the polished result.
REFINABLE_LANES = (PENDING_LANE, IMPORTED_LANE)
PROMOTABLE_LANES = (PENDING_LANE, IMPORTED_LANE, REFINING_LANE)


@dataclass(frozen=True)
class SuggestResult:
    path: str
    title: str
    author: str
    status: str = "pending"
    memory_class: str | None = None
    content_class: str | None = None
    future_job: str | None = None
    admission_reason: str | None = None

    def to_dict(self) -> dict[str, str]:
        result = {"path": self.path, "title": self.title, "author": self.author, "status": self.status}
        for key in ("memory_class", "content_class", "future_job", "admission_reason"):
            value = getattr(self, key)
            if value is not None:
                result[key] = value
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class SuggestBatchResult:
    suggestions: list[SuggestResult]

    def to_dict(self) -> dict[str, object]:
        return {
            "suggestions": [suggestion.to_dict() for suggestion in self.suggestions],
            "count": len(self.suggestions),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class PendingEntry:
    path: str
    title: str
    author: str
    created_at: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "title": self.title, "author": self.author, "created_at": self.created_at}


@dataclass(frozen=True)
class PendingListResult:
    pending: list[PendingEntry]

    def to_dict(self) -> dict[str, object]:
        return {"pending": [entry.to_dict() for entry in self.pending]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class RefineResult:
    source: str
    target: str
    refined_by: str

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "target": self.target, "refined_by": self.refined_by, "status": "refining"}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class RefiningListResult:
    refining: list[PendingEntry]

    def to_dict(self) -> dict[str, object]:
        return {"refining": [entry.to_dict() for entry in self.refining]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class PromoteResult:
    source: str
    target: str
    promoted_by: str

    def to_dict(self) -> dict[str, str]:
        return {"source": self.source, "target": self.target, "promoted_by": self.promoted_by}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class RejectResult:
    source: str
    target: str
    rejected_by: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {
            "source": self.source,
            "target": self.target,
            "rejected_by": self.rejected_by,
            "reason": self.reason,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def _publish_suggestions(staged: list[tuple[Path, Path, str]]) -> None:
    try:
        _publish_suggestions_locked(staged)
    except OSError as exc:
        # FileNotFoundError is a domain refusal at transport boundaries; a
        # publication/barrier failure instead must leave dispatch unresolved.
        raise OSError("suggestion publication durability failed") from exc


def _publish_suggestions_locked(staged: list[tuple[Path, Path, str]]) -> None:
    """Publish under memory_mutation; return only after durable names and bytes.

    Rollback retains the existing identity guard against deleting replacements.
    A crash mid-batch remains reconciliation-required at the dispatch journal;
    neither this helper nor the transport retries a partially dispatched batch.
    """
    # Preflight the entire batch before any staging or publication. JSON
    # metadata escaping and UTF-8 bytes can exceed character admission limits.
    encoded = [(temporary, target, memory_document_bytes(text))
               for temporary, target, text in staged]
    published: list[tuple[Path, tuple[int, int, str]]] = []
    directories = {target.parent for _, target, _ in staged}
    try:
        for directory in directories:
            durable_mkdir(directory)
        for temporary, _, payload in encoded:
            stage(temporary, payload)
        for temporary, target, _ in staged:
            # Capture ownership before publication, including the case where the
            # following identity read or directory barrier would fail.
            identity = _file_identity(temporary)
            if identity is None:
                raise OSError("staged suggestion identity unavailable")
            # Exclusive publication: an out-of-lock editor may have claimed
            # the allocated name. Never overwrite it, even transiently.
            os.link(temporary, target, follow_symlinks=False)
            published.append((target, identity))
            temporary.unlink()
        for directory in directories:
            fsync_directory(directory)
    except BaseException:
        for temporary, _, _ in staged:
            temporary.unlink(missing_ok=True)
        for target, identity in published:
            if _file_identity(target, missing_ok=True) == identity:
                target.unlink(missing_ok=True)
        for directory in directories:
            if directory.exists():
                fsync_directory(directory)
        raise


def suggest_memory(
    vault: Path,
    project: str,
    title: str,
    content: str,
    author: str,
    tags: list[str] | None = None,
) -> SuggestResult:
    """Write an agent memory suggestion into the excluded pending lane.

    Suggestions never enter recall until a promote moves them to the
    curated notes lane. This legacy single-item interface shares batch size,
    tag and secret admission limits, but does not fabricate the batch-only
    future-job/quality evidence absent from its callers. Promotion is separate.
    """
    vault_root = vault.resolve()
    project = validate_project_id(project)
    _require_single_line("suggestion title", title)
    _require_single_line("suggestion author", author)
    if tags is not None and (not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags)):
        raise ValueError("suggestion tags must be an array of strings")
    for tag in tags or []:
        _require_single_line("suggestion tag", tag)
    title = title.strip()
    content = content.strip()
    author = author.strip()
    if not title:
        raise ValueError("suggestion title must not be empty")
    if not content:
        raise ValueError("suggestion content must not be empty")
    if not author:
        raise ValueError("suggestion author must not be empty")
    _refuse_secret_shape("suggestion title", title)
    if len(title) > MAX_SUGGESTION_TITLE_CHARS or len(content) > MAX_SUGGESTION_CONTENT_CHARS:
        raise ValueError('suggestion title or content exceeds admission limit')
    if len(tags or []) > MAX_TAGS_PER_SUGGESTION or any(
            not tag.strip() or len(tag.strip()) > MAX_SUGGESTION_TAG_CHARS for tag in tags or []):
        raise ValueError('suggestion tags exceed admission limit or contain empty values')
    _refuse_secret_shape("suggestion content", content)
    _refuse_secret_shape("suggestion author", author)
    _refuse_secret_shape("suggestion tags", tags or [])

    pending_root = resolve_under(vault_root, "projects", project, PENDING_LANE)
    created_at = _now()
    with memory_mutation(vault_root):
        target = _unique_target(pending_root, _slug(title))
        text = (
            _suggestion_metadata(target.stem, project, author, created_at, tags or [])
            + "---\n\n"
            f"# {title}\n\n"
            f"{content}\n"
        )
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        _publish_suggestions([(temporary, target, text)])
    return SuggestResult(
        path=target.relative_to(vault_root).as_posix(),
        title=title,
        author=author,
    )


def suggest_memory_batch(
    vault: Path,
    project: str,
    author: str,
    payload: object,
) -> SuggestBatchResult:
    """Validate a closed-schema LLM batch before writing any suggestion."""
    vault_root = vault.resolve()
    project = validate_project_id(project)
    _require_single_line("suggestion author", author)
    author = author.strip()
    if not author:
        raise ValueError("suggestion author must not be empty")
    _refuse_secret_shape("suggestion author", author)

    if not isinstance(payload, dict):
        raise ValueError("suggestion batch must be an object")
    unknown_root = sorted(set(payload) - _BATCH_ROOT_FIELDS)
    if unknown_root:
        raise ValueError(f"suggestion batch has unknown field(s): {', '.join(unknown_root)}")
    if "memories" not in payload:
        raise ValueError("suggestion batch requires memories")
    memories = payload["memories"]
    if not isinstance(memories, list):
        raise ValueError("memories must be an array")
    if not memories:
        raise ValueError("memories must contain at least one suggestion")
    if len(memories) > MAX_SUGGESTIONS_PER_BATCH:
        raise ValueError(f"memories must contain at most {MAX_SUGGESTIONS_PER_BATCH} suggestions")

    # Reject malformed shapes across the whole batch before deeper admission
    # checks so an unknown field in a later item cannot be masked by an earlier
    # quality or relation error.
    for index, raw in enumerate(memories):
        if not isinstance(raw, dict):
            raise ValueError(f"memories[{index}] must be an object")
        unknown_item = sorted(set(raw) - _BATCH_ITEM_FIELDS)
        if unknown_item:
            raise ValueError(f"memories[{index}] has unknown field(s): {', '.join(unknown_item)}")
        # Reject logical line injection before recovery or any filesystem effects.
        if isinstance(raw.get("title"), str):
            _require_single_line(f"memories[{index}].title", raw["title"])
        if isinstance(raw.get("tags"), list):
            for tag in raw["tags"]:
                if isinstance(tag, str):
                    _require_single_line(f"memories[{index}].tags", tag)

    with memory_mutation(vault_root):
        validated: list[dict[str, object]] = []
        seen_titles: set[str] = set()
        for index, raw in enumerate(memories):
            label = f"memories[{index}]"
            if not isinstance(raw, dict):
                raise ValueError(f"{label} must be an object")
            unknown_item = sorted(set(raw) - _BATCH_ITEM_FIELDS)
            if unknown_item:
                raise ValueError(f"{label} has unknown field(s): {', '.join(unknown_item)}")
            for required in ("title", "content"):
                if required not in raw:
                    raise ValueError(f"{label}.{required} is required")
                if not isinstance(raw[required], str):
                    raise ValueError(f"{label}.{required} must be a string")
            _require_single_line(f"{label}.title", raw["title"])
            title = raw["title"].strip()
            content = raw["content"].strip()
            if not title:
                raise ValueError(f"{label}.title must not be empty")
            if not content:
                raise ValueError(f"{label}.content must not be empty")
            if len(title) > MAX_SUGGESTION_TITLE_CHARS:
                raise ValueError(f"{label}.title must contain at most {MAX_SUGGESTION_TITLE_CHARS} characters")
            if len(content) > MAX_SUGGESTION_CONTENT_CHARS:
                raise ValueError(f"{label}.content must contain at most {MAX_SUGGESTION_CONTENT_CHARS} characters")
            title_key = title.casefold()
            if title_key in seen_titles:
                raise ValueError(f"{label} has duplicate title in batch: {title}")
            seen_titles.add(title_key)
            tags_value = raw.get("tags", [])
            if not isinstance(tags_value, list):
                raise ValueError(f"{label}.tags must be an array")
            if len(tags_value) > MAX_TAGS_PER_SUGGESTION:
                raise ValueError(f"{label}.tags must contain at most {MAX_TAGS_PER_SUGGESTION} items")
            if any(not isinstance(tag, str) for tag in tags_value):
                raise ValueError(f"{label}.tags items must be strings")
            for tag_index, tag in enumerate(tags_value):
                _require_single_line(f"{label}.tags[{tag_index}]", tag)
            tags = [tag.strip() for tag in tags_value]
            if any(not tag for tag in tags):
                raise ValueError(f"{label}.tags items must not be empty")
            if any(len(tag) > MAX_SUGGESTION_TAG_CHARS for tag in tags):
                raise ValueError(f"{label}.tags items must contain at most {MAX_SUGGESTION_TAG_CHARS} characters")
            _refuse_secret_shape(f"{label}.title", title)
            _refuse_secret_shape(f"{label}.content", content)
            _refuse_secret_shape(f"{label}.tags", tags)
            inferred = raw.get("inferred", False)
            if not isinstance(inferred, bool):
                raise ValueError(f"{label}.inferred must be a boolean")
            relations = _validate_relations(
                vault_root, project, raw.get("relations", []), inferred, f"{label}.relations"
            )
            missing_quality = sorted(_QUALITY_FIELDS - set(raw))
            if missing_quality:
                raise ValueError(f"QUALITY_METADATA_REQUIRED: {label} requires {', '.join(missing_quality)}")
            for field in ("content_class", "memory_class", "future_job"):
                value = raw[field]
                if not isinstance(value, str):
                    raise ValueError(f"{label}.{field} must be a string")
            accepted = raw["assistant_suggestion_accepted"]
            if not isinstance(accepted, bool):
                raise ValueError(f"{label}.assistant_suggestion_accepted must be a boolean")
            content_class = raw["content_class"].strip()
            memory_class = raw["memory_class"].strip()
            future_job = raw["future_job"].strip()
            if content_class not in CONTENT_CLASSES:
                raise ValueError(f"INVALID_CONTENT_CLASS: {label}.content_class")
            if memory_class not in MEMORY_CLASSES:
                raise ValueError(f"INVALID_MEMORY_CLASS: {label}.memory_class must be static or dynamic")
            rejection = _REJECTED_CONTENT_CLASSES.get(content_class)
            if rejection:
                raise ValueError(f"{rejection}: {label} is not admissible memory")
            if content_class == "assistant_suggestion" and not accepted:
                raise ValueError(f"ASSISTANT_SUGGESTION_UNACCEPTED: {label} requires explicit acceptance")
            if not future_job:
                raise ValueError(f"NO_FUTURE_JOB: {label}.future_job must describe a concrete downstream use")
            if memory_class == "static" and content_class != "durable_identity":
                raise ValueError(f"STATIC_REQUIRES_DURABLE_IDENTITY: {label}")
            _refuse_secret_shape(f"{label}.future_job", future_job)
            validated.append({
                "title": title, "content": content, "tags": tags,
                "inferred": inferred, "relations": relations,
                "content_class": content_class, "memory_class": memory_class,
                "future_job": future_job,
                "assistant_suggestion_accepted": accepted,
            })

        pending_root = resolve_under(vault_root, "projects", project, PENDING_LANE)
        created_at = _now()
        results: list[SuggestResult] = []
        reserved: set[Path] = set()
        staged: list[tuple[Path, Path, str, dict[str, object]]] = []
        for item in validated:
            title = str(item["title"])
            content = str(item["content"])
            tags = cast(list[str], item["tags"])
            target = _unique_target_reserved(pending_root, _slug(title), reserved)
            reserved.add(target)
            text = (
                _suggestion_metadata(target.stem, project, author, created_at, tags)
                +
                f"inferred: {metadata_json(item['inferred'])}\n"
                f"relations: {metadata_json(item['relations'])}\n"
                f"memory_class: {metadata_json(item['memory_class'])}\n"
                f"content_class: {metadata_json(item['content_class'])}\n"
                f"future_job: {metadata_json(item['future_job'])}\n"
                f"assistant_suggestion_accepted: {str(item['assistant_suggestion_accepted']).lower()}\n"
                'admission_reason: "FUTURE_JOB_ACCEPTED"\n'
                "---\n\n"
                f"# {title}\n\n"
                f"{content}\n"
            )
            temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
            staged.append((temporary, target, text, item))

        _publish_suggestions([(temporary, target, text) for temporary, target, text, _ in staged])

        for _, target, _, item in staged:
            results.append(
                SuggestResult(
                    path=target.relative_to(vault_root).as_posix(),
                    title=str(item["title"]),
                    author=author,
                    memory_class=str(item["memory_class"]),
                    content_class=str(item["content_class"]),
                    future_job=str(item["future_job"]),
                    admission_reason="FUTURE_JOB_ACCEPTED",
                )
            )
    return SuggestBatchResult(suggestions=results)


def _validate_relations(
    vault_root: Path, project: str, value: object, inferred: bool, label: str
) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    if len(value) > MAX_RELATIONS_PER_SUGGESTION:
        raise ValueError(f"{label} must contain at most {MAX_RELATIONS_PER_SUGGESTION} items")
    result: list[dict[str, str]] = []
    seen_parents: set[str] = set()
    prefix = f"projects/{project}/notes/"
    for index, raw in enumerate(value):
        item_label = f"{label}[{index}]"
        if not isinstance(raw, dict):
            raise ValueError(f"{item_label} must be an object")
        unknown = sorted(set(raw) - _RELATION_FIELDS)
        if unknown:
            raise ValueError(f"{item_label} has unknown field(s): {', '.join(unknown)}")
        for required in ("type", "parent_source_path"):
            if required not in raw:
                raise ValueError(f"{item_label}.{required} is required")
            if not isinstance(raw[required], str):
                raise ValueError(f"{item_label}.{required} must be a string")
        relation_type = raw["type"].strip()
        parent = raw["parent_source_path"].replace("\\", "/").strip("/")
        if relation_type not in _RELATION_TYPES:
            raise ValueError(f"{item_label}.type must be one of: updates, extends, derives")
        if relation_type == "derives" and inferred is not True:
            raise ValueError(f"{item_label} derives requires inferred=true")
        project_prefix = f"projects/{project}/"
        if not parent.startswith(prefix):
            if parent.startswith(project_prefix):
                raise ValueError(f"{item_label}.parent_source_path must be an explicit curated notes source path")
            if parent.startswith("projects/"):
                raise ValueError(f"{item_label}.parent_source_path must belong to the current project")
            raise ValueError(f"{item_label}.parent_source_path must be an explicit curated notes source path")
        path = resolve_under(vault_root, *parent.split("/"))
        # Canonicalize once and use the canonical vault-relative path for both
        # the dedup key and the persisted relation, so `notes/./x.md` and
        # `notes/x.md` cannot smuggle the same parent in twice.
        canonical = path.relative_to(vault_root).as_posix()
        if not path.is_file() or path.suffix.lower() != ".md" or not canonical.startswith(prefix):
            raise ValueError(f"{item_label}.parent_source_path must name an existing curated notes file")
        if _frontmatter_status_value(_frontmatter(path.read_text(encoding="utf-8")).get("status", "")) == "superseded":
            raise ValueError(f"{item_label}.parent_source_path must name current curated truth")
        if canonical in seen_parents:
            raise ValueError(f"{item_label} duplicates an earlier parent")
        seen_parents.add(canonical)
        result.append({"type": relation_type, "parent_source_path": canonical})
    return result


def _suggestion_metadata(identifier: str, project: str, author: str, created_at: str, tags: list[str]) -> str:
    """Shared single/batch metadata sink; caller validates before mutation."""
    return (
        "---\n"
        f"id: {identifier}\n"
        "type: memory-suggestion\n"
        f"project: {project}\n"
        f"author: {metadata_json(author)}\n"
        f"created_at: {created_at}\n"
        "status: pending\n"
        f"tags: {metadata_json(['suggested', *tags])}\n"
    )


def _require_single_line(label: str, value: str) -> None:
    if any(character in value for character in "\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029"):
        raise ValueError(f"{label} must be single-line")


def _unique_target_reserved(root: Path, stem: str, reserved: set[Path]) -> Path:
    stem = _filename_stem(stem)
    candidate = root / f"{stem}.md"
    index = 2
    while candidate.exists() or candidate.is_symlink() or candidate in reserved:
        if index > 1024:
            raise ValueError('suggestion filename collision budget exhausted')
        candidate = root / f"{stem}-{index}.md"
        index += 1
    return candidate


def list_pending(vault: Path, project: str) -> PendingListResult:
    return PendingListResult(pending=_list_lane(vault, project, PENDING_LANE, ("author",), ("created_at",)))


def refine_memory(
    vault: Path,
    project: str,
    source_path: str,
    refined_by: str,
    content: str | None = None,
    notes: str = "",
) -> RefineResult:
    """Claim a raw pending/imported suggestion into the refining lane.

    A refiner may rewrite the body (`content`) before an operator promotes
    it; the refined text is secret-linted like any other governed write.
    """
    vault_root = vault.resolve()
    project = validate_project_id(project)
    refined_by = refined_by.strip()
    if not refined_by:
        raise ValueError("refined_by must not be empty")
    _refuse_secret_shape('refined_by', refined_by)
    _refuse_secret_shape('refine notes', notes)
    if content is not None:
        content = content.strip()
        if not content:
            raise ValueError("refined content must not be empty when provided")
        if contains_literal_secret(content):
            raise ValueError(
                "refined content contains a secret-shaped string; store a "
                "secret://broker/path reference instead of the literal value"
            )
    with memory_mutation(vault_root):
        source = _resolve_promotable(vault_root, project, source_path, lanes=REFINABLE_LANES)
        source_bytes = _read_memory_bytes(source)
        text = source_bytes.decode("utf-8")
        _refuse_secret_shape('refine source', text)
        _validated_persisted_relations(vault_root, project, text)
        if content is not None:
            text = _replace_body(text, content)
        refining_root = resolve_under(vault_root, "projects", project, REFINING_LANE)
        refining_root.mkdir(parents=True, exist_ok=True)
        target = _unique_target(refining_root, source.stem)
        text = _set_frontmatter_status(
            text,
            status="refining",
            extra={"refined_by": refined_by, "refined_at": _now(), "refine_notes": notes},
        )
        publish(vault_root, source, target, memory_document_bytes(text), {}, source_bytes=source_bytes)
    return RefineResult(
        source=source_path,
        target=target.relative_to(vault_root).as_posix(),
        refined_by=refined_by,
    )


def list_refining(vault: Path, project: str) -> RefiningListResult:
    return RefiningListResult(
        refining=_list_lane(vault, project, REFINING_LANE, ("refined_by", "author"), ("refined_at", "created_at"))
    )


def _list_lane(
    vault: Path,
    project: str,
    lane: str,
    author_keys: tuple[str, ...],
    created_keys: tuple[str, ...],
) -> list[PendingEntry]:
    vault_root = vault.resolve()
    project = validate_project_id(project)
    lane_root = vault_root / 'projects' / project / lane
    entries: list[PendingEntry] = []
    if lane_root.exists():
        for path in sorted(lane_root.glob("*.md")):
            text = _read_memory_bytes(path).decode('utf-8')
            _refuse_secret_shape('listed memory', text)
            frontmatter = _frontmatter(text)
            entries.append(
                PendingEntry(
                    path=path.relative_to(vault_root).as_posix(),
                    title=_first_heading_in(text) or path.stem,
                    author=_first_present(frontmatter, author_keys),
                    created_at=_first_present(frontmatter, created_keys),
                )
            )
    return entries


def _first_present(frontmatter: dict[str, str], keys: tuple[str, ...]) -> str:
    for key in keys:
        if frontmatter.get(key):
            return scalar_value(frontmatter[key])
    return ""


def promote_memory(vault: Path, project: str, source_path: str, promoted_by: str) -> PromoteResult:
    """Move a pending suggestion or imported doc into the curated notes lane."""
    vault_root = vault.resolve()
    project = validate_project_id(project)
    promoted_by = promoted_by.strip()
    if not promoted_by:
        raise ValueError("promoted_by must not be empty")
    _refuse_secret_shape("promoted_by", promoted_by)
    with memory_mutation(vault_root):
        source = _resolve_promotable(vault_root, project, source_path)
        notes_root = resolve_under(vault_root, "projects", project, NOTES_LANE)
        notes_root.mkdir(parents=True, exist_ok=True)
        target = _unique_target(notes_root, source.stem)
        source_bytes = _read_memory_bytes(source)
        text = source_bytes.decode("utf-8")
        _refuse_secret_shape('promotion source', text)
        relations = _validated_persisted_relations(vault_root, project, text)
        update_parents = list(dict.fromkeys(
            resolve_under(vault_root, *relation["parent_source_path"].split("/"))
            for relation in relations
            if relation["type"] == "updates"
        ))
        for parent in update_parents:
            if not parent.is_file() or _is_superseded_status(
                _frontmatter(parent.read_text(encoding="utf-8")).get("status", "")
            ):
                raise ValueError("updates parent must still be current curated truth at promotion")
        text = _set_frontmatter_status(
            text,
            status="promoted",
            extra={"promoted_by": promoted_by, "promoted_at": _now()},
        )
        target_relative = target.relative_to(vault_root).as_posix()
        # Preserve byte-exact originals (including CRLF) in a durable recovery
        # journal. Publication and rollback never truncate a curated parent.
        parents = {}
        for parent in update_parents:
            original = parent.read_bytes()
            original_text = original.decode('utf-8')
            if _is_superseded_status(_frontmatter(original_text).get('status', '')):
                raise ValueError('updates parent must still be current curated truth at promotion')
            replacement = _set_frontmatter_status(
                original_text, status='superseded',
                extra={'superseded_by': target_relative, 'superseded_at': _now()},
            )
            replacement = memory_document_bytes(replacement)
            parents[parent] = original, replacement
        publish(vault_root, source, target, memory_document_bytes(text), parents, source_bytes=source_bytes)

    return PromoteResult(
        source=source_path,
        target=target.relative_to(vault_root).as_posix(),
        promoted_by=promoted_by,
    )


def _validated_persisted_relations(
    vault_root: Path, project: str, text: str
) -> list[dict[str, str]]:
    frontmatter = _frontmatter(text)
    raw = frontmatter.get("relations", "[]")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid persisted relation metadata") from exc
    if not isinstance(value, list):
        raise ValueError("invalid persisted relation metadata")
    inferred_raw = frontmatter.get("inferred", "false")
    if inferred_raw not in {"true", "false"}:
        raise ValueError("invalid persisted inferred metadata")
    return _validate_relations(
        vault_root,
        project,
        value,
        inferred_raw == "true",
        "relations",
    )


def reject_memory(vault: Path, project: str, source_path: str, rejected_by: str, reason: str = "") -> RejectResult:
    """Move a pending suggestion into the excluded archive lane."""
    vault_root = vault.resolve()
    project = validate_project_id(project)
    rejected_by = rejected_by.strip()
    if not rejected_by:
        raise ValueError("rejected_by must not be empty")
    _refuse_secret_shape("rejected_by", rejected_by)
    _refuse_secret_shape("reject reason", reason)
    with memory_mutation(vault_root):
        source = _resolve_promotable(vault_root, project, source_path)
        archive_root = resolve_under(vault_root, "projects", project, "archive")
        archive_root.mkdir(parents=True, exist_ok=True)
        target = _unique_target(archive_root, source.stem)
        source_bytes = _read_memory_bytes(source)
        text = source_bytes.decode("utf-8")
        text = _set_frontmatter_status(
            text,
            status="rejected",
            extra={"rejected_by": rejected_by, "rejected_at": _now(), "reject_reason": reason},
        )
        publish(vault_root, source, target, memory_document_bytes(text), {}, source_bytes=source_bytes)
    return RejectResult(
        source=source_path,
        target=target.relative_to(vault_root).as_posix(),
        rejected_by=rejected_by,
        reason=reason,
    )


def _resolve_promotable(
    vault_root: Path,
    project: str,
    source_path: str,
    lanes: tuple[str, ...] = PROMOTABLE_LANES,
) -> Path:
    relative = source_path.replace("\\", "/")
    if relative.startswith("/") or ".." in relative.split("/"):
        raise ValueError("source path must be relative and must not contain traversal")
    prefix = f"projects/{project}/"
    if not relative.startswith(prefix):
        # Allow lane-relative shorthand like pending/foo.md.
        relative = prefix + relative
    lane = relative[len(prefix):].split("/", 1)[0]
    if lane not in lanes:
        raise ValueError(
            f"only {' and '.join(lanes)} lane(s) allowed here, got: {lane}"
        )
    # The lexical lane root is intentional: resolving a symlinked lane root
    # first would incorrectly make an outside directory an allowed boundary.
    lane_root = vault_root / "projects" / project / lane
    path = resolve_under(vault_root, *relative.split("/"))
    if not path.is_relative_to(lane_root):
        raise ValueError("source path resolves outside the allowed project lane")
    if not path.is_file() or path.suffix.lower() != ".md":
        raise FileNotFoundError(source_path)
    return path


def _replace_body(text: str, new_body: str) -> str:
    """Swap the document body, preserving the frontmatter block if present.

    Only treats the leading `---` as frontmatter when a closing `\\n---\\n`
    fence is actually found; an imported doc that opens with `---` but has no
    terminator (e.g. a markdown thematic break) is treated as bodyless so the
    whole document is not swallowed into a giant frontmatter block.
    """
    head, _ = split_frontmatter(text)
    body = f"{new_body.strip()}\n"
    return render_frontmatter(head, "\n" + body) if head is not None else body


def _frontmatter_safe(value: str) -> str:
    """Make a value safe to embed as a single frontmatter line.

    Collapsing newlines stops a free-text field (refine notes, reject
    reason) from injecting extra frontmatter keys — e.g. an `updated_at`
    that would poison temporal ranking — and redaction keeps a literal
    secret out of a metadata field the write-time content lint never saw.
    """
    collapsed = collapse_metadata_lines(str(value))
    return redact_secrets(collapsed).strip()


def _refuse_secret_shape(label: str, value: object) -> None:
    if isinstance(value, list):
        for item in value:
            _refuse_secret_shape(label, item)
        return
    if value is None:
        return
    if contains_literal_secret(str(value)):
        raise ValueError(f"{label} {SECRET_METADATA_ERROR}")

def _set_frontmatter_status(text: str, status: str, extra: dict[str, str]) -> str:
    lines = [f"{key}: {metadata_json(_frontmatter_safe(value))}" for key, value in extra.items() if value]
    lines.append(f"status: {status}")
    head, body = split_frontmatter(text)
    if head is not None:
        replaced = {"status", *extra}
        retained = [line for line in head.splitlines() if line.partition(":")[0].strip() not in replaced]
        return render_frontmatter("\n".join([*retained, *lines]), body)
    return render_frontmatter("\n".join(lines), "\n" + body)


def _frontmatter(text: str) -> dict[str, str]:
    return frontmatter_values(text)


def _frontmatter_status_value(raw: str) -> str:
    return scalar_value(raw)


def _is_superseded_status(raw: str) -> bool:
    return _frontmatter_status_value(raw) == "superseded"


def _file_identity(path: Path, *, missing_ok: bool = False) -> tuple[int, int, str] | None:
    """Content-hash + inode identity of a file, used to gate rollback unlinks.

    A rollback may only delete a target it published itself. If any other
    writer replaced or rewrote the file mid-operation, the identity tuple
    differs and the file is preserved.
    """
    try:
        data = path.read_bytes()
        stat = path.stat()
    except OSError:
        if missing_ok:
            return None
        raise
    return (stat.st_dev, stat.st_ino, hashlib.sha256(data).hexdigest())


def _first_heading_in(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("#"):
            return line.lstrip("#").strip()
    return None


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return _filename_stem(slug or "suggestion")


def _filename_stem(stem: str) -> str:
    # Reserve bytes for .md, collision suffix and UUID staging components.
    raw = stem.encode('utf-8')
    if len(raw) <= 160:
        return stem
    return raw[:135].decode('utf-8', errors='ignore') + '-' + hashlib.sha256(raw).hexdigest()[:24]


def _read_memory_bytes(path: Path) -> bytes:
    """No-follow, nonblocking, bounded reads for write/list-only authorities."""
    absolute = path.absolute()
    if '..' in absolute.parts:
        raise ValueError('memory path traversal refused')
    with ExitStack() as stack:
        fd = os.open(absolute.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, fd)
        for part in absolute.parts[1:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            stack.callback(os.close, fd)
        try:
            leaf = os.open(absolute.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        except OSError:
            raise ValueError('memory listing/source must be a regular non-aliased file') from None
        with os.fdopen(leaf, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('memory listing/source must be a regular non-aliased file')
            data = stream.read(MAX_MEMORY_DOCUMENT_BYTES + 1)
            if len(data) > MAX_MEMORY_DOCUMENT_BYTES:
                raise ValueError('memory listing/source byte limit exceeded')
            return data


def _unique_target(root: Path, stem: str) -> Path:
    return _unique_target_reserved(root, stem, set())


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
