from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re

from .embeddings import EmbeddingConfig, EmbeddingError, embed_texts, load_embedding_config
from .index import (
    IndexedChunk,
    chunk_text,
    is_forbidden_relative,
    load_index,
    searchable_text,
)
from .paths import resolve_under, validate_project_id
from .security import redact_secrets


WORD_RE = re.compile(r"[a-z0-9][a-z0-9_.-]*", re.IGNORECASE)
SENTENCE_RE = re.compile(r"(?<=[.!?])\s+|\n+-\s+")
MAX_RECALL_LIMIT = 20
MAX_RECALL_TOKENS = 2_000
MAX_EXCERPT_LINES = 80
RETRIEVAL_MODES = {"lexical", "hybrid", "semantic"}
SEMANTIC_MIN_SIMILARITY = 0.08
SECONDS_PER_DAY = 86_400.0

BM25_K1 = 1.2
BM25_B = 0.75
ALIAS_WEIGHT = 0.5
CONFIDENCE_SCALE = 6.0
# Matches scoring far below the best hit are noise, not evidence;
# returning them as "sources" pollutes citations.
RELATIVE_SCORE_FLOOR = 0.2

# Function words carry no recall signal and let unrelated chunks
# accumulate score across many near-zero-idf matches.
STOPWORDS = frozenset(
    """a an and are as at be but by did do does for from how in is it of on or
    should still that the this to was we were what when where which why will
    with""".split()
)

# Static, query-independent priors. Curated "current truth" lanes rank
# slightly above supporting docs; imported material ranks below curated
# docs until it is promoted.
DOC_PRIORS = {
    "STATUS.md": 1.3,
    "DECISIONS.md": 1.25,
    "RUNBOOK.md": 1.15,
    "OVERVIEW.md": 1.1,
}
IMPORTED_LANE_PRIOR = 0.85

TERM_ALIASES = {
    "approval": {"approve", "approved", "permission", "gate"},
    "approve": {"approval", "approved", "permission", "gate"},
    "auth": {"authentication", "authorization", "credential", "token"},
    "authentication": {"auth", "authorization", "credential", "token"},
    "bridge": {"proxy", "gateway", "adapter"},
    "credential": {"auth", "authentication", "authorization", "token"},
    "credentials": {"auth", "authentication", "authorization", "credential", "token"},
    "guardrail": {"safety", "safe", "policy"},
    "hash": {"digest", "fingerprint"},
    "memory": {"recall", "remember", "context"},
    "permission": {"approval", "approve", "gate"},
    "proxy": {"bridge", "gateway", "adapter"},
    "recall": {"memory", "remember", "context"},
    "remember": {"memory", "recall", "context"},
    "safety": {"safe", "guardrail", "policy"},
    "task": {"todo", "work", "handoff"},
    "token": {"auth", "authentication", "credential"},
}


@dataclass(frozen=True)
class Source:
    path: str
    lines: str
    score: float


@dataclass(frozen=True)
class RecallResult:
    question: str
    retrieval_mode: str
    answer: list[str]
    confidence: float
    cards: list[MemoryCard]
    sources: list[Source]
    expandable: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "question": self.question,
            "retrieval_mode": self.retrieval_mode,
            "answer": self.answer,
            "confidence": self.confidence,
            "cards": [card.to_dict() for card in self.cards],
            "sources": [
                {"path": source.path, "lines": source.lines, "score": round(source.score, 3)}
                for source in self.sources
            ],
            "expandable": self.expandable,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class MemoryCard:
    claim: str
    source: Source
    why_it_matters: str

    def to_dict(self) -> dict[str, object]:
        return {
            "claim": self.claim,
            "why_it_matters": self.why_it_matters,
            "source": {
                "path": self.source.path,
                "lines": self.source.lines,
                "score": round(self.source.score, 3),
            },
        }


@dataclass(frozen=True)
class ExcerptResult:
    path: str
    lines: str
    text: str

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "lines": self.lines, "text": self.text}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


@dataclass(frozen=True)
class ContextPackResult:
    question: str
    retrieval_mode: str
    answer: list[str]
    excerpts: list[ExcerptResult]
    cards: list[MemoryCard]
    sources: list[Source]
    confidence: float

    def to_dict(self) -> dict[str, object]:
        return {
            "question": self.question,
            "retrieval_mode": self.retrieval_mode,
            "answer": self.answer,
            "confidence": self.confidence,
            "cards": [card.to_dict() for card in self.cards],
            "sources": [
                {"path": source.path, "lines": source.lines, "score": round(source.score, 3)}
                for source in self.sources
            ],
            "excerpts": [excerpt.to_dict() for excerpt in self.excerpts],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def recall(
    question: str,
    vault: Path,
    project: str | None = None,
    max_tokens: int = 350,
    limit: int = 4,
    retrieval_mode: str = "lexical",
    recency_half_life_days: float | None = None,
    _snapshots: dict[tuple[str, str], str] | None = None,
    _allow_network_embeddings: bool = True,
) -> RecallResult:
    if not question.strip():
        # A malformed request must not be answered like an empty vault. REST, MCP and the
        # CLI all reached here with a blank question and were told "no matching memory",
        # which a caller reads as a fact about the vault rather than about its own request.
        raise ValueError("question is required")
    if len(question) > 200:
        raise ValueError("question must be at most 200 characters")
    retrieval_mode = _validate_retrieval_mode(retrieval_mode)
    max_tokens = _clamp_int(max_tokens, minimum=40, maximum=MAX_RECALL_TOKENS)
    limit = _clamp_int(limit, minimum=1, maximum=MAX_RECALL_LIMIT)
    query_terms = _terms(question)
    weighted_terms = _weighted_terms(query_terms)
    embed_config = (_optional_embedding_config(vault)
                    if _allow_network_embeddings and retrieval_mode in {"hybrid", "semantic"} else None)
    chunks = _scoped_chunks(vault, project, embed_config)
    # Only source text can support a citation. In particular an empty snapshot
    # must never acquire evidence from a cached heading.
    chunks = [chunk for chunk in chunks if chunk_text(vault, chunk).strip()]
    query_vector = _embed_query(embed_config, question)
    now = datetime.now(timezone.utc).timestamp()
    scored = _score_chunks(
        chunks,
        weighted_terms,
        question,
        retrieval_mode,
        query_vector=query_vector,
        recency_half_life_days=recency_half_life_days,
        now=now,
    )
    if scored:
        floor = scored[0][1] * RELATIVE_SCORE_FLOOR
        scored = [(chunk, score) for chunk, score in scored if score >= floor]
    matches = _distinct_matches(scored, limit=limit)
    if not matches:
        return RecallResult(
            question=question,
            retrieval_mode=retrieval_mode,
            answer=["No matching memory found in the curated vault."],
            confidence=0.0,
            cards=[],
            sources=[],
            expandable=False,
        )

    expanded_query = set(weighted_terms)
    budget = max(40, max_tokens)
    answer: list[str] = []
    used_words = 0
    accepted: list[tuple[str, IndexedChunk, float]] = []
    for chunk, _score_value in matches:
        text = chunk_text(vault, chunk)
        sentence = _best_sentence(text, expanded_query)
        sentence = _clean_sentence(sentence)
        if not sentence:
            continue
        dense_support = (_dense_cosine(query_vector, chunk.vector)
                         if retrieval_mode in {"hybrid", "semantic"}
                         and query_vector is not None and chunk.vector is not None else None)
        if not (_terms(sentence) & expanded_query) and not (
            dense_support is not None and dense_support >= SEMANTIC_MIN_SIMILARITY
        ):
            continue
        remaining = budget - used_words
        if remaining <= 0:
            break
        clipped = _clip_words(sentence, min(remaining, 80))
        used_words += _content_cost(clipped)
        answer.append(clipped)
        accepted.append((clipped, chunk, _score_value))

    max_score = matches[0][1]
    confidence = min(0.95, max_score / (max_score + CONFIDENCE_SCALE))
    if _snapshots is not None:
        for chunk, _ in matches:
            _snapshots[(chunk.relative_path, f"{chunk.start_line}-{chunk.end_line}")] = chunk_text(vault, chunk)
    sources = [
        Source(
            path=chunk.relative_path,
            lines=f"{chunk.start_line}-{chunk.end_line}",
            score=score,
        )
        for chunk, score in matches
    ]
    cards = [
        MemoryCard(
            claim=claim,
            source=Source(chunk.relative_path, f"{chunk.start_line}-{chunk.end_line}", score),
            why_it_matters=_why_it_matters(chunk),
        )
        for claim, chunk, score in accepted
    ]
    return RecallResult(
        question=question,
        retrieval_mode=retrieval_mode,
        answer=answer or ["Matching memory exists, but no compact answer could be extracted."],
        confidence=round(confidence, 2),
        cards=cards,
        sources=sources,
        expandable=True,
    )


def excerpt(
    vault: Path,
    source_path: str,
    lines: str,
    max_tokens: int = 220,
) -> ExcerptResult:
    vault_root = vault.resolve()
    path = _resolve_source_path(vault, source_path)
    relative = path.relative_to(vault_root).as_posix()
    # Apply the curated lane policy to both the requested path and its resolved
    # target: a curated-looking symlink must not expose an unpromoted archive.
    requested = (vault_root / source_path).relative_to(vault_root)
    for candidate in (requested, path.relative_to(vault_root)):
        if (
            not candidate.parts
            or candidate.parts[0] not in ("projects", "agents")
            or candidate.suffix != ".md"
            or ".." in candidate.parts
            or is_forbidden_relative(candidate.as_posix())
        ):
            raise ValueError(f"refusing to read forbidden or non-curated memory path: {source_path}")

    start_line, end_line = _parse_line_range(lines)
    if end_line - start_line + 1 > MAX_EXCERPT_LINES:
        end_line = start_line + MAX_EXCERPT_LINES - 1
    max_tokens = _clamp_int(max_tokens, minimum=40, maximum=MAX_RECALL_TOKENS)
    all_lines = redact_secrets(path.read_text(encoding="utf-8")).splitlines()
    selected = all_lines[start_line - 1 : end_line]
    text = "\n".join(selected).strip()
    return ExcerptResult(
        path=relative,
        lines=f"{start_line}-{min(end_line, len(all_lines))}",
        text=redact_secrets(_clip_words(text, max(40, max_tokens))),
    )


def context_pack(
    question: str,
    vault: Path,
    project: str | None = None,
    max_tokens: int = 700,
    limit: int = 3,
    retrieval_mode: str = "lexical",
    recency_half_life_days: float | None = None,
) -> ContextPackResult:
    retrieval_mode = _validate_retrieval_mode(retrieval_mode)
    max_tokens = _clamp_int(max_tokens, minimum=80, maximum=MAX_RECALL_TOKENS)
    limit = _clamp_int(limit, minimum=1, maximum=MAX_RECALL_LIMIT)
    snapshots: dict[tuple[str, str], str] = {}
    recall_result = recall(
        question=question,
        vault=vault,
        project=project,
        max_tokens=max(40, max_tokens // 3),
        limit=limit,
        retrieval_mode=retrieval_mode,
        recency_half_life_days=recency_half_life_days,
        _snapshots=snapshots,
    )
    answer_words = sum(_content_cost(item) for item in recall_result.answer)
    remaining = max_tokens - answer_words
    excerpts = []
    for source in recall_result.sources:
        if remaining < 40:
            break
        try:
            # Reuse recall's generation instead of rereading newer source ranges.
            item = ExcerptResult(path=source.path, lines=source.lines,
                                 text=redact_secrets(_clip_words(
                                     snapshots[(source.path, source.lines)], remaining)))
            excerpts.append(item)
            remaining -= _content_cost(item.text)
        except (FileNotFoundError, ValueError):
            # a source recall surfaced but excerpt cannot re-read (moved, or an
            # index/excerpt confinement mismatch) must not fail the whole pack
            continue
    return ContextPackResult(
        question=question,
        retrieval_mode=retrieval_mode,
        answer=recall_result.answer,
        excerpts=excerpts,
        cards=recall_result.cards,
        sources=recall_result.sources,
        confidence=recall_result.confidence,
    )


def _scoped_chunks(
    vault: Path, project: str | None, embed_config: EmbeddingConfig | None = None
) -> list[IndexedChunk]:
    if project:
        project = validate_project_id(project)
        # Validate the path stays under the vault even though the index
        # already works on relative paths.
        resolve_under(vault.resolve(), "projects", project)
        prefixes = (f"projects/{project}/",)
    else:
        prefixes = ("projects/", "agents/")
    return [
        chunk
        for chunk in load_index(vault, embed_config, prefixes=prefixes)
        if chunk.relative_path.startswith(prefixes)
    ]


def _optional_embedding_config(vault: Path) -> EmbeddingConfig | None:
    """Keep optional configuration failures inside retrieval's fallback boundary."""
    try:
        return load_embedding_config(vault)
    except (EmbeddingError, OSError, ValueError, TypeError, OverflowError, RecursionError):
        # Loader failures are normalized to EmbeddingError; keep a defensive
        # boundary for alternate loaders without exposing configuration contents.
        return None


def _embed_query(embed_config: EmbeddingConfig | None, question: str) -> tuple[float, ...] | None:
    if embed_config is None:
        return None
    try:
        vectors = embed_texts(embed_config, [question])
    except EmbeddingError:
        return None  # fall back to lexical/trigram, never fail recall
    return tuple(vectors[0]) if vectors else None


def _weighted_terms(query_terms: set[str]) -> dict[str, float]:
    content_terms = query_terms - STOPWORDS
    if content_terms:
        query_terms = content_terms
    weighted = {term: 1.0 for term in query_terms}
    for term in query_terms:
        for alias in TERM_ALIASES.get(term, ()):
            if alias not in weighted:
                weighted[alias] = ALIAS_WEIGHT
    return weighted


def _score_chunks(
    chunks: list[IndexedChunk],
    weighted_terms: dict[str, float],
    question: str,
    retrieval_mode: str,
    query_vector: tuple[float, ...] | None = None,
    recency_half_life_days: float | None = None,
    now: float | None = None,
) -> list[tuple[IndexedChunk, float]]:
    if not chunks or not weighted_terms:
        return []
    total = len(chunks)
    avg_length = sum(chunk.length for chunk in chunks) / total
    df = {
        term: sum(1 for chunk in chunks if term in chunk.terms)
        for term in weighted_terms
    }
    use_similarity = retrieval_mode in {"hybrid", "semantic"}
    question_trigrams = _trigram_vector({term: 1 for term in _terms(question)}) if use_similarity else {}

    scored: list[tuple[IndexedChunk, float]] = []
    for chunk in chunks:
        bm25 = _bm25(chunk, weighted_terms, df, total, avg_length)
        similarity = 0.0
        if use_similarity:
            if query_vector is not None and chunk.vector is not None:
                similarity = _dense_cosine(query_vector, chunk.vector)
            else:
                similarity = None
            if similarity is None:
                # Unusable dense vectors follow the same trigram fallback as
                # missing embeddings; zero similarity is a valid comparison.
                similarity = _cosine(question_trigrams, _trigram_vector(chunk.terms))

        if retrieval_mode == "semantic":
            if similarity < SEMANTIC_MIN_SIMILARITY:
                continue
            score = similarity * 10.0 + bm25 * 0.25
        elif retrieval_mode == "hybrid":
            if bm25 <= 0 and similarity < SEMANTIC_MIN_SIMILARITY:
                continue
            score = bm25 * (1.0 + similarity) + similarity * 2.0
        else:  # lexical
            score = bm25

        if score <= 0:
            continue
        score *= _structural_prior(chunk.relative_path)
        score *= _temporal_decay(chunk.timestamp, recency_half_life_days, now)
        scored.append((chunk, score))
    scored.sort(key=lambda item: (-item[1], item[0].relative_path, item[0].start_line))
    return scored


def _temporal_decay(timestamp: float, half_life_days: float | None, now: float | None) -> float:
    """Multiplicative recency weight; 1.0 when decay is off or age unknown."""
    if not half_life_days or half_life_days <= 0 or timestamp <= 0 or now is None:
        return 1.0
    age_days = max(0.0, (now - timestamp) / SECONDS_PER_DAY)
    return 0.5 ** (age_days / half_life_days)


def _dense_cosine(left: tuple[float, ...], right: tuple[float, ...]) -> float | None:
    """Scale before squaring; None requests the lexical/trigram fallback.

    Empty, mismatched, zero-norm or non-finite vectors have no usable cosine.
    A genuine zero or negative cosine is valid and must not trigger fallback.
    """
    if not left or not right or len(left) != len(right):
        return None
    if not all(math.isfinite(value) for value in (*left, *right)):
        return None
    left_scale = max(abs(value) for value in left)
    right_scale = max(abs(value) for value in right)
    if left_scale == 0 or right_scale == 0:
        return None
    # Divide rather than multiply by a reciprocal: tiny scales may have an
    # infinite reciprocal. Each scaled vector has at least one unit component.
    left_scaled = tuple(value / left_scale for value in left)
    right_scaled = tuple(value / right_scale for value in right)
    left_norm = math.sqrt(math.fsum(value * value for value in left_scaled))
    right_norm = math.sqrt(math.fsum(value * value for value in right_scaled))
    similarity = math.fsum(
        (a / left_norm) * (b / right_norm)
        for a, b in zip(left_scaled, right_scaled)
    )
    if not math.isfinite(similarity):
        return None
    return max(-1.0, min(1.0, similarity))


def _bm25(
    chunk: IndexedChunk,
    weighted_terms: dict[str, float],
    df: dict[str, int],
    total: int,
    avg_length: float,
) -> float:
    score = 0.0
    norm = BM25_K1 * (1 - BM25_B + BM25_B * chunk.length / max(1.0, avg_length))
    for term, weight in weighted_terms.items():
        tf = chunk.terms.get(term, 0)
        if not tf:
            continue
        idf = math.log(1 + (total - df[term] + 0.5) / (df[term] + 0.5))
        score += weight * idf * tf * (BM25_K1 + 1) / (tf + norm)
    return score


def _structural_prior(relative_path: str) -> float:
    prior = DOC_PRIORS.get(relative_path.rsplit("/", 1)[-1], 1.0)
    if "/imported/" in relative_path:
        prior *= IMPORTED_LANE_PRIOR
    return prior


def _trigram_vector(terms: dict[str, int]) -> dict[str, float]:
    vector: dict[str, float] = {}
    for token, count in terms.items():
        features = {token}
        if len(token) >= 4:
            features.update(token[index : index + 3] for index in range(len(token) - 2))
        for feature in features:
            vector[feature] = vector.get(feature, 0.0) + float(count)
    return vector


def _cosine(left: dict[str, float], right: dict[str, float]) -> float:
    if not left or not right:
        return 0.0
    numerator = sum(value * right.get(key, 0.0) for key, value in left.items())
    left_norm = math.sqrt(sum(value * value for value in left.values()))
    right_norm = math.sqrt(sum(value * value for value in right.values()))
    if left_norm == 0 or right_norm == 0:
        return 0.0
    return numerator / (left_norm * right_norm)


def _distinct_matches(
    scored: list[tuple[IndexedChunk, float]],
    limit: int,
) -> list[tuple[IndexedChunk, float]]:
    matches: list[tuple[IndexedChunk, float]] = []
    seen_paths: set[str] = set()
    for chunk, score in scored:
        if chunk.relative_path in seen_paths:
            continue
        seen_paths.add(chunk.relative_path)
        matches.append((chunk, score))
        if len(matches) >= limit:
            break
    return matches


def coerce_int(value: object, default: int) -> int:
    """Coerce request input to an int with a clean ValueError.

    Absent/null falls back to the default; booleans, dicts, lists, and
    non-numeric strings raise ValueError so handlers return a structured
    error instead of crashing on int(None) / int({}).
    """
    if value is None:
        return default
    if isinstance(value, bool):
        raise ValueError("expected an integer, got a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value)
    raise ValueError(f"expected an integer, got {type(value).__name__}")


def _clamp_int(value: int, minimum: int, maximum: int) -> int:
    return min(maximum, max(minimum, value))


def _validate_retrieval_mode(value: str) -> str:
    if value not in RETRIEVAL_MODES:
        raise ValueError(f"retrieval_mode must be one of: {', '.join(sorted(RETRIEVAL_MODES))}")
    return value


def _best_sentence(text: str, query_terms: set[str]) -> str:
    # Index partitions never split a fence; use the same line-preserving
    # Markdown mask as term production and outbound document embeddings.
    text = searchable_text(text)
    candidates = [
        candidate.strip()
        for candidate in SENTENCE_RE.split(text)
        if candidate.strip() and _is_answer_candidate(candidate)
    ]
    if not candidates:
        return text.strip()
    return max(candidates, key=lambda sentence: _sentence_score(sentence, query_terms))


def _sentence_score(sentence: str, query_terms: set[str]) -> int:
    stripped = sentence.strip()
    score = len(_terms(stripped) & query_terms) * 2
    if stripped.startswith("Decision:"):
        score += 4
    if stripped.startswith(("Reason:", "Consequence:")):
        score += 2
    if stripped.startswith("#"):
        score -= 2
    return score


def _why_it_matters(chunk: IndexedChunk) -> str:
    name = chunk.relative_path.rsplit("/", 1)[-1]
    if name == "STATUS.md":
        return "Current truth is boosted so agents start from the latest operational state."
    if name == "DECISIONS.md":
        return "Durable decisions explain why the system behaves this way."
    if name == "RUNBOOK.md":
        return "Runbook memory gives the agent an executable next step."
    if name == "OPEN_QUESTIONS.md":
        return "Open questions mark uncertainty the agent should not invent away."
    if "/imported/" in chunk.relative_path:
        return "Imported memory is recallable but ranks below curated docs until promoted."
    return "Curated memory is safe to cite before expanding exact source lines."


def _terms(text: str) -> set[str]:
    return {term.lower() for term in WORD_RE.findall(text)}


def _clean_sentence(text: str) -> str:
    text = re.sub(r"^#+\s*", "", text.strip())
    text = re.sub(r"\s+", " ", text)
    return text.strip("- ")


def _is_answer_candidate(text: str) -> bool:
    stripped = text.strip()
    if "```" in stripped:
        return False
    if stripped.lower() in {"run:", "expected:"}:
        return False
    return True


def _content_cost(text: str) -> int:
    # Bounded content units, not a model-specific tokenizer: both whitespace
    # words and UTF-8 bytes must fit (at most 16 bytes per unit).
    return max(len(text.split()), (len(text.encode("utf-8")) + 15) // 16)


def _clip_words(text: str, max_words: int) -> str:
    # Redact before truncation so clipping cannot hide a credential suffix.
    text = redact_secrets(text)
    if max_words <= 0:
        return ""
    if _content_cost(text) <= max_words:
        return text
    prefix = " ".join(text.split()[:max_words])
    prefix = prefix.encode("utf-8")[:max_words * 16 - 3].decode("utf-8", errors="ignore")
    return prefix.rstrip(" ,;:") + "..."


def _parse_line_range(lines: str) -> tuple[int, int]:
    match = re.fullmatch(r"(\d+)(?:-(\d+))?", lines.strip())
    if not match:
        raise ValueError(f"invalid line range: {lines}")
    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))
    if start < 1 or end < start:
        raise ValueError(f"invalid line range: {lines}")
    return start, end


def _resolve_source_path(vault: Path, source_path: str) -> Path:
    vault_root = vault.resolve()
    path = (vault_root / source_path).resolve()
    # containment BEFORE existence: an outside path must be refused uniformly
    # whether or not it exists, so this cannot be used as a host file-existence
    # oracle via the FileNotFoundError vs ValueError distinction
    if vault_root not in path.parents and path != vault_root:
        raise ValueError(f"refusing to read outside vault: {source_path}")
    if not path.is_file():
        raise FileNotFoundError(source_path)
    return path
