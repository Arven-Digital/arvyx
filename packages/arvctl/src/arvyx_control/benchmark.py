from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

from . import __version__
from .index import FORBIDDEN_SEGMENTS, INDEXED_ROOTS, INDEX_FORMAT, WORD_RE, _current_file_stats
from .recall import _optional_embedding_config, recall

PROVENANCE_SCHEMA = "arvyx-benchmark-provenance/v2"


def _dataset_sha256(cases_path: Path) -> str:
    return _file_sha256(cases_path)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _corpus_sha256(vault: Path) -> str:
    """Bind canonical relative names and bytes for every retrievable source."""
    digest = hashlib.sha256()
    for relative, (_mtime_ns, _size, content_hash) in sorted(_current_file_stats(vault).items()):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content_hash.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _retrieval_config(vault: Path, retrieval_mode: str, *, allow_network_embeddings: bool = True) -> dict[str, Any]:
    embedding = (_optional_embedding_config(vault)
                 if allow_network_embeddings and retrieval_mode in {"hybrid", "semantic"} else None)
    return {
        "index_format": INDEX_FORMAT,
        "indexed_roots": list(INDEXED_ROOTS),
        "forbidden_segments": sorted(FORBIDDEN_SEGMENTS),
        "token_pattern": WORD_RE.pattern,
        "token_flags": WORD_RE.flags,
        "embedding_fingerprint": embedding.fingerprint() if embedding is not None else None,
        "allow_network_embeddings": allow_network_embeddings,
    }


def _implementation_sha256() -> str:
    digest = hashlib.sha256()
    source_root = Path(__file__).resolve().parent
    for name in ("benchmark.py", "index.py", "recall.py", "embeddings.py"):
        digest.update(name.encode("ascii"))
        digest.update(b"\0")
        digest.update(_file_sha256(source_root / name).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _run_id(inputs: dict[str, Any]) -> str:
    """Deterministic run identity: identical inputs produce an identical ID."""
    canonical = json.dumps(
        inputs,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    question: str
    project: str | None
    category: str
    expected_sources: list[str]
    forbidden_sources: list[str]
    min_confidence: float


@dataclass(frozen=True)
class BenchmarkCaseResult:
    id: str
    category: str
    retrieval_mode: str
    ok: bool
    question: str
    confidence: float
    sources: list[str]
    missing_sources: list[str]
    forbidden_hits: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "retrieval_mode": self.retrieval_mode,
            "ok": self.ok,
            "question": self.question,
            "confidence": self.confidence,
            "sources": self.sources,
            "missing_sources": self.missing_sources,
            "forbidden_hits": self.forbidden_hits,
        }


@dataclass(frozen=True)
class BenchmarkResult:
    ok: bool
    retrieval_mode: str
    score: int
    passed: int
    total: int
    metadata: dict[str, Any]
    categories: dict[str, dict[str, Any]]
    cases: list[BenchmarkCaseResult]
    provenance: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "retrieval_mode": self.retrieval_mode,
            "score": self.score,
            "passed": self.passed,
            "total": self.total,
            "metadata": self.metadata,
            "categories": self.categories,
            "cases": [case.to_dict() for case in self.cases],
            "provenance": self.provenance,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def run_recall_benchmark(
    vault: Path,
    cases_path: Path,
    max_tokens: int = 160,
    retrieval_mode: str = "lexical",
    *,
    allow_network_embeddings: bool = True,
) -> BenchmarkResult:
    # Parse and identify the same byte snapshot, not two path generations.
    dataset_bytes = cases_path.read_bytes()
    metadata, cases = _parse_cases(dataset_bytes)
    dataset_sha256 = hashlib.sha256(dataset_bytes).hexdigest()
    corpus_sha256 = _corpus_sha256(vault)
    inputs = {
        "provenance_schema": PROVENANCE_SCHEMA,
        "dataset_sha256": dataset_sha256,
        "corpus_sha256": corpus_sha256,
        "retrieval_mode": retrieval_mode,
        "max_tokens": max_tokens,
        "metadata": metadata,
        "retrieval_config": _retrieval_config(vault, retrieval_mode, allow_network_embeddings=allow_network_embeddings),
        "implementation_version": __version__,
        "implementation_sha256": _implementation_sha256(),
    }
    provenance = {
        **inputs,
        "dataset_path": cases_path.as_posix(),
        "run_id": _run_id(inputs),
        "case_count": len(cases),
    }
    results: list[BenchmarkCaseResult] = []
    for case in cases:
        recalled = recall(
            question=case.question,
            vault=vault,
            project=case.project,
            max_tokens=max_tokens,
            retrieval_mode=retrieval_mode,
            _allow_network_embeddings=allow_network_embeddings,
        )
        sources = [source.path for source in recalled.sources]
        missing_sources = [source for source in case.expected_sources if source not in sources]
        forbidden_hits = [source for source in case.forbidden_sources if source in sources]
        ok = not missing_sources and not forbidden_hits and recalled.confidence >= case.min_confidence
        results.append(
            BenchmarkCaseResult(
                id=case.id,
                category=case.category,
                retrieval_mode=retrieval_mode,
                ok=ok,
                question=case.question,
                confidence=recalled.confidence,
                sources=sources,
                missing_sources=missing_sources,
                forbidden_hits=forbidden_hits,
            )
        )
    if _corpus_sha256(vault) != corpus_sha256:
        raise RuntimeError("vault corpus changed during benchmark run")
    passed = sum(1 for result in results if result.ok)
    total = len(results)
    score = round((passed / total) * 100) if total else 0
    return BenchmarkResult(
        ok=passed == total and total > 0,
        retrieval_mode=retrieval_mode,
        score=score,
        passed=passed,
        total=total,
        metadata=metadata,
        categories=_category_summary(results),
        cases=results,
        provenance=provenance,
    )


def _load_cases(path: Path) -> tuple[dict[str, Any], list[BenchmarkCase]]:
    return _parse_cases(path.read_bytes())


def _parse_cases(data: bytes) -> tuple[dict[str, Any], list[BenchmarkCase]]:
    payload = json.loads(data.decode("utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("cases"), list):
        raise ValueError("benchmark file must contain a cases list")
    metadata = {key: value for key, value in payload.items() if key != "cases"}
    return metadata, [_case_from_payload(item) for item in payload["cases"]]


def _case_from_payload(item: object) -> BenchmarkCase:
    if not isinstance(item, dict):
        raise ValueError("benchmark case must be an object")
    case_id = item.get("id")
    question = item.get("question")
    if not isinstance(case_id, str) or not case_id:
        raise ValueError("benchmark case id must be a non-empty string")
    if not isinstance(question, str) or not question:
        raise ValueError(f"benchmark case {case_id} question must be a non-empty string")
    category = item.get("category", "default")
    if not isinstance(category, str) or not category:
        raise ValueError(f"benchmark case {case_id} category must be a non-empty string")
    return BenchmarkCase(
        id=case_id,
        question=question,
        project=_optional_string(item.get("project")),
        category=category,
        expected_sources=_string_list(item.get("expected_sources", []), case_id, "expected_sources"),
        forbidden_sources=_string_list(item.get("forbidden_sources", []), case_id, "forbidden_sources"),
        min_confidence=float(item.get("min_confidence", 0.1)),
    )


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("project must be a string when present")
    return value


def _string_list(value: object, case_id: str, field: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"benchmark case {case_id} {field} must be a string list")
    return value


def _category_summary(results: list[BenchmarkCaseResult]) -> dict[str, dict[str, Any]]:
    categories: dict[str, dict[str, Any]] = {}
    for result in results:
        summary = categories.setdefault(result.category, {"passed": 0, "total": 0, "score": 0, "ok": False})
        summary["total"] += 1
        if result.ok:
            summary["passed"] += 1
    for summary in categories.values():
        total = int(summary["total"])
        passed = int(summary["passed"])
        summary["score"] = round((passed / total) * 100) if total else 0
        summary["ok"] = total > 0 and passed == total
    return categories
