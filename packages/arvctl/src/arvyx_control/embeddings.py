from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request
from urllib.parse import urlsplit
from .http_bounds import BoundedOpener

from .security import is_http_url


_OPENER = BoundedOpener()
urlopen = _OPENER.open


# Embeddings are optional and provider-agnostic. When no config is present
# retrieval stays purely lexical (BM25 + trigram). When configured, the
# provider is any OpenAI-compatible /embeddings endpoint — OpenAI, a local
# vLLM / llama.cpp / text-embeddings-inference server, or a self-hosted
# model — so it is not tied to any single vendor or harness.
CONFIG_ENV = "ARVYX_EMBEDDINGS"
CONFIG_RELATIVE = Path(".arvyx") / "embeddings.json"


class EmbeddingError(RuntimeError):
    pass


@dataclass(frozen=True)
class EmbeddingConfig:
    provider: str
    url: str
    model: str
    api_key_env: str | None
    timeout_seconds: float
    batch_size: int

    def __post_init__(self) -> None:
        # Validate direct constructors as well as JSON discovery. No coercion:
        # booleans, numeric strings and fractional batch counts are not config.
        if self.provider != "http":
            raise EmbeddingError("unsupported embeddings provider")
        try:
            valid_url = isinstance(self.url, str) and is_http_url(self.url)
            if valid_url:
                parsed_url = urlsplit(self.url)
                valid_url = bool(parsed_url.hostname) and not any(char.isspace() for char in self.url)
                # Access validates malformed/out-of-range ports without I/O.
                parsed_url.port
        except ValueError as exc:
            raise EmbeddingError("invalid embeddings URL") from exc
        if not valid_url:
            raise EmbeddingError("embeddings config requires an http(s) URL")
        if not isinstance(self.model, str) or not self.model.strip():
            raise EmbeddingError("embeddings config requires a model")
        if self.api_key_env is not None and (
            not isinstance(self.api_key_env, str) or not self.api_key_env.strip()
        ):
            raise EmbeddingError("embeddings api_key_env must be a nonempty string or null")
        if type(self.timeout_seconds) not in (int, float):
            raise EmbeddingError("embeddings timeout_seconds must be numeric")
        try:
            valid_timeout = math.isfinite(self.timeout_seconds) and 0 < self.timeout_seconds <= 60
        except (OverflowError, ValueError, TypeError) as exc:
            raise EmbeddingError("invalid embeddings timeout_seconds") from exc
        if not valid_timeout:
            raise EmbeddingError("embeddings timeout_seconds must be finite and in (0, 60]")
        if type(self.batch_size) is not int or not 1 <= self.batch_size <= 2048:
            raise EmbeddingError("embeddings batch_size must be an integer in [1, 2048]")

    def fingerprint(self) -> str:
        # Changing provider/model/url must invalidate cached vectors.
        raw = json.dumps(
            {"provider": self.provider, "url": self.url, "model": self.model},
            sort_keys=True,
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def load_embedding_config(vault: Path | None = None) -> EmbeddingConfig | None:
    for candidate in _config_candidates(vault):
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except FileNotFoundError:
            continue
        except (OSError, ValueError, UnicodeError, RecursionError, OverflowError, TypeError) as exc:
            # Normalize discovery/read/JSON failures without echoing config or
            # paths; retrieval handles this one optional-enhancement error type.
            raise EmbeddingError("embeddings configuration could not be read or decoded") from exc
        if not isinstance(payload, dict):
            raise EmbeddingError("embeddings config must be a JSON object")
        provider = payload.get("provider", "http")
        if provider != "http":
            raise EmbeddingError("unsupported embeddings provider")
        url = payload.get("url")
        model = payload.get("model")
        if not isinstance(url, str) or not url:
            raise EmbeddingError("embeddings config requires 'url'")
        if not isinstance(model, str) or not model:
            raise EmbeddingError("embeddings config requires 'model'")
        return EmbeddingConfig(
            provider=provider,
            url=url,
            model=model,
            api_key_env=payload.get("api_key_env"),
            timeout_seconds=payload.get("timeout_seconds", 20),
            batch_size=payload.get("batch_size", 64),
        )
    return None


def embed_texts(config: EmbeddingConfig, texts: list[str]) -> list[list[float]]:
    """Return one embedding per input text via an OpenAI-compatible API.

    Indexed responses must identify every batch input exactly once. For
    legacy providers only, fully unindexed responses are positional in input
    order; mixed indexed/unindexed responses are never accepted.
    """
    if not texts:
        return []
    from .security import redact_secrets
    # Last outbound boundary also covers query/direct callers. Redact complete
    # inputs before batching; document callers already redact before clipping.
    texts = [redact_secrets(text) for text in texts]
    vectors: list[list[float]] = []
    for start in range(0, len(texts), max(1, config.batch_size)):
        batch = texts[start : start + max(1, config.batch_size)]
        vectors.extend(_embed_batch(config, batch))
    return vectors


def _embed_batch(config: EmbeddingConfig, batch: list[str]) -> list[list[float]]:
    body = json.dumps({"model": config.model, "input": batch}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if config.api_key_env:
        key = os.environ.get(config.api_key_env)
        if not key:
            raise EmbeddingError(f"embeddings api key env not set: {config.api_key_env}")
        headers["Authorization"] = f"Bearer {key}"
    if not is_http_url(config.url):
        raise EmbeddingError(f"refusing non-http(s) embeddings endpoint: {config.url}")
    request = Request(config.url, data=body, headers=headers, method="POST")
    try:
        with urlopen(request, timeout=config.timeout_seconds) as response:  # noqa: S310 - operator-configured endpoint
            data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise EmbeddingError("embeddings response exceeds limit")
            _check_response_depth(data)
            payload = json.loads(data.decode("utf-8"))
    except HTTPError as exc:
        exc.close()
        raise EmbeddingError(f"embeddings endpoint HTTP {exc.code}") from None
    except URLError as exc:
        raise EmbeddingError(f"embeddings endpoint unreachable: {exc.reason}") from exc
    except (OSError, ValueError, RecursionError) as exc:
        raise EmbeddingError("embeddings response invalid or incomplete") from exc
    return _vectors_from_response(payload, expected=len(batch))


def _check_response_depth(data: bytes) -> None:
    """Bound container nesting before the recursive JSON decoder runs.

    Scan iteratively, ignoring delimiters inside strings (including escaped
    quotes/backslashes). The JSON decoder remains responsible for syntax.
    The existing byte cap bounds scan work; no recursive traversal is needed.
    """
    depth = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 92:  # backslash
                escaped = True
            elif byte == 34:  # quote
                in_string = False
        elif byte == 34:
            in_string = True
        elif byte in (91, 123):  # array/object opening
            depth += 1
            if depth > 64:
                raise EmbeddingError("embeddings response nesting exceeds limit")
        elif byte in (93, 125):
            depth -= 1


def _vectors_from_response(payload: Any, expected: int) -> list[list[float]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise EmbeddingError("embeddings response missing 'data' array")
    data = payload["data"]
    if len(data) != expected:
        raise EmbeddingError(f"embeddings response returned {len(data)} vectors, expected {expected}")
    if any(not isinstance(item, dict) for item in data):
        raise EmbeddingError("embeddings response item must be an object")
    # Legacy fully unindexed responses use input order. Once any index is
    # present, require a complete bijection; never guess mixed mappings.
    if any("index" in item for item in data):
        indices = [item.get("index") for item in data]
        if any(type(value) is not int for value in indices) or set(indices) != set(range(expected)):
            raise EmbeddingError("embeddings response indices must cover each input exactly once")
        data = sorted(data, key=lambda item: item["index"])
    vectors: list[list[float]] = []
    for item in data:
        if not isinstance(item, dict) or not isinstance(item.get("embedding"), list):
            raise EmbeddingError("embeddings response item missing 'embedding'")
        try:
            vector = [float(value) for value in item["embedding"]]
        except (TypeError, ValueError, OverflowError) as exc:
            # a hostile/buggy vector value must degrade recall, not crash it:
            # callers only catch EmbeddingError
            raise EmbeddingError("embeddings response has a non-numeric vector value") from exc
        if not all(math.isfinite(value) for value in vector):
            raise EmbeddingError("embeddings response has a non-finite (NaN/inf) vector value")
        vectors.append(vector)
    if len(vectors) != expected:
        raise EmbeddingError(f"embeddings response returned {len(vectors)} vectors, expected {expected}")
    return vectors



def _config_candidates(vault: Path | None) -> list[Path]:
    candidates: list[Path] = []
    env_path = os.environ.get(CONFIG_ENV)
    if env_path:
        candidates.append(Path(env_path))
    if vault is not None:
        candidates.append(vault / CONFIG_RELATIVE)
    return candidates
