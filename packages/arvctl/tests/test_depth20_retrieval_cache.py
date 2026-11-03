"""Depth20 retrieval regressions. Authored only; execution requires approval."""
from contextlib import closing
import importlib
import json
import math

import pytest

from arvyx_control import index
from arvyx_control.embeddings import EmbeddingConfig
from arvyx_control.checkpoint_jobs import rebuild_index_checkpointed
from arvyx_control.security import redact_secrets
from arvyx_control.replica_authority import authority_context

retrieval = importlib.import_module("arvyx_control.recall")


def note(vault, relative="projects/a/note.md", text="Needle is current."):
    path = vault / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize("damage", ["empty", "length", "frequency"])
@pytest.mark.parametrize("repair", ["load", "artifact", "checkpoint"])
def test_corrupt_counts_repair_to_retrievable_source(tmp_path, damage, repair):
    note(tmp_path)
    note(tmp_path, "projects/a/empty.md", "")
    with authority_context(tmp_path):
        rebuild_index_checkpointed(tmp_path, owner="regression")
    cache = tmp_path / index.INDEX_RELATIVE
    payload = json.loads(cache.read_text())
    entry = payload["files"]["projects/a/note.md"]
    if damage == "empty":
        entry["chunks"] = []
    elif damage == "length":
        entry["chunks"][0]["length"] = 10**400
    else:
        entry["chunks"][0]["terms"]["needle"] = 10**400
    cache.write_text(json.dumps(payload))
    if repair == "checkpoint":
        import sqlite3
        with closing(sqlite3.connect(tmp_path / ".arvyx/jobs.sqlite3")) as connection, connection:
            connection.execute("UPDATE checkpoints SET entry_json=? WHERE relative_path=?",
                               (json.dumps(entry), "projects/a/note.md"))
        cache.unlink()
    if repair != "load":
        with authority_context(tmp_path):
            rebuild_index_checkpointed(tmp_path, owner="repair")
    result = retrieval.recall("needle", tmp_path)
    assert any("Needle" in claim for claim in result.answer)
    assert result.sources and all(math.isfinite(source.score) for source in result.sources)
    assert not [c for c in index.load_index(tmp_path) if c.relative_path.endswith("empty.md")]


@pytest.mark.parametrize("mode", ["semantic", "hybrid"])
@pytest.mark.parametrize("warm", [False, True])
def test_scope_dense_answer_and_context_generation(tmp_path, monkeypatch, mode, warm):
    path = note(tmp_path, text="Car repairs require certified mechanics.")
    note(tmp_path, "projects/b/note.md", "UNRELATED_PROJECT_MARKER")
    note(tmp_path, "agents/helper/MEMORY.md", "UNRELATED_AGENT_MARKER")
    if warm:
        index.load_index(tmp_path)
    config = EmbeddingConfig("http", "https://offline.invalid", "test", None, 1, 64)
    sent = []
    def embed(config, texts):
        sent.extend(texts)
        return [[1.0, 0.0] for _ in texts]
    monkeypatch.setattr(index, "embed_texts", embed)
    monkeypatch.setattr(retrieval, "embed_texts", embed)
    monkeypatch.setattr(retrieval, "load_embedding_config", lambda vault: config)
    original = retrieval._embed_query
    def query(*args):
        # Replacement after document snapshot/scoring input collection.
        path.write_text("New unrelated generation.")
        return original(*args)
    monkeypatch.setattr(retrieval, "_embed_query", query)
    result = retrieval.context_pack("automobile maintenance", tmp_path, project="a", retrieval_mode=mode)
    assert result.cards and "Car repairs" in result.cards[0].claim
    assert result.excerpts and "Car repairs" in result.excerpts[0].text
    assert all("UNRELATED_" not in text for text in sent)
    if warm:
        assert "projects/b/note.md" in index._read_cache(tmp_path)
        assert "agents/helper/MEMORY.md" in index._read_cache(tmp_path)


def test_change_during_document_embedding_is_dropped(tmp_path, monkeypatch):
    path = note(tmp_path)
    config = EmbeddingConfig("http", "https://offline.invalid", "test", None, 1, 64)
    def embed(config, texts):
        path.write_text("---\nstatus: superseded\n---\nObsolete")
        return [[1.0] for _ in texts]
    monkeypatch.setattr(index, "embed_texts", embed)
    assert index.load_index(tmp_path, config) == []
    assert "projects/a/note.md" not in index._read_cache(tmp_path)


def test_crossline_redaction_keeps_original_citations(tmp_path):
    secret = "abcdefghijklmnopqrstuvwx1234567890"
    text = "token=\n" + secret + "\n# Needle\nNeedle is current.\n"
    note(tmp_path, text=text)
    assert len(redact_secrets(text).splitlines()) == len(text.splitlines())
    item = retrieval.excerpt(tmp_path, "projects/a/note.md", "3-3")
    assert item.text == "# Needle"
    result = retrieval.recall("needle", tmp_path)
    assert any(source.lines == "3-4" for source in result.sources)
    assert secret not in str(result)
