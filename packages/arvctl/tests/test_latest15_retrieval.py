"""Latest15 retrieval regressions; authored, NOT EXECUTED in the fix round."""
from datetime import datetime, timedelta, timezone
from email.message import Message
import importlib
import json
import sqlite3
import sys
import time

import pytest

from arvyx_control import checkpoint_jobs as jobs, embeddings, http_bounds, index

retrieval = importlib.import_module("arvyx_control.recall")
RELATIVE = "projects/demo/RUNBOOK.md"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def owned_rebuild(root,**kwargs):
    from arvyx_control.replica_authority import authority_context
    with authority_context(root):return jobs.rebuild_index_checkpointed(root,**kwargs)


def seed(root, text="# Runbook\nNeedle remains available.\n"):
    source = root / RELATIVE
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(text, encoding="utf-8")
    return source


@pytest.mark.parametrize("timeout", [60, 61, 120, 300])
def test_timeout_discovery_matches_actual_transport(tmp_path, monkeypatch, timeout):
    seed(tmp_path)
    monkeypatch.delenv("ARVYX_EMBEDDINGS", raising=False)
    config_path = tmp_path / ".arvyx/embeddings.json"
    config_path.parent.mkdir()
    config_path.write_text(json.dumps(dict(url="http://offline.invalid/embeddings",
                                         model="test", timeout_seconds=timeout)))
    if timeout > 60:
        with pytest.raises(embeddings.EmbeddingError, match="60"):
            embeddings.load_embedding_config(tmp_path)
        return
    config = embeddings.load_embedding_config(tmp_path)
    observed = []

    class Response:
        status = 200
        reason = "OK"
        chunked = False
        _method = "POST"
        def __init__(self, body):
            self.body = body
            self.headers = Message()
            self.headers["Content-Length"] = str(len(body))
            self.length = len(body)
        def read(self, size):
            self.length = 0
            return self.body
        def close(self):
            pass

    class Connection:
        _transport_deadline: float
        def __init__(self, host, port, timeout):
            self.timeout = timeout
            self.sock = None
        def connect(self):
            assert 0 < self._transport_deadline - time.monotonic() <= 60
        def request(self, method, path, body, headers):
            self.deadline = self._transport_deadline
            self.inputs = json.loads(body)["input"]
            observed.extend(self.inputs)
        def getresponse(self):
            assert self.deadline == self._transport_deadline
            return Response(json.dumps({"data": [dict(index=i, embedding=[1., 0.])
                            for i in range(len(self.inputs))]}).encode())
        def close(self):
            pass

    # Keep the real opener, bounded_connection and response checks. Only the
    # connection is fake: no DNS, sockets, provider or service is involved.
    monkeypatch.setattr(http_bounds.http.client, "HTTPConnection", Connection)
    chunks = index.load_index(tmp_path, config)
    assert chunks and all(c.vector for c in chunks)
    assert retrieval._embed_query(config, "needle query") == (1., 0.)
    assert any("Needle remains" in text for text in observed)
    assert "needle query" in observed


def corrupt_json(kind):
    if kind == "depth":
        return "[" * 2000 + "0" + "]" * 2000
    if not hasattr(sys, "get_int_max_str_digits") or not sys.get_int_max_str_digits():
        pytest.skip("runtime integer-string limit is disabled")
    return "1" * (sys.get_int_max_str_digits() + 1)


@pytest.mark.parametrize("kind", ["depth", "integer"])
@pytest.mark.parametrize("surface", ["recall", "context_pack", "artifact", "checkpoint"])
def test_decoder_failure_repairs_from_source(tmp_path, kind, surface):
    seed(tmp_path)
    owned_rebuild(tmp_path, owner="first", now=NOW)
    cache = tmp_path / index.INDEX_RELATIVE
    bad = corrupt_json(kind)
    if surface == "checkpoint":
        with sqlite3.connect(jobs._journal_path(tmp_path)) as connection:
            connection.execute("UPDATE checkpoints SET entry_json=?", (bad,))
        cache.unlink()
    else:
        cache.write_text(bad)
    if surface in {"artifact", "checkpoint"}:
        assert owned_rebuild(tmp_path, owner="repair",
                   now=NOW + timedelta(seconds=1)).status == "completed"
    result = getattr(retrieval, surface if surface in {"recall", "context_pack"} else "recall")(
        "needle", tmp_path)
    assert result.cards and any("Needle remains" in claim for claim in result.answer)
    assert json.loads(cache.read_text())["format"] == index.INDEX_FORMAT
    assert jobs._cache_matches_manifest(tmp_path, index._current_file_stats(tmp_path))


@pytest.mark.parametrize("opening,closing", [("```sh", "```"), ("~~~~sh", "~~~~"),
                                              ("   ````sh", "   ````"), ("```sh", "")])
def test_fence_exclusion_survives_rebuild_reload_and_embeddings(tmp_path, monkeypatch, opening, closing):
    text = "\n".join(["# Runbook", opening, "# Historical recipe",
                       "Decision: quuxneedle disable deployment approval.", closing])
    if closing:
        text += "\n# Current\nNeedle remains available.\n"
    seed(tmp_path, text)
    owned_rebuild(tmp_path, owner="first", now=NOW)
    chunks = index.load_index(tmp_path)
    assert all("quuxneedle" not in c.terms and c.heading != "Historical recipe" for c in chunks)
    if closing:
        assert [(c.start_line, c.end_line) for c in chunks] == [(1, 5), (6, 7)]
    for operation in (retrieval.recall, retrieval.context_pack):
        result = operation("quuxneedle", tmp_path)
        assert not result.sources and not result.cards
    sent = []
    def embed(config, texts):
        sent.extend(texts)
        return [[1., 0.] for _ in texts]
    monkeypatch.setattr(index, "embed_texts", embed)
    config = embeddings.EmbeddingConfig("http", "http://offline.invalid", "test", None, 60, 64)
    index.load_index(tmp_path, config)
    assert sent and all("quuxneedle" not in s and "Historical recipe" not in s for s in sent)
    assert all("quuxneedle" not in retrieval._best_sentence(index.chunk_text(tmp_path, c),
                       {"quuxneedle"}) for c in index.load_index(tmp_path))
    assert jobs._cache_matches_manifest(tmp_path, index._current_file_stats(tmp_path))


def test_old_cache_and_same_partition_old_checkpoint_terms_are_invalidated(tmp_path):
    seed(tmp_path, "# Runbook\n```sh\nquuxneedle\n```\n")
    owned_rebuild(tmp_path, owner="first", now=NOW)
    cache = tmp_path / index.INDEX_RELATIVE
    payload = json.loads(cache.read_text())
    entry = payload["files"][RELATIVE]
    entry["chunks"][0]["terms"]["quuxneedle"] = 1
    entry["chunks"][0]["length"] += 1
    payload["format"] = 5
    cache.write_text(json.dumps(payload))
    with sqlite3.connect(jobs._journal_path(tmp_path)) as connection:
        connection.execute("UPDATE checkpoints SET entry_json=?", (json.dumps(entry),))
    owned_rebuild(tmp_path, owner="repair", now=NOW + timedelta(seconds=1))
    assert all("quuxneedle" not in c.terms for c in index.load_index(tmp_path))
    assert json.loads(cache.read_text())["format"] == index.INDEX_FORMAT
