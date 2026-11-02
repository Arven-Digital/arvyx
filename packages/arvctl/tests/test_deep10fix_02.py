"""Lane 02 regressions. Disposable sources/SQLite; embeddings never use network."""
import copy
from datetime import datetime, timedelta, timezone
import importlib
import json
import sqlite3
import threading
from unittest.mock import patch

import pytest

from arvyx_control import checkpoint_jobs as jobs, embeddings, index

retrieval = importlib.import_module("arvyx_control.recall")
RELATIVE = "projects/synthetic/STATUS.md"
TEXT = "# Needle\nNeedle memory has supporting source text.\n## Recovery\nNeedle recovery remains available.\n"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
CONFIG = {"url": "http://synthetic.invalid/embeddings", "model": "synthetic"}


@pytest.fixture
def vault(tmp_path, monkeypatch):
    source = tmp_path / RELATIVE
    source.parent.mkdir(parents=True)
    source.write_text(TEXT, encoding="utf-8")
    monkeypatch.delenv("ARVYX_EMBEDDINGS", raising=False)
    # Ancillary audit persistence is outside these retrieval/publication tests.
    monkeypatch.setattr(jobs, "_audit_event", lambda *a, **kw: None)
    return tmp_path


def assert_supported(result):
    assert result["sources"] and result["cards"]
    for card in result["cards"]:
        assert card["source"]["path"] == RELATIVE
        start, end = map(int, card["source"]["lines"].split("-"))
        assert 1 <= start <= end <= len(TEXT.splitlines())
        assert "Needle" in "\n".join(TEXT.splitlines()[start - 1:end])


BAD_CONFIGS = [
    "{", "[]", json.dumps({**CONFIG, "provider": "unsupported"}),
    json.dumps({"url": CONFIG["url"]}), json.dumps({"model": "synthetic"}),
    *[json.dumps({**CONFIG, "timeout_seconds": value})
      for value in (None, {}, "bad", "20", True, False, 0, -1, float("nan"), float("inf"), 61, 120, 300, 301, 10**400)],
    *[json.dumps({**CONFIG, "batch_size": value})
      for value in (None, {}, "bad", "64", True, False, 1.5, 64.0, 0, -1, float("nan"), float("inf"), 2049, 10**400)],
    *[json.dumps({**CONFIG, "api_key_env": value}) for value in (True, 1, [], {}, "")],
    *[json.dumps({**CONFIG, "url": value}) for value in
      ("file:///synthetic", "http://[", "http:", "http://host:99999", "http://bad host", 1)],
]


@pytest.mark.parametrize("payload", BAD_CONFIGS)
def test_direct_loader_normalizes_invalid_config(vault, payload):
    config_path = vault / ".arvyx/embeddings.json"
    config_path.parent.mkdir()
    config_path.write_text(payload, encoding="utf-8")
    with pytest.raises(embeddings.EmbeddingError):
        embeddings.load_embedding_config(vault)


@pytest.mark.parametrize("timeout,batch", [(0.001, 1), (60, 2048), (20.5, 64)])
def test_typed_configuration_bounds_are_inclusive_where_documented(vault, timeout, batch):
    config_path = vault / ".arvyx/embeddings.json"
    config_path.parent.mkdir()
    config_path.write_text(json.dumps({**CONFIG, "timeout_seconds": timeout, "batch_size": batch}))
    config = embeddings.load_embedding_config(vault)
    assert config.timeout_seconds == timeout and config.batch_size == batch


@pytest.mark.parametrize("failure", [PermissionError("synthetic"), UnicodeError("synthetic"),
                                     RecursionError("synthetic"), OverflowError("synthetic")])
def test_direct_loader_read_failures_use_embedding_error(vault, failure):
    from pathlib import Path
    with patch.object(Path, "read_text", side_effect=failure):
        with pytest.raises(embeddings.EmbeddingError):
            embeddings.load_embedding_config(vault)


@pytest.mark.parametrize("mode", ["hybrid", "semantic"])
@pytest.mark.parametrize("payload", BAD_CONFIGS)
def test_bad_optional_config_falls_back_without_provider(vault, mode, payload):
    config_path = vault / ".arvyx/embeddings.json"
    config_path.parent.mkdir()
    config_path.write_text(payload, encoding="utf-8")
    with patch.object(embeddings, "urlopen", side_effect=AssertionError("provider must not start")):
        assert_supported(retrieval.recall("Needle", vault, retrieval_mode=mode).to_dict())
        assert_supported(retrieval.context_pack("Needle", vault, retrieval_mode=mode).to_dict())
        config_path.unlink()
        assert_supported(retrieval.recall("Needle", vault, retrieval_mode=mode).to_dict())


@pytest.mark.parametrize("surface", ["cli-recall", "cli-pack", "http", "mcp-recall", "mcp-pack"])
@pytest.mark.parametrize("mode", ["hybrid", "semantic"])
def test_config_failure_survives_public_entry_and_followup(vault, surface, mode, capsys):
    config_path = vault / "bad-config.json"
    config_path.write_text("{", encoding="utf-8")
    with patch.dict("os.environ", {"ARVYX_EMBEDDINGS": str(config_path)}), \
         patch.object(embeddings, "urlopen", side_effect=AssertionError("provider must not start")):
        if surface.startswith("cli"):
            from arvyx_control.cli import main
            command = "recall" if surface == "cli-recall" else "context-pack"
            for _ in range(2):
                assert main([command, "Needle", "--vault", str(vault), "--retrieval-mode", mode, "--json"]) == 0
                assert_supported(json.loads(capsys.readouterr().out))
        elif surface == "http":
            from arvyx_control.api import handle_api_request
            with patch("arvyx_control.api._audit_api_request"):
                for _ in range(2):
                    response = handle_api_request("POST", "/memory/recall",
                        {"question": "Needle", "retrieval_mode": mode},
                        vault, vault / "state.jsonl", allow_unauthenticated_demo=True)
                    assert response.status == 200
                    assert_supported(response.body)
        else:
            from arvyx_control.mcp import handle_request
            name = "memory.recall" if surface == "mcp-recall" else "memory.context_pack"
            for request_id in (1, 2):
                response = handle_request({"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                    "params": {"name": name, "arguments": {"question": "Needle", "retrieval_mode": mode}}},
                    vault, state=vault / "state.jsonl")
                assert response["id"] == request_id and "result" in response
                assert_supported(response["result"]["structuredContent"])


@pytest.mark.parametrize("failure", [OSError("synthetic unreadable"), UnicodeError("synthetic encoding"),
                                     RecursionError("synthetic nesting"), OverflowError("synthetic numeric")])
def test_discovery_read_and_decode_failures_are_optional(vault, failure):
    with patch.object(retrieval, "load_embedding_config", side_effect=failure):
        assert_supported(retrieval.recall("Needle", vault, retrieval_mode="hybrid").to_dict())


def corrupt(entry, kind):
    if kind == "beyond-eof":
        entry["chunks"][0].update(start_line=99, end_line=100)
    elif kind == "overlap":
        entry["chunks"][1]["start_line"] = 1
    elif kind == "truncated":
        entry["chunks"][0]["end_line"] = 1
    elif kind == "missing":
        entry["chunks"].pop()


@pytest.mark.parametrize("kind", ["beyond-eof", "overlap", "truncated", "missing"])
def test_cache_ranges_rebuild_from_captured_source(vault, kind):
    index.load_index(vault)
    good = index._read_cache(vault)
    bad = copy.deepcopy(good)
    corrupt(bad[RELATIVE], kind)
    index._write_cache(vault, bad)
    result = retrieval.context_pack("Needle", vault).to_dict()
    assert index._read_cache(vault) == good
    assert_supported(result)
    assert result["excerpts"][0]["text"]


@pytest.mark.parametrize("kind", ["beyond-eof", "overlap", "truncated", "missing"])
@pytest.mark.parametrize("artifact", ["corrupt", "absent"])
def test_completed_artifact_repair_revalidates_checkpoints(vault, kind, artifact):
    first = jobs.rebuild_index_checkpointed(vault, owner="synthetic", now=NOW, max_attempts=1)
    assert first.status == "completed"
    good = index._read_cache(vault)
    bad = copy.deepcopy(good)
    corrupt(bad[RELATIVE], kind)
    with sqlite3.connect(jobs._journal_path(vault)) as connection:
        connection.execute("UPDATE checkpoints SET entry_json=? WHERE relative_path=?",
                           (json.dumps(bad[RELATIVE]), RELATIVE))
    if artifact == "corrupt":
        index._write_cache(vault, bad)
    else:
        (vault / index.INDEX_RELATIVE).unlink()
    repaired = jobs.rebuild_index_checkpointed(vault, owner="synthetic-repair",
        now=NOW + timedelta(seconds=1), max_attempts=1)
    assert repaired.status == "completed" and repaired.attempt == 1
    assert index._read_cache(vault) == good
    with sqlite3.connect(jobs._journal_path(vault)) as connection:
        stored = json.loads(connection.execute("SELECT entry_json FROM checkpoints").fetchone()[0])
    assert stored == good[RELATIVE]


def test_failed_attempt_revalidates_corrupt_checkpoint_on_retry(vault):
    def interrupt(*args):
        raise RuntimeError("synthetic interruption")
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        jobs.rebuild_index_checkpointed(vault, owner="synthetic", now=NOW, after_checkpoint=interrupt)
    with sqlite3.connect(jobs._journal_path(vault)) as connection:
        bad = json.loads(connection.execute("SELECT entry_json FROM checkpoints").fetchone()[0])
        corrupt(bad, "beyond-eof")
        connection.execute("UPDATE checkpoints SET entry_json=?", (json.dumps(bad),))
    result = jobs.rebuild_index_checkpointed(vault, owner="synthetic-retry", now=NOW + timedelta(seconds=61))
    assert result.status == "completed" and result.attempt == 2
    assert index._read_cache(vault)[RELATIVE]["chunks"][0]["start_line"] == 1


def test_empty_snapshot_never_becomes_heading_evidence(vault):
    chunk = index.IndexedChunk(RELATIVE, 99, 100, "Needle", {"needle": 1}, 1, snapshot_text="")
    with patch.object(retrieval, "_scoped_chunks", return_value=[chunk]):
        result = retrieval.context_pack("Needle", vault).to_dict()
    assert result["cards"] == [] and result["sources"] == [] and result["excerpts"] == []


def test_hybrid_writer_cannot_fail_durable_publication_or_spend_retry_budget(vault):
    config = embeddings.EmbeddingConfig("http", CONFIG["url"], "synthetic", None, .5, 64)
    attempted, finished = threading.Event(), threading.Event()
    writer_errors = []
    real_write, real_scoped = index._write_cache, index._write_scoped_cache
    thread = None

    def gated_scoped(*args, **kwargs):
        attempted.set()
        return real_scoped(*args, **kwargs)

    def hybrid_writer():
        try:
            assert_supported(retrieval.recall("Needle", vault, retrieval_mode="hybrid").to_dict())
        except BaseException as exc:
            writer_errors.append(exc)
        finally:
            finished.set()

    def publish_then_race(root, files):
        nonlocal thread
        real_write(root, files)
        thread = threading.Thread(target=hybrid_writer, daemon=True)
        thread.start()
        assert attempted.wait(5), "hybrid producer never reached publication"
        # Old code permits replacement here; fixed code excludes it until COMMIT.
        finished.wait(1)

    with patch.object(jobs, "_write_cache", side_effect=publish_then_race), \
         patch.object(index, "_write_scoped_cache", side_effect=gated_scoped), \
         patch.object(retrieval, "load_embedding_config", return_value=config), \
         patch.object(index, "embed_texts", side_effect=lambda cfg, texts: [[1., 0.] for _ in texts]), \
         patch.object(retrieval, "embed_texts", return_value=[[1., 0.]]):
        try:
            result = jobs.rebuild_index_checkpointed(vault, owner="synthetic", now=NOW, max_attempts=1)
        finally:
            if thread is not None:
                thread.join(5)
        assert finished.is_set() and not writer_errors
        assert result.status == "completed" and result.attempt == 1
        assert jobs._cache_matches_manifest(vault, index._current_file_stats(vault))
        assert index._read_cache(vault)[RELATIVE]["emb_fingerprint"] == config.fingerprint()
        again = jobs.rebuild_index_checkpointed(vault, owner="synthetic-next",
            now=NOW + timedelta(seconds=1), max_attempts=1)
        assert again.status == "completed" and again.attempt == 1


def test_completed_artifact_acceptance_and_readback_hold_publication_lock(vault):
    import fcntl
    real_validate = jobs._cache_matches_manifest
    validations = []

    def validate(root, stats):
        # A separate open file description must be excluded, including on the
        # completed-job shortcut; this tests the real flock rather than a mock.
        with (root / ".arvyx/index-publication.lock").open("a") as contender:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        validations.append(True)
        return real_validate(root, stats)

    with patch.object(jobs, "_cache_matches_manifest", side_effect=validate):
        assert jobs.rebuild_index_checkpointed(vault, owner="first", now=NOW).status == "completed"
        assert jobs.rebuild_index_checkpointed(vault, owner="next",
            now=NOW + timedelta(seconds=1)).status == "completed"
    assert len(validations) == 2

