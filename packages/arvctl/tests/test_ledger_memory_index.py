"""Ledger memory/index regressions; authored, not executed in this round."""
from datetime import datetime, timezone
import sqlite3

import pytest

from arvyx_control import checkpoint_jobs as jobs
from arvyx_control.index import is_forbidden_relative, load_index
from arvyx_control.recall import excerpt, recall
from arvyx_control.replica_authority import authority_context


@pytest.mark.parametrize("project", ["raw", "archive", "pending", "refining"])
def test_lane_named_project_curated_note_is_retrievable(tmp_path, project):
    relative = f"projects/{project}/notes/current.md"
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_text("# Quorum\nQuorum requires three nodes.\n", encoding="utf-8")
    assert not is_forbidden_relative(relative)
    assert relative in {chunk.relative_path for chunk in load_index(tmp_path)}
    assert relative in {source.path for source in recall("quorum", tmp_path, project=project).sources}
    assert "three nodes" in excerpt(tmp_path, relative, "1-2").text
    for lane in ("raw", "archive", "pending", "refining", ".git", ".arvyx"):
        assert is_forbidden_relative(f"projects/{project}/{lane}/hidden.md")
        assert is_forbidden_relative(f"projects/{project}/notes/{lane}/hidden.md")
    assert is_forbidden_relative("projects/archive/hidden.md")
    assert is_forbidden_relative("projects/.git/notes/hidden.md")


@pytest.mark.parametrize("tail", [[], None, "scalar", 7, False])
def test_nonobject_audit_tail_is_corruption_not_worker_crash(tmp_path, tail):
    import json
    from arvyx_control.audit_log import AuditCorruptionError, _last_hash
    audit = tmp_path / "audit.jsonl"
    audit.write_text(json.dumps(tail) + "\n", encoding="utf-8")
    with pytest.raises(AuditCorruptionError):
        _last_hash(audit)


@pytest.mark.parametrize("boundary", ["snapshot", "index"])
def test_single_file_drift_releases_worker_lease(tmp_path, monkeypatch, boundary):
    relative = "projects/a/notes/current.md"
    path = tmp_path / relative
    path.parent.mkdir(parents=True)
    path.write_text("# Quorum\nOriginal generation.\n", encoding="utf-8")
    if boundary == "snapshot":
        original = jobs._source_snapshot
        def changed_snapshot(root, name):
            path.write_text("# Quorum\nChanged generation.\n", encoding="utf-8")
            return original(root, name)
        monkeypatch.setattr(jobs, "_source_snapshot", changed_snapshot)
    else:
        original = jobs._index_file
        def changed_index(*args, **kwargs):
            chunks = original(*args, **kwargs)
            path.write_text("# Quorum\nChanged generation.\n", encoding="utf-8")
            return chunks
        monkeypatch.setattr(jobs, "_index_file", changed_index)
    moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with authority_context(tmp_path), pytest.raises(jobs.SourceDriftError):
        jobs.rebuild_index_checkpointed(tmp_path, owner="drift-worker", now=moment)
    with sqlite3.connect(tmp_path / ".arvyx/jobs.sqlite3") as connection:
        status, lease, updated = connection.execute(
            "SELECT status, lease_expires_at, updated_at FROM jobs WHERE name='index-rebuild'"
        ).fetchone()
    assert status == "failed"
    assert lease == updated == jobs._timestamp(moment)
