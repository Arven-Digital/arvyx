"""Lane A: rendered memory, retained restore witnesses and portable publication.

All state belongs to pytest's explicitly scratch-rooted basetemp. No providers,
native processes, live databases or transports are used.
"""
import builtins
from datetime import datetime, timezone
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
from types import ModuleType

import pytest

from arvyx_control import forget, importers, index, locks, writes
from arvyx_control.importers import MAX_IMPORT_FILE_BYTES, import_markdown
from arvyx_control.recall import context_pack, recall
from arvyx_control.replica_authority import authority_context
from arvyx_control.vault import init_vault


LIMIT = 1024 * 1024


@pytest.fixture
def vault(tmp_path):
    root = tmp_path / "vault"
    init_vault(root)
    return root


def pending(vault):
    return writes.suggest_memory(vault, "demo-agent", "Bounded note", "Useful body", "operator").path


def item(title="A bounded item", **changes):
    return {"title": title, "content": "Useful body", "content_class": "durable_fact",
            "memory_class": "dynamic", "future_job": "Answer later questions",
            "assistant_suggestion_accepted": False, **changes}


@pytest.mark.parametrize("changes", [
    {"content": "word " * (LIMIT // 5 + 1)},
    {"content": "界" * (LIMIT // 3 + 1)},
    {"notes": "x" * LIMIT},
    {"refined_by": "x" * LIMIT},
])
def test_oversized_refinement_preserves_source(vault, changes):
    source = pending(vault)
    original = (vault / source).read_bytes()
    before = sorted((vault / "projects/demo-agent/refining").glob("*.md"))
    kwargs = {"refined_by": "operator", **changes}
    with pytest.raises(ValueError, match="byte limit"):
        writes.refine_memory(vault, "demo-agent", source, **kwargs)
    assert (vault / source).read_bytes() == original
    assert sorted((vault / "projects/demo-agent/refining").glob("*.md")) == before


def test_single_suggestion_checks_encoded_metadata_before_publication(vault):
    before = list((vault / "projects/demo-agent/pending").glob("*.md"))
    # JSON escapes expand this short, single-line author beyond the stored bound.
    with pytest.raises(ValueError, match="byte limit"):
        writes.suggest_memory(vault, "demo-agent", "Encoded author", "body", "\x01" * 180_000)
    assert list((vault / "projects/demo-agent/pending").glob("*.md")) == before


def test_batch_preflights_every_rendered_document(vault):
    before = list((vault / "projects/demo-agent/pending").glob("*.md"))
    with pytest.raises(ValueError, match="byte limit"):
        writes.suggest_memory_batch(vault, "demo-agent", "operator", {"memories": [
            item(), item("Oversized metadata", future_job="\x01" * 180_000),
        ]})
    assert list((vault / "projects/demo-agent/pending").glob("*.md")) == before


@pytest.mark.parametrize("dry_run", [False, True])
def test_import_wrapper_preflight_refuses_input_limit_without_partial_batch(vault, tmp_path, dry_run):
    incoming = tmp_path / "incoming"
    incoming.mkdir()
    (incoming / "a-small.md").write_text("small body", encoding="utf-8")
    large = incoming / "z-large.md"
    original = b"x" * MAX_IMPORT_FILE_BYTES
    large.write_bytes(original)
    target = vault / "projects/demo-agent/imported"
    before = {p: p.read_bytes() for p in target.rglob("*") if p.is_file()}
    with pytest.raises(ValueError, match="byte limit"):
        import_markdown(incoming, vault, "demo-agent", dry_run=dry_run)
    assert large.read_bytes() == original
    assert {p: p.read_bytes() for p in target.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("operation", ["promote", "reject"])
def test_lifecycle_metadata_expansion_preserves_source(vault, operation):
    source = pending(vault)
    original = (vault / source).read_bytes()
    with pytest.raises(ValueError, match="byte limit"):
        if operation == "promote":
            writes.promote_memory(vault, "demo-agent", source, "x" * LIMIT)
        else:
            writes.reject_memory(vault, "demo-agent", source, "operator", "x" * LIMIT)
    assert (vault / source).read_bytes() == original


def test_superseded_parent_expansion_preserves_both_sources(vault):
    parent = vault / "projects/demo-agent/notes/full.md"
    parent.parent.mkdir(exist_ok=True)
    original = b"# Nearly full parent\n".ljust(LIMIT - 10, b"x")
    parent.write_bytes(original)
    result = writes.suggest_memory_batch(vault, "demo-agent", "operator", {"memories": [item(
        relations=[{"type": "updates", "parent_source_path": parent.relative_to(vault).as_posix()}],
    )]})
    source = result.suggestions[0].path
    source_bytes = (vault / source).read_bytes()
    with pytest.raises(ValueError, match="byte limit"):
        writes.promote_memory(vault, "demo-agent", source, "operator")
    assert parent.read_bytes() == original
    assert (vault / source).read_bytes() == source_bytes


def test_valid_multibyte_lifecycle_remains_readable(vault, tmp_path):
    source = writes.suggest_memory(vault, "demo-agent", "Unicode note", "界 " * 30_000, "operator").path
    assert any(e.path == source for e in writes.list_pending(vault, "demo-agent").pending)
    refined = writes.refine_memory(vault, "demo-agent", source, "operator").target
    assert any(e.path == refined for e in writes.list_refining(vault, "demo-agent").refining)
    final = writes.promote_memory(vault, "demo-agent", refined, "operator").target
    assert len(writes._read_memory_bytes(vault / final)) <= LIMIT
    incoming = tmp_path / "unicode.md"
    incoming.write_text("# Imported\n" + "界 " * 30_000, encoding="utf-8")
    imported = import_markdown(incoming, vault, "demo-agent").imported[0]
    refined_import = writes.refine_memory(vault, "demo-agent", imported, "operator").target
    promoted = writes.promote_memory(vault, "demo-agent", refined_import, "operator").target
    assert len(writes._read_memory_bytes(vault / promoted)) <= LIMIT


def test_exact_stored_limit_is_readable_but_metadata_growth_is_refused(vault, tmp_path):
    incoming = tmp_path / "exact.md"
    overhead = len(importers._wrap_import(incoming, "x", "demo-agent", "imported-markdown", ["imported"]).encode()) - 1
    incoming.write_bytes(b"x" * (LIMIT - overhead))
    result = import_markdown(incoming, vault, "demo-agent")
    source = vault / result.imported[0]
    original = writes._read_memory_bytes(source)
    assert len(original) == LIMIT
    with pytest.raises(ValueError, match="byte limit"):
        writes.refine_memory(vault, "demo-agent", result.imported[0], "operator")
    assert source.read_bytes() == original


def forgotten(vault, basename):
    source = vault / "projects/demo-agent/notes" / basename
    source.parent.mkdir(exist_ok=True)
    original = b"# Original\r\n\r\nexact restore bytes\r\n"
    source.write_bytes(original)
    result = forget.soft_forget(vault, "demo-agent", source.relative_to(vault).as_posix(),
                                "superseded", "test-batch", "operator", "forget-operation-A-0001")
    assert not source.exists()
    return source, original, result


@pytest.mark.parametrize("basename", ["a" * 252 + ".md", "é" * 126 + ".md"])
def test_filesystem_limit_forget_restore_replay(vault, basename):
    assert len(basename.encode("utf-8")) == 255
    source, original, result = forgotten(vault, basename)
    restored = forget.restore_forgotten(vault, result.tombstone_path, "operator", "restore-operation-A-0001")
    assert source.read_bytes() == original
    assert source.stat().st_nlink == 1
    intent = json.loads(forget._operation_path(vault, "restore-operation-A-0001").with_suffix(".intent.json").read_text())
    assert not (vault / intent["stage_path"]).exists()
    source.write_bytes(b"unrelated later revision")
    assert forget.restore_forgotten(vault, result.tombstone_path, "operator", "restore-operation-A-0001") == restored
    assert source.read_bytes() == b"unrelated later revision"


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("phase", ["before-receipt", "cleanup"])
def test_restore_recovers_published_intent_and_retires_exact_witness(vault, monkeypatch, legacy, phase):
    source, original, result = forgotten(vault, "legacy.md" if legacy else "é" * 126 + ".md")
    key = "restore-operation-A-0001"
    receipt = forget._operation_path(vault, key)
    atomic = forget._atomic_json
    unlink = Path.unlink
    def interrupted(path, payload):
        if phase == "before-receipt" and path == receipt:
            raise OSError("synthetic death after target publication")
        return atomic(path, payload)
    def interrupted_cleanup(path, *args, **kwargs):
        if phase == "cleanup" and path.parent == source.parent and path.name.endswith(".stage"):
            assert receipt.exists()
            raise OSError("synthetic death during witness cleanup")
        return unlink(path, *args, **kwargs)
    with monkeypatch.context() as m:
        m.setattr(forget, "_atomic_json", interrupted)
        m.setattr(Path, "unlink", interrupted_cleanup)
        with pytest.raises(OSError, match="synthetic death"):
            forget.restore_forgotten(vault, result.tombstone_path, "operator", key)
    intent_path = receipt.with_suffix(".intent.json")
    intent = json.loads(intent_path.read_text())
    witness = vault / intent["stage_path"]
    assert source.read_bytes() == original
    if legacy:
        old = source.with_name("." + source.name + "." + "a" * 32 + ".stage")
        witness.rename(old)
        witness = old
        intent["stage_path"] = witness.relative_to(vault).as_posix()
        atomic(intent_path, intent)
    forget.restore_forgotten(vault, result.tombstone_path, "operator", key)
    assert source.read_bytes() == original
    assert source.stat().st_nlink == 1
    assert not witness.exists()


def test_restore_cleanup_preserves_replacement_witness(vault, monkeypatch):
    source, original, result = forgotten(vault, "replacement.md")
    key = "restore-operation-A-0001"
    with monkeypatch.context() as m:
        m.setattr(forget, "_retire_restore_witness", lambda *args: None)
        forget.restore_forgotten(vault, result.tombstone_path, "operator", key)
    intent = json.loads(forget._operation_path(vault, key).with_suffix(".intent.json").read_text())
    witness = vault / intent["stage_path"]
    # Retain the original inode so allocator reuse cannot make this ambiguous.
    witness.rename(witness.with_suffix(".held"))
    witness.write_bytes(b"unrelated witness replacement")
    source.unlink()
    source.write_bytes(b"unrelated final replacement")
    forget.restore_forgotten(vault, result.tombstone_path, "operator", key)
    assert witness.read_bytes() == b"unrelated witness replacement"
    assert source.read_bytes() == b"unrelated final replacement"


@pytest.mark.parametrize("operation", ["forget", "restore"])
def test_direct_forget_and_restore_refuse_secret_keys_before_persistence(vault, operation):
    key = "ghp_" + "a" * 36  # Synthetic secret shape, never a credential.
    before = {p.relative_to(vault): p.read_bytes() for p in vault.rglob("*") if p.is_file()}
    with pytest.raises(ValueError, match="secret"):
        if operation == "forget":
            forget.soft_forget(vault, "demo-agent", "projects/demo-agent/STATUS.md", "superseded", "test-batch", "operator", key)
        else:
            forget.restore_forgotten(vault, "excluded/forgotten/missing/test.tombstone.json", "operator", key)
    assert {p.relative_to(vault): p.read_bytes() for p in vault.rglob("*") if p.is_file()} == before


def block_fcntl(monkeypatch):
    real_import = builtins.__import__
    def portable_import(name, *args, **kwargs):
        if name == "fcntl":
            raise ModuleNotFoundError("synthetic Windows: no fcntl")
        return real_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", portable_import)


def test_cold_warm_recall_and_context_pack_without_fcntl(vault, monkeypatch):
    block_fcntl(monkeypatch)
    for call in (recall, recall, context_pack, context_pack):
        result = call("current operational status", vault, project="demo-agent", retrieval_mode="lexical")
        assert any(s.path == "projects/demo-agent/STATUS.md" for s in result.sources)
    assert (vault / index.INDEX_RELATIVE).is_file()


def test_publication_lock_serializes_competing_threads(vault):
    entered = threading.Event()
    attempting = threading.Event()
    finished = threading.Event()
    failures = []
    def competitor():
        try:
            attempting.set()
            with index._publication_lock(vault):
                entered.set()
        except BaseException as exc:
            failures.append(exc)
        finally:
            finished.set()
    with index._publication_lock(vault):
        thread = threading.Thread(target=competitor)
        thread.start()
        try:
            assert attempting.wait(2)
            assert not entered.wait(.05)
        finally:
            pass
    assert finished.wait(2)
    thread.join(2)
    assert entered.is_set()
    assert not failures


def test_cache_uses_shared_conditional_directory_barrier(vault, monkeypatch):
    from arvyx_control import filesystem
    class WindowsOS:
        name='nt'
        def __getattr__(self,name):return getattr(os,name)
    monkeypatch.setattr(filesystem,'os',WindowsOS())
    calls = []
    real_open = os.open
    def no_directory_open(path, flags, *args, **kwargs):
        if Path(path) == vault / ".arvyx":
            raise PermissionError("synthetic Windows directory handle refusal")
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(index.os, "open", no_directory_open)
    def barrier(path):
        calls.append(path);filesystem.fsync_directory(path)
    monkeypatch.setattr(index, "fsync_directory", barrier, raising=False)
    index._write_cache(vault, {})
    assert calls == [vault / ".arvyx"]
    assert json.loads((vault / index.INDEX_RELATIVE).read_text())["files"] == {}


def test_portable_windows_branch_and_rebuild_order(vault, monkeypatch):
    """Emulated msvcrt API on Linux; deliberately not Windows runtime evidence."""
    from arvyx_control import checkpoint_jobs,filesystem
    class WindowsOS:
        name='nt'
        def __getattr__(self,name):return getattr(os,name)
    monkeypatch.setattr(filesystem,'os',WindowsOS())
    calls = []
    fake = ModuleType("msvcrt")
    fake.LK_NBLCK, fake.LK_LOCK, fake.LK_UNLCK = 1, 2, 3
    def locking(fd, mode, count):
        calls.append((mode, count, os.lseek(fd, 0, os.SEEK_CUR)))
    fake.locking = locking
    monkeypatch.setitem(sys.modules, "msvcrt", fake)
    block_fcntl(monkeypatch)
    spec = importlib.util.spec_from_file_location("arvyx_control._completion_A_windows_locks", locks.__file__)
    portable = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(portable)
    active = []
    connections = []
    @contextmanager
    def publication(path):
        assert all(not c.in_transaction for c in connections), "SQLite holder must not wait for publication"
        with portable.exclusive_lock(path):
            active.append(path)
            try:
                yield
            finally:
                active.pop()
    monkeypatch.setattr(index, "exclusive_lock", publication, raising=False)
    # Windows conditional policy performs file fsync but has no directory fsync.
    # A strict directory-open recorder rejects the previous POSIX-only cache path.
    real_open = os.open
    def no_directory_open(path, flags, *args, **kwargs):
        if Path(path) == vault / ".arvyx":
            raise PermissionError("synthetic Windows directory handle refusal")
        return real_open(path, flags, *args, **kwargs)
    monkeypatch.setattr(index.os, "open", no_directory_open)
    # The wrapper forwards dir_fd unchanged; secure source reads remain the
    # real Linux capability. Without registering it, the identity-based
    # capability check correctly refuses to index through an unknown open().
    monkeypatch.setattr(os, "supports_dir_fd", os.supports_dir_fd | {no_directory_open})
    monkeypatch.setattr(index, "fsync_directory", filesystem.fsync_directory, raising=False)
    connect = checkpoint_jobs._connect
    def ordered_connect(path):
        connection = connect(path)
        connections.append(connection)
        return connection
    start_attempt = checkpoint_jobs._start_attempt
    write_cache = checkpoint_jobs._write_cache
    def ordered_start(*args, **kwargs):
        assert active, "publication lock must precede attempt transaction"
        return start_attempt(*args, **kwargs)
    def ordered_write(*args, **kwargs):
        assert active and connections[0].in_transaction
        return write_cache(*args, **kwargs)
    monkeypatch.setattr(checkpoint_jobs, "_connect", ordered_connect)
    monkeypatch.setattr(checkpoint_jobs, "_start_attempt", ordered_start)
    monkeypatch.setattr(checkpoint_jobs, "_write_cache", ordered_write)
    with authority_context(vault):
        result = checkpoint_jobs.rebuild_index_checkpointed(vault, owner="fixture", now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert result.status == "completed"
    assert calls and all(count == 1 and offset == 0 for _, count, offset in calls)
    assert [mode for mode, _, _ in calls].count(fake.LK_LOCK) == [mode for mode, _, _ in calls].count(fake.LK_UNLCK)
