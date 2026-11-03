"""Lane D: real offload and offline composition boundaries on disposable state."""
from arvyx_control import safe_open
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import sqlite3
from contextlib import closing
import stat
import threading

import pytest

from arvyx_control import capture_offload as offload
from arvyx_control import composition_recovery as recovery
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_archive import WorkCapture, sync_capture
from retention_fixture_helpers import retention_receipt


@pytest.fixture
def captured_owner(tmp_path):
    vault = tmp_path / 'vault'
    vault.mkdir()
    owner = LocalCockpit(tmp_path / 'runtime', vault, tmp_path / 'events.jsonl', 'fixture')
    with owner.db:
        owner.db.execute("INSERT INTO sessions(id,name,status,kind) VALUES('sid','fixture','stopped','work')")
    stream = WorkCapture(owner, 'sid')
    stream.feed(b'retained fixture history\n')
    stream.finish()
    sync_capture(owner, lambda row: row['event_id'])
    directory = tmp_path / 'offload'
    directory.mkdir(mode=0o700)
    try:
        yield owner, directory
    finally:
        owner.close()


def retained(owner):
    return owner.db.execute('SELECT count(*) FROM work_capture').fetchone()[0]


def fd_path(fd):
    return Path(safe_open.descriptor_path(fd))


@pytest.mark.skipif(os.name != 'posix', reason='directory fsync barriers are not performed on Windows and file flushes bypass os.fsync (docs/limitations.md, Windows durability)')
def test_offload_retry_repeats_failed_file_barrier_and_reopens(captured_owner, monkeypatch):
    owner, directory = captured_owner
    real_sync = os.fsync
    attempts = []
    def fail_file(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode) and fd_path(fd).parent == directory:
            attempts.append(fd_path(fd))
            raise OSError('injected bundle file fsync failure')
        return real_sync(fd)
    monkeypatch.setattr(os, 'fsync', fail_file)
    with pytest.raises((OSError, ValueError)):
        owner.prepare_capture_offload(directory, actor='operator')
    assert len(list(directory.glob('*.json'))) == 1
    assert retained(owner) == 1
    with pytest.raises((OSError, ValueError)):
        owner.prepare_capture_offload(directory, actor='operator')
    assert len(attempts) >= 2
    assert retained(owner) == 1
    monkeypatch.setattr(os, 'fsync', real_sync)
    prepared = owner.prepare_capture_offload(directory, actor='operator')
    assert owner.acknowledge_capture_offload(directory, prepared['sha256'], actor='operator', confirmed=True, retention_receipt=retention_receipt(owner,directory,prepared['sha256']))['released'] == 1
    owner.close()
    reopened = LocalCockpit(owner.root, owner.vault, owner.state, owner.host)
    try:
        assert retained(reopened) == 0
        assert offload.read_offload_chain(directory, prepared['sha256'])[0]['text'] == 'retained fixture history\n'
        with pytest.raises(ValueError):
            reopened.acknowledge_capture_offload(directory, prepared['sha256'], actor='operator', confirmed=True)
    finally:
        reopened.close()


@pytest.mark.parametrize('barrier', ['file', 'directory'])
def test_offload_ack_requires_its_own_durability_barriers(captured_owner, monkeypatch, barrier):
    owner, directory = captured_owner
    prepared = owner.prepare_capture_offload(directory, actor='operator')
    real_sync = os.fsync
    def fail(fd):
        path = fd_path(fd)
        if (barrier == 'file' and path.parent == directory) or (barrier == 'directory' and path == directory):
            raise OSError('injected acknowledgement barrier failure')
        return real_sync(fd)
    monkeypatch.setattr(os, 'fsync', fail)
    with pytest.raises((OSError, ValueError)):
        owner.acknowledge_capture_offload(directory, prepared['sha256'], actor='operator', confirmed=True)
    assert retained(owner) == 1
    assert not owner.db.execute('SELECT * FROM capture_offload_head').fetchall()


@pytest.mark.skipif(os.name != 'posix', reason='directory fsync barriers are not performed on Windows and file flushes bypass os.fsync (docs/limitations.md, Windows durability)')
@pytest.mark.parametrize('change', ['replace', 'mutate'])
def test_offload_refuses_bundle_changed_during_file_barrier(captured_owner, monkeypatch, change):
    owner, directory = captured_owner
    prepared = owner.prepare_capture_offload(directory, actor='operator')
    bundle = directory / (prepared['sha256'] + '.json')
    original = bundle.read_bytes()
    real_sync = os.fsync
    changed = False
    def race(fd):
        nonlocal changed
        if not changed and fd_path(fd) == bundle:
            changed = True
            if change == 'replace':
                other = directory / 'replacement'
                other.write_bytes(original)
                other.replace(bundle)
            else:
                bundle.write_bytes(b'{}')
        return real_sync(fd)
    monkeypatch.setattr(os, 'fsync', race)
    with pytest.raises((OSError, ValueError)):
        owner.acknowledge_capture_offload(directory, prepared['sha256'], actor='operator', confirmed=True)
    assert changed and retained(owner) == 1


@pytest.mark.parametrize('link', ['symlink', 'hardlink'])
def test_offload_retry_refuses_linked_bundle(captured_owner, link):
    owner, directory = captured_owner
    prepared = owner.prepare_capture_offload(directory, actor='operator')
    bundle = directory / (prepared['sha256'] + '.json')
    other = directory / 'retained'
    bundle.rename(other)
    if link == 'symlink':
        bundle.symlink_to(other)
    else:
        os.link(other, bundle)
    with pytest.raises((OSError, ValueError)):
        owner.prepare_capture_offload(directory, actor='operator')
    with pytest.raises((OSError, ValueError)):
        owner.acknowledge_capture_offload(directory, prepared['sha256'], actor='operator', confirmed=True)
    assert retained(owner) == 1


def test_concurrent_offload_preparations_release_exactly_once(captured_owner):
    owner, directory = captured_owner
    def together(action):
        barrier = threading.Barrier(2)
        def run():
            barrier.wait(timeout=5)
            return action()
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(run) for _ in range(2)]
            return [future.result(timeout=5) for future in futures]
    prepared = together(lambda: owner.prepare_capture_offload(directory, actor='operator'))
    assert prepared[0]['sha256'] == prepared[1]['sha256']
    assert len(list(directory.glob('*.json'))) == 1 and retained(owner) == 1
    receipt=retention_receipt(owner,directory,prepared[0]['sha256'])
    def acknowledge():
        try:
            return owner.acknowledge_capture_offload(directory, prepared[0]['sha256'], actor='operator', confirmed=True, retention_receipt=receipt)['released']
        except ValueError:
            return 'refused'
    results = together(acknowledge)
    assert results.count(1) == 1 and results.count('refused') == 1
    assert retained(owner) == 0


def test_offload_release_database_failure_rolls_back_for_retry(captured_owner):
    owner, directory = captured_owner
    prepared = owner.prepare_capture_offload(directory, actor='operator')
    receipt=retention_receipt(owner,directory,prepared['sha256'])
    with owner.db:
        owner.db.execute("CREATE TRIGGER fixture_abort BEFORE DELETE ON work_capture BEGIN SELECT RAISE(ABORT,'injected transaction failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match='injected transaction'):
        owner.acknowledge_capture_offload(directory, prepared['sha256'], actor='operator', confirmed=True, retention_receipt=receipt)
    assert retained(owner) == 1
    assert not owner.db.execute('SELECT * FROM capture_offload_head').fetchall()
    with owner.db:
        owner.db.execute('DROP TRIGGER fixture_abort')
    assert owner.acknowledge_capture_offload(directory, prepared['sha256'], actor='operator', confirmed=True, retention_receipt=receipt)['released'] == 1


def topology(tmp_path):
    root = tmp_path / 'source'
    (root / 'vault' / 'nested' / 'empty').mkdir(parents=True)
    (root / 'vault' / 'nested' / 'note.md').write_text('fixture note')
    (root / 'state').mkdir()
    (root / 'state' / 'events.jsonl').write_text('fixture journal')
    roles = {role: [] for role in recovery.ROLES}
    roles.update(vault=['vault'], journal=['state/events.jsonl'])
    return recovery.Topology(root, 'vault', roles, ['vault/.arvyx/vault.lock'])


def watch_sync(monkeypatch, fail=None):
    real_sync = os.fsync
    events = []
    def sync(fd):
        path = fd_path(fd)
        events.append(('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file', path))
        if fail and fail(path):
            raise OSError('injected namespace barrier failure')
        return real_sync(fd)
    monkeypatch.setattr(os, 'fsync', sync)
    return events


@pytest.mark.skipif(os.name != 'posix', reason='directory fsync barriers are not performed on Windows and file flushes bypass os.fsync (docs/limitations.md, Windows durability)')
@pytest.mark.parametrize('missing_parent', [False, True])
def test_restore_fence_namespace_is_durable_before_state(tmp_path, monkeypatch, missing_parent):
    t = topology(tmp_path)
    bundle = tmp_path / 'bundle'
    recovery.capture(t, bundle)
    candidate = tmp_path / 'ancestors' / 'candidate' if missing_parent else tmp_path / 'candidate'
    events = watch_sync(monkeypatch)
    recovery.restore(bundle, candidate)
    fence_file = events.index(('file', candidate / 'vault' / recovery.FENCE))
    first_state = min(events.index(('file', candidate / name)) for name in ('state/events.jsonl', 'vault/nested/note.md'))
    assert ('directory', candidate / 'vault') in events[fence_file + 1:first_state]
    assert ('directory', candidate.parent) in events[:first_state]
    assert ('directory', tmp_path) in events[:first_state]
    assert recovery.inspect_candidate(candidate)['mutable'] is False


@pytest.mark.skipif(os.name != 'posix', reason='directory fsync barriers are not performed on Windows and file flushes bypass os.fsync (docs/limitations.md, Windows durability)')
def test_restore_fence_barrier_failure_never_publishes_state(tmp_path, monkeypatch):
    t = topology(tmp_path)
    bundle = tmp_path / 'bundle'
    recovery.capture(t, bundle)
    candidate = tmp_path / 'candidate'
    watch_sync(monkeypatch, lambda p: p == candidate / 'vault' and (p / recovery.FENCE).exists())
    with pytest.raises((OSError, ValueError)):
        recovery.restore(bundle, candidate)
    assert not (candidate / 'state' / 'events.jsonl').exists()
    assert not (candidate / 'restore-receipt.json').exists()
    from arvyx_control.replica_authority import assert_mutation_authority, ReplicaAuthorityUnavailable
    with pytest.raises(ReplicaAuthorityUnavailable):
        assert_mutation_authority(candidate / 'vault')
    with pytest.raises(ValueError):
        recovery.inspect_candidate(candidate)
    with pytest.raises(ValueError, match='new offline'):
        recovery.restore(bundle, candidate)


@pytest.mark.skipif(os.name != 'posix', reason='directory fsync barriers are not performed on Windows and file flushes bypass os.fsync (docs/limitations.md, Windows durability)')
@pytest.mark.parametrize('operation', ['capture', 'restore'])
def test_nested_directory_barrier_failure_withholds_completion(tmp_path, monkeypatch, operation):
    t = topology(tmp_path)
    bundle = tmp_path / 'bundle'
    if operation == 'restore':
        recovery.capture(t, bundle)
    destination = tmp_path / ('candidate' if operation == 'restore' else 'bundle')
    nested = destination / ('vault/nested' if operation == 'restore' else 'files/vault/nested')
    watch_sync(monkeypatch, lambda p: p == nested and (p / 'note.md').exists())
    with pytest.raises((OSError, ValueError)):
        (recovery.restore(bundle, destination) if operation == 'restore' else recovery.capture(t, destination))
    marker = 'restore-receipt.json' if operation == 'restore' else 'manifest.json'
    assert not (destination / marker).exists()
    with pytest.raises(ValueError):
        (recovery.inspect_candidate(destination) if operation == 'restore' else recovery.load_bundle(destination))
    if operation == 'restore':
        from arvyx_control.replica_authority import ReplicaAuthorityUnavailable
        with pytest.raises(ReplicaAuthorityUnavailable):
            LocalCockpit(destination / 'runtime', destination / 'vault', destination / 'state/events.jsonl', 'fixture')
        assert not (destination / 'runtime').exists()


@pytest.mark.skipif(os.name != 'posix', reason='directory fsync barriers are not performed on Windows and file flushes bypass os.fsync (docs/limitations.md, Windows durability)')
def test_capture_syncs_populated_namespace_before_complete_manifest(tmp_path, monkeypatch):
    t = topology(tmp_path)
    destination = tmp_path / 'bundle'
    events = watch_sync(monkeypatch)
    recovery.capture(t, destination)
    marker = events.index(('file', destination / 'manifest.json'))
    for path in (destination.parent, destination, destination / 'files', destination / 'files/vault', destination / 'files/vault/nested', destination / 'files/state'):
        assert ('directory', path) in events[:marker]
    recovery.load_bundle(destination)


@pytest.mark.parametrize('suffix', ['-wal', '-shm', '-journal'])
@pytest.mark.parametrize('sqlite', [False, True])
def test_declared_suffix_named_authority_survives_restore(tmp_path, suffix, sqlite):
    t = topology(tmp_path)
    name = 'grants' + suffix
    path = t.root / name
    if sqlite:
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE proof(value TEXT)')
            db.execute("INSERT INTO proof VALUES('retained')")
    else:
        path.write_bytes(b'authoritative fixture')
    t.roles['external_grants'] = [name]
    bundle = tmp_path / 'bundle'
    record = recovery.capture(t, bundle)
    assert name in record['files']
    candidate = tmp_path / 'candidate'
    recovery.restore(bundle, candidate)
    if sqlite:
        with closing(sqlite3.connect(candidate / name)) as db, db:
            assert db.execute('SELECT value FROM proof').fetchall() == [('retained',)]
    else:
        assert (candidate / name).read_bytes() == path.read_bytes()
    recovery.inspect_candidate(candidate)


@pytest.mark.parametrize('suffix', ['-wal', '-shm', '-journal'])
def test_explicit_database_sidecar_is_rejected_before_publication(tmp_path, suffix):
    t = topology(tmp_path)
    with closing(sqlite3.connect(t.root / 'grants')) as db, db:
        if suffix != '-journal':
            db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE proof(value TEXT)')
        db.commit()
        if suffix == '-journal':
            db.execute("INSERT INTO proof VALUES('uncommitted fixture')")
        assert (t.root / ('grants' + suffix)).exists()
        t.roles['external_grants'] = ['grants', 'grants' + suffix]
        destination = tmp_path / 'bundle'
        with pytest.raises(ValueError, match='sidecar'):
            recovery.capture(t, destination)
        assert not destination.exists()


def test_tree_sqlite_wal_is_folded_into_backup_with_ordinary_suffix_files(tmp_path):
    t = topology(tmp_path)
    profile = t.root / 'profiles'
    profile.mkdir()
    t.roles['profile_tree'] = ['profiles']
    (profile / 'memo-journal').write_bytes(b'ordinary authoritative file')
    with closing(sqlite3.connect(profile / 'state.db')) as db, db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('CREATE TABLE proof(value TEXT)')
        db.execute("INSERT INTO proof VALUES('committed WAL')")
        db.commit()
        assert (profile / 'state.db-wal').exists()
        record = recovery.capture(t, tmp_path / 'bundle')
        assert 'profiles/state.db-wal' not in record['files']
        assert 'profiles/state.db-shm' not in record['files']
        assert 'profiles/memo-journal' in record['files']
    recovery.restore(tmp_path / 'bundle', tmp_path / 'candidate')
    with closing(sqlite3.connect(tmp_path / 'candidate/profiles/state.db')) as db, db:
        assert db.execute('SELECT value FROM proof').fetchall() == [('committed WAL',)]
