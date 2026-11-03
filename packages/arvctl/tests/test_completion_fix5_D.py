"""Lane D bounded restore and capture-history regressions; synthetic state only."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
from contextlib import closing
import subprocess
import sys
import tarfile

import pytest

from arvyx_control import capture_offload as offload
from arvyx_control import composition_recovery as recovery
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_archive import WorkCapture, sync_capture

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='the deployment scripts take POSIX locks and fail closed elsewhere')


SCRIPT = Path(__file__).resolve().parents[3] / 'scripts/backup_restore.py'
SPEC = importlib.util.spec_from_file_location('completion_fix5_D_backup', SCRIPT)
backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup)


def restore_failure(tmp_path, monkeypatch, fault, *, cleanup_fails=False):
    """Real pointer publication/rollback; every Docker/process boundary records."""
    data = tmp_path / 'data/vault'
    data.mkdir(parents=True)
    (data / '.arvyx-vault').write_text('arvyx-vault-format: 1\n')
    archive = tmp_path / 'fixture.tar.gz'
    with tarfile.open(archive, 'w:gz') as bundle:
        bundle.add(data.parent, arcname='data')
    checksum = tmp_path / 'fixture.tar.gz.sha256'
    backup._write_checksum(archive, checksum)
    previous = 'fixture_deploy-0001_arvyx-data'
    env_file = tmp_path / '.env'
    env_file.write_text('ARVYX_DATA_VOLUME=' + previous + '\n')
    monkeypatch.setattr(backup, 'ROOT', tmp_path)
    monkeypatch.setenv('ARVYX_DATA_VOLUME', previous)
    monkeypatch.setenv('ARVYX_DEPLOYMENT_ID', 'deploy-0001')
    monkeypatch.setenv('ARVYX_CONTROL_SECRET_FILE', 'fixture-control-file')
    events = []

    def run(command, *, env, check=True):
        events.append((tuple(command), env.get('ARVYX_DATA_VOLUME')))
        if cleanup_fails and 'down' in command and env.get('ARVYX_DATA_VOLUME') != previous and '-p' in command and command[command.index('-p') + 1] == 'fixture':
            return subprocess.CompletedProcess(command, 1, stdout='')
        return subprocess.CompletedProcess(command, 0, stdout='')

    def no_process(*args, **kwargs):
        raise AssertionError('unrecorded process execution')

    monkeypatch.setattr(backup, '_run', run)
    monkeypatch.setattr(backup.subprocess, 'run', no_process)
    for name in ('_create_candidate_volume', '_materialize_candidate_volume', '_reseed_pristine_candidate_volume', '_persist_candidate_volume', '_assert_data_volume', '_acceptance_probe', '_verify_candidate_volume_ownership'):
        monkeypatch.setattr(backup, name, lambda *args, **kwargs: None)
    def healthy(*args, **kwargs):
        if fault == 'postcommit' and kwargs['phase'] == 'candidate cutover':
            raise RuntimeError('injected candidate health failure')
        return 'fixture-container'
    monkeypatch.setattr(backup, '_wait_healthy', healthy)
    real_parent_sync = backup._fsync_parent_directory
    real_fsync = os.fsync
    publication_failed = False

    def parent_sync(path):
        nonlocal publication_failed
        if fault == 'postcommit':
            return real_parent_sync(path)
        if not publication_failed:
            publication_failed = True
            if fault == 'non_utf8':
                env_file.write_bytes(b'\xff')
            raise OSError('injected publication directory barrier failure')
        if fault == 'rollback_directory':
            raise OSError('injected rollback directory barrier failure')
        return real_parent_sync(path)

    def file_sync(fd):
        if publication_failed and fault == 'rollback_file' and '.restore-' in os.readlink('/proc/self/fd/' + str(fd)):
            raise OSError('injected rollback file barrier failure')
        return real_fsync(fd)

    monkeypatch.setattr(backup, '_fsync_parent_directory', parent_sync)
    monkeypatch.setattr(os, 'fsync', file_sync)
    with pytest.raises(RuntimeError) as caught:
        backup.restore(project='fixture', archive=archive, checksum=checksum,
                       confirm_destroy_volume=True, env_file=env_file)
    return previous, env_file, events, caught.value


@pytest.mark.parametrize('fault', ['rollback_file', 'rollback_directory', 'non_utf8'])
def test_unreconciled_pointer_never_restarts_or_deletes_either_volume(tmp_path, monkeypatch, fault):
    previous, env_file, events, error = restore_failure(tmp_path, monkeypatch, fault)
    assert isinstance(error, backup.VolumePointerReconciliationRequired)
    assert not [cmd for cmd, volume in events if 'up' in cmd and volume == previous], events
    assert not [cmd for cmd, _ in events if cmd[:3] == ('docker', 'volume', 'rm')], events
    assert error.candidate_volume.startswith(previous + '-restore-')
    assert error.restart_failed is False
    assert error.restart_blocked is True
    if fault == 'rollback_file':
        assert backup._read_active_volume_pointer(env_file) == error.candidate_volume


def test_confirmed_durable_rollback_can_restart_previous_volume(tmp_path, monkeypatch):
    previous, env_file, events, error = restore_failure(tmp_path, monkeypatch, 'rollback_ok')
    assert isinstance(error, backup.VolumePointerPublicationDurabilityError)
    assert backup._read_active_volume_pointer(env_file) == previous
    assert len([cmd for cmd, volume in events if 'up' in cmd and volume == previous]) == 1


def test_unproven_teardown_also_blocks_rollback_restart(tmp_path, monkeypatch):
    previous, _, events, error = restore_failure(tmp_path, monkeypatch, 'rollback_ok', cleanup_fails=True)
    assert isinstance(error, backup.RestoreCleanupRequired)
    assert not [cmd for cmd, volume in events if 'up' in cmd and volume == previous], events
    assert error.restart_blocked is True
    assert error.cleanup_failures


def test_previous_pointer_still_requires_a_durable_barrier(tmp_path, monkeypatch):
    env_file = tmp_path / '.env'
    env_file.write_text('ARVYX_DATA_VOLUME=fixture-previous\n')
    def fail(path):
        raise OSError('injected retry directory barrier failure')
    monkeypatch.setattr(backup, '_fsync_parent_directory', fail)
    with pytest.raises(backup.VolumePointerReconciliationRequired):
        backup._rollback_active_volume_pointer(env_file, previous_volume='fixture-previous', candidate_volume='fixture-candidate')


def test_postcommit_failure_retains_candidate_authority_and_stops_admission(tmp_path, monkeypatch):
    previous, env_file, events, error = restore_failure(tmp_path, monkeypatch, 'postcommit')
    assert isinstance(error, backup.VolumePointerReconciliationRequired)
    assert backup._read_active_volume_pointer(env_file) == error.candidate_volume
    assert error.previous_volume == previous and error.restart_blocked is True
    assert not [cmd for cmd, volume in events if 'up' in cmd and volume == previous]
    assert any('stop' in cmd and volume == error.candidate_volume for cmd, volume in events)
    assert not [cmd for cmd, _ in events if cmd[:3] == ('docker', 'volume', 'rm')]


def test_cli_reports_blocked_restart_and_both_retained_volumes(tmp_path, monkeypatch, capsys):
    previous, env_file, _, error = restore_failure(tmp_path, monkeypatch, 'rollback_file')
    def failed_restore(**kwargs):
        raise error
    monkeypatch.setattr(backup, 'restore', failed_restore)
    monkeypatch.setattr(sys, 'argv', ['backup_restore', '--project', 'fixture', 'restore', str(tmp_path / 'fixture.tar.gz'), '--env-file', str(env_file), '--confirm-cutover'])
    assert backup.main() == 1
    result = json.loads(capsys.readouterr().out)
    assert result['error'] == 'VolumePointerReconciliationRequired'
    assert result['previous_volume'] == previous
    assert result['candidate_volume'] == error.candidate_volume
    assert result['restart_blocked'] is True and result['restart_failed'] is False


@pytest.fixture
def owner(tmp_path):
    vault = tmp_path / 'vault'
    vault.mkdir()
    o = LocalCockpit(tmp_path / 'runtime', vault, tmp_path / 'events.jsonl', 'fixture')
    with o.db:
        o.db.execute("INSERT INTO sessions(id,name,status,kind) VALUES('sid','fixture','stopped','work')")
    try:
        yield o
    finally:
        o.close()


def capture_row(owner, text):
    stream = WorkCapture(owner, 'sid')
    stream.feed(text.encode())
    stream.finish()
    sync_capture(owner, lambda row: row['event_id'])


def acknowledge(owner, directory):
    prepared = owner.prepare_capture_offload(directory, actor='operator')
    from retention_fixture_helpers import retention_receipt
    receipt = retention_receipt(owner,directory,prepared['sha256'])
    owner.acknowledge_capture_offload(directory, prepared['sha256'], actor='operator', confirmed=True, retention_receipt=receipt)
    return prepared


def rows(owner):
    return [dict(row) for row in owner.db.execute('SELECT * FROM work_capture ORDER BY sequence')]


def test_destination_change_refused_before_preparation_or_row_release(owner, tmp_path):
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir(); second.mkdir()
    capture_row(owner, 'first fixture\n')
    acknowledged = acknowledge(owner, first)
    capture_row(owner, 'second fixture\n')
    retained = rows(owner)
    with pytest.raises(ValueError, match='storage'):
        owner.prepare_capture_offload(second, actor='operator')
    assert rows(owner) == retained
    assert offload.head(owner) == (acknowledged['sha256'], acknowledged['through'])
    assert not list(second.iterdir())


def test_acknowledgement_cannot_move_a_prepared_bundle(owner, tmp_path):
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir(); second.mkdir()
    capture_row(owner, 'fixture\n')
    prepared = owner.prepare_capture_offload(first, actor='operator')
    shutil.copyfile(first / (prepared['sha256'] + '.json'), second / (prepared['sha256'] + '.json'))
    with pytest.raises(ValueError, match='storage'):
        owner.acknowledge_capture_offload(second, prepared['sha256'], actor='operator', confirmed=True)
    assert len(rows(owner)) == 1
    assert offload.head(owner) == ('', 0)


def test_missing_predecessor_after_prepare_blocks_release(owner, tmp_path):
    directory = tmp_path / 'offload'; directory.mkdir()
    capture_row(owner, 'first fixture\n')
    first = acknowledge(owner, directory)
    capture_row(owner, 'second fixture\n')
    second = owner.prepare_capture_offload(directory, actor='operator')
    from retention_fixture_helpers import retention_receipt
    receipt = retention_receipt(owner,directory,second['sha256'])
    (directory / (first['sha256'] + '.json')).unlink()
    with pytest.raises(ValueError, match='bundle'):
        owner.acknowledge_capture_offload(directory, second['sha256'], actor='operator', confirmed=True, retention_receipt=receipt)
    assert len(rows(owner)) == 1
    assert offload.head(owner) == (first['sha256'], first['through'])


def test_replaced_directory_with_equal_bytes_requires_explicit_relocation(owner, tmp_path):
    directory = tmp_path / 'offload'; directory.mkdir()
    capture_row(owner, 'first fixture\n')
    acknowledge(owner, directory)
    directory.rename(tmp_path / 'retained')
    shutil.copytree(tmp_path / 'retained', directory)
    capture_row(owner, 'second fixture\n')
    with pytest.raises(ValueError, match='storage'):
        owner.prepare_capture_offload(directory, actor='operator')
    assert len(rows(owner)) == 1


def test_complete_relocation_is_confirmed_exact_and_survives_owner_reopen(owner, tmp_path):
    first, second = tmp_path / 'first', tmp_path / 'second'
    first.mkdir(); second.mkdir()
    capture_row(owner, 'first fixture\n')
    one = acknowledge(owner, first)
    capture_row(owner, 'second fixture\n')
    two = acknowledge(owner, first)
    shutil.copyfile(first / (two['sha256'] + '.json'), second / (two['sha256'] + '.json'))
    with pytest.raises(ValueError):
        offload.relocate_offload_storage(owner, second, actor='operator', expected_head=two['sha256'], confirmed=True)
    shutil.copyfile(first / (one['sha256'] + '.json'), second / (one['sha256'] + '.json'))
    with pytest.raises(ValueError):
        offload.relocate_offload_storage(owner, second, actor='operator', expected_head=two['sha256'])
    with pytest.raises(ValueError):
        offload.relocate_offload_storage(owner, second, actor='operator', expected_head=one['sha256'], confirmed=True)
    from retention_fixture_helpers import retention_receipt
    receipt = retention_receipt(owner,second,two['sha256'],kind='relocate')
    offload.relocate_offload_storage(owner, second, actor='operator', expected_head=two['sha256'], confirmed=True, retention_receipt=receipt)
    owner.close()
    reopened = LocalCockpit(owner.root, owner.vault, owner.state, owner.host)
    try:
        capture_row(reopened, 'third fixture\n')
        with pytest.raises(ValueError, match='storage'):
            reopened.prepare_capture_offload(first, actor='operator')
        three = acknowledge(reopened, second)
        assert [row['text'] for row in offload.read_offload_chain(second, three['sha256'])] == ['first fixture\n', 'second fixture\n', 'third fixture\n']
    finally:
        reopened.close()


def legacy_head(owner, directory):
    capture_row(owner, 'legacy fixture\n')
    offload.schema(owner)
    records = offload.current_rows(owner)
    bundle = dict(schema=1, previous='', after=0, through=records[-1]['sequence'], records=records)
    data = offload.encoded(bundle)
    digest = offload.hashlib.sha256(data).hexdigest()
    (directory / (digest + '.json')).write_bytes(data)
    with owner.db:
        owner.db.execute('DELETE FROM work_capture')
        owner.db.execute('INSERT INTO capture_offload_head VALUES(1,?,?)', (digest, bundle['through']))
    return digest


def test_legacy_head_requires_confirmed_complete_adoption(owner, tmp_path):
    directory = tmp_path / 'offload'; directory.mkdir()
    latest = legacy_head(owner, directory)
    capture_row(owner, 'new fixture\n')
    with pytest.raises(ValueError, match='storage'):
        owner.prepare_capture_offload(directory, actor='operator')
    from retention_fixture_helpers import retention_receipt
    offload.relocate_offload_storage(owner, directory, actor='operator', expected_head=latest, confirmed=True, retention_receipt=retention_receipt(owner,directory,latest,kind='relocate'))
    prepared = acknowledge(owner, directory)
    assert [row['text'] for row in offload.read_offload_chain(directory, prepared['sha256'])] == ['legacy fixture\n', 'new fixture\n']


def test_storage_binding_is_rolled_back_with_failed_row_release(owner, tmp_path):
    directory = tmp_path / 'offload'; directory.mkdir()
    capture_row(owner, 'fixture\n')
    prepared = owner.prepare_capture_offload(directory, actor='operator')
    from retention_fixture_helpers import retention_receipt
    receipt = retention_receipt(owner,directory,prepared['sha256'])
    with owner.db:
        owner.db.execute("CREATE TRIGGER fixture_abort BEFORE DELETE ON work_capture BEGIN SELECT RAISE(ABORT,'injected release failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        owner.acknowledge_capture_offload(directory, prepared['sha256'], actor='operator', confirmed=True, retention_receipt=receipt)
    assert len(rows(owner)) == 1
    assert not owner.db.execute('SELECT * FROM capture_offload_storage').fetchall()
    with owner.db:
        owner.db.execute('DROP TRIGGER fixture_abort')
    owner.acknowledge_capture_offload(directory, prepared['sha256'], actor='operator', confirmed=True, retention_receipt=receipt)
    assert not rows(owner)


def test_composition_restore_preserves_storage_binding_without_rebinding(owner, tmp_path):
    directory = tmp_path / 'offload'; directory.mkdir()
    capture_row(owner, 'fixture\n')
    latest = acknowledge(owner, directory)
    binding = tuple(owner.db.execute('SELECT * FROM capture_offload_storage').fetchone())
    owner.close()
    roles = {role: [] for role in recovery.ROLES}
    roles.update(vault=['vault'], journal=['events.jsonl'], owner=['runtime/sessions.sqlite'], profile_tree=['offload'])
    (tmp_path / 'events.jsonl').touch()
    topology = recovery.Topology(tmp_path, 'vault', roles, ['events.jsonl.lock', 'events.jsonl.cockpit-owner.lock', 'vault/.arvyx/vault.lock'])
    bundle = tmp_path.parent / (tmp_path.name + '-bundle')
    candidate = tmp_path.parent / (tmp_path.name + '-candidate')
    recovery.capture(topology, bundle)
    recovery.restore(bundle, candidate)
    assert recovery.inspect_candidate(candidate)['mutable'] is False
    with closing(sqlite3.connect(candidate / 'runtime/sessions.sqlite')) as db, db:
        assert db.execute('SELECT * FROM capture_offload_storage').fetchone() == binding
    assert offload.read_offload_chain(candidate / 'offload', latest['sha256'])[0]['text'] == 'fixture\n'
    from arvyx_control.replica_authority import ReplicaAuthorityUnavailable
    with pytest.raises(ReplicaAuthorityUnavailable):
        LocalCockpit(candidate / 'runtime', candidate / 'vault', candidate / 'events.jsonl', 'fixture')


def test_offload_never_releases_before_bounded_chain_continuation_completes(owner, tmp_path, monkeypatch):
    directory = tmp_path / 'offload'; directory.mkdir()
    capture_row(owner, 'first fixture\n')
    acknowledge(owner, directory)
    capture_row(owner, 'second fixture\n')
    latest = acknowledge(owner, directory)
    capture_row(owner, 'third fixture\n')
    monkeypatch.setattr(offload,'MAX_VERIFY_BUNDLES',1)
    with pytest.raises(ValueError, match='continuation'):
        owner.prepare_capture_offload(directory, actor='operator')
    assert len(rows(owner)) == 1
    assert offload.head(owner) == (latest['sha256'], latest['through'])
    assert len(offload.read_offload_chain(directory, latest['sha256'])) == 2
    review=owner.prepare_capture_offload(directory,actor='operator')
    from retention_fixture_helpers import retention_receipt
    receipt=retention_receipt(owner,directory,review['sha256'])
    for attempt in range(4):
        try:
            result=owner.acknowledge_capture_offload(directory,review['sha256'],actor='operator',confirmed=True,retention_receipt=receipt);break
        except ValueError as error:
            assert 'continuation' in str(error) and len(rows(owner))==1
    else:pytest.fail('bounded verification failed to complete')
    assert result['released']==1 and len(offload.read_offload_chain(directory,result['sha256']))==3


def test_offload_preserves_unrelated_empty_and_aborted_run_evidence(owner, tmp_path):
    directory = tmp_path / 'offload'; directory.mkdir()
    # A failed fork stays open/charged; a known pre-process abort is distinct.
    WorkCapture(owner, 'sid', run='fixture-failed-fork')
    aborted = WorkCapture(owner, 'sid', run='fixture-aborted-before-process')
    aborted.abort_before_process()
    empty = WorkCapture(owner, 'sid', run='fixture-empty-complete')
    empty.finish()
    original = [tuple(row) for row in owner.db.execute('SELECT * FROM capture_runs ORDER BY run')]
    charge = owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting').fetchone()[0]
    capture_row(owner, 'offloaded fixture\n')
    acknowledge(owner, directory)
    assert [tuple(row) for row in owner.db.execute('SELECT * FROM capture_runs ORDER BY run')] == original
    assert owner.db.execute('SELECT bytes+metadata_bytes FROM capture_accounting').fetchone()[0] == charge


def test_finished_run_already_in_history_can_release_its_remaining_charge(owner, tmp_path):
    directory = tmp_path / 'offload'; directory.mkdir()
    stream = WorkCapture(owner, 'sid', run='fixture-prior-offloaded')
    stream.feed(b'first fixture\n')
    sync_capture(owner, lambda row: row['event_id'])
    acknowledge(owner, directory)
    stream.finish()  # EOF has no new text row; completion follows offload.
    capture_row(owner, 'second fixture\n')
    acknowledge(owner, directory)
    assert not owner.db.execute('SELECT * FROM capture_runs').fetchall()
