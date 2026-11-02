from arvyx_control.replica_authority import authority_context
"""Transcript/control cut regression source. NOT_EXECUTED in this round."""
from contextlib import contextmanager
import hashlib
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from arvyx_control import control, replica
from arvyx_control.cockpit_archive_authority import append_transcript, transcript_receipt


def setup_archive(tmp_path):
    vault = tmp_path / 'vault'
    agents = vault / 'registry/agents'
    agents.mkdir(parents=True)
    (agents / 'operator.json').write_text('{}')
    state = tmp_path / 'control-events.jsonl'
    return vault, state


def publish(vault, state, event_id):
    with authority_context(vault, state):
        return append_transcript(vault, state, {
            'event_id': event_id, 'session': 'session', 'run': 'run',
            'text': 'A bounded work record.', 'project': '', 'task': '',
            'host': 'host', 'kind': 'organizer', 'agent': 'operator',
        }, actor='operator')


def test_interphase_publication_preserves_exact_control_cut_and_replicated_receipt(tmp_path, monkeypatch):
    vault, state = setup_archive(tmp_path)
    first = publish(vault, state, 'first')
    captured = state.read_bytes()
    real_boundary = replica.memory_mutation
    real_lock = replica.exclusive_lock
    active_control = False
    active_vault = False

    @contextmanager
    def writer_lock(path):
        nonlocal active_control
        assert not active_vault
        with real_lock(path):
            active_control = True
            try:
                yield
            finally:
                active_control = False

    @contextmanager
    def boundary(root):
        nonlocal active_vault
        assert not active_control
        # This uses the real transcript publisher and writer lock. Publication
        # occurs after the control snapshot, before any blob enumeration.
        publish(vault, state, 'later')
        with real_boundary(root):
            active_vault = True
            try:
                yield
            finally:
                active_vault = False

    with monkeypatch.context() as m:
        m.setattr(replica, 'exclusive_lock', writer_lock)
        m.setattr(replica, 'memory_mutation', boundary)
        manifest = replica.build_manifest(vault, state)
    assert manifest['state_files']['control-events.jsonl'] == {
        'sha256': hashlib.sha256(captured).hexdigest(), 'size': len(captured),
    }
    assert 'conversations/cockpit-archive/later.json' in manifest['files']

    def get_json(url, **kwargs):
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)
        if parsed.path == '/replica/manifest':
            return manifest
        if parsed.path == '/replica/file':
            return replica.read_vault_file(vault, query['path'][0])
        assert parsed.path == '/replica/state'
        return replica.read_state_file(query['name'][0], state, None,
            size=int(query['size'][0]), sha256=query['sha256'][0])

    monkeypatch.setattr(replica, '_get_json', get_json)
    target = tmp_path / 'replica'
    target_state = tmp_path / 'replica-state'
    replica.sync_replica('http://localhost', target, state_dir=target_state)
    replicated = target_state / 'control-events.jsonl'
    assert replicated.read_bytes() == captured
    assert replica.replica_status(target).sync_complete
    receipt = transcript_receipt(target, replicated, 'first',
        identity=SimpleNamespace(binds_actor=True, agent_id='operator'))
    assert receipt['sha256'] == first['sha256']
    with pytest.raises(ValueError, match='unknown transcript'):
        transcript_receipt(target, replicated, 'later',
            identity=SimpleNamespace(binds_actor=True, agent_id='operator'))


@pytest.mark.parametrize('damage', ['missing', 'mismatch', 'symlink', 'wrong_ref'])
def test_manifest_refuses_any_unfulfilled_transcript_reference(tmp_path, damage):
    vault, state = setup_archive(tmp_path)
    publish(vault, state, 'first')
    publish(vault, state, 'second')
    blob = vault / 'conversations/cockpit-archive/first.json'
    if damage == 'missing':
        blob.unlink()
    elif damage == 'mismatch':
        blob.write_bytes(b'{}')
    elif damage == 'symlink':
        original = blob.read_bytes()
        blob.unlink()
        outside = tmp_path / 'outside.json'
        outside.write_bytes(original)
        blob.symlink_to(outside)
    else:
        rows = [json.loads(line) for line in state.read_bytes().splitlines()]
        rows[0]['payload']['storage_ref'] = 'conversations/cockpit-archive/second.json'
        state.write_text(''.join(json.dumps(row) + '\n' for row in rows))
    with pytest.raises(ValueError, match='transcript'):
        replica.build_manifest(vault, state)


def test_control_capture_is_bounded_before_vault_boundary(tmp_path, monkeypatch):
    vault, state = setup_archive(tmp_path)
    state.write_bytes(b'x' * 33)
    monkeypatch.setattr(replica, 'MAX_REPLICA_FILE_BYTES', 32)
    def forbidden(root):
        pytest.fail('vault boundary entered before control bound check')
    monkeypatch.setattr(replica, 'memory_mutation', forbidden)
    with pytest.raises(ValueError, match='size cap'):
        replica.build_manifest(vault, state)
