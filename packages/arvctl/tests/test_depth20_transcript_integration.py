"""Transcript replay integration regressions; authored, not executed."""
from contextlib import contextmanager
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from arvyx_control import cockpit_archive_authority as archive


def replay_context(tmp_path, monkeypatch, *, organizer=True):
    vault = tmp_path / 'vault'
    state = tmp_path / 'state.jsonl'
    actor = 'agent'
    payload = dict(event_id='event', session='session', run='run', text='ordinary transcript',
                   project='', task='', host='host', kind='organizer', agent=actor)
    if organizer:
        registry = vault / 'registry/agents'
        registry.mkdir(parents=True)
        (registry / 'agent.json').write_text('{}')
    else:
        payload.pop('kind')
        payload.pop('agent')
        payload.update(project='project', task='task')
        registry = vault / 'registry/projects'
        registry.mkdir(parents=True)
        (registry / 'project.json').write_text(json.dumps({'owner_agent_id': actor}))
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    previous = SimpleNamespace(payload={'actor': actor, 'sha256': digest})
    held = []

    @contextmanager
    def lock(target):
        assert target == state
        held.append(True)
        try:
            yield
        finally:
            held.pop()

    monkeypatch.setattr(archive.control, '_locked_state', lock)
    monkeypatch.setattr(archive.control, 'list_tasks', lambda _: SimpleNamespace(
        tasks=[SimpleNamespace(id='task', owner=actor)]))
    lookup = Mock(return_value=previous)
    append = Mock(side_effect=AssertionError('replay must not append'))
    monkeypatch.setattr(archive.control, '_idempotent_event', lookup)
    monkeypatch.setattr(archive.control, '_append_event_unlocked', append)
    return vault, state, actor, payload, previous, held, lookup, append


@pytest.mark.parametrize('organizer', [False, True])
def test_transcript_replay_retries_barrier_before_success(tmp_path, monkeypatch, organizer):
    vault, state, actor, payload, previous, held, lookup, append = replay_context(
        tmp_path, monkeypatch, organizer=organizer)
    calls = []
    directory = vault / 'conversations/cockpit-archive'
    directory.mkdir(parents=True)
    blob = directory / 'event.json'
    raw = json.dumps(payload, sort_keys=True).encode()
    blob.write_bytes(raw)

    def acknowledge(target, event):
        assert held == [True]
        assert target == state and event is previous
        calls.append(event)
        if len(calls) < 3:
            raise OSError('uncertain control log durability')

    monkeypatch.setattr(archive.control, '_acknowledge_replay_unlocked', acknowledge)
    for _ in range(2):
        with pytest.raises(OSError, match='uncertain control log durability'):
            archive.append_transcript(vault, state, payload, actor=actor)
        assert held == []
    result = archive.append_transcript(vault, state, payload, actor=actor)
    assert result == dict(event_id='event', sha256=previous.payload['sha256'],
                          recorded=True, curated_memory=False)
    assert len(calls) == 3
    lookup.assert_called_with(state, 'work.transcript', 'event')
    append.assert_not_called()
    assert blob.read_bytes() == raw


@pytest.mark.parametrize('field', ['actor', 'sha256'])
def test_transcript_conflict_never_repairs_durability(tmp_path, monkeypatch, field):
    vault, state, actor, payload, previous, held, _, append = replay_context(tmp_path, monkeypatch)
    previous.payload[field] = 'different'
    acknowledge = Mock(side_effect=AssertionError('conflict must precede barrier'))
    monkeypatch.setattr(archive.control, '_acknowledge_replay_unlocked', acknowledge)
    with pytest.raises(ValueError, match='transcript event conflict'):
        archive.append_transcript(vault, state, payload, actor=actor)
    acknowledge.assert_not_called()
    append.assert_not_called()
    assert held == []


def test_receipt_get_is_read_only(tmp_path, monkeypatch):
    vault, state, actor, payload, previous, _, lookup, append = replay_context(tmp_path, monkeypatch)
    directory = vault / 'conversations/cockpit-archive'
    directory.mkdir(parents=True)
    (directory / 'event.json').write_bytes(json.dumps(payload, sort_keys=True).encode())
    acknowledge = Mock(side_effect=AssertionError('GET must not repair durability'))
    monkeypatch.setattr(archive.control, '_acknowledge_replay_unlocked', acknowledge)
    monkeypatch.setattr(archive.control, '_locked_state', Mock(side_effect=AssertionError('GET must not lock for mutation')))
    result = archive.transcript_receipt(vault, state, 'event', identity=SimpleNamespace(
        binds_actor=True, agent_id=actor))
    assert result['sha256'] == previous.payload['sha256']
    lookup.assert_called_once_with(state, 'work.transcript', 'event')
    acknowledge.assert_not_called()
    append.assert_not_called()
