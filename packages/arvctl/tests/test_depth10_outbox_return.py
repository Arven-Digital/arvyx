"""Supplemental regressions; execution is explicitly not authorized this round."""
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from arvyx_control import outbox
from arvyx_control.replica_authority import authority_context
from arvyx_control.session_return import SessionReturn, _overlay_delivery

from types import SimpleNamespace
from unittest.mock import patch


def test_recovery_never_wakes_replacement_attempt_or_archived_subject(tmp_path):
    state = tmp_path / 'events.jsonl'
    payload = {'delivery_mode': 'session_return', 'execution_id': 'fixture-execution',
               'attempt_id': 'original-attempt'}
    original = replace(wake_item(), subject_id='return-request', status='delivered',
        payload=payload, payload_hash=outbox._payload_hash(payload), provider_receipt='receipt')
    for attempt, archived in [('replacement-attempt', set()), ('original-attempt', {'canonical-task'})]:
        execution = SimpleNamespace(id='fixture-execution', subject_id='canonical-task',
                                    target=original.target, attempt_id=attempt)
        with patch.object(outbox, 'read_events', return_value=[]), \
             patch('arvyx_control.execution.project_executions', return_value={execution.id: execution}), \
             patch('arvyx_control.operator_archive.archived_ids', return_value=archived), \
             patch('arvyx_control.session_return.session_return_continuation_payload') as build, \
             patch.object(outbox, '_append_event_unlocked') as append:
            assert outbox._recover_session_return_continuations_unlocked(
                state, {original.id: original}, now=NOW, limit=10) == 0
            build.assert_not_called()
            append.assert_not_called()


NOW = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)
STAMP = '2026-10-28T12:00:00Z'


def wake_item():
    return outbox.OutboxItem(
        id='fixture-wake', subject_id='fixture-execution', target='amir',
        payload={'delivery_mode': outbox.EXECUTION_WAKE_MODE}, payload_hash='fixture',
        epoch=0, status='leased', attempts=2, created_at=STAMP, updated_at=STAMP,
        next_attempt_at=STAMP, lease_owner='shared-worker',
        lease_expires_at='2026-10-28T12:05:00Z',
    )


@pytest.mark.parametrize('accepted', [True, False])
@pytest.mark.parametrize('worker,generation', [('shared-worker', 1), ('other-worker', 2),
                                             ('shared-worker', True)])
def test_execution_wake_finalizer_requires_original_claim(tmp_path, accepted, worker, generation):
    state, vault = tmp_path / 'events.jsonl', tmp_path / 'vault'
    vault.mkdir()
    with authority_context(vault, state):
        item = outbox.record_execution_wake_unlocked(state, wake_item())
        before = state.read_bytes()
        with pytest.raises(ValueError):
            outbox.finalize_execution_wake(state, outbox_id=item.id, worker=worker,
                claim_attempts=generation, accepted=accepted, detail='fixture', now=NOW)
        assert state.read_bytes() == before
        assert outbox.project_outbox(state)[item.id] == item


@pytest.mark.parametrize('accepted,status', [(True, 'delivered'), (False, 'dead_lettered')])
def test_execution_wake_current_claim_finalizes(tmp_path, accepted, status):
    state, vault = tmp_path / 'events.jsonl', tmp_path / 'vault'
    vault.mkdir()
    with authority_context(vault, state):
        item = outbox.record_execution_wake_unlocked(state, wake_item())
        result = outbox.finalize_execution_wake(state, outbox_id=item.id,
            worker=item.lease_owner, claim_attempts=item.attempts,
            accepted=accepted, detail='fixture', now=NOW)
        assert result.status == status
        # A duplicate result never regresses an already finalized wake.
        assert outbox.finalize_execution_wake(state, outbox_id=item.id,
            worker=item.lease_owner, claim_attempts=item.attempts,
            accepted=not accepted, detail='duplicate', now=NOW) == result


@pytest.mark.parametrize('field,value', [('message', 'different body'), ('word_count', 99)])
def test_matching_digest_alone_does_not_prove_return_payload(field, value):
    request = SessionReturn(request_id='fixture-return', execution_id='fixture-execution',
        attempt_id='fixture-attempt', target='amir', message='fixture message',
        message_sha256='fixture-digest', word_count=2, idempotency_key='fixture-return-key',
        requested_at=STAMP)
    original = replace(wake_item(), id='actual-send', subject_id=request.request_id,
        payload={'delivery_mode': 'session_return', 'execution_id': request.execution_id,
                 'attempt_id': request.attempt_id, 'message': request.message,
                 'message_sha256': request.message_sha256, 'word_count': request.word_count},
        status='delivered', provider_receipt='actual-receipt')
    unrelated = replace(original, id='unrelated', epoch=99, status='dead_lettered',
        payload=dict(original.payload, **{field: value}), provider_receipt='')
    result = _overlay_delivery(request, {original.id: original, unrelated.id: unrelated})
    assert (result.delivery_id, result.status, result.provider_receipt) == (
        original.id, 'delivered', 'actual-receipt')
