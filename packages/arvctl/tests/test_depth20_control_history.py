"""Control/history lane regression sources. Not executed in the static fix round."""
from copy import deepcopy
import sqlite3

import pytest

from arvyx_control import control
from arvyx_control.auth import OPERATOR_IDENTITY
from arvyx_control.execution import materialize_executions, hold_execution, close_execution
from arvyx_control.operator_alert_dismissal import prepare_alert_dismissal
from arvyx_control.operator_archive import _validate_archival_thread_history
from arvyx_control.replica_authority import authority_context
from arvyx_control.retirement import abandon_stale_thread
from arvyx_control.store import sync_sqlite
from arvyx_control.thread_history import validate_thread_history


@pytest.mark.parametrize('review', [False, True])
def test_accepting_actor_survives_real_producers_and_sqlite(tmp_path, review):
    state, db = tmp_path / 'events.jsonl', tmp_path / 'projection.sqlite'
    with authority_context(tmp_path / 'vault', state):
        created = control.create_handoff(state, title='Transfer', from_agent='author', to_agent='owner')
        accepted = control.accept_handoff(state, created.handoff.id, actor='owner', actor_identity_bound=True)
        assert accepted.handoff.accepted_by == accepted.event.payload['accepted_by'] == 'owner'
        results = [accepted]
        if review:
            results.append(control.review_handoff(state, created.handoff.id))
        # Check every intermediate projection, not just the final state.
        for result in results:
            assert result.handoff.accepted_by == result.event.payload['accepted_by'] == 'owner'
        sync_sqlite(state, db)
        with sqlite3.connect(db) as connection:
            assert connection.execute('SELECT accepted_by FROM handoffs WHERE id=?', (created.handoff.id,)).fetchone() == ('owner',)
        completed = control.complete_handoff(state, created.handoff.id, actor='owner', actor_identity_bound=True)
        assert completed.handoff.accepted_by == completed.event.payload['accepted_by'] == 'owner'
        assert control.list_handoffs(state).handoffs[0].accepted_by == 'owner'
        sync_sqlite(state, db)
        with sqlite3.connect(db) as connection:
            assert connection.execute('SELECT accepted_by FROM handoffs WHERE id=?', (created.handoff.id,)).fetchone() == ('owner',)


@pytest.mark.parametrize('barrier', ['file', 'directory'])
@pytest.mark.parametrize('producer', ['task', 'approval', 'handoff', 'bus', 'reply'])
def test_failed_append_replay_repairs_barriers_without_duplicate(tmp_path, monkeypatch, barrier, producer):
    state = tmp_path / 'events.jsonl'
    with authority_context(tmp_path / 'vault', state):
        # Establish the log before fault injection to isolate the append barrier.
        control.create_task(state, title='Existing', owner='synthetic-owner')
        thread = control.post_thread(state, title='Reply target', actor='operator', target='owner').thread
        def invoke():
            kwargs = {'idempotency_key': 'same-request'}
            if producer == 'task':
                return control.create_task(state, title='Durable replay', owner='synthetic-owner', **kwargs)
            if producer == 'approval':
                return control.request_approval(state, command='review', requester='owner', **kwargs)
            if producer == 'handoff':
                return control.create_handoff(state, title='Transfer', from_agent='author', to_agent='owner', **kwargs)
            if producer == 'bus':
                return control.post_bus_message(state, message='Durable replay', actor='owner', **kwargs)
            return control.post_thread_message(state, thread.id, text='Durable replay', actor='owner', **kwargs)
        original_file, original_directory = control.os.fsync, control.fsync_directory
        def fail(*args, **kwargs):
            raise OSError('injected persistence failure')
        with monkeypatch.context() as fault:
            if barrier == 'file':
                fault.setattr(control.os, 'fsync', fail)
                # Do not fail directory establishment before the append.
                fault.setattr(control, 'durable_mkdir', lambda path: None)
            else:
                fault.setattr(control, 'fsync_directory', fail)
            for _ in range(2):
                with pytest.raises(OSError, match='injected persistence'):
                    invoke()
            recorded = [e for e in control.read_events(state) if e.payload.get('idempotency_key') == 'same-request']
            assert len(recorded) == 1
        calls = []
        def file_sync(fd):
            # os is shared with filesystem helpers: a directory fsync is not
            # another log-file barrier. Observe the exact event-log inode.
            info, expected = control.os.fstat(fd), state.stat()
            if (info.st_dev,info.st_ino)==(expected.st_dev,expected.st_ino):
                calls.append('file')
            original_file(fd)
        def directory_sync(path):
            calls.append('directory')
            original_directory(path)
        monkeypatch.setattr(control.os, 'fsync', file_sync)
        monkeypatch.setattr(control, 'fsync_directory', directory_sync)
        replay = invoke()
        assert replay.event.id == recorded[0].id
        assert calls[-2:] == ['file', 'directory']
        assert len([e for e in control.read_events(state) if e.id == replay.event.id]) == 1


def test_acknowledged_abandonment_flows_through_alert_consumer(tmp_path):
    state = tmp_path / 'events.jsonl'
    with authority_context(tmp_path / 'vault', state):
        subject = control.post_thread(state, title='Work', actor='operator', target='demobot', actor_identity_bound=True).thread
        ack = control.acknowledge_thread(state, subject.id, actor='demobot', actor_identity_bound=True)
        execution = materialize_executions(state, execution_capable_targets={'demobot'})[0]
        hold_execution(state, execution_id=execution.id, reason='Obsolete hold', held_by='operator')
        alert = control.post_thread(state, title=f'[watchdog] execution {execution.id} held for operator',
            actor='arvyx-watchdog', target='operator', thread_type='blocker',
            body=f'target=demobot subject=thread {subject.id}; Obsolete hold').thread
        close_execution(state, execution_id=execution.id, reason='Explicit closure', closed_by='operator',
                        resolution_category='no_longer_actionable')
        retired = abandon_stale_thread(state, thread_id=subject.id, reason='No longer needed',
                                       approval_reference='synthetic:operator', dry_run=False)
        assert retired['record']['acked_by'] == ack.thread.acked_by
        assert retired['record']['acked_at'] == ack.thread.acked_at
        assert retired['record']['done_at'] == ''
        control.read_thread(state, subject.id)
        events = control.read_events(state)
        for validate in (validate_thread_history, _validate_archival_thread_history):
            validate(events, subject.id)
        prepare_alert_dismissal(state, record_id=alert.id, identity=OPERATOR_IDENTITY,
            reason='Dismiss obsolete alert only', approval_reference='synthetic:operator',
            approval_quote='Dismiss this exact alert only.', evidence_references=['synthetic:history'])
        for mutation in ('category', 'operator', 'prior_status', 'extra', 'legacy_retirement', 'acked_by', 'done_at'):
            changed = deepcopy(events)
            payload = next(e.payload for e in changed if e.task_id == subject.id and e.type == 'thread.retired')
            if mutation in {'category', 'operator', 'prior_status', 'extra'}:
                payload['retirement'][mutation] = 'invalid'
            elif mutation == 'legacy_retirement':
                payload['retirement'] = {'operation': 'retire_thread'}
            else:
                payload[mutation] = 'invented'
            for validate in (validate_thread_history, _validate_archival_thread_history):
                with pytest.raises(ValueError):
                    validate(changed, subject.id)
