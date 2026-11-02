"""Unexecuted regression sources for the final caller integration."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from arvyx_control import control, health_ops, notifiers
from arvyx_control.replica_authority import authority_context


def test_shared_claim_generation_and_stale_release(tmp_path):
    state = tmp_path / 'events.jsonl'
    vault = tmp_path / 'vault'
    vault.mkdir()
    with authority_context(vault, state):
        thread = control.post_thread(state=state, title='Synthetic claim',
                                     thread_type='ask', target='fixture', actor='operator').thread
        start = datetime(2099, 1, 1, tzinfo=timezone.utc)
        with patch.object(health_ops, '_utcnow', return_value=start), \
                patch.object(control, '_now', return_value='2099-01-01T00:00:00Z'):
            first = health_ops.notify_check(state, dedupe_window_minutes=1)
        a = next(c for c in first.candidates if c['kind'] == 'notification')
        with patch.object(health_ops, '_utcnow', return_value=start + timedelta(minutes=2)), \
                patch.object(control, '_now', return_value='2099-01-01T00:02:00Z'):
            second = notifiers.notify_check(state, dedupe_window_minutes=1)
            b = next(c for c in second.candidates if c['kind'] == 'notification')
            assert a['claim_event_id'] != b['claim_event_id']
            assert notifiers.record_thread_notification_failure is control.record_thread_notification_failure
            before = state.read_bytes()
            assert not control.record_thread_notification_failure(
                state, thread.id, 'notification', 'late', claim_event_id=a['claim_event_id'])
            assert before == state.read_bytes()
            # Even a stale or generationless imported historical result must not
            # release a replacement claim during projection.
            for payload in ({'kind': 'notification'},
                            {'kind': 'notification', 'claim_event_id': a['claim_event_id']}):
                control._append_event(state, control._event(
                    control.THREAD_NOTIFICATION_FAILED_EVENT, thread.id, control._now(), payload))
                assert 'notification' in control.project_thread_notifications(state)[thread.id]
            assert control.record_thread_notification_failure(
                state, thread.id, 'notification', 'current', claim_event_id=b['claim_event_id'])
            assert 'notification' not in control.project_thread_notifications(state)[thread.id]


def test_health_candidates_include_exact_appended_event(tmp_path):
    state = tmp_path / 'events.jsonl'
    vault = tmp_path / 'vault'
    vault.mkdir()
    with authority_context(vault, state):
        control.post_thread(state=state, title='Synthetic exact generation',
                            thread_type='ask', target='fixture', actor='operator')
        dry = health_ops.notify_check(state, dry_run=True)
        assert all('claim_event_id' not in c for c in dry.candidates)
        result = health_ops.notify_check(state)
        events = {e.id: e for e in control.read_events(state)}
        for candidate in result.candidates:
            event = events[candidate['claim_event_id']]
            assert event.task_id == candidate['thread_id']
            assert event.payload['kind'] == candidate['kind']
            assert control.record_thread_notification_failure(
                state, candidate['thread_id'], candidate['kind'], 'definite refusal',
                claim_event_id=event.id)
            before = state.read_bytes()
            assert not control.record_thread_notification_failure(
                state, candidate['thread_id'], candidate['kind'], 'duplicate refusal',
                claim_event_id=event.id)
            assert before == state.read_bytes()
