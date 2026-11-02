"""Unexecuted regressions for remaining ledger admission/provenance repairs."""
from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import patch
import pytest
from arvyx_control.control import post_thread, acknowledge_thread, list_thread_inbox
from arvyx_control.replica_authority import authority_context
from arvyx_control.session_return import request_session_return, project_session_returns
from test_session_return import SessionReturnTests, T0


def test_expiry_resampled_after_locked_projection(tmp_path):
    state = tmp_path / 'events.jsonl'
    with authority_context(tmp_path / 'vault', state):
        execution = SessionReturnTests()._leased(state)
        from arvyx_control import session_return
        from datetime import datetime
        moment = [T0 + timedelta(seconds=599)]
        samples = []
        real_lock = session_return._locked_state
        locked = []
        @contextmanager
        def delayed_lock(path):
            with real_lock(path):
                locked.append(path)
                moment[0] = T0 + timedelta(seconds=601)
                yield
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                samples.append(moment[0])
                return moment[0]
        # The initial admission saw a live lease; the final lock acquired it late.
        with patch.object(session_return, '_locked_state', delayed_lock), patch.object(session_return, 'datetime', Clock):
            with pytest.raises(ValueError, match='expired'):
                request_session_return(state, execution_id=execution.id, attempt_id=execution.attempt_id,
                    actor='amir', message='one message', expected_word_count=2,
                    idempotency_key='expiry-lock-regression')
        assert project_session_returns(state) == {}
        assert locked == [state]
        assert samples == [T0 + timedelta(seconds=599), T0 + timedelta(seconds=601)]


def test_explicit_clock_preserved_at_final_admission(tmp_path):
    state = tmp_path / 'events.jsonl'
    with authority_context(tmp_path / 'vault', state):
        execution = SessionReturnTests()._leased(state)
        result = request_session_return(state, execution_id=execution.id, attempt_id=execution.attempt_id,
            actor='amir', message='one message', expected_word_count=2,
            idempotency_key='explicit-clock-regression', now=T0)
        assert result.requested_at == T0.isoformat().replace('+00:00', 'Z')


@pytest.mark.parametrize('bound', [True, False, None])
def test_thread_projection_retains_creation_provenance_after_ack(tmp_path, bound):
    state = tmp_path / 'events.jsonl'
    with authority_context(tmp_path / 'vault', state):
        posted = post_thread(state, title='watchdog title', actor='watchdog', target='amir', actor_identity_bound=bound)
        acknowledge_thread(state, posted.thread.id, actor='amir', actor_identity_bound=True)
        thread = next(t for t in list_thread_inbox(state=state).threads if t.id == posted.thread.id)
        assert thread.actor_identity_bound is bound
        assert thread.to_dict()['actor_identity_bound'] is bound
