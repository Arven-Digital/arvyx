"""Latest15 regressions. Authored only; execution requires separate approval."""
from dataclasses import replace
from unittest import TestCase

from arvyx_control.control import _event
from arvyx_control.decisions import Decision, DECISION_HOLD_PREFIX, _is_awaited
from types import SimpleNamespace
from unittest.mock import patch


class DecisionHoldFenceTests(TestCase):
    def test_only_the_exact_request_owned_hold_is_awaited(self):
        decision = Decision('d', 'e', 'a', 'amir', 't', 'thread', 'Question?', False, 'key', 'stamp')
        payload = dict(id='e', status='held', hold_reason=DECISION_HOLD_PREFIX + 'd',
                       held_by='amir', target='amir', attempt_id='a', subject_id='t', subject_type='thread')
        execution = SimpleNamespace(**payload, to_dict=lambda: dict(payload))
        request = _event('decision.requested', 'd', 'stamp', decision.to_dict())
        hold = _event('execution.held', 'e', 'stamp', dict(payload))
        with patch('arvyx_control.operator_archive.archived_ids', return_value=set()):
            self.assertTrue(_is_awaited(decision, {'e': execution}, [request, hold]))
            replay = _event('execution.replayed', 'e', 'stamp', {})
            self.assertFalse(_is_awaited(decision, {'e': execution}, [request, hold, replay, hold]))
            execution.held_by = 'operator'
            self.assertFalse(_is_awaited(decision, {'e': execution}, [request, hold]))
            execution.held_by = 'amir'
            execution.attempt_id = 'new-attempt'
            self.assertFalse(_is_awaited(decision, {'e': execution}, [request, hold]))
            execution.attempt_id = 'a'
            # thread.done names its terminal actor in done_by; ``actor`` is the
            # thread creator and never makes a terminal authoritative.
            creator_only = _event('thread.done', 't', 'stamp', {'actor': 'amir', 'done_by': 'operator',
                                                                 'actor_identity_bound': True})
            self.assertTrue(_is_awaited(decision, {'e': execution}, [request, hold, creator_only]))
            terminal = _event('thread.done', 't', 'stamp', {'done_by': 'amir', 'actor_identity_bound': True})
            self.assertFalse(_is_awaited(decision, {'e': execution}, [request, hold, terminal]))
            unbound = _event('thread.done', 't', 'stamp', {'done_by': 'amir', 'actor_identity_bound': False})
            self.assertTrue(_is_awaited(decision, {'e': execution}, [request, hold, unbound]))
        with patch('arvyx_control.operator_archive.archived_ids', return_value={'t'}):
            self.assertFalse(_is_awaited(decision, {'e': execution}, [request, hold]))
from arvyx_control.notifiers import _http_status_outcome


class NotifierHTTPClassificationTests(TestCase):
    def test_acceptance_unknown_statuses_retain_claim(self):
        for status in (408, 500, 502, 503, 504):
            with self.subTest(status=status):
                self.assertEqual(_http_status_outcome(status).status, "ambiguous")

    def test_definite_client_refusal_releases_claim(self):
        for status in (400, 401, 403, 404, 429):
            with self.subTest(status=status):
                self.assertEqual(_http_status_outcome(status).status, "failed")
