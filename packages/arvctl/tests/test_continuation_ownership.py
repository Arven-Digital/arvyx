from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from arvyx_control.replica_authority import authority_context
from arvyx_control.control import (
    acknowledge_thread, complete_thread, post_thread, post_thread_message, read_events,
)
from arvyx_control.execution import (
    cancel_execution, claim_execution, execution_session, heartbeat_execution_as_target,
    project_executions, reconcile_executions, resume_execution,
)


class ContinuationOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / 'events.jsonl'
        self.vault = Path(self.tmp.name) / "vault"
        self.vault.mkdir()
        self.enterContext(authority_context(self.vault, self.state))
        self.now = datetime.now(timezone.utc)
        self.parent = post_thread(self.state, title='owned routine work', actor='esme',
                                  target='amir', thread_type='ask', actor_identity_bound=True).thread.id
        acknowledge_thread(self.state, self.parent, actor='amir', actor_identity_bound=True)

    def claim(self, seconds=0):
        return claim_execution(self.state, worker='test-worker', execution_capable_targets={'amir'},
                               now=self.now + timedelta(seconds=seconds), lease_seconds=10,
                               retry_backoff_seconds=0, max_attempts=8)

    def child(self):
        child = post_thread(self.state, title='independent dependency', actor='amir', target='kiran',
                            continuation_thread_id=self.parent, actor_identity_bound=True).thread.id
        acknowledge_thread(self.state, child, actor='kiran', actor_identity_bound=True)
        return child

    def test_child_done_is_new_input_not_another_identical_blocker(self):
        first = self.claim()
        post_thread_message(self.state, self.parent, 'BLOCKED: dependency missing', actor='amir')
        second = self.claim(11)
        self.assertEqual(first.id, second.id)
        post_thread_message(self.state, self.parent, 'BLOCKED: dependency still missing', actor='amir')
        child = self.child()
        self.assertIsNone(self.claim(22))  # waiting does not burn attempt budget
        self.assertEqual(project_executions(self.state)[first.id].attempts, 2)
        complete_thread(self.state, child, actor='kiran', actor_identity_bound=True)
        resumed = self.claim(23)
        self.assertIsNotNone(resumed, 'canonical child DONE must clear stale blocker streak')
        self.assertEqual(resumed.id, first.id)
        self.assertEqual(resumed.attempts, 3)
        self.assertNotEqual(resumed.attempt_id, second.attempt_id)
        self.assertIsNone(self.claim(24))  # notification/duplicate tick cannot claim again

    def test_only_first_identity_bound_child_terminal_resets_blockers(self):
        from dataclasses import replace
        from arvyx_control.execution import _blocked_streaks
        first = self.claim()
        post_thread_message(self.state, self.parent, 'BLOCKED: dependency missing', actor='amir')
        child = self.child()
        complete_thread(self.state, child, actor='kiran', actor_identity_bound=True)
        events = read_events(self.state)
        terminal = next(e for e in events if e.type == 'thread.done' and e.task_id == child)
        executions = project_executions(self.state, events=events)
        for changes in ({'actor_identity_bound': False}, {'done_by': 'esme'}):
            with self.subTest(changes=changes):
                forged = replace(terminal, payload={**terminal.payload, **changes})
                candidate = [forged if e.id == terminal.id else e for e in events]
                self.assertEqual(_blocked_streaks(candidate, executions)[first.id][0], 1)
        self.assertNotIn(first.id, _blocked_streaks(events, executions))
        post_thread_message(self.state, self.parent, 'BLOCKED: a new missing authority', actor='amir')
        renewed = self.claim(23)
        self.assertIsNotNone(renewed)
        self.assertEqual(renewed.id, first.id)
        self.assertEqual(renewed.attempts, 2)
        post_thread_message(self.state, self.parent, 'BLOCKED: still missing after child', actor='amir')
        again = self.claim(34)
        self.assertIsNotNone(again)
        self.assertEqual(again.attempts, 3)
        post_thread_message(self.state, self.parent, 'BLOCKED: still missing after child', actor='amir')
        self.assertIsNone(self.claim(45), 'one child completion does not waive the next identical blocker')
        self.assertEqual(project_executions(self.state)[first.id].status, 'held')

    def test_self_targeted_child_cannot_clear_parent_blocker(self):
        first = self.claim()
        post_thread_message(self.state, self.parent, 'BLOCKED: dependency missing', actor='amir')
        self.claim(11)
        post_thread_message(self.state, self.parent, 'BLOCKED: dependency still missing', actor='amir')
        child = post_thread(self.state, title='self-owned subtask', actor='amir', target='amir',
                            continuation_thread_id=self.parent, actor_identity_bound=True).thread.id
        acknowledge_thread(self.state, child, actor='amir', actor_identity_bound=True)
        complete_thread(self.state, child, actor='amir', actor_identity_bound=True)
        self.assertIsNone(self.claim(23), 'same-identity child DONE is not new blocker input')
        self.assertEqual(project_executions(self.state)[first.id].status, 'held')

    def test_child_done_does_not_resume_explicit_hold(self):
        from arvyx_control.execution import hold_execution
        first = self.claim()
        child = self.child()
        hold_execution(self.state, execution_id=first.id, reason='review gate', held_by='operator')
        complete_thread(self.state, child, actor='kiran', actor_identity_bound=True)
        self.assertIsNone(self.claim(50))
        self.assertEqual(project_executions(self.state)[first.id].status, 'held')

    def test_parent_chat_and_duplicate_ticks_do_not_steal_worker(self):
        first = self.claim()
        def chat(_):
            with authority_context(self.vault, self.state):
                post_thread(self.state, title='unrelated human input', actor='esme', target='kiran',
                            thread_type='update', actor_identity_bound=True)
        def duplicate(_):
            with authority_context(self.vault, self.state):
                return self.claim(1)
        with ThreadPoolExecutor(max_workers=8) as pool:
            chats = [pool.submit(chat, n) for n in range(12)]
            duplicates = [pool.submit(duplicate, n) for n in range(12)]
            for result in chats:
                result.result()
            self.assertTrue(all(result.result() is None for result in duplicates))
        heartbeat_execution_as_target(self.state, execution_id=first.id, attempt_id=first.attempt_id,
                                      actor='amir', now=self.now + timedelta(seconds=2), lease_seconds=10)
        complete_thread(self.state, self.parent, actor='amir', actor_identity_bound=True)
        reconcile_executions(self.state)
        actual = project_executions(self.state)[first.id]
        self.assertEqual(actual.status, 'completed')
        self.assertEqual(actual.attempts, 1)
        self.assertEqual(sum(e.type == 'execution.created' and e.task_id == first.id
                             for e in read_events(self.state)), 1)

    def test_crash_resume_and_cancel_keep_one_root_and_fence_old_attempt(self):
        first = self.claim()
        # Runtime restart before expiry rediscovers the same attempt without a new claim.
        self.assertEqual(execution_session(self.state, execution_id=first.id, attempt_id=first.attempt_id,
                                          actor='amir', now=self.now).id, first.id)
        self.assertIsNone(self.claim(1))
        recovered = self.claim(11)  # dead runtime's lease expires; normal worker reclaims
        self.assertEqual(first.id, recovered.id)
        self.assertNotEqual(first.attempt_id, recovered.attempt_id)
        with self.assertRaises(ValueError):
            heartbeat_execution_as_target(self.state, execution_id=first.id, attempt_id=first.attempt_id,
                                          actor='amir', now=self.now + timedelta(seconds=12))
        cancel_execution(self.state, execution_id=first.id, reason='operator stop', cancelled_by='operator')
        with self.assertRaises(ValueError):
            execution_session(self.state, execution_id=first.id, attempt_id=recovered.attempt_id, actor='amir')
        self.assertIsNone(self.claim(30))
        resume_execution(self.state, execution_id=first.id, resumed_by='operator')
        resumed = self.claim(31)
        self.assertEqual(first.id, resumed.id)
        self.assertNotEqual(recovered.attempt_id, resumed.attempt_id)


if __name__ == '__main__':
    unittest.main()
