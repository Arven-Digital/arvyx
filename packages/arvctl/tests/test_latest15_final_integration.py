"""Final integration regression source; deliberately not executed."""
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from arvyx_control import decisions, mcp, outbox


class CanonicalMCPGates(TestCase):
    def test_all_target_and_thread_gates_share_concrete_identity(self):
        state = Path('synthetic-events')
        for name in mcp.THREAD_SCOPED_READ_TOOLS:
            self.assertEqual(mcp._apply_thread_scope(name, {'target': 'NOVA'}, 'nova', state)['target'], 'nova')
            for foreign in ('uma', 'all'):
                with self.assertRaises(ValueError):
                    mcp._apply_thread_scope(name, {'target': foreign}, 'nova', state)
        for name in ('control.thread_get', 'control.thread_reply', 'control.thread_ack', 'control.thread_done'):
            for target in ('Nova', 'Uma', 'all'):
                thread = SimpleNamespace(id='Literal-ID', target=target, actor='Sender')
                arguments = {'thread_id': 'Literal-ID'}
                with patch.object(mcp, 'list_thread_inbox', return_value=SimpleNamespace(threads=[thread])):
                    if target == 'Nova' or (target == 'all' and name in ('control.thread_get', 'control.thread_reply')):
                        self.assertEqual(mcp._apply_thread_scope(name, arguments, 'nova', state), arguments)
                    else:
                        with self.assertRaises(ValueError):
                            mcp._apply_thread_scope(name, arguments, 'nova', state)
                self.assertEqual(thread.id, 'Literal-ID')
                self.assertEqual(thread.target, target)
        for name in ('control.thread_get', 'control.thread_reply'):
            thread = SimpleNamespace(id='Literal-ID', target='Uma', actor='NoVa')
            with patch.object(mcp, 'list_thread_inbox', return_value=SimpleNamespace(threads=[thread])):
                self.assertEqual(mcp._apply_thread_scope(name, {'thread_id': thread.id}, 'nova', state), {'thread_id': thread.id})

    def test_delivery_get_and_receipt_gate_preserve_literal_ids(self):
        for name in ('control.delivery_get', 'control.delivery_receipt'):
            for target in ('Nova', 'Uma', 'all'):
                arguments = {'delivery_id': 'Literal-Delivery'}
                with patch.object(mcp, 'project_outbox', return_value={'Literal-Delivery': SimpleNamespace(target=target)}):
                    if target == 'Nova':
                        self.assertEqual(mcp._apply_thread_scope(name, arguments, 'nova', Path('state')), arguments)
                    else:
                        with self.assertRaises(ValueError):
                            mcp._apply_thread_scope(name, arguments, 'nova', Path('state'))


class DecisionLockLifecycle(TestCase):
    def test_public_classifier_acquires_lock_and_outbox_uses_unlocked_helper(self):
        held = False

        @contextmanager
        def nonreentrant_lock(state):
            nonlocal held
            self.assertFalse(held, 'nested state lock would deadlock')
            held = True
            try:
                yield
            finally:
                held = False

        def classify(*args, **kwargs):
            self.assertTrue(held)
            return None

        now = datetime(2026, 10, 28, tzinfo=timezone.utc)
        item = SimpleNamespace(id='Literal-Card', payload={'delivery_mode': 'decision_card', 'decision_id': 'Literal-Decision'},
                               target='nova', lease_expires_at='2026-10-28T01:00:00Z')
        with patch.object(decisions, '_locked_state', nonreentrant_lock), \
             patch.object(decisions, '_classify_decision_card_dispatch_unlocked', side_effect=classify) as classifier:
            self.assertIsNone(decisions.classify_decision_card_dispatch(Path('state'), decision_id='Literal-Decision', target='nova'))
            with patch.object(outbox, '_locked_state', nonreentrant_lock), \
                 patch('arvyx_control.replica_authority.assert_state_authority'), \
                 patch.object(outbox, '_leased_item', return_value=item), \
                 patch.object(outbox, 'replace', return_value=item), \
                 patch.object(outbox, '_event'), \
                 patch.object(outbox, '_append_event_unlocked'), \
                 patch.object(outbox, '_timestamp', return_value='stamp'):
                # A fake projection is sufficient: finalization must never call
                # the public lock-owning classifier while this lock is held.
                item.to_dict = lambda: {}
                self.assertIs(outbox.mark_delivered(Path('state'), outbox_id=item.id, worker='worker',
                              claim_attempts=1, now=now, provider_receipt='receipt'), item)
            self.assertEqual(classifier.call_count, 2)
        self.assertFalse(held)
