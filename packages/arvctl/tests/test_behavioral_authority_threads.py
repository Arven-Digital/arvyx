"""Behavioral authority ownership across threads; NOT_EXECUTED by instruction."""
from pathlib import Path
import tempfile
import threading
import unittest

from arvyx_control.control import create_task, list_tasks
from arvyx_control.replica_authority import (
    ReplicaAuthorityUnavailable,
    assert_state_authority,
    authority_context,
)


class BehavioralAuthorityThreadTests(unittest.TestCase):
    def test_worker_binds_its_own_exact_authority_and_resets_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = root / "owned-vault"
            vault.mkdir()
            state = root / "external-state" / "events.jsonl"
            results = []
            errors = []

            def worker():
                try:
                    # A parent binding must not admit a fresh worker thread.
                    with self.assertRaises(ReplicaAuthorityUnavailable):
                        create_task(state, "unbound", owner="demobot")
                    self.assertFalse(state.parent.exists())
                    with authority_context(vault, state):
                        task = create_task(state, "explicit worker", owner="demobot").task
                        results.append(task.id)
                        with self.assertRaises(ReplicaAuthorityUnavailable):
                            assert_state_authority(state.with_name("wrong.jsonl"))
                    with self.assertRaises(ReplicaAuthorityUnavailable):
                        create_task(state, "after cleanup", owner="demobot")
                except BaseException as error:
                    errors.append(error)

            with authority_context(vault, state):
                thread = threading.Thread(target=worker)
                thread.start()
                thread.join(timeout=10)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])
                self.assertEqual([task.id for task in list_tasks(state).tasks], results)
                self.assertEqual(len(results), 1)
                assert_state_authority(state)
            with self.assertRaises(ReplicaAuthorityUnavailable):
                assert_state_authority(state)
