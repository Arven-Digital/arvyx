"""Candidate45 authority contracts. NOT_EXECUTED by instruction."""
import ast
from pathlib import Path
import tempfile
import unittest

from arvyx_control.replica_authority import (
    ReplicaAuthorityUnavailable, authority_context, assert_state_authority,
    bound_entry, owner_entry,
)
from arvyx_control.control import _locked_state


class AuthorityContextTests(unittest.TestCase):
    def test_missing_context_cannot_create_lock_or_state_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'absent/events.jsonl'
            with self.assertRaises(ReplicaAuthorityUnavailable):
                with _locked_state(state):
                    self.fail('must not enter')
            self.assertFalse(state.parent.exists())

    def test_primary_requires_exact_caller_owned_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            vault, state = Path(directory) / 'actual-vault', Path(directory) / 'external/events.jsonl'
            vault.mkdir()
            with authority_context(vault, state):
                assert_state_authority(state)
                with _locked_state(state):
                    pass
                with self.assertRaises(ReplicaAuthorityUnavailable):
                    assert_state_authority(state.with_name('other.jsonl'))
            with self.assertRaises(ReplicaAuthorityUnavailable):
                assert_state_authority(state)

    def test_nested_context_cannot_change_vault_or_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with authority_context(root / 'vault', root / 'events'):
                with self.assertRaises(ReplicaAuthorityUnavailable):
                    with authority_context(root / 'other', root / 'events'):
                        pass
                with self.assertRaises(ReplicaAuthorityUnavailable):
                    with authority_context(root / 'vault', root / 'other-events'):
                        pass

    def test_replica_and_historical_lineage_refuse_before_state_creation(self):
        for marker in ('.arvyx-replica', '.arvyx/failover.json'):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                vault = Path(directory) / 'actual-vault'
                path = vault / marker
                path.parent.mkdir(parents=True)
                path.write_text('malformed historical authority')
                state = Path(directory) / 'not-created/events.jsonl'
                with authority_context(vault, state):
                    with self.assertRaises(ReplicaAuthorityUnavailable):
                        with _locked_state(state):
                            self.fail('must not enter')
                self.assertFalse(state.parent.exists())

    def test_role_rechecked_after_entry_context_was_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            vault, state = Path(directory), Path(directory) / 'events'
            with authority_context(vault, state):
                assert_state_authority(state)
                (vault / '.arvyx-replica').write_text('replica')
                with self.assertRaises(ReplicaAuthorityUnavailable):
                    with _locked_state(state):
                        pass

    def test_public_entry_propagates_exact_external_state(self):
        @bound_entry
        def dispatch(vault, state):
            assert_state_authority(state)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dispatch(root / 'vault', root / 'external-state')

    def test_owner_entry_binds_actual_owner_in_worker_thread(self):
        import threading
        class Owner:
            vault: Path
            state: Path
            @owner_entry
            def dispatch(self):
                assert_state_authority(self.state)
        with tempfile.TemporaryDirectory() as directory:
            owner = Owner()
            owner.vault, owner.state = Path(directory), Path(directory) / 'events'
            errors = []
            def worker():
                try:
                    owner.dispatch()
                except Exception as error:
                    errors.append(error)
            thread = threading.Thread(target=worker)
            thread.start()
            thread.join()
            self.assertEqual(errors, [])

    def test_static_canonical_append_and_worker_have_pre_effect_guards(self):
        import arvyx_control.control as control
        import arvyx_control.dispatcher as dispatcher
        for module, names in ((control, {'_locked_state', '_append_event_unlocked'}),
                              (dispatcher, {'dispatch_once', '_authority_dispatch'})):
            tree = ast.parse(Path(module.__file__).read_text())
            functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
            for name in names:
                calls = [node.func.id for node in ast.walk(functions[name])
                         if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
                self.assertIn('assert_state_authority', calls)
