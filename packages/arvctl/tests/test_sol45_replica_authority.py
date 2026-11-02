"""Replica admission contracts. NOT_EXECUTED in the candidate45 fix task."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.mutation_dispatch import claim_mutation
from arvyx_control.promotion_transaction import memory_mutation
from arvyx_control.replica_authority import ReplicaAuthorityUnavailable
from arvyx_control.session import set_session


class ReplicaAuthorityTests(unittest.TestCase):
    def test_explicit_vault_not_external_journal_location_controls_admission(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            primary = root / "primary"
            replica = root / "replica"
            primary.mkdir()
            replica.mkdir()
            (replica / ".arvyx-replica").touch()
            store = root / "external-audit" / "operations.sqlite3"
            arguments = dict(
                principal_scope="agent:operator", action="POST:/tasks",
                idempotency_key="candidate45-explicit-vault", body={"title": "one"},
                route="/tasks", legacy_action="POST:/tasks",
            )
            with self.assertRaises(ReplicaAuthorityUnavailable):
                claim_mutation(store, vault=replica, **arguments)
            self.assertFalse(store.exists())
            claim = claim_mutation(store, vault=primary, **arguments)
            self.assertTrue(claim.created)
            with self.assertRaises(ReplicaAuthorityUnavailable):
                claim_mutation(store, vault=replica, **arguments)

    def test_historical_lineage_fences_session_and_recovery_before_effects(self):
        for lineage in ('{}', '{"phase":"complete"}', 'malformed'):
            with self.subTest(lineage=lineage), tempfile.TemporaryDirectory() as temporary:
                vault = Path(temporary)
                (vault / ".arvyx").mkdir()
                (vault / ".arvyx" / "failover.json").write_text(lineage)
                with self.assertRaises(ReplicaAuthorityUnavailable):
                    set_session(vault, "operator", "working note")
                self.assertFalse((vault / "agents").exists())
                with patch("arvyx_control.promotion_transaction.recover") as recovery:
                    with self.assertRaises(ReplicaAuthorityUnavailable):
                        with memory_mutation(vault):
                            self.fail("replica context must not yield")
                    recovery.assert_not_called()

    def test_ordinary_primary_session_still_publishes(self):
        with tempfile.TemporaryDirectory() as temporary:
            vault = Path(temporary)
            result = set_session(vault, "operator", "ordinary primary note")
            self.assertIn("ordinary primary note", (vault / result.path).read_text())
