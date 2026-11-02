"""Promotion refusal contracts. NOT_EXECUTED by explicit task instruction."""
from datetime import UTC, datetime
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.replica import (
    REPLICA_FAILOVER, REPLICA_MARKER, REPLICA_STATUS,
    auto_failover, promote_replica, replica_status,
)
from arvyx_control.replica_authority import ReplicaAuthorityUnavailable


class PromotionRefusalTests(unittest.TestCase):
    def make_replica(self, root):
        (root / REPLICA_MARKER).write_text("replica-of: http://primary\n")
        (root / REPLICA_STATUS).parent.mkdir(exist_ok=True)
        (root / REPLICA_STATUS).write_text(json.dumps({
            "source": "http://primary", "sync_complete": True,
            "last_synced_at": datetime.now(UTC).isoformat(), "files": 0,
        }))

    def test_manual_forced_and_eligible_auto_raise_without_publication(self):
        for mode in ("manual", "forced", "eligible-auto"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.make_replica(root)
                marker = (root / REPLICA_MARKER).read_bytes()
                status = (root / REPLICA_STATUS).read_bytes()
                with patch("arvyx_control.replica._durable_write") as write:
                    with self.assertRaisesRegex(ReplicaAuthorityUnavailable, "writable failover is unavailable"):
                        if mode == "manual":
                            promote_replica(root, reason="drill", prior_source="http://primary")
                        else:
                            auto_failover(
                                root, "http://primary", peers=("http://peer",),
                                force=mode == "forced",
                                probe=lambda url, *_: url == "http://peer",
                            )
                    write.assert_not_called()
                self.assertEqual((root / REPLICA_MARKER).read_bytes(), marker)
                self.assertEqual((root / REPLICA_STATUS).read_bytes(), status)
                self.assertFalse((root / REPLICA_FAILOVER).exists())
                self.assertFalse((root / ".arvyx-vault").exists())
                self.assertTrue(replica_status(root).is_replica)

    def test_prepared_and_completed_retries_preserve_existing_lineage(self):
        for phase in ("prepared", "complete"):
            for automatic in (False, True):
                with self.subTest(phase=phase, automatic=automatic), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    self.make_replica(root)
                    if phase == "complete":
                        (root / REPLICA_MARKER).unlink()
                        (root / ".arvyx-vault").write_text("existing primary marker\n")
                    lineage = root / REPLICA_FAILOVER
                    lineage.write_text(json.dumps({
                        "schema_version": 1, "phase": phase, "reason": "original",
                        "promoted_at": "2026-01-01T00:00:00Z", "prior_source": "http://primary",
                    }))
                    before = lineage.read_bytes()
                    with patch("arvyx_control.replica._durable_write") as write:
                        with self.assertRaises(ReplicaAuthorityUnavailable):
                            if automatic:
                                auto_failover(root, "http://primary", force=True,
                                              probe=lambda *_: self.fail("retry must refuse before probes"))
                            else:
                                promote_replica(root, reason="retry")
                        write.assert_not_called()
                    self.assertEqual(lineage.read_bytes(), before)
                    self.assertEqual((root / REPLICA_MARKER).exists(), phase == "prepared")
                    self.assertEqual((root / ".arvyx-vault").exists(), phase == "complete")

    def test_lineage_and_completed_role_validation_still_precede_shared_refusal(self):
        for lineage, message in (({"phase": "prepared"}, "invalid failover transaction lineage"),
                                 ({"schema_version": 1, "phase": "complete", "reason": "drill",
                                   "promoted_at": "2026-01-01T00:00:00Z", "prior_source": None},
                                  "completed failover has inconsistent role markers")):
            with self.subTest(lineage=lineage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.make_replica(root)
                (root / REPLICA_FAILOVER).write_text(json.dumps(lineage))
                with patch("arvyx_control.replica_authority.assert_promotion_authority") as refusal:
                    with self.assertRaisesRegex(ValueError, message):
                        promote_replica(root)
                    refusal.assert_not_called()

    def test_auto_availability_refusal_remains_a_nonpromotion_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_replica(root)
            result = auto_failover(root, "http://primary", peers=("http://peer",), probe=lambda *_: True)
            self.assertFalse(result.promoted)
            self.assertEqual(result.reason, "primary-reachable")
            self.assertIsNone(result.promoted_at)
            self.assertEqual(result.to_dict()["promoted"], False)
            self.assertFalse((root / REPLICA_FAILOVER).exists())
