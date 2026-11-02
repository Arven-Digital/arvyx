"""Scoped regression specifications; NOT_EXECUTED under static-only authority."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from arvyx_control.audit import _release_blockers
from arvyx_control.container_readiness import _STATE_READINESS_TAIL_BYTES, _verify_state_tail
from arvyx_control.release_host import ReleaseHostCheck, release_host_report


class RemainingClaimsTests(unittest.TestCase):
    def test_g36_audit_release_blockers_fail_closed_for_dirty_and_unknown(self):
        for dirty, expected in [([], []),
                                ([" M source.py"], ["release worktree has uncommitted or untracked changes"]),
                                (None, ["release worktree cleanliness is unknown"])]:
            with (
                self.subTest(dirty=dirty),
                patch("arvyx_control.audit.worktree_dirty_paths", return_value=dirty),
                patch("arvyx_control.audit._status_value", return_value="complete"),
                patch("arvyx_control.audit._valid_model_review_attestation", return_value=True),
            ):
                self.assertEqual(_release_blockers(Path(".")), expected)

    def test_g36_host_diagnostics_do_not_imply_public_readiness(self):
        complete = ReleaseHostCheck("fixture", "synthetic check", "complete", [], "preserve")
        for dirty in ([], ["?? untracked.py"], None):
            with (
                self.subTest(dirty=dirty),
                patch("arvyx_control.release_host.worktree_dirty_paths", return_value=dirty),
                patch("arvyx_control.release_host._provenance_check", return_value=complete),
                patch("arvyx_control.release_host._mcp_client_check", return_value=complete),
            ):
                report = release_host_report(Path("."), require_provenance=True)
                self.assertTrue(report.ok)
                self.assertEqual(report.public_release_ready, dirty == [])
                self.assertEqual(bool(report.blockers), dirty != [])

    def test_g36_git_observation_errors_block_both_public_paths(self):
        complete = ReleaseHostCheck("fixture", "synthetic check", "complete", [], "preserve")
        for error in (OSError("synthetic git failure"), UnicodeError("synthetic decoding failure")):
            with (
                self.subTest(error=type(error).__name__),
                patch("arvyx_control.audit.worktree_dirty_paths", side_effect=error),
                patch("arvyx_control.audit._status_value", return_value="complete"),
                patch("arvyx_control.audit._valid_model_review_attestation", return_value=True),
                patch("arvyx_control.release_host.worktree_dirty_paths", side_effect=error),
                patch("arvyx_control.release_host._provenance_check", return_value=complete),
                patch("arvyx_control.release_host._mcp_client_check", return_value=complete),
            ):
                self.assertEqual(_release_blockers(Path(".")), ["release worktree cleanliness is unknown"])
                report = release_host_report(Path("."), require_provenance=True)
                self.assertTrue(report.ok)
                self.assertFalse(report.public_release_ready)
                self.assertEqual(report.blockers, ["release worktree cleanliness is unknown"])

    def test_g40_tail_success_does_not_certify_historical_prefix(self):
        event = b'{"id":"e","type":"fixture","task_id":"t","timestamp":"fixture","payload":{}}\n'
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.jsonl"
            # Deliberately outside the inspected window: healthy means tail-only.
            state.write_bytes(b"{broken historical record}\n" + event * (_STATE_READINESS_TAIL_BYTES // len(event) + 2))
            self.assertTrue(_verify_state_tail(state))
            state.write_bytes(event + b"{broken tail}\n")
            self.assertFalse(_verify_state_tail(state))
