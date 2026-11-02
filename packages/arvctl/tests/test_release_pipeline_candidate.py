"""Release-candidate pipeline tests.

Moved out of test_recall.py so that pytest-xdist (one file per worker) spreads the
release-pipeline tests, each of which runs a full audit and benchmark, across
workers instead of serialising them behind the rest of that module.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from test_recall import (  # noqa: E402  (shared fixtures and helpers of the recall suite)
    ROOT, VAULT, _git_head, _git_tree, _make_pinned_signer, _pinned_release_policy,
    _release_host_fake_run, _write_signed_external_mcp_evidence, main,
)
from arvyx_control.dogfood import dogfood_self
from arvyx_control.evidence import export_evidence
from arvyx_control.mcp_client_evidence import generate_mcp_client_evidence
from arvyx_control.release_candidate import release_candidate_report


class ReleaseCandidatePipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        # The same example denylist RecallTests provides: the pipeline audits the
        # repository and must find a loaded denylist, whatever the host environment.
        self._denylist_environment = patch.dict(
            os.environ,
            {"ARVYX_PRIVATE_DENYLIST": str(ROOT / "fixtures" / "private-denylist.example.txt")},
        )
        self._denylist_environment.start()
        self.addCleanup(self._denylist_environment.stop)

    @patch.dict(os.environ, {"ARVYX_PRIVATE_DENYLIST": str(ROOT / "requirements/dev.lock/not-a-directory")})
    def test_release_candidate_report_blocks_preview_without_assurance(self) -> None:
        result = release_candidate_report(
            repo=ROOT,
            vault=VAULT,
            benchmark_cases=ROOT / "fixtures/recall-benchmark.json",
        )

        self.assertFalse(result.private_preview_allowed)
        self.assertFalse(result.public_release_allowed)
        self.assertEqual(result.summary, "private preview blocked")
        self.assertIn("security audit multi-model review is missing or invalid", result.blockers)
        self.assertTrue(result.internal_evidence_blockers)
        self.assertIn("security audit multi-model review is missing or invalid", result.public_release_blockers)
        self.assertIn("private context denylist was not loaded", result.public_release_blockers)
        self.assertFalse(result.evidence["audit"]["ok"])
        self.assertTrue(result.evidence["recall_benchmarks"]["hybrid"]["ok"])

    @patch.dict(os.environ, {"ARVYX_PRIVATE_DENYLIST": str(ROOT / "requirements/dev.lock/not-a-directory")})
    def test_release_candidate_accepts_mcp_client_evidence(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            mcp_evidence = Path(tmp) / "mcp-client-evidence.json"
            generate_mcp_client_evidence(vault=VAULT, output=mcp_evidence)
            result = release_candidate_report(
                repo=ROOT,
                vault=VAULT,
                benchmark_cases=ROOT / "fixtures/recall-benchmark.json",
                mcp_client_evidence=mcp_evidence,
            )

        self.assertFalse(result.private_preview_allowed)
        # Client evidence cannot bypass missing strict audit assurance.
        self.assertTrue(any("mcp_client_real" in blocker for blocker in result.public_release_blockers))
        self.assertTrue(result.internal_evidence_blockers)

    @patch.dict(os.environ, {"ARVYX_PRIVATE_DENYLIST": str(ROOT / "requirements/dev.lock/not-a-directory")})
    def test_release_candidate_can_include_docker_host_check(self) -> None:
        import subprocess
        from unittest.mock import patch

        head = _git_head()
        tree = _git_tree()
        real_run = subprocess.run

        fake_run = _release_host_fake_run(real_run, head, tree)

        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "mcp-client-evidence.json"
            key, allowed = _make_pinned_signer(Path(tmp))
            _write_signed_external_mcp_evidence(evidence, key)
            with _pinned_release_policy(allowed):
                with patch("arvyx_control.release_host.shutil.which", return_value="/usr/bin/docker"):
                    with patch("arvyx_control.release_host.subprocess.run", side_effect=fake_run):
                        result = release_candidate_report(
                            repo=ROOT,
                            vault=VAULT,
                            benchmark_cases=ROOT / "fixtures/recall-benchmark.json",
                            run_docker=True,
                            run_bridge=True,
                            mcp_client_evidence=evidence,
                        )

        self.assertFalse(result.private_preview_allowed)
        self.assertFalse(any("docker_runtime" in blocker for blocker in result.blockers))
        self.assertFalse(any("safe_mcp_bridge_e2e" in blocker for blocker in result.blockers))
        self.assertFalse(any("mcp_client_real" in blocker for blocker in result.blockers))
        self.assertTrue(result.internal_evidence_blockers)

    @patch.dict(os.environ, {"ARVYX_PRIVATE_DENYLIST": str(ROOT / "requirements/dev.lock/not-a-directory")})
    def test_cli_release_candidate_json_output(self) -> None:
        from contextlib import redirect_stdout
        from io import StringIO

        out = StringIO()
        with redirect_stdout(out):
            code = main(
                [
                    "release-candidate",
                    "--repo",
                    str(ROOT),
                    "--vault",
                    str(VAULT),
                    "--json",
                ]
            )

        self.assertEqual(code, 1)
        payload = json.loads(out.getvalue())
        self.assertFalse(payload["private_preview_allowed"])
        self.assertFalse(payload["public_release_allowed"])
        self.assertTrue(payload["internal_evidence_blockers"])
        self.assertTrue(payload["public_release_blockers"])
        self.assertTrue(payload["blockers"])
