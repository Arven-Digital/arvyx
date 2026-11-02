"""Evidence export pipeline tests.

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


class EvidencePipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        # The same example denylist RecallTests provides: the pipeline audits the
        # repository and must find a loaded denylist, whatever the host environment.
        self._denylist_environment = patch.dict(
            os.environ,
            {"ARVYX_PRIVATE_DENYLIST": str(ROOT / "fixtures" / "private-denylist.example.txt")},
        )
        self._denylist_environment.start()
        self.addCleanup(self._denylist_environment.stop)

    def test_evidence_export_writes_release_review_bundle(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "evidence.json"
            result = export_evidence(
                repo=ROOT,
                vault=VAULT,
                benchmark_cases=ROOT / "fixtures/recall-benchmark.json",
                output=output,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            output_exists = output.exists()

        self.assertTrue(output_exists)
        self.assertEqual(payload["git_head"], result.git_head)
        self.assertIn("readiness", payload)
        self.assertIn("audit", payload)
        self.assertIn("recall_benchmark", payload)
        self.assertEqual(payload["recall_benchmark"]["retrieval_mode"], "lexical")
        self.assertEqual(payload["recall_benchmarks"]["hybrid"]["retrieval_mode"], "hybrid")
        self.assertTrue(payload["recall_benchmarks"]["hybrid"]["ok"])
        self.assertIn("release_host", payload)
        self.assertFalse(payload["release_host"]["public_release_ready"])
        self.assertTrue(payload["release_blockers"])

    def test_evidence_export_redacts_absolute_paths(self) -> None:
        result = export_evidence(
            repo=ROOT,
            vault=VAULT,
            benchmark_cases=ROOT / "fixtures" / "recall-benchmark.json",
        )

        self.assertEqual(result.repo, ".")
        self.assertEqual(result.vault, "fixtures/synthetic-vault")
        self.assertFalse(result.repo.startswith("/"))
        self.assertFalse(result.vault.startswith("/"))

    def test_evidence_export_accepts_mcp_client_evidence(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            mcp_evidence = Path(tmp) / "mcp-client-evidence.json"
            generate_mcp_client_evidence(vault=VAULT, output=mcp_evidence)
            result = export_evidence(
                repo=ROOT,
                vault=VAULT,
                benchmark_cases=ROOT / "fixtures" / "recall-benchmark.json",
                mcp_client_evidence=mcp_evidence,
            )

        release_host_checks = {check["id"]: check for check in result.release_host["checks"]}
        # Self-generated evidence (client=arvyx-cli) is self-attested and must
        # never satisfy the "real external client" gate.
        self.assertEqual(release_host_checks["mcp_client_real"]["status"], "blocked")
        self.assertTrue(any("mcp_client_real" in blocker for blocker in result.release_blockers))

    def test_evidence_export_can_run_docker_host_check(self) -> None:
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
                        result = export_evidence(
                            repo=ROOT,
                            vault=VAULT,
                            benchmark_cases=ROOT / "fixtures" / "recall-benchmark.json",
                            run_docker=True,
                            run_bridge=True,
                            mcp_client_evidence=evidence,
                        )

        release_host_checks = {check["id"]: check for check in result.release_host["checks"]}
        self.assertEqual(release_host_checks["docker_runtime"]["status"], "complete")
        self.assertEqual(release_host_checks["safe_mcp_bridge_e2e"]["status"], "complete")
        self.assertEqual(release_host_checks["mcp_client_real"]["status"], "complete")
        self.assertFalse(any("docker_runtime" in blocker for blocker in result.release_blockers))
        self.assertFalse(any("safe_mcp_bridge_e2e" in blocker for blocker in result.release_blockers))
        self.assertFalse(any("mcp_client_real" in blocker for blocker in result.release_blockers))

    def test_cli_evidence_export_json_output(self) -> None:
        import tempfile
        from contextlib import redirect_stdout
        from io import StringIO

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "evidence.json"
            out = StringIO()
            with redirect_stdout(out):
                code = main(
                    [
                        "evidence",
                        "export",
                        "--repo",
                        str(ROOT),
                        "--vault",
                        str(VAULT),
                        "--output",
                        str(output),
                        "--json",
                    ]
                )
            output_exists = output.exists()

        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertTrue(output_exists)
        self.assertEqual(payload["recall_benchmark"]["score"], 100)
        self.assertEqual(payload["recall_benchmarks"]["lexical"]["score"], 100)
        self.assertEqual(payload["recall_benchmarks"]["hybrid"]["score"], 100)
        self.assertIn("release_host", payload)
        self.assertTrue(payload["release_blockers"])
