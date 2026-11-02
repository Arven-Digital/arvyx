"""Self-dogfood pipeline tests.

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


class DogfoodPipelineTests(unittest.TestCase):
    def test_self_dogfood_imports_public_docs_and_recalls_retrieval(self) -> None:
        result = dogfood_self(repo=ROOT)
        checks = {check.name: check for check in result.checks}

        self.assertTrue(result.ok)
        self.assertTrue(checks["import_repo_docs"].ok)
        self.assertTrue(checks["recall_public_docs"].ok)
        self.assertTrue(checks["evidence_after_self_import"].ok)

    def test_self_dogfood_accepts_release_host_evidence(self) -> None:
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
                        result = dogfood_self(
                            repo=ROOT,
                            run_docker=True,
                            run_bridge=True,
                            mcp_client_evidence=evidence,
                        )

        checks = {check.name: check for check in result.checks}
        release_blockers = checks["evidence_after_self_import"].detail["release_blockers"]
        self.assertTrue(result.ok)
        self.assertFalse(any("docker_runtime" in blocker for blocker in release_blockers))
        self.assertFalse(any("safe_mcp_bridge_e2e" in blocker for blocker in release_blockers))
        self.assertFalse(any("mcp_client_real" in blocker for blocker in release_blockers))

    def test_cli_self_dogfood_json_output(self) -> None:
        from contextlib import redirect_stdout
        from io import StringIO

        out = StringIO()
        with redirect_stdout(out):
            code = main(["dogfood", "self", "--repo", str(ROOT), "--json"])

        self.assertEqual(code, 0)
        payload = json.loads(out.getvalue())
        self.assertTrue(payload["ok"])
        self.assertTrue(any(check["name"] == "recall_public_docs" and check["ok"] for check in payload["checks"]))
