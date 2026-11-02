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
    def setUp(self) -> None:
        # The same example denylist RecallTests provides: the pipeline audits the
        # repository and must find a loaded denylist, whatever the host environment.
        self._denylist_environment = patch.dict(
            os.environ,
            {"ARVYX_PRIVATE_DENYLIST": str(ROOT / "fixtures" / "private-denylist.example.txt")},
        )
        self._denylist_environment.start()
        self.addCleanup(self._denylist_environment.stop)

    _default_result = None

    @classmethod
    def default_result(cls):
        """One real default self-dogfood per class; the CLI test forwards it."""
        if cls._default_result is None:
            cls._default_result = dogfood_self(repo=ROOT)
        return cls._default_result

    def test_self_dogfood_imports_public_docs_and_recalls_retrieval(self) -> None:
        result = self.default_result()
        checks = {check.name: check for check in result.checks}

        self.assertTrue(result.ok)
        self.assertTrue(checks["import_repo_docs"].ok)
        self.assertTrue(checks["recall_public_docs"].ok)
        self.assertTrue(checks["evidence_after_self_import"].ok)

    def test_cli_self_dogfood_json_output(self) -> None:
        """CLI contract: the repo argument reaches dogfood_self, the JSON is the
        result, exit 0 when every check passed."""
        from contextlib import redirect_stdout
        from io import StringIO
        from arvyx_control import cli

        result = self.default_result()
        calls = []

        def forward(**kwargs):
            calls.append(kwargs)
            return result

        out = StringIO()
        with patch.object(cli, "dogfood_self", side_effect=forward), redirect_stdout(out):
            code = main(["dogfood", "self", "--repo", str(ROOT), "--json"])

        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["repo"], ROOT)
        self.assertFalse(calls[0]["run_docker"])
        self.assertFalse(calls[0]["run_bridge"])
        payload = json.loads(out.getvalue())
        self.assertEqual(payload, json.loads(result.to_json()))
        self.assertTrue(payload["ok"])
        self.assertTrue(any(check["name"] == "recall_public_docs" and check["ok"] for check in payload["checks"]))
