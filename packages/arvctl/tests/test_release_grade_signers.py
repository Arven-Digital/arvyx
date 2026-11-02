"""Pinned is not release-grade: the public verdict needs a release-grade signer.

The release-gate reviewers found that a principal pinned in
``docs/trusted-signers.allowed`` and documented as *not* release-grade still
verified, so an operator-signed machine-evidence file could open the public gate.
These tests pin the rule that closes it: a signature must verify *and* its
principal must be named in ``docs/release-grade-signers.allowed``.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from arvyx_control.attestation import release_grade_principals
from arvyx_control.release_candidate import _non_release_grade_signers


def _evidence(directory: Path, name: str, principal: str) -> Path:
    path = directory / name
    path.write_text(
        json.dumps({"attestation": {"method": "ssh-ed25519", "principal": principal}}),
        encoding="utf-8",
    )
    return path


def _repo_with_release_grade(tmp: Path, content: str | None) -> Path:
    repo = tmp / "repo"
    (repo / "docs").mkdir(parents=True)
    if content is not None:
        (repo / "docs" / "release-grade-signers.allowed").write_text(content, encoding="utf-8")
    return repo


class ReleaseGradeSignerTests(unittest.TestCase):
    def test_list_parses_principals_and_ignores_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo_with_release_grade(
                Path(tmp),
                "# comment\n\narven-release-tooling-ci\narven-release-tooling-ci\n",
            )
            self.assertEqual(
                release_grade_principals(repo),
                frozenset({"arven-release-tooling-ci"}),
            )

    def test_prose_line_is_not_read_as_a_principal(self) -> None:
        """Only a lone principal name counts; this list carries no key material."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo_with_release_grade(
                Path(tmp),
                "arven-release-tooling-ci\n"
                "other signer notes\n"
                "see docs/release-gate.md for the rule\n",
            )
            self.assertEqual(
                release_grade_principals(repo),
                frozenset({"arven-release-tooling-ci"}),
            )

    def test_absent_list_makes_every_signer_non_release_grade(self) -> None:
        """Fail closed: no list must not mean 'any pinned signer'."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo_with_release_grade(Path(tmp), None)
            self.assertEqual(release_grade_principals(repo), frozenset())
            prov = Path(tmp) / "prov"
            prov.mkdir()
            _evidence(prov, "docker_runtime.provenance.json", "arven-release-tooling-ci")
            self.assertEqual(
                _non_release_grade_signers(
                    repo, mcp_client_evidence=None, provenance_dir=prov
                ),
                {"arven-release-tooling-ci"},
            )

    def test_drill_signer_is_rejected_even_though_it_is_pinned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo_with_release_grade(Path(tmp), "arven-release-tooling-ci\n")
            prov = Path(tmp) / "prov"
            prov.mkdir()
            _evidence(prov, "docker_runtime.provenance.json", "arven-release-tooling-local")
            mcp = _evidence(Path(tmp), "mcp-client-evidence.json", "arven-release-tooling-ci")
            self.assertEqual(
                _non_release_grade_signers(repo, mcp_client_evidence=mcp, provenance_dir=prov),
                {"arven-release-tooling-local"},
            )

    def test_ci_signer_passes_on_every_supplied_artefact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo_with_release_grade(Path(tmp), "arven-release-tooling-ci\n")
            prov = Path(tmp) / "prov"
            prov.mkdir()
            _evidence(prov, "docker_runtime.provenance.json", "arven-release-tooling-ci")
            _evidence(prov, "safe_mcp_bridge_e2e.provenance.json", "arven-release-tooling-ci")
            mcp = _evidence(Path(tmp), "mcp-client-evidence.json", "arven-release-tooling-ci")
            self.assertEqual(
                _non_release_grade_signers(repo, mcp_client_evidence=mcp, provenance_dir=prov),
                set(),
            )


if __name__ == "__main__":
    unittest.main()
