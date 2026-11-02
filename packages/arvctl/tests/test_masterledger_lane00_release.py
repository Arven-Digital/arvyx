"""Lane 00 regression sources. Not executed in the source-only remediation."""
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from arvyx_control import audit, release_host, security

ROOT = Path(__file__).resolve().parents[3]


def boundary_module():
    spec = importlib.util.spec_from_file_location("lane00_boundary", ROOT / "scripts/public_release_boundary.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("spec", [None, [], {"renames": {}, "additions": []},
    {"renames": [None], "additions": []}, {"renames": [], "additions": "file"}])
def test_candidate_schema_fails_with_boundary_error(tmp_path, spec):
    boundary = boundary_module()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"version": 1, "paths": {}}))
    with patch.object(boundary, "git_tracked_paths", return_value=[]):
        with pytest.raises(boundary.BoundaryError):
            boundary.validate_working_candidate(tmp_path, manifest, spec)


@pytest.mark.parametrize("path", ["dir/../outside", "../outside", "/outside", "dir\\outside", None, ""])
def test_candidate_rejects_unsafe_paths(path):
    boundary = boundary_module()
    with pytest.raises(boundary.BoundaryError):
        boundary._normalize(path)


def test_candidate_rejects_symlink_ancestor(tmp_path):
    boundary = boundary_module()
    external = tmp_path / "outside"
    external.mkdir()
    (external / "source.txt").write_text("ordinary source")
    root = tmp_path / "repo"
    root.mkdir()
    try:
        (root / "linked").symlink_to(external, target_is_directory=True)
    except OSError:
        pytest.skip("platform cannot create symlinks")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"version": 1, "paths": {"linked/source.txt": "public-approved"}}))
    with patch.object(boundary, "git_tracked_paths", return_value=[]):
        with pytest.raises(boundary.BoundaryError, match="symlink"):
            boundary.validate_working_candidate(root, manifest, {"renames": [], "additions": ["linked/source.txt"]})


def test_audit_requires_actual_private_name_assurance(tmp_path):
    with patch.object(audit, "scan_private_context", return_value=(set(), 0, False, 0)):
        result = audit._private_context_check(tmp_path)
    assert not result.ok
    assert "private context denylist was not loaded" in result.findings


@pytest.mark.parametrize("exempted,expected", [(None, False), (0, True)])
def test_audit_requires_valid_release_manifest(tmp_path, exempted, expected):
    # Synthetic detector result isolates the wrapper policy, not audit acceptance.
    with patch.object(audit, "scan_private_context", return_value=(set(), exempted, True, 0)):
        result = audit._private_context_check(tmp_path)
    assert result.ok is expected
    if not expected:
        assert "release classification manifest is missing or invalid" in result.findings
        assert audit._failed_check_blockers([result]) == ["audit check failed: private_context"]


def test_configured_denylist_never_falls_back(tmp_path, monkeypatch):
    (tmp_path / ".arvyx").mkdir()
    # Test-only synthetic input, never release assurance.
    (tmp_path / security.DENYLIST_RELATIVE).write_text("synthetic-fixture-term\n")
    monkeypatch.setenv(security.DENYLIST_ENV, str(tmp_path / "missing-private-input"))
    with pytest.raises(ValueError, match="configured private denylist"):
        security.load_private_denylist(tmp_path)


def test_comment_only_configured_denylist_is_rejected(tmp_path, monkeypatch):
    denylist = tmp_path / "input.txt"
    denylist.write_text("# fixture comment only\n")
    monkeypatch.setenv(security.DENYLIST_ENV, str(denylist))
    with pytest.raises(ValueError, match="no terms"):
        security.load_private_denylist(tmp_path)


def test_unsigned_host_runs_never_establish_public_readiness(tmp_path):
    complete = release_host.ReleaseHostCheck("fixture", "fixture", "complete", [], "")
    with patch.object(release_host, "_docker_runtime_check", return_value=complete), \
         patch.object(release_host, "_mcp_client_check", return_value=complete), \
         patch.object(release_host, "_bridge_e2e_check", return_value=complete):
        result = release_host.release_host_report(tmp_path)
    assert result.ok  # In-place completion is distinct from signed release readiness.
    assert not result.public_release_ready
    assert any("run-provenance" in blocker for blocker in result.blockers)


@pytest.mark.parametrize("grade,tree,accepted", [(set(), "a" * 40, False), ({"ci"}, None, False), ({"ci"}, "a" * 40, True)])
def test_host_provenance_requires_release_grade_and_known_tree(tmp_path, grade, tree, accepted):
    payload = {"check_id": "docker_runtime", "git_tree": "a" * 40, "result": "pass", "attestation": {"principal": "ci"}}
    (tmp_path / "docker_runtime.provenance.json").write_text(json.dumps(payload))
    # Signature verification is mocked for policy isolation, not a crypto receipt.
    with patch.object(release_host, "verify_payload", return_value=(True, "")), \
         patch.object(release_host, "release_grade_principals", return_value=grade), \
         patch.object(release_host, "git_tree_sha", return_value=tree):
        result = release_host._provenance_check(tmp_path, "docker_runtime", "fixture", tmp_path)
    assert (result.status == "complete") is accepted
