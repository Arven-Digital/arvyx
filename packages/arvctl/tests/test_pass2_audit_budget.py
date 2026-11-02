"""Exhausted audits must fail closed rather than certify a partial tree."""
from unittest.mock import patch
from types import SimpleNamespace
import pytest
from arvyx_control import audit,security,evidence


def test_audit_byte_budget_refuses_before_materializing_file(tmp_path):
    source=tmp_path/'source.txt';source.write_bytes(b'A'*100)
    with patch.object(audit,'AUDIT_MAX_BYTES',10,create=True):
        with pytest.raises(ValueError,match='budget'):
            audit.scan_private_context(tmp_path)


def test_audit_clock_budget_is_nonrenewable(tmp_path):
    (tmp_path/'source.txt').write_text('small clean text')
    with patch.object(audit,'AUDIT_MAX_SECONDS',.001,create=True):
        with patch('time.monotonic',side_effect=[0,1,2,3,4]):
            with pytest.raises(ValueError,match='budget'):audit.scan_private_context(tmp_path)


def test_binding_refuses_external_symlinks_instead_of_hashing_outside_content(tmp_path):
    outside=tmp_path/'outside';outside.write_text('unbound outside material')
    repo=tmp_path/'repo';repo.mkdir();source=repo/'source.txt';source.symlink_to(outside)
    with patch.object(evidence,'iter_source_files',return_value=[source]),patch.object(evidence.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'')):
        with pytest.raises(ValueError,match='symlink'):evidence._AuditOperation(repo)
