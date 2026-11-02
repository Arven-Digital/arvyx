"""Authored regression coverage. NOT_EXECUTED in the source-only fix round."""
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from arvyx_control import attestation, dogfood, security


def test_report_hash_and_verdict_use_one_capture(tmp_path, monkeypatch):
    report = tmp_path / '.arvyx/model-reviews/review.md'
    report.parent.mkdir(parents=True)
    report.write_bytes(b'Verdict: block\n')
    entry = dict(reviewer_id='p/m', provider='p', model='m', verdict='approve',
                 reviewed_at='2026-10-29T00:00:00Z', scope=['release'],
                 report_path='.arvyx/model-reviews/review.md',
                 report_sha256=hashlib.sha256(b'Verdict: block\n').hexdigest())
    original = Path.read_bytes
    reads = []
    def capture(path):
        data = original(path)
        if path == report:
            reads.append(path)
            report.write_bytes(b'Verdict: approve\n')
        return data
    monkeypatch.setattr(Path, 'read_bytes', capture)
    assert "states 'block'" in attestation._model_review_error(entry, repo=tmp_path)
    assert reads == [report]


@pytest.mark.parametrize('tag', [b'S', b's', b'h'])
def test_clean_status_cannot_hide_index_flags(tmp_path, monkeypatch, tag):
    calls = iter([SimpleNamespace(returncode=0, stdout=''),
                  SimpleNamespace(returncode=0, stdout=tag + b' docs/policy.md\0')])
    monkeypatch.setattr(attestation.subprocess, 'run', lambda *a, **k: next(calls))
    assert attestation.worktree_dirty_paths(tmp_path) == ['index-flags docs/policy.md']


def test_tracked_build_input_is_scanned_untracked_dependencies_pruned(tmp_path, monkeypatch):
    (tmp_path / '.git').mkdir()
    for relative in ('docs/build/release.md', 'node_modules/untracked.js'):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('synthetic input')
    calls = iter([SimpleNamespace(stdout=b'docs/build/release.md\0'),
                  SimpleNamespace(stdout=b'node_modules/untracked.js\0')])
    monkeypatch.setattr(security.subprocess, 'run', lambda *a, **k: next(calls))
    assert list(security.iter_source_files(tmp_path)) == [tmp_path / 'docs/build/release.md']


@pytest.mark.parametrize('hybrid', [False, None, True])
def test_dogfood_propagates_separate_vault_hybrid_result(tmp_path, monkeypatch, hybrid):
    monkeypatch.setattr(dogfood, 'init_vault', lambda *a: SimpleNamespace(files_created=['demo']))
    monkeypatch.setattr(dogfood, '_stage_public_docs', lambda *a: None)
    monkeypatch.setattr(dogfood, 'import_markdown', lambda **k: SimpleNamespace(imported=['demo'], manifest_path='manifest'))
    source = SimpleNamespace(path='imported/retrieval.md')
    monkeypatch.setattr(dogfood, 'recall', lambda *a, **k: SimpleNamespace(sources=[source], confidence=1))
    monkeypatch.setattr(dogfood, 'context_pack', lambda *a, **k: SimpleNamespace(excerpts=[source]))
    monkeypatch.setattr(dogfood, 'run_demo', lambda *a: SimpleNamespace(ok=True, checks=[]))
    modes = {'lexical': {'ok': True}}
    if hybrid is not None:
        modes['hybrid'] = {'ok': hybrid}
    monkeypatch.setattr(dogfood, 'export_evidence', lambda **k: SimpleNamespace(
        recall_benchmark={'ok': True}, recall_benchmarks=modes,
        audit={'ok': True}, release_blockers=[]))
    result = dogfood.dogfood_self(tmp_path)
    assert result.ok is (hybrid is True)
    assert result.checks[-1].detail['recall_benchmarks'] == modes
