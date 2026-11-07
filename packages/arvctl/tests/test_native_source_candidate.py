"""Source-candidate pins must not confer runtime artifact admission."""
import json
from pathlib import Path
import runpy
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[3]
BUILD = runpy.run_path(str(ROOT / 'scripts/build_arvyx_native.py'))


def test_candidate_pin_is_not_runtime_admission():
    candidate = json.loads((ROOT / 'frontends/arvyx/candidates/herdr-upstream.json').read_text())
    assert candidate['upstream']['commit'] == 'ee5bfb5041bb3e4a49d591c72308aae3c81ecdde'
    assert candidate['runtime_acceptance'] is False
    assert candidate['release_approved'] is False
    for receipt in (ROOT / 'frontends/arvyx/receipts').glob('onboarding-v1-*.json'):
        assert json.loads(receipt.read_text())['upstream']['commit'] == '5bd900d88c80d95f5b145397e45bbeea398b8165'


def test_source_pin_rejects_wrong_revision_and_local_edits(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()
    git('init', '-q')
    (source / 'source.rs').write_text('original')
    git('add', '.')
    git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture')
    commit = git('rev-parse', 'HEAD')
    validate = BUILD['validate_source_candidate']
    assert validate(source, {'upstream': {'commit': commit}}) == commit
    with pytest.raises(ValueError, match='revision'):
        validate(source, {'upstream': {'commit': '0' * 40}})
    (source / 'source.rs').write_text('modified')
    with pytest.raises(ValueError, match='clean'):
        validate(source, {'upstream': {'commit': commit}})
    git('checkout', '--', 'source.rs')
    (source / 'extra.rs').write_text('untracked')
    with pytest.raises(ValueError, match='clean'):
        validate(source, {'upstream': {'commit': commit}})
    git('clean', '-fd')
    (source / '.gitignore').write_text('ignored.rs\n')
    git('add', '.gitignore')
    git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'ignore fixture')
    commit = git('rev-parse', 'HEAD')
    (source / 'ignored.rs').write_text('ignored input')
    with pytest.raises(ValueError, match='clean'):
        validate(source, {'upstream': {'commit': commit}})
    with pytest.raises(ValueError, match='revision'):
        validate(source, {'upstream': {'commit': 'not-a-sha'}})
    nested = source / 'nested'
    nested.mkdir()
    with pytest.raises(ValueError, match='checkout root'):
        validate(nested, {'upstream': {'commit': commit}})
