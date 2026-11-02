"""Explicit dirty rename validation never changes the index or release gate."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import pytest
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts'))
import public_release_boundary as gate


def test_exact_rename_candidate(tmp_path):
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    old = tmp_path / 'old.py'
    old.write_text('# PRIVATE: DO NOT PUBLISH\nold = True\n')
    subprocess.run(['git', 'add', 'old.py'], cwd=tmp_path, check=True)
    blob = subprocess.check_output(['git', 'rev-parse', ':old.py'], cwd=tmp_path, text=True).strip()
    old.rename(tmp_path / 'new.py')
    manifest = tmp_path / 'manifest.json'
    manifest.write_text(json.dumps({'version': 1, 'paths': {'new.py': 'private-only'}}))
    with pytest.raises(gate.BoundaryError):
        gate.validate_tracked_paths(manifest, gate.git_tracked_paths(tmp_path))
    spec = {'renames': [{'source': 'old.py', 'target': 'new.py', 'indexed_blob': blob, 'classification': 'private-only'}], 'additions': []}
    assert gate.validate_working_candidate(tmp_path, manifest, spec) == {'new.py': 'private-only'}
    spec['renames'][0]['indexed_blob'] = '0' * 40
    with pytest.raises(gate.BoundaryError):
        gate.validate_working_candidate(tmp_path, manifest, spec)


def test_unrelated_missing_path_cannot_be_dropped(tmp_path):
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    (tmp_path/'unclassified.py').write_text('x=1')
    subprocess.run(['git', 'add', '.'], cwd=tmp_path, check=True)
    (tmp_path/'unclassified.py').unlink()
    manifest=tmp_path/'manifest.json'
    manifest.write_text(json.dumps({'version':1,'paths':{}}))
    with pytest.raises(gate.BoundaryError):
        gate.validate_working_candidate(tmp_path, manifest, {'renames':[], 'additions':[]})
