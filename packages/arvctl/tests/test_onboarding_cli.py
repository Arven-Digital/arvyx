import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

SRC = Path(__file__).resolve().parents[1] / 'src'


def run(home, state, answers='', *args):
    env = dict(os.environ, PYTHONPATH=str(SRC), HOME=str(home))
    return subprocess.run([sys.executable, '-m', 'arvyx_control.onboarding_cli',
                           '--state-dir', str(state), '--home', str(home), *args],
                          input=answers, text=True, capture_output=True, env=env)


def test_menu_persists_exact_connection_and_optional_organizer(tmp_path):
    home = tmp_path / 'home'
    (home / '.hermes').mkdir(parents=True)
    marker = home / '.hermes/config.yaml'
    marker.write_text('DO NOT READ OR MODIFY')
    state = tmp_path / 'amc'
    result = run(home, state, 'connect\nAlice\nskip\nskip\n')
    assert result.returncode == 0, result.stderr + result.stdout
    data = json.loads(run(home, state, '', 'status').stdout)
    assert data['connections'][0]['name'] == 'Alice'
    assert data['connections'][0]['candidate']['path'] == str(marker)
    from arvyx_control.onboarding_cli import Onboarding
    store = Onboarding(state)
    try:
        identity = data['connections'][0]['connection_id']
        store.organizer(identity)
    finally:
        store.close()
    data = json.loads(run(home, state, '', 'status').stdout)
    assert data['organizer'] == {'version': 2, 'connection_id': identity}
    assert data['connections'][0]['status'] == 'consented_unverified'
    assert marker.read_text() == 'DO NOT READ OR MODIFY'


def test_skip_then_clean_named_create(tmp_path):
    home = tmp_path / 'home'
    home.mkdir()
    state = tmp_path / 'amc'
    result = run(home, state, 'skip\ncreate\nNova\n')
    assert result.returncode == 0, result.stderr + result.stdout
    data = json.loads(run(home, state, '', 'status').stdout)
    assert data['organizer'] is None
    agent = data['agents'][0]
    assert agent['name'] == 'Nova'
    assert agent['status'] == 'metadata_only'
    assert (state / 'profiles' / agent['agent_id']).is_dir()


def test_remote_confirmation_fails_without_enrollment(tmp_path):
    result = run(tmp_path, tmp_path / 'amc', '', '-confirm', 'A' * 32)
    assert result.returncode == 2
    assert 'requires --url and --name on REMOTE' in result.stderr
    assert not (tmp_path / 'amc').exists()


def test_skip_candidate_no_implicit_connection(tmp_path):
    (tmp_path / '.codex').mkdir()
    (tmp_path / '.codex/config.toml').touch()
    state = tmp_path / 'amc'
    assert run(tmp_path, state, 'skip\nskip\nskip\n').returncode == 0
    assert json.loads(run(tmp_path, state, '', 'status').stdout)['connections'] == []
