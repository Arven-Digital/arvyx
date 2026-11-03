"""Real filesystem fixtures; discovery must never open user file contents."""
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from arvyx_control.harness_discovery import discovery_catalog, discover_harnesses


def marker(home, relative):
    path = home / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('SECRET must not be read')
    return path


def test_catalog_has_33_unique_families_covering_25_product_targets():
    catalog = discovery_catalog('linux')
    assert len(catalog) == len({item['family'] for item in catalog}) == 33
    assert sum(item['product_target'] for item in catalog) == 25
    assert {'hermes', 'openclaw', 'pi', 'claude', 'codex', 'cursor', 'vscode',
            'copilot', 'opencode', 'gemini', 'cline'} <= {x['family'] for x in catalog}
    assert all(x['evidence'].startswith('https://') for x in catalog)
    assert all(x['requires_explicit_connect'] and not x['auto_import'] for x in catalog)
    assert all(x['reason'] for x in catalog if not x['supported'])


def test_metadata_only_and_editor_is_not_agent(tmp_path):
    marker(tmp_path, '.claude/settings.json')
    marker(tmp_path, '.cursor/mcp.json')
    marker(tmp_path, '.config/Code/User/settings.json')
    marker(tmp_path, 'project/.gemini/settings.json')
    with patch.object(Path, 'open', side_effect=AssertionError('content read')), \
         patch('builtins.open', side_effect=AssertionError('content read')), \
         patch('subprocess.run', side_effect=AssertionError('execution')):
        result = discover_harnesses(tmp_path, platform='linux')
    candidates = {x['family']: x for x in result['candidates']}
    assert set(candidates) == {'claude', 'cursor', 'vscode'}
    assert candidates['cursor']['kind'] == 'editor'
    assert candidates['vscode']['kind'] == 'editor'
    assert candidates['claude']['kind'] == 'agent'
    assert all(x['requires_explicit_connect'] and not x['connected'] and not x['auto_import']
               for x in candidates.values())
    assert 'SECRET' not in str(result)


def test_shallow_profiles_and_agents_are_distinct(tmp_path):
    marker(tmp_path, '.hermes/config.yaml')
    marker(tmp_path, '.hermes/profiles/work/config.yaml')
    marker(tmp_path, '.hermes/profiles/work/profiles/nested/config.yaml')
    marker(tmp_path, '.openclaw/openclaw.json')
    (tmp_path / '.openclaw/agents/builder/agent').mkdir(parents=True)
    marker(tmp_path, '.config/Code/User/profiles/abc/settings.json')
    result = discover_harnesses(tmp_path, platform='linux')
    found = {(x['family'], x['kind'], x['local_id']) for x in result['candidates']}
    assert ('hermes', 'profile', 'work') in found
    assert ('openclaw', 'agent', 'builder') in found
    assert ('vscode', 'editor_profile', 'abc') in found
    assert not any(x['local_id'] == 'nested' for x in result['candidates'])


@pytest.mark.parametrize('relative', ['.hermes', '.hermes/profiles', '.hermes/profiles/escape'])
def test_symlink_traversal_rejected(tmp_path, relative):
    outside = tmp_path / 'outside'
    marker(outside, 'config.yaml')
    path = tmp_path / 'home' / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(outside, target_is_directory=True)
    assert not discover_harnesses(tmp_path / 'home', platform='linux')['candidates']


def test_leaf_symlink_and_nonregular_marker_rejected(tmp_path):
    target = marker(tmp_path, 'secret')
    path = tmp_path / '.claude/settings.json'
    path.parent.mkdir()
    path.symlink_to(target)
    (tmp_path / '.gemini/settings.json').mkdir(parents=True)
    assert not discover_harnesses(tmp_path, platform='linux')['candidates']


def test_candidate_dedupe(tmp_path):
    marker(tmp_path, '.config/opencode/opencode.json')
    marker(tmp_path, '.config/opencode/opencode.jsonc')
    result = discover_harnesses(tmp_path, platform='linux')
    assert len(result['candidates']) == 1
    assert result['candidates'][0]['family'] == 'opencode'


def test_scan_and_result_bounds(tmp_path):
    for i in range(20):
        marker(tmp_path, f'.hermes/profiles/p{i}/config.yaml')
    result = discover_harnesses(tmp_path, platform='linux', max_entries=3)
    assert len(result['candidates']) <= 3
    assert result['truncated']
    result = discover_harnesses(tmp_path, platform='linux', max_probes=5)
    assert result['probes'] <= 5
    assert result['truncated']
    result = discover_harnesses(tmp_path, platform='linux', max_candidates=2)
    assert len(result['candidates']) == 2
    assert result['truncated']


@pytest.mark.parametrize('platform,relative', [
    ('windows', 'AppData/Roaming/Code/User/settings.json'),
    ('darwin', 'Library/Application Support/Code/User/settings.json'),
    ('linux', '.config/Code/User/settings.json'),
])
def test_os_specific_known_paths(tmp_path, platform, relative):
    marker(tmp_path, relative)
    marker(tmp_path, '.gemini/settings.json')
    result = discover_harnesses(tmp_path, platform=platform)
    assert {x['family'] for x in result['candidates']} == {'vscode', 'gemini'}


def test_wrong_os_paths_not_scanned(tmp_path):
    marker(tmp_path, 'AppData/Roaming/Code/User/settings.json')
    assert not discover_harnesses(tmp_path, platform='linux')['candidates']


@pytest.mark.parametrize('kwargs', [{'platform': 'plan9'}, {'max_probes': 0},
                                  {'max_entries': 10000}, {'max_candidates': True}])
def test_invalid_limits_and_platform(tmp_path, kwargs):
    with pytest.raises(ValueError):
        discover_harnesses(tmp_path, **kwargs)


@pytest.mark.parametrize('platform', ['linux', 'darwin', 'windows'])
def test_every_supported_family_has_real_fixture_detection(tmp_path, platform):
    catalog = discovery_catalog(platform)
    expected = {d['family'] for d in catalog if d['supported']}
    for descriptor in catalog:
        for path in descriptor['paths']:
            marker(tmp_path, path)
    result = discover_harnesses(tmp_path, platform=platform)
    assert {c['family'] for c in result['candidates']} == expected
    assert not result['truncated']


@pytest.mark.skipif(os.name != 'posix', reason='POSIX directory-only descriptor safety')
def test_only_directories_are_opened(tmp_path):
    marker(tmp_path, '.hermes/config.yaml')
    original = os.open
    opened = []

    def directory_open(path, flags, *args, **kwargs):
        assert flags & os.O_DIRECTORY
        opened.append(str(path))
        return original(path, flags, *args, **kwargs)

    with patch('os.open', side_effect=directory_open):
        result = discover_harnesses(tmp_path, platform='linux')
    assert opened
    assert len(result['candidates']) == 1
    assert 'config.yaml' not in opened


def test_permission_errors_do_not_escape(tmp_path):
    with patch('os.open', side_effect=PermissionError('fixture denied')):
        result = discover_harnesses(tmp_path, platform='linux')
    assert not result['candidates']


def test_untrusted_profile_names_and_symlink_home(tmp_path):
    # NTFS cannot hold names containing ':' or '\\'; the other untrusted shapes still apply.
    names = ['.hidden', 'x' * 129] if os.name == 'nt' else ['bad:name', 'bad\\\\name', '.hidden', 'x' * 129]
    for name in names:
        marker(tmp_path, f'.hermes/profiles/{name}/config.yaml')
    assert not discover_harnesses(tmp_path, platform='linux')['candidates']
    alias = tmp_path / 'alias'
    if os.name == 'nt':
        # A directory symlink needs a privilege on Windows; a junction is the same reparse-point refusal.
        import subprocess
        subprocess.run(['cmd', '/c', 'mklink', '/J', str(alias), str(tmp_path)], check=True, capture_output=True)
    else:
        alias.symlink_to(tmp_path, target_is_directory=True)
    assert not discover_harnesses(alias, platform='linux')['candidates']
    with pytest.raises(ValueError):
        discover_harnesses(tmp_path / '..', platform='linux')


def test_historical_research_receipt_remains_bound_to_its_original_families():
    receipt = json.loads(Path(__file__).with_name('harness_discovery_research_receipt.json').read_text())
    families = receipt['families']
    assert len(families) == 25
    historical = {r['family']: r['url'] for r in families}
    assert historical == {d['family']: d['evidence'] for d in discovery_catalog('linux')
                          if d['family'] in historical}
    # Additional product references have not been fetched or probed.
    added = [d for d in discovery_catalog('linux') if d['family'] not in historical]
    assert len(added) == 8
    assert all(not d['supported'] and not d['paths'] for d in added)
    assert all(r['http_status'] == 200 and r['sha256'] for r in families)


def test_missing_home_is_empty(tmp_path):
    assert not discover_harnesses(tmp_path / 'missing', platform='linux')['candidates']


def test_unsupported_descriptors_never_probe_guessed_paths(tmp_path):
    marker(tmp_path, '.trae/config.json')
    result = discover_harnesses(tmp_path, platform='linux')
    assert not result['candidates']
    assert next(x for x in result['catalog'] if x['family'] == 'trae')['supported'] is False
