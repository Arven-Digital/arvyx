"""Candidate16 Sol findings 1 and 8: curated excerpts and operator authority."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from arvyx_control.api import handle_api_request
from arvyx_control.auth import Identity, tools_for_scopes
from arvyx_control.mcp import handle_request
from arvyx_control.recall import excerpt

MARKER = 'SOL17_SYNTHETIC_UNPROMOTED_TRANSCRIPT'


@pytest.fixture
def vault(tmp_path):
    private = tmp_path / 'conversations/cockpit-archive/private.md'
    private.parent.mkdir(parents=True)
    private.write_text(MARKER)
    curated = tmp_path / 'projects/sample/NOTE.md'
    curated.parent.mkdir(parents=True)
    curated.write_text('Curated synthetic note.')
    (curated.parent / 'private-link.md').symlink_to(private)
    (curated.parent / 'archive-dir').symlink_to(private.parent, target_is_directory=True)
    (curated.parent / 'private.txt').write_text(MARKER)
    return tmp_path


@pytest.mark.parametrize('source', [
    'conversations/cockpit-archive/private.md',
    'projects/sample/private-link.md',
    'projects/sample/archive-dir/private.md',
    'projects/sample/private.txt',
    'projects/sample/../../conversations/cockpit-archive/private.md',
])
@pytest.mark.parametrize('surface', ['direct', 'http', 'mcp'])
def test_memory_only_cannot_excerpt_private_archive(vault, source, surface):
    if surface == 'direct':
        with pytest.raises(ValueError):
            excerpt(vault, source, '1')
        return
    request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
        'name': 'memory.excerpt', 'arguments': {'source_path': source, 'lines': '1'}}}
    if surface == 'http':
        identity = Identity('reader', frozenset({'memory.read'}), 'agent')
        with patch('arvyx_control.api.resolve_identity', return_value=identity):
            response = handle_api_request('POST', '/mcp', request, vault, vault / 'events.jsonl',
                                          authorization='Bearer synthetic')
        result = json.loads(response.body)
    else:
        result = handle_request(request, vault, allowed_tools=tools_for_scopes({'memory.read'}), actor='reader')
    assert MARKER not in json.dumps(result)
    assert 'error' in result or result.get('result', {}).get('isError') is True


@pytest.mark.parametrize('source', ['projects/sample/NOTE.md', 'agents/reader/NOTE.md'])
def test_curated_markdown_still_readable(vault, source):
    path = vault / source
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('Curated synthetic note.')
    assert excerpt(vault, source, '1').text == 'Curated synthetic note.'


def test_control_write_documentation_excludes_approval_decisions():
    text = (Path(__file__).resolve().parents[3] / 'docs/auth.md').read_text()
    row = next(line for line in text.splitlines() if line.startswith('| `control.write` |'))
    assert 'request/approve/consume' not in row
    assert 'operator-only approval decisions' in row
