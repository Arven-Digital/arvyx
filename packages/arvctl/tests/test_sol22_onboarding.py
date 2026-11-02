"""Candidate 21 Sol findings 5–7 regression coverage."""
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from arvyx_control.local_onboarding import LocalOnboarding
from arvyx_control.shared_onboarding_cli import menu

@pytest.mark.parametrize('text', ['a' * (256*1024), '\x01' * (256*1024), '😀' * (64*1024)], ids=['ascii', 'json-controls', 'non-bmp'])
def test_sol22_cli_reviews_individual_bounded_pages(tmp_path, text):
    from arvyx_control.agent_creation import _IDENTITY
    paths = sorted(_IDENTITY)
    for path in paths:
        (tmp_path / path).write_text(text)
    from arvyx_control.hermes_history import HermesHistory
    from arvyx_control.agent_sessions import AgentSessions
    history = HermesHistory(tmp_path)
    target = history.target
    service = object.__new__(LocalOnboarding)
    service.vault = tmp_path / 'vault'
    service.sources = {'source': (tmp_path, target)}
    service.owner = SimpleNamespace(targets={target}, sessions=AgentSessions({target:history}))
    service.workspaces = SimpleNamespace(route=lambda *args: None)
    pages = []
    prepared = []
    def call(path, body=None):
        if path == 'capabilities':
            return {'mode':'test', 'instruction_sources':[{'id':'source'}]}
        if path == 'instructions/preview':
            assert len(body['paths']) == 1, 'preview must request one file at a time'
            status, response = service.route(path, 'POST', body)
            assert status == 200
            assert len(json.dumps(response).encode()) <= 1024*1024
            pages.append(response)
            return response
        if path == 'agents/prepare':
            prepared.append(body)
            return {'request':body}
        raise AssertionError(path)
    answers = iter(['create', 'new-agent', 'copy', 'source', ','.join(paths), *(['yes'] * len(paths)), 'skip', 'quit'])
    with patch('builtins.input', side_effect=lambda *args: next(answers)), patch('builtins.print'):
        assert menu(call) == 0
    assert len(pages) >= 2
    assert [f['path'] for f in prepared[0]['identity_files']] == paths
    assert all(f['approved_sha256'] == hashlib.sha256(text.encode()).hexdigest() for f in prepared[0]['identity_files'])
    assert ''.join(p['files'][0]['content'] for p in pages if p['files'][0]['path'] == paths[0]) == text
