import json
from unittest.mock import patch
import os
import pytest
from arvyx_control.public_onboarding_api import fixture_composition
from arvyx_control.harness_discovery import discover_harnesses
from arvyx_control.onboarding_cli import Onboarding, menu

@pytest.fixture
def api(tmp_path):
    api, token, adapter = fixture_composition(tmp_path)
    def call(path, body=None):
        return api.dispatch('GET' if body is None else 'POST','/api/public-onboarding/'+path,'Bearer '+token, body or {})
    yield api, call
    api.close()

@pytest.mark.parametrize('route', ['x', [], 42, None])
def test_malformed_route_is_400(api,route):
    _, call=api
    assert call('sessions/select',dict(route=route,confirmed=True))[0]==400


@pytest.mark.skipif(os.name != 'posix', reason='POSIX mode bits and umask')
def test_discovery_reports_permission_and_unsafe_ancestor(tmp_path):
    with patch('os.open',side_effect=PermissionError('denied')):
        result=discover_harnesses(tmp_path)
    assert result['incomplete'] is True
    assert 'unreadable_location' in result['incomplete_reasons']
    alias=tmp_path/'alias';alias.symlink_to(tmp_path,target_is_directory=True)
    assert discover_harnesses(alias)['incomplete'] is True


def test_cli_unicode_control_parity(tmp_path):
    root=tmp_path/'state';root.mkdir(mode=0o700)
    store=Onboarding(root)
    try:
        for name in ('zero\u200bwidth','del\x7f','surrogate\ud800'):
            with pytest.raises(ValueError): store._name(name)
    finally: store.close()


def test_truncation_warning_precedes_connect_prompt():
    events=[]
    def choose(prompt,options):
        events.append(('prompt',prompt));return 'skip'
    scan=dict(candidates=[dict(label='test',local_id='profile',path='/test')],truncated=True)
    with patch('arvyx_control.onboarding_cli.discover_harnesses',return_value=scan),patch('arvyx_control.onboarding_cli.choose',side_effect=choose),patch('builtins.print',side_effect=lambda *args: events.append(('print',' '.join(map(str,args))))):
        menu(None,'/explicit')
    assert next(i for i,e in enumerate(events) if 'truncated' in e[1]) < next(i for i,e in enumerate(events) if e[0]=='prompt')
