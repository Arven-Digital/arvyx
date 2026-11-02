"""Real loopback HTTP composition acceptance; all state is disposable fixture state."""
import hashlib
import json
import threading
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import pytest

from arvyx_control.public_onboarding_api import fixture_composition, make_server


@pytest.fixture
def local(tmp_path):
    api, token, adapter = fixture_composition(tmp_path, session_count=1205)
    server = make_server(api)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = 'http://127.0.0.1:' + str(server.server_port)
    def call(path, body=None, credential=token, origin=None):
        headers = {'Authorization': 'Bearer ' + credential}
        # Positive requests use the browser's same-origin boundary. Pass False
        # explicitly to exercise missing-Origin denial without weakening the gate.
        if origin is not False:
            headers['Origin'] = base if origin is None else origin
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            headers['Content-Type'] = 'application/json'
        req = Request(base + '/api/public-onboarding/' + path, data=data, headers=headers)
        try:
            response = urlopen(req)
        except HTTPError as exc:
            response = exc
        return response.status, json.load(response)
    yield api, adapter, call
    server.shutdown()
    server.server_close()
    thread.join()
    api.close()


def test_discover_connect_requires_each_confirmation(local):
    api, adapter, call = local
    status, found = call('discover', {})
    assert status == 200
    candidate = found['candidates'][0]
    assert 'path' not in candidate
    assert not adapter.connected
    assert call('connect', {'candidate_id': candidate['id']})[0] == 400
    assert call('connect', {'candidate_id': 'invented', 'confirmed': True})[0] == 404
    status, connected = call('connect', {'candidate_id': candidate['id'], 'confirmed': True})
    assert status == 200 and connected['target'] == api.fixture_target
    assert adapter.connected


def connect(call):
    _, found = call('discover', {})
    return call('connect', {'candidate_id': found['candidates'][0]['id'], 'confirmed': True})[1]['target']


def test_1205_metadata_search_and_exact_select(local):
    api, adapter, call = local
    target = connect(call)
    assert len(call('sessions/recent', {'target': target})[1]['items']) == 5
    items, cursor = [], None
    while True:
        body = {'target': target, 'limit': 100}
        if cursor:
            body['cursor'] = cursor
        status, page = call('sessions/all', body)
        assert status == 200 and page['total'] == 1205
        items.extend(page['items'])
        cursor = page['next_cursor']
        if cursor is None:
            break
    assert len({x['route']['session_id'] for x in items}) == 1205
    assert adapter.actions == []
    status, page = call('sessions/search', {'target': target, 'query': 'session-1204'})
    assert status == 200 and page['total'] == 1
    route = page['items'][0]['route']
    assert call('sessions/select', {'route': route})[0] == 400
    status, result = call('sessions/select', {'route': route, 'confirmed': True})
    assert status == 200 and result['route'] == route
    assert adapter.actions == [(adapter.target, 'select', 'session-1204')]
    for key in target:
        wrong = dict(target, **{key: 'other'})
        assert call('sessions/select', {'route': {'target': wrong, 'session_id': 'session-1204'}, 'confirmed': True})[0] == 403
    adapter.connected = False
    assert call('sessions/select', {'route': route, 'confirmed': True})[0] == 409
    assert len(adapter.actions) == 1


def test_create_unique_clean_and_list(local):
    _, _, call = local
    body = {'name': 'New Agent', 'harness': 'fixture', 'confirmed': True}
    assert call('agents/create', dict(body, confirmed=False))[0] == 400
    status, created = call('agents/create', body)
    assert status == 201 and created['status'] == 'metadata_only'
    assert call('agents/create', dict(body, name='new agent'))[0] == 400
    assert call('agents')[1]['items'] == [created]
    for key in ['source_root', 'identity_files', 'owner_host', 'provider_auth_handle', 'root', 'remote_workspace_id']:
        assert call('agents/create', dict(body, **{key: '/etc'}))[0] == 400


@pytest.mark.parametrize('path', ['native/install', 'root/execute', 'remote/connect', 'pairing/confirm', 'organizer/provision'])
def test_unavailable_fails_closed(local, path):
    _, adapter, call = local
    assert call(path, {'confirmed': True})[0] == 501
    assert not adapter.actions


def test_auth_origin_and_arbitrary_paths(local):
    _, _, call = local
    assert call('agents', credential='invalid')[0] == 401
    assert call('discover', {}, origin='https://attacker.example')[0] == 403
    assert call('discover', {}, origin=False)[0] == 403
    assert call('discover', {'home': '/etc'})[0] == 400
    assert call('discover?home=/etc', {})[0] == 400
    assert call('sessions/all', {'target': {'machine_id': '/etc'}})[0] == 400


def test_unknown_candidate_has_no_adapter(local):
    api, _, call = local
    api.owner.discovery = lambda: {'candidates': [{'id': 'native:default', 'family': 'native', 'label': 'Native', 'kind': 'agent', 'local_id': 'default'}], 'truncated': False}
    call('discover', {})
    assert call('connect', {'candidate_id': 'native:default', 'confirmed': True})[0] == 501


def test_two_owner_isolation(local, tmp_path):
    api, adapter, call = local
    target = connect(call)
    other, token, _ = fixture_composition(tmp_path / 'other', session_count=0)
    other_owner = other.owner
    other_owner.targets = frozenset()
    api.owners['other-owner'] = other_owner
    api.credentials[hashlib.sha256(token.encode()).hexdigest()] = 'other-owner'
    call('agents/create', {'name': 'Private owner agent', 'harness': 'fixture', 'confirmed': True})
    assert call('agents', credential=token)[1]['items'] == []
    assert call('sessions/all', {'target': target}, credential=token)[0] == 403
    assert call('connect', {'candidate_id': 'hermes:agent:default', 'confirmed': True}, credential=token)[0] == 404
    assert not adapter.actions


def test_bind_is_loopback_only(local):
    api, _, _ = local
    with pytest.raises(ValueError):
        make_server(api, host='0.0.0.0', port=0)
