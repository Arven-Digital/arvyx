"""Composition authority regressions; intentionally not executed in this fix round."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import http.client
import json
import threading

import pytest

from arvyx_control.public_onboarding_api import fixture_composition, make_server
from arvyx_control.external_demo import build_fixture_server
from arvyx_control.replica_authority import ReplicaAuthorityUnavailable, assert_state_authority


@contextmanager
def serving(server):
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join()


def request(server, path, body=None, *, token=None, cookie=None):
    host, port = server.server_address
    headers = {'Origin': f'http://{host}:{port}'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if cookie:
        headers['Cookie'] = cookie
    data = None if body is None else json.dumps(body).encode()
    if data is not None:
        headers['Content-Type'] = 'application/json'
    conn = http.client.HTTPConnection(host, port, timeout=3)
    try:
        conn.request('GET' if body is None else 'POST', path, data, headers)
        response = conn.getresponse()
        return response.status, json.loads(response.read())
    finally:
        conn.close()


def fresh(function, *args, **kwargs):
    # No test-global authority binding, and no copied ContextVar context.
    with ThreadPoolExecutor(max_workers=1) as workers:
        return workers.submit(function, *args, **kwargs).result()


def test_onboarding_fixture_worker_journey_and_unbound_refusal(tmp_path):
    api, token, _ = fresh(fixture_composition, tmp_path)
    try:
        with serving(make_server(api)) as server:
            def call(path, body=None):
                return request(server, '/api/public-onboarding/' + path, body, token=token)
            status, found = call('discover', {})
            assert status == 200
            assert call('connect', dict(candidate_id=found['candidates'][0]['id'], confirmed=True))[0] == 200
            status, created = call('agents/create', dict(name='Fixture', harness='fixture', confirmed=True))
            assert status == 201
            assert created in call('agents')[1]['items']
            assert call('sessions/all', dict(target=api.fixture_target))[0] == 200
            # A mode label and a database directory confer no authority.
            api.owner.vault = None
            api.owner.state = None
            assert call('discover', {})[0] == 400
    finally:
        api.close()


def test_shipped_onboarding_demo_cookie_request_entry(tmp_path, monkeypatch):
    import importlib.util
    from pathlib import Path
    import shutil
    monkeypatch.setenv('TMPDIR', str(tmp_path))
    script = Path(__file__).resolve().parents[3] / 'scripts' / 'public_onboarding_demo.py'
    spec = importlib.util.spec_from_file_location('depth20_onboarding_demo', script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = fresh(module.make_demo)
    try:
        with serving(server):
            host, port = server.server_address
            conn = http.client.HTTPConnection(host, port, timeout=3)
            conn.request('POST', '/fixture-session', '{}',
                {'Origin': f'http://{host}:{port}', 'Content-Type': 'application/json'})
            response = conn.getresponse()
            assert response.status == 200
            header = response.getheader('Set-Cookie')
            assert header is not None
            cookie = header.split(';')[0]
            response.read()
            conn.close()
            def call(path, body=None):
                return request(server, '/api/public-onboarding/' + path, body, cookie=cookie)
            status, found = call('discover', {})
            assert status == 200
            assert call('connect', dict(candidate_id=found['candidates'][0]['id'], confirmed=True))[0] == 200
            assert call('agents/create', dict(name='Demo', harness='fixture', confirmed=True))[0] == 201
            assert call('sessions/all', dict(target=server.api.fixture_target))[0] == 200
    finally:
        server.api.close()
        shutil.rmtree(server.state)


@pytest.mark.parametrize('marker', ['.arvyx-replica', '.arvyx/failover.json'])
def test_composed_pairing_fences_all_proof_writes_without_human_bearer(tmp_path, marker):
    from arvyx_control.local_onboarding import local_composition
    from arvyx_control.machine_pairing_transport import PairingTransport, _crypto
    private, _, _ = _crypto()
    key = private.generate()
    vault = tmp_path / 'actual-vault'
    vault.mkdir()
    directory = tmp_path / 'onboarding'
    directory.mkdir()
    transport = PairingTransport(tmp_path / 'pairing')
    def human_only():
        raise PermissionError('remote proof must not require main human credential')
    api = local_composition(directory, vault=vault, machine_id='main', capability='main-secret',
                            pairing=transport, authorize=human_only)
    api.remote_pairing = transport
    try:
        with serving(make_server(api)) as server:
            challenges = []
            for purpose in ('confirm', 'check'):
                status, challenge = request(server, '/challenge',
                    dict(**transport.public(key, 'remote'), purpose=purpose, code='invitation'))
                assert status == 200  # Deliberately no Authorization header.
                challenges.append(dict(challenge=challenge['challenge'], code='invitation',
                    signature=base64.b64encode(key.sign(base64.b64decode(challenge['message']))).decode()))
            marker_path = vault / marker
            marker_path.parent.mkdir(exist_ok=True)
            marker_path.write_text('fenced')
            before = '\n'.join(transport.store.db.iterdump())
            assert request(server, '/challenge', dict(**transport.public(key, 'remote'), purpose='check'))[0] == 400
            for proof in challenges:
                assert request(server, '/prove', proof)[0] == 400
            assert '\n'.join(transport.store.db.iterdump()) == before
    finally:
        api.close()


def test_external_fixture_provisions_and_binds_each_http_worker(tmp_path):
    frontend = tmp_path / 'frontend'
    frontend.mkdir()
    (frontend / 'index.html').write_text('fixture')
    home = tmp_path / 'owner'
    (home / 'vault').mkdir(parents=True)
    server = fresh(build_fixture_server, home, frontend, tmp_path / 'private', fixture_only=True)
    assert server.external.vault == (home / 'vault').resolve()
    assert server.external.state == (home / 'events.jsonl').resolve()
    # Inspect the actual binding at the store boundary, not merely the API fields.
    serialized = server.external.store.serialized
    def inspect_binding(action):
        assert_state_authority(home / 'events.jsonl')
        return serialized(action)
    server.external.store.serialized = inspect_binding
    with serving(server):
        cookie = 'external_fixture=' + server.fixture_session
        def call(path, body=None):
            return request(server, path, body, cookie=cookie)
        status, config = call('/external/config')
        assert status == 200
        status, grant = call('/external/grants', dict(recipient=config['recipients'][0]['id'],
            resources=['workspace:fixture-review'], operations=['read'], provenance='fixture review'))
        assert status == 201
        path = '/external/grants/' + grant['id']
        assert call(path)[1]['state'] == 'active'
        assert call(path + '/revoke', {})[0] == 200
        assert call(path)[1]['state'] == 'revoked'
        (home / 'vault' / '.arvyx-replica').write_text('replica')
        before = '\n'.join(server.external.store.db.iterdump())
        assert call('/external/config')[0] == 400
        assert call('/external/grants', {})[0] == 400
        assert '\n'.join(server.external.store.db.iterdump()) == before


def test_external_fixture_refuses_fenced_vault_before_provisioning(tmp_path):
    home = tmp_path / 'owner'
    (home / 'vault').mkdir(parents=True)
    (home / 'vault' / '.arvyx-replica').write_text('replica')
    with pytest.raises(ReplicaAuthorityUnavailable):
        fresh(build_fixture_server, home, tmp_path / 'frontend', tmp_path / 'private', fixture_only=True)
    assert not (tmp_path / 'private').exists()
