"""Lane E entry-to-effect regressions; disposable authority and native metadata only."""
import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import os
import pytest

from arvyx_control.external_api import ExternalAPI, Principal
from arvyx_control.external_grants import ExternalGrantStore
from arvyx_control.external_presentation import load_presentation
from arvyx_control.replica_authority import authority_context
from test_local_onboarding_services import services

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='host-shell execution policy (host_uid) and the PTY owner are POSIX-only')


@pytest.fixture
def exports(tmp_path):
    vault = tmp_path / 'vault'
    vault.mkdir()
    root = tmp_path / 'selection'
    root.mkdir()
    (root / 'A.txt').write_text('Approved A\n')
    (root / 'B.txt').write_text('Separately approved B\n')
    (root / 'SKILL.md').write_text('Approved skill\n')
    credentials = {hashlib.sha256(token.encode()).hexdigest(): dict(name=name, role=role)
                   for token, name, role in [('issuer-test', 'issuer', 'issuer'),
                       ('recipient-test', 'recipient', 'external'), ('observer-test', 'observer', 'observer'),
                       ('stranger-test', 'stranger', 'observer')]}
    resources = ['workspace:project', 'prompt:request', 'artifact:result', 'skill:review', 'task:A', 'task:B']
    with authority_context(vault):
        store = ExternalGrantStore(tmp_path / 'grants.db')
        store.set_authority('issuer', resources=resources,
            operations=['read', 'lookup', 'list', 'search', 'submit', 'delegate'], can_issue=True, can_export=True)
        store.close()
        credential = tmp_path / 'issuer.txt'
        credential.write_text('issuer-test')
        credential.chmod(0o600)
        config = tmp_path / 'external.json'
        def configure(name):
            def selection(files):
                return dict(root=str(root), reviewed_sha256={f: hashlib.sha256((root / f).read_bytes()).hexdigest() for f in files})
            config.write_text(json.dumps(dict(grants=str(tmp_path / 'grants.db'), work=str(tmp_path / 'work.db'),
                credentials=credentials, issuer_credential=str(credential), workspaces={'project': selection([name])},
                documents={key: selection([name] if key != 'skill:review' else ['SKILL.md',] )
                           for key in ['prompt:request', 'artifact:result', 'skill:review']},
                memory_selections={}, tasks=['A', 'B'], recipients={})))
            config.chmod(0o600)
            return load_presentation(config, vault=vault, state=None)
        yield configure, root, tmp_path, vault


def external_call(presentation, method, path, body=None, token='recipient-test'):
    return presentation.api.dispatch(method, path, 'Bearer ' + token, body or {})


def issue(presentation, resources, operations):
    status, config = presentation.dispatch('GET', '/external/config', {})
    assert status == 200, config
    reviewed = {r['key']: r['manifest'] for r in config['resources'] if r['key'] in resources and 'manifest' in r}
    status, result = presentation.dispatch('POST', '/external/grants', dict(recipient='recipient', resources=resources,
        operations=operations, provenance='explicit fixture review', reviewed_manifests=reviewed))
    assert status == 201, result
    return result['id']


def close(presentation):
    presentation.api.close()
    presentation.api.store.close()


@pytest.mark.parametrize('resource', ['workspace:project', 'prompt:request', 'artifact:result', 'skill:review'])
def test_reloaded_selection_cannot_expand_old_grant(exports, resource):
    configure, root, _, _ = exports
    first = configure('A.txt')
    grant = issue(first, [resource], ['read', 'lookup', 'list', 'search'])
    kind, name = resource.split(':')
    assert external_call(first, 'GET', f'/external/grants/{grant}/resources/{kind}/{name}')[0] == 200
    close(first)
    if kind == 'skill':
        (root / 'SKILL.md').write_text('Newly reviewed skill bytes\n')
    second = configure('B.txt')
    try:
        entry = next(r['manifest']['files'][0] for r in second.dispatch('GET', '/external/config', {})[1]['resources'] if r['key'] == resource)
        calls = [
            ('GET', f'/external/grants/{grant}/resources/{kind}/{name}', {}),
            ('GET', f'/external/grants/{grant}/resources', {}),
            ('POST', f'/external/grants/{grant}/manifest', dict(resource=resource, cursor=None, limit=1)),
            ('POST', f'/external/grants/{grant}/download', dict(resource=resource, path=entry['path'], sha256=entry['sha256'], offset=0, limit=10)),
        ]
        for op, args in [('read', {'resource': resource}), ('lookup', {'resource': resource}), ('list', {}), ('search', {'query': ''})]:
            calls.append(('POST', f'/external/grants/{grant}/mcp', dict(jsonrpc='2.0', id=1, method='tools/call', params=dict(name='external.'+op, arguments=args))))
        for method, path, body in calls:
            status, result = external_call(second, method, path, body)
            assert status == 403, (method, path, status, result)
        fresh = issue(second, [resource], ['read', 'lookup', 'list', 'search'])
        assert external_call(second, 'GET', f'/external/grants/{fresh}/resources/{kind}/{name}')[0] == 200
    finally:
        close(second)


def test_submit_only_observer_scope_and_lifecycle(exports):
    configure, _, _, _ = exports
    p = configure('A.txt')
    p.api.observers = frozenset({'observer'})
    try:
        grant = issue(p, ['task:A'], ['submit'])
        path = f'/external/grants/{grant}/tasks/A/results'
        status, row = external_call(p, 'POST', path, dict(kind='progress', text='Public progress', source='fixture'))
        assert status == 201, row
        assert external_call(p, 'GET', path)[0] == 403
        assert external_call(p, 'GET', path, token='stranger-test')[0] == 403
        status, result = external_call(p, 'GET', path + '?limit=1', token='observer-test')
        assert status == 200, result
        assert [r['id'] for r in result['items']] == [row['id']]
        assert external_call(p, 'GET', path.replace('/tasks/A/', '/tasks/B/'), token='observer-test')[0] == 403
        assert external_call(p, 'POST', path, dict(kind='result', text='Observer cannot submit', source='fixture'), token='observer-test')[0] == 403
        now = p.api.store.clock()
        p.api.store.clock = lambda: now + timedelta(days=2)
        assert external_call(p, 'GET', path, token='observer-test')[0] == 403
        p.api.store.clock = lambda: now
        p.api.store.set_authority('issuer', resources=['task:B'], operations=['submit'], can_issue=True, can_export=True)
        assert external_call(p, 'GET', path, token='observer-test')[0] == 403
        p.api.store.set_authority('issuer', resources=['task:A'], operations=['submit'], can_issue=True, can_export=True)
        assert external_call(p, 'GET', path, token='observer-test')[0] == 200
        p.api.store.revoke(grant, actor='issuer')
        assert external_call(p, 'GET', path, token='observer-test')[0] == 403
    finally:
        close(p)


def raw_onboarding(api, path, body=None):
    return api.dispatch('GET' if body is None else 'POST', '/api/public-onboarding/' + path,
                        'Bearer browser-test', body or {})


@pytest.mark.parametrize('action', ['manual/connect', 'profiles/connect'])
@pytest.mark.parametrize('replacement', ['database', 'directory'])
def test_replacement_after_commit_validation_cannot_publish(services, action, replacement):
    api, _, profile, root = services
    owner = api.owners['local-owner']
    candidate = dict(id='hermes:profile:one', family='hermes', label='Hermes', kind='profile', local_id='one',
        path=str(profile / 'config.yaml'), location='~/.hermes/profiles/one/config.yaml')
    owner.discovery = lambda: dict(candidates=[candidate], truncated=False)
    raw_onboarding(api, 'discover', {})
    body = dict(family='hermes', path=str(profile), agent_id='agent-a', confirmed=True) if action == 'manual/connect' else dict(candidate_id=candidate['id'], agent_id='agent-a', confirmed=True)
    status, prepared = raw_onboarding(api, 'actions/prepare', dict(action=action, request=body))
    assert status == 200, prepared
    route = api._route
    def replace(key, routed_owner, method, path, payload, **kwargs):
        if path == action and kwargs.get('reviewed'):
            if replacement == 'database':
                (profile / 'state.db').rename(profile / 'old.db')
            else:
                profile.rename(root / 'old-profile')
                profile.mkdir(mode=0o700)
            with closing(sqlite3.connect(profile / 'state.db')) as db, db:
                db.executescript('CREATE TABLE sessions(id TEXT,title TEXT,started_at REAL);')
        return route(key, routed_owner, method, path, payload, **kwargs)
    with patch.object(api, '_route', side_effect=replace):
        status, result = raw_onboarding(api, 'actions/commit', dict(consent_id=prepared['consent_id'], consent_sha256=prepared['sha256'], confirmed=True))
    assert status == 503, result
    assert raw_onboarding(api, 'targets')[1]['items'] == []
    assert owner.creation.db.execute('SELECT COUNT(*) FROM onboarding_connections').fetchone()[0] == 0
    assert not owner.extension.sources
    assert raw_onboarding(api, 'actions/commit', dict(consent_id=prepared['consent_id'], consent_sha256=prepared['sha256'], confirmed=True))[0] == 400


def test_unchanged_reload_and_legacy_unbound_grant(exports):
    configure, _, _, _ = exports
    p = configure('A.txt')
    grant = issue(p, ['workspace:project'], ['read'])
    legacy = p.api.store.issue(issuer='issuer', recipient='recipient', resources=['workspace:project'],
        operations=['read'], expires_at=p.api.store.clock()+timedelta(hours=1), provenance='legacy unbound fixture')
    close(p)
    reopened = configure('A.txt')
    try:
        assert external_call(reopened, 'GET', f'/external/grants/{grant}/resources/workspace/project')[0] == 200
        assert external_call(reopened, 'GET', f'/external/grants/{legacy.id}/resources/workspace/project')[0] == 403
    finally:
        close(reopened)


def test_issue_rolls_back_grant_and_manifest_together(exports):
    configure, _, directory, _ = exports
    p = configure('A.txt')
    class Crash(BaseException):
        pass
    try:
        record = p.api.store._record
        def crash(event, *args, **kwargs):
            if event == 'created':
                raise Crash('simulated termination before authority commit')
            return record(event, *args, **kwargs)
        with patch.object(p.api.store, '_record', side_effect=crash), pytest.raises(Crash):
            issue(p, ['workspace:project'], ['read'])
    finally:
        close(p)
    reopened = configure('B.txt')
    try:
        assert reopened.api.store.db.execute('SELECT COUNT(*) FROM external_grants').fetchone()[0] == 0
        assert reopened.api.store.db.execute('SELECT COUNT(*) FROM external_grant_manifests').fetchone()[0] == 0
        fresh = issue(reopened, ['workspace:project'], ['read'])
        assert external_call(reopened, 'GET', f'/external/grants/{fresh}/resources/workspace/project')[0] == 200
    finally:
        close(reopened)


def test_review_snapshot_binds_profile_directory_identity(services):
    api, _, profile, _ = services
    status, prepared = raw_onboarding(api, 'actions/prepare', dict(action='manual/connect', request=dict(
        family='hermes', path=str(profile), agent_id='agent-a', confirmed=True)))
    assert status == 200, prepared
    saved = json.loads(api.owners['local-owner'].creation.db.execute('SELECT snapshot FROM reviewed_actions').fetchone()[0])
    info = profile.stat()
    assert saved['home_identity'] == [info.st_dev, info.st_ino]


def test_delegation_cannot_rebind_or_upgrade_unbound_parent(exports):
    configure, _, _, _ = exports
    p = configure('A.txt')
    store = p.api.store
    try:
        store.set_authority('recipient', resources=['workspace:project'], operations=['read', 'delegate'], can_issue=True, can_export=True)
        parent = store.issue(issuer='issuer', recipient='recipient', resources=['workspace:project'], operations=['read', 'delegate'],
            expires_at=store.clock()+timedelta(hours=1), provenance='legacy parent')
        with pytest.raises(PermissionError):
            store.issue(issuer='recipient', recipient='downstream', resources=['workspace:project'], operations=['read'],
                expires_at=parent.expires_at, provenance='cannot upgrade legacy consent', parent_id=parent.id,
                manifest_bindings={'workspace:project': 'a'*64})
        parent = store.issue(issuer='issuer', recipient='recipient', resources=['workspace:project'], operations=['read', 'delegate'],
            expires_at=store.clock()+timedelta(hours=1), provenance='bound parent', manifest_bindings={'workspace:project': 'a'*64})
        for bindings in [{}, {'workspace:project': 'b'*64}]:
            with pytest.raises(PermissionError):
                store.issue(issuer='recipient', recipient='downstream', resources=['workspace:project'], operations=['read'],
                    expires_at=parent.expires_at, provenance='cannot replace consent', parent_id=parent.id, manifest_bindings=bindings)
        child = store.issue(issuer='recipient', recipient='downstream', resources=['workspace:project'], operations=['read'],
            expires_at=parent.expires_at, provenance='same consent', parent_id=parent.id, manifest_bindings={'workspace:project': 'a'*64})
        assert store.manifest_bindings(child.id) == store.manifest_bindings(parent.id)
        store.revoke(parent.id, actor='issuer')
        assert not store.decide(child.id, principal='downstream', resource='workspace:project', operation='read').allowed
    finally:
        close(p)


def test_issue_cannot_bind_selection_changed_during_review(exports):
    from arvyx_control.external_workspace import snapshot_workspace
    configure, root, _, _ = exports
    p = configure('A.txt')
    try:
        config = p.dispatch('GET', '/external/config', {})[1]
        reviewed = {r['key']: r['manifest'] for r in config['resources'] if r['key'] == 'workspace:project'}
        snapshot = p.api._snapshot
        changed = False
        def swap(resource, **kwargs):
            nonlocal changed
            result = snapshot(resource, **kwargs)
            if resource.kind == 'workspace' and not changed:
                changed = True
                p.api.workspaces['project'] = snapshot_workspace(root, ['B.txt'])
            return result
        with patch.object(p.api, '_snapshot', side_effect=swap):
            status, result = p.dispatch('POST', '/external/grants', dict(recipient='recipient', resources=['workspace:project'],
                operations=['read'], provenance='reviewed A only', reviewed_manifests=reviewed))
        assert changed
        assert status in (201, 400)
        if status == 201:
            assert external_call(p, 'GET', f"/external/grants/{result['id']}/resources/workspace/project")[0] == 403
    finally:
        close(p)


def complete_snapshot_fixture(api, profile, body):
    """Construct the requested shared snapshot contract; not an integrated producer."""
    extension = api.owners['local-owner'].extension
    snapshot = extension.reviewed_actions.snapshot(api, 'local-owner', 'manual/connect', body)
    info = profile.stat()
    return dict(snapshot, identity=list(snapshot['identity']), home_identity=[info.st_dev, info.st_ino])


@pytest.mark.parametrize('action', ['manual/connect', 'profiles/connect'])
def test_complete_snapshot_contract_connects_and_reopens(services, action):
    api, _, profile, root = services
    owner = api.owners['local-owner']
    body = dict(family='hermes', path=str(profile), agent_id='agent-a', confirmed=True)
    snapshot = complete_snapshot_fixture(api, profile, body)
    if action == 'profiles/connect':
        candidate = dict(id='hermes:profile:one', family='hermes', label='Hermes', kind='profile', local_id='one',
            path=str(profile/'config.yaml'), location='~/.hermes/profiles/one/config.yaml')
        owner.discovery = lambda: dict(candidates=[candidate], truncated=False)
        raw_onboarding(api, 'discover', {})
        body = dict(candidate_id=candidate['id'], agent_id='agent-a', confirmed=True)
        snapshot = dict(candidate=candidate, profile=snapshot)
    status, result = api._route('local-owner', owner, 'POST', action, body, reviewed=True, review_snapshot=snapshot)
    assert status == 200, result
    assert raw_onboarding(api, 'targets')[1]['items'] == [result['target']]
    from arvyx_control.local_onboarding import local_composition
    reopened = local_composition(root, vault=owner.extension.vault, machine_id='machine-a', capability='browser-test')
    try:
        assert raw_onboarding(reopened, 'targets')[1]['items'] == [result['target']]
    finally:
        reopened.close()


def test_complete_snapshot_contract_removes_connection_on_final_identity_failure(services):
    from arvyx_control.hermes_history import HermesHistory
    api, _, profile, _ = services
    owner = api.owners['local-owner']
    body = dict(family='hermes', path=str(profile), agent_id='agent-a', confirmed=True)
    snapshot = complete_snapshot_fixture(api, profile, body)
    validate = HermesHistory.validate_review
    changed = False
    def replace_at_publication(adapter):
        nonlocal changed
        if not changed and owner.creation.db.execute('SELECT COUNT(*) FROM onboarding_connections').fetchone()[0]:
            if not owner.creation.db.in_transaction:
                changed = True
                (profile/'state.db').rename(profile/'old.db')
                with closing(sqlite3.connect(profile/'state.db')) as db, db:
                    db.executescript('CREATE TABLE sessions(id TEXT,title TEXT,started_at REAL);')
        return validate(adapter)
    with patch.object(HermesHistory, 'validate_review', replace_at_publication), pytest.raises(ValueError):
        api._route('local-owner', owner, 'POST', 'manual/connect', body, reviewed=True, review_snapshot=snapshot)
    assert changed
    assert owner.creation.db.execute('SELECT COUNT(*) FROM onboarding_connections').fetchone()[0] == 0
    assert raw_onboarding(api, 'targets')[1]['items'] == []
    assert not owner.extension.sources


def test_real_process_exit_before_grant_commit_recovers_without_partial_authority(exports):
    import os
    import subprocess
    import sys
    configure, _, directory, vault = exports
    p = configure('A.txt')
    close(p)
    code = '''import os,sys
from arvyx_control.external_presentation import load_presentation
from arvyx_control.replica_authority import authority_context
with authority_context(sys.argv[2]):
    p=load_presentation(sys.argv[1],vault=sys.argv[2],state=None)
    config=p.dispatch('GET','/external/config',{})[1]
    reviewed={r['key']:r['manifest'] for r in config['resources'] if r['key']=='workspace:project'}
    record=p.api.store._record
    def crash(event,*args,**kwargs):
        if event=='created':os._exit(73)
        return record(event,*args,**kwargs)
    p.api.store._record=crash
    p.dispatch('POST','/external/grants',dict(recipient='recipient',resources=['workspace:project'],operations=['read'],provenance='crash fixture',reviewed_manifests=reviewed))
'''
    result = subprocess.run([sys.executable, '-c', code, str(directory/'external.json'), str(vault)],
                            capture_output=True, timeout=10, env=os.environ.copy())
    assert result.returncode == 73, result.stderr
    recovered = configure('B.txt')
    try:
        assert recovered.dispatch('GET', '/external/grants', {}) == (200, [])
        assert recovered.api.store.db.execute('SELECT COUNT(*) FROM external_grant_manifests').fetchone()[0] == 0
        grant = issue(recovered, ['workspace:project'], ['read'])
        assert external_call(recovered, 'GET', f'/external/grants/{grant}/resources/workspace/project')[0] == 200
    finally:
        close(recovered)


def test_independent_revocation_waits_for_manifest_export(exports):
    import threading
    import arvyx_control.external_api as module
    configure, _, directory, vault = exports
    p = configure('A.txt')
    grant = issue(p, ['workspace:project'], ['read'])
    entered, release, revoked, started = (threading.Event() for _ in range(4))
    outcomes = []
    export = module.export_snapshot
    def blocked(snapshot):
        entered.set()
        assert release.wait(3)
        return export(snapshot)
    def reader():
        with authority_context(vault):
            outcomes.append(external_call(p, 'GET', f'/external/grants/{grant}/resources/workspace/project'))
    def revoker():
        with authority_context(vault):
            store = ExternalGrantStore(directory/'grants.db')
            try:
                started.set()
                store.revoke(grant, actor='issuer')
                revoked.set()
            finally:
                store.close()
    first = threading.Thread(target=reader)
    second = threading.Thread(target=revoker)
    try:
        with patch.object(module, 'export_snapshot', side_effect=blocked):
            first.start()
            assert entered.wait(2)
            second.start()
            assert started.wait(2)
            assert not revoked.wait(.05)
            release.set()
            first.join(3)
            second.join(3)
        assert not first.is_alive() and not second.is_alive()
        assert outcomes[0][0] == 200 and revoked.is_set()
        assert external_call(p, 'GET', f'/external/grants/{grant}/resources/workspace/project')[0] == 403
    finally:
        release.set()
        if first.ident: first.join(3)
        if second.ident: second.join(3)
        close(p)


def test_reopen_rejects_directory_replacement_even_if_database_inode_survives(services):
    from arvyx_control.local_onboarding import local_composition
    api, _, profile, root = services
    owner = api.owners['local-owner']
    body = dict(family='hermes', path=str(profile), agent_id='agent-a', confirmed=True)
    snapshot = complete_snapshot_fixture(api, profile, body)
    assert api._route('local-owner', owner, 'POST', 'manual/connect', body, reviewed=True, review_snapshot=snapshot)[0] == 200
    old = root/'old-profile'
    profile.rename(old)
    profile.mkdir(mode=0o700)
    (old/'state.db').rename(profile/'state.db')
    reopened = local_composition(root, vault=owner.extension.vault, machine_id='machine-a', capability='browser-test')
    try:
        assert raw_onboarding(reopened, 'targets')[1]['items'] == []
        assert not reopened.owners['local-owner'].extension.sources
    finally:
        reopened.close()


@pytest.mark.parametrize('operation', ['preview', 'copy'])
def test_replaced_published_profile_cannot_supply_instructions(services, operation):
    api, _, profile, _ = services
    owner = api.owners['local-owner']
    body = dict(family='hermes', path=str(profile), agent_id='agent-a', confirmed=True)
    snapshot = complete_snapshot_fixture(api, profile, body)
    connected = api._route('local-owner', owner, 'POST', 'manual/connect', body, reviewed=True, review_snapshot=snapshot)[1]
    (profile/'state.db').rename(profile/'old.db')
    with closing(sqlite3.connect(profile/'state.db')) as db, db:
        db.executescript('CREATE TABLE sessions(id TEXT,title TEXT,started_at REAL);')
    if operation == 'preview':
        request = dict(source_id=connected['instruction_source_id'], paths=['SOUL.md'], confirmed=True)
        status, prepared = raw_onboarding(api, 'actions/prepare', dict(action='instructions/preview', request=request))
        assert status == 200, prepared
        status, result = raw_onboarding(api, 'actions/commit', dict(consent_id=prepared['consent_id'], consent_sha256=prepared['sha256'], confirmed=True))
        assert status == 503, result
        assert 'files' not in result
    else:
        digest = hashlib.sha256((profile/'SOUL.md').read_bytes()).hexdigest()
        status, result = raw_onboarding(api, 'agents/prepare', dict(name='Copied agent', harness='hermes', environment='metadata',
            identity_mode='copy', source_id=connected['instruction_source_id'], identity_files=[dict(path='SOUL.md', approved_sha256=digest)]))
        assert (status, result) == (409, dict(error='exact_route_unavailable', queued=False))
        assert owner.creation.db.execute('SELECT COUNT(*) FROM onboarding_consents').fetchone()[0] == 0


def test_fresh_lookup_only_grant_keeps_content_withheld(exports):
    configure, _, _, _ = exports
    p = configure('A.txt')
    try:
        grant = issue(p, ['skill:review'], ['lookup'])
        body = dict(jsonrpc='2.0', id=1, method='tools/call', params=dict(name='external.lookup', arguments=dict(resource='skill:review')))
        status, result = external_call(p, 'POST', f'/external/grants/{grant}/mcp', body)
        assert status == 200, result
        assert all('content_base64' not in entry for entry in json.loads(result['result']['content'][0]['text'])['files'])
        body['params']['name'] = 'external.read'
        assert external_call(p, 'POST', f'/external/grants/{grant}/mcp', body)[0] == 403
    finally:
        close(p)


def test_reviewed_manifest_pages_and_mcp_chunk_recheck_original_grant(exports):
    import base64
    from arvyx_control.external_workspace import snapshot_workspace
    configure, root, _, _ = exports
    p = configure('A.txt')
    try:
        old = issue(p, ['workspace:project'], ['read', 'lookup'])
        names = [f'page-{i:03}.txt' for i in range(105)]
        for name in names:
            (root/name).write_text('Approved page bytes\n')
        p.api.workspaces['project'] = snapshot_workspace(root, names)
        grant = issue(p, ['workspace:project'], ['read', 'lookup'])
        assert external_call(p, 'POST', f'/external/grants/{old}/manifest', dict(resource='workspace:project', cursor=None, limit=17))[0] == 403
        seen = []
        cursor = None
        while True:
            status, result = external_call(p, 'POST', f'/external/grants/{grant}/manifest', dict(resource='workspace:project', cursor=cursor, limit=17))
            assert status == 200, result
            seen.extend(f['path'] for f in result['files'])
            cursor = result['next_cursor']
            if cursor is None:
                break
        assert seen == names
        body = dict(jsonrpc='2.0', id=1, method='tools/call', params=dict(name='external.read', arguments=dict(resource='workspace:project',
            path=names[0], sha256=hashlib.sha256((root/names[0]).read_bytes()).hexdigest(), offset=0, limit=4)))
        status, result = external_call(p, 'POST', f'/external/grants/{grant}/mcp', body)
        assert status == 200, result
        assert base64.b64decode(json.loads(result['result']['content'][0]['text'])['content_base64']) == b'Appr'
        p.api.store.revoke(grant, actor='issuer')
        assert external_call(p, 'POST', f'/external/grants/{grant}/mcp', body)[0] == 403
    finally:
        close(p)


@pytest.mark.skipif(os.name != 'posix', reason='host-shell execution policy (host_uid) and the PTY owner are POSIX-only')
def test_failed_publication_cleanup_preserves_concurrent_new_connection(services):
    from arvyx_control.hermes_history import HermesHistory
    from arvyx_control.local_onboarding import local_composition
    api, _, profile, root = services
    owner = api.owners['local-owner']
    body = dict(family='hermes', path=str(profile), agent_id='agent-a', confirmed=True)
    snapshot = complete_snapshot_fixture(api, profile, body)
    second = local_composition(root, vault=owner.extension.vault, machine_id='machine-a', capability='browser-test')
    second_owner = second.owners['local-owner']
    validate = HermesHistory.validate_review
    published = []
    entered = False
    def supersede(adapter):
        nonlocal entered
        if not entered and not owner.creation.db.in_transaction and owner.creation.db.execute('SELECT COUNT(*) FROM onboarding_connections').fetchone()[0]:
            entered = True
            published.append(second._route('local-owner', second_owner, 'POST', 'manual/connect', body, reviewed=True, review_snapshot=snapshot)[1]['target'])
            raise ValueError('first publication failed after concurrent publication')
        return validate(adapter)
    try:
        with patch.object(HermesHistory, 'validate_review', supersede), pytest.raises(ValueError):
            api._route('local-owner', owner, 'POST', 'manual/connect', body, reviewed=True, review_snapshot=snapshot)
        row = owner.creation.db.execute('SELECT target FROM onboarding_connections').fetchone()
        assert row is not None and json.loads(row[0]) == published[0]
        assert owner.creation.db.execute('SELECT COUNT(*) FROM onboarding_connection_pins').fetchone()[0] == 1
        assert owner.creation.db.execute('SELECT COUNT(*) FROM onboarding_profiles').fetchone()[0] == 1
    finally:
        second.close()


# Integrator: the real leaf consumer must retain the reviewed onboarding pin.
from test_session_workspace_journey import journey

@pytest.fixture
def pinned_leaf(journey, tmp_path):
    import os
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.native_lifecycle import OwnerProducer
    from arvyx_control.local_executor import ExecutionPolicy
    from arvyx_control.local_executor_service import LocalExecutorService
    api, _, target, root, connect = journey
    ext = api.owners['local-owner'].extension
    from arvyx_control.organizer_authority import OrganizerAuthority
    database=tmp_path/'leaf-policy.sqlite'
    with authority_context(ext.vault):
        policy=OrganizerAuthority(database=database)
        actor=policy.provision_identity('organizer',kind='internal',organizer=True)
        worker=policy.provision_identity('agent-a',kind='internal')
        policy.enroll_machine('machine-a');policy.bind_agent(worker,machine='machine-a')
        policy.bind_executor(worker,machine='machine-a',environments=['host'])
    owner = LocalCockpit(tmp_path/'owner', ext.vault, tmp_path/'events.jsonl', 'machine-a',
        execution_policy=ExecutionPolicy(host_uid=os.geteuid(), allow_host=True),delegation_authority_database=database)
    producer = OwnerProducer(owner, policy=owner.execution_policy)
    args = dict(credential='x'*48, producer=producer, target=target, session='leaf', workspace=root/'existing',
        environments=['host'], identity_store=Path(ext.owner.creation.db.execute('PRAGMA database_list').fetchone()[2]),authority_database=database)
    leaf = LocalExecutorService(tmp_path/'leaf.db', **args)
    leaf.fixture_policy,leaf.fixture_actor,leaf.fixture_worker=policy,actor,worker
    yield leaf, args, ext, Path(connect['path']), tmp_path/'leaf.db'
    leaf.close(); owner.close();policy.close()


def leaf_request(leaf,identifier='a'*32):
    from delegation_fixture_helpers import issue
    with authority_context(leaf.vault,leaf.state):
        return issue(leaf.fixture_policy,leaf.fixture_actor,leaf.fixture_worker,dict(machine='machine-a',executing_agent='agent-a',session='leaf',operation='invoke_host',environment='host',goal='new-local-shell'),attempt=identifier,receiving_leaf=leaf.receiving_leaf)


def leaf_call(leaf, body=None):
    return leaf.dispatch('POST' if body else 'GET', '/api/public-onboarding/executor/execute' if body else
        '/api/public-onboarding/capabilities', 'Bearer '+'x'*48, body or {})


@pytest.mark.parametrize('boundary', ['authority', 'effect', 'reopen'])
def test_leaf_rejects_replaced_directory_with_original_database_inode(pinned_leaf, boundary):
    from arvyx_control.local_executor_service import LocalExecutorService
    leaf, args, ext, profile, db = pinned_leaf
    def replace():
        moved=profile.with_name('original-profile');profile.rename(moved);profile.mkdir(mode=0o700)
        (moved/'state.db').rename(profile/'state.db')
    if boundary == 'effect':
        plan=leaf.producer.plan
        def race(*a, **kw):
            result=plan(*a, **kw);replace();return result
        with patch.object(leaf.producer, 'plan', side_effect=race), patch.object(leaf.producer, 'create') as effect:
            assert leaf_call(leaf, leaf_request(leaf))[0] in (403,503)
            effect.assert_not_called()
        assert leaf.db.execute('SELECT status FROM executor_attempts').fetchone()[0]=='ambiguous'
    else:
        replace()
        if boundary == 'reopen':
            with pytest.raises((PermissionError, ValueError)):
                LocalExecutorService(db, **args)
        else:
            assert leaf_call(leaf)[0]==403


@pytest.mark.parametrize('mutation', ['missing', 'target', 'malformed', 'legacy-table'])
def test_leaf_requires_exact_durable_pin_and_explicit_legacy_review(pinned_leaf, mutation):
    leaf, args, ext, profile, db = pinned_leaf
    conn=ext.owner.creation.db
    if mutation=='missing':conn.execute('DELETE FROM onboarding_connection_pins')
    elif mutation=='target':conn.execute("UPDATE onboarding_connection_pins SET target='{}'")
    elif mutation=='malformed':conn.execute("UPDATE onboarding_connection_pins SET snapshot='{}'")
    else:conn.execute('DROP TABLE onboarding_connection_pins')
    conn.commit()
    with patch.object(leaf.producer, 'create') as effect:
        assert leaf_call(leaf, leaf_request(leaf))[0]==403
        effect.assert_not_called()
    from arvyx_control.local_executor_service import LocalExecutorService
    with pytest.raises((PermissionError, ValueError)):
        LocalExecutorService(db, **args)


def test_leaf_unchanged_pin_reopens_and_never_rebinds_lease(pinned_leaf):
    from arvyx_control.local_executor_service import LocalExecutorService
    leaf, args, ext, profile, db = pinned_leaf
    assert leaf_call(leaf)[0]==200
    reopened=LocalExecutorService(db, **args)
    try:assert leaf_call(reopened)[0]==200
    finally:reopened.close()
    snapshot=json.loads(ext.owner.creation.db.execute('SELECT snapshot FROM onboarding_connection_pins').fetchone()[0])
    snapshot['home_identity']=[0,0]
    ext.owner.creation.db.execute('UPDATE onboarding_connection_pins SET snapshot=?',(json.dumps(snapshot),));ext.owner.creation.db.commit()
    assert leaf_call(leaf)[0]==403
