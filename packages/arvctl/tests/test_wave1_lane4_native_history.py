"""Wave 1 lane 4: native chooser history, attachment fence and sandbox mount source.

Every test drives the production path. Only true external boundaries are
substituted: the clock, process creation (pty.fork / subprocess) and the native
binary trust anchor where a synthetic artifact must reach the capability check.
No real operator owner, profile, native binary or provider is touched.
"""
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from test_local_onboarding_services import services  # noqa: F401  (fixture)


# --------------------------------------------------------------------------
# REV-0020 / REV-0026 / REV-0066 / REV-0080: shared per-agent history consumed by
# the native onboarding-v1 chooser (frontends/arvyx/amc_session_rpc.rs Model).
# --------------------------------------------------------------------------

SEGMENTS = 1300


def _sid(i):
    # Opaque IDs whose lexical order is unrelated to activity or insertion order.
    return 'seg-' + hashlib.sha256(str(i).encode()).hexdigest()[:12]


def _rust_accept(response, exact, *, recent):
    """Python mirror of Model::accept in frontends/arvyx/amc_session_rpc.rs."""
    items = response['items']
    assert len(items) <= (5 if recent else 20), 'Metadata page exceeds requested limit'
    seen = set()
    for row in items:
        sid = row['route']['session_id']
        assert isinstance(sid, str) and sid
        assert row['route']['target'] == exact, 'Metadata destination mismatch; reload'
        assert sid not in seen
        seen.add(sid)
        assert isinstance(row['title'], str)
    nxt = response.get('next_cursor')
    if nxt is not None:
        assert isinstance(nxt, str) and 0 < len(nxt) <= 1024
    total = len(items) if recent else response['total']
    assert type(total) is int and total >= len(items)
    if nxt is not None:
        assert items and total > len(items), 'Inconsistent metadata page total or continuation'
    return items, total, nxt


@pytest.fixture
def connected_history(services):  # noqa: F811
    api, call, profile, root = services
    # Rebuild the synthetic profile's metadata in place (same state.db inode as the
    # fixture) with a Hermes-like schema: archived, hidden, child and ended rows,
    # out-of-ID-order activity and a transcript body that must never be exposed.
    with sqlite3.connect(profile / 'state.db') as db:
        db.executescript('''DROP TABLE sessions; DROP TABLE messages;
            CREATE TABLE sessions(id TEXT PRIMARY KEY,title TEXT,started_at REAL,ended_at REAL,
                end_reason TEXT,cwd TEXT,parent_session_id TEXT,archived INTEGER,hidden INTEGER);
            CREATE TABLE messages(id INTEGER PRIMARY KEY,session_id TEXT,timestamp REAL,content TEXT);''')
        db.executemany('INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?)', [
            (_sid(i), f'Segment {i}', float(i), None, None, str(profile),
             _sid(i - 1) if i % 97 == 0 else None, int(i % 11 == 0), int(i % 13 == 0))
            for i in range(SEGMENTS)])
        # Old, otherwise low-ranked segments that are the most recently active.
        db.execute("INSERT INTO messages(session_id,timestamp,content) VALUES(?,?,?)",
                   (_sid(3), 10_000.0, 'SYNTHETIC TRANSCRIPT BODY'))
        db.execute('UPDATE sessions SET ended_at=9000 WHERE id=?', (_sid(770),))  # archived row
        db.execute('UPDATE sessions SET ended_at=8000 WHERE id=?', (_sid(1067),))  # child + archived
    body = dict(family='hermes', path=str(profile), agent_id='agent-a', confirmed=True)
    status, result = call('manual/connect', body)
    assert status == 200, result
    return api, call, profile, result['target']


def test_native_last5_is_activity_ordered_persisted_history_not_running_bindings(connected_history):
    api, call, profile, target = connected_history
    status, response = call('sessions/recent', {'target': target})  # exact Rust body
    assert status == 200, response
    items, _, _ = _rust_accept(response, target, recent=True)
    expected = [_sid(3), _sid(770), _sid(1067), _sid(SEGMENTS - 1), _sid(SEGMENTS - 2)]
    assert [x['route']['session_id'] for x in items] == expected
    assert [x['route']['session_id'] for x in items] != sorted(expected)  # not ID order
    assert all(x['updated_at'] > 0 for x in items)  # real activity, not zero timestamps
    # Nothing is running: there is no owner, pane or binding in this composition.
    assert 'SYNTHETIC TRANSCRIPT BODY' not in json.dumps(response)
    # Refresh: new activity on a stopped, old segment is reflected on the next call.
    with sqlite3.connect(profile / 'state.db') as db:
        db.execute("INSERT INTO messages(session_id,timestamp,content) VALUES(?,?,'x')", (_sid(5), 20_000.0))
    refreshed = call('sessions/recent', {'target': target})[1]['items']
    assert refreshed[0]['route']['session_id'] == _sid(5)
    assert [x['route']['session_id'] for x in refreshed[1:]] == expected[:4]


def test_native_all_enumerates_every_persisted_segment_through_final_cursor(connected_history):
    api, call, profile, target = connected_history
    cursor, seen, pages = None, [], 0
    while True:
        # Exact Model::page body, including the explicit null cursor on page one.
        status, response = call('sessions/all', {'target': target, 'query': '', 'limit': 20, 'cursor': cursor})
        assert status == 200, response
        items, total, cursor = _rust_accept(response, target, recent=False)
        assert total == SEGMENTS
        seen.extend(x['route']['session_id'] for x in items)
        pages += 1
        if cursor is None:
            break
    assert pages == -(-SEGMENTS // 20)
    assert len(seen) == len(set(seen)) == SEGMENTS
    assert set(seen) == {_sid(i) for i in range(SEGMENTS)}  # archived/hidden/child included
    assert seen[:3] == [_sid(3), _sid(770), _sid(1067)]  # same activity order as Last 5
    # Metadata-only search through the same operation the native client uses.
    status, response = call('sessions/all', {'target': target, 'query': 'segment 1067', 'limit': 20, 'cursor': None})
    items, total, nxt = _rust_accept(response, target, recent=False)
    assert total == 1 and nxt is None and items[0]['route']['session_id'] == _sid(1067)
    status, response = call('sessions/all', {'target': target, 'query': 'TRANSCRIPT', 'limit': 20, 'cursor': None})
    assert status == 200 and response['total'] == 0


def test_native_all_cursor_expiry_and_cross_query_reuse_are_refused(connected_history):
    api, call, profile, target = connected_history
    sessions = api.owners['local-owner'].sessions
    now = [1000.0]
    sessions._clock = lambda: now[0]  # clock is the only substituted boundary
    first = call('sessions/all', {'target': target, 'query': '', 'limit': 20, 'cursor': None})[1]
    cursor = first['next_cursor']
    assert call('sessions/all', {'target': target, 'query': 'Segment', 'limit': 20, 'cursor': cursor})[0] != 200
    assert call('sessions/all', {'target': target, 'query': '', 'limit': 20, 'cursor': cursor})[0] == 200
    now[0] += 121
    status, response = call('sessions/all', {'target': target, 'query': '', 'limit': 20, 'cursor': cursor})
    assert status != 200 and 'items' not in response


def test_native_shared_chooser_requires_onboarding_v1_and_admitted_artifact_refuses(tmp_path):
    """The legacy mouse-only digest lacks onboarding-v1; the shared chooser fails closed on it.

    Only the separately admitted onboarding-v1 digest opens the shared chooser.
    """
    from arvyx_control import native_artifact_policy as policy
    from arvyx_control.terminal_sessions import ExistingArvyxAdapter
    from arvyx_control.agent_sessions import RoutingError
    data = b'synthetic native artifact bytes for capability check'
    binary = tmp_path / 'native'
    binary.write_bytes(data)
    binary.chmod(0o700)
    digest = hashlib.sha256(data).hexdigest()
    (tmp_path / 'bindings.json').write_text(json.dumps(dict(
        authority_home=str(tmp_path), binary_sha256=digest, bindings=[])))
    adapter = ExistingArvyxAdapter(tmp_path, tmp_path, binary, request_fn=lambda *a, **k: [])
    assert policy.native_platform_policy()['capabilities'] == ['mouse-existing', 'onboarding-v1']
    assert policy.admitted_capabilities(policy.NATIVE_MOUSE_BINARY_SHA256) == ['mouse-existing']
    assert policy.admitted_capabilities(policy.NATIVE_ONBOARDING_BINARY_SHA256) == ['mouse-existing', 'onboarding-v1']
    assert policy.admitted_capabilities(digest) == []
    # Substitute only the trust anchor so the synthetic bytes reach the real
    # capability decision inside the real sealed VerifiedNative.
    with patch.object(policy, 'NATIVE_MOUSE_BINARY_SHA256', digest), \
            patch('sys.stdin.isatty', return_value=True), patch('sys.stdout.isatty', return_value=True), \
            patch('subprocess.call') as process:
        with pytest.raises(RoutingError, match='lacks the requested capability'):
            adapter.open_ui(onboarding=dict(origin='http://127.0.0.1:4555', capability='fixture-capability'))
        process.assert_not_called()
        # Positive control: the admitted capability itself is accepted.
        with policy.VerifiedNative(binary, adapter.binding, required_capability='mouse-existing') as native:
            assert native.digest == digest
    # The onboarding-v1 digest, and only it, opens the shared chooser.
    with patch.object(policy, 'NATIVE_ONBOARDING_BINARY_SHA256', digest), \
            patch('sys.stdin.isatty', return_value=True), patch('sys.stdout.isatty', return_value=True), \
            patch('subprocess.call', return_value=0) as process:
        adapter.open_ui(onboarding=dict(origin='http://127.0.0.1:4555', capability='fixture-capability'))
        process.assert_called_once()
        env = process.call_args.kwargs['env']
        assert json.loads(env['AMC_ONBOARDING_RPC']) == dict(origin='http://127.0.0.1:4555', capability='fixture-capability')


# --------------------------------------------------------------------------
# REV-0226: an absent exact owner blocks the trial; nothing is started.
# --------------------------------------------------------------------------

def test_existing_owner_trial_with_absent_owner_refuses_without_starting_anything(tmp_path):
    from arvyx_control.terminal_sessions import ExistingArvyxAdapter
    owner = tmp_path / 'owner'
    (owner / 'runtime').mkdir(parents=True)
    frontend = tmp_path / 'frontend'
    frontend.mkdir()
    (frontend / 'bindings.json').write_text(json.dumps(dict(
        authority_home=str(owner), binary_sha256='0' * 64, bindings=[dict(sid='s', pane='p')])))
    before = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob('*'))
    adapter = ExistingArvyxAdapter(owner, frontend, tmp_path / 'never-executed')
    with patch('subprocess.call') as call, patch('subprocess.Popen') as popen, \
            patch('subprocess.check_output') as output:
        with pytest.raises(OSError):
            adapter.metadata(adapter.target)
        with pytest.raises(OSError):
            adapter.open_ui()
        call.assert_not_called(); popen.assert_not_called(); output.assert_not_called()
    assert sorted(p.relative_to(tmp_path) for p in tmp_path.rglob('*')) == before  # no socket/owner created


# --------------------------------------------------------------------------
# REV-0538: the sandbox mount source is the pinned directory descriptor.
# --------------------------------------------------------------------------

@pytest.fixture
def sandbox_owner(tmp_path):
    from arvyx_control import cockpit_client, control
    from arvyx_control.cockpit import LocalCockpit
    from arvyx_control.replica_authority import authority_context
    root = tmp_path / 'pilot'
    cockpit_client.initialize(root)
    owner = LocalCockpit(root / 'runtime', root / 'vault', root / 'events.jsonl', 'fixture-host')
    with authority_context(owner.vault, owner.state):
        task = control.create_task(owner.state, 'synthetic', owner='demobot').task
    sid = owner.open(project='demo-agent', task=task.id, name='synthetic', actor='operator')['id']
    launcher = tmp_path / 'launcher'
    launcher.write_bytes(b'synthetic launcher bytes; never executed')
    launcher.chmod(0o700)
    yield owner, sid, launcher
    owner.close()


def test_rev0538_ordinary_launcher_sandbox_refuses_before_any_effect(sandbox_owner):
    from arvyx_control.local_executor import ExecutionPolicy
    owner, sid, launcher = sandbox_owner
    owner.execution_policy = ExecutionPolicy(host_uid=os.geteuid(), sandbox_launcher=launcher)
    with patch('pty.fork') as fork, patch.object(owner, '_start', wraps=owner._start) as start:
        with pytest.raises(PermissionError, match='pathname workspace binds refused'):
            owner.start(sid, actor='operator', environment='sandbox')
        fork.assert_not_called(); start.assert_not_called()
    assert owner._get(sid)['status'] == 'stopped'


def test_rev0538_replacement_after_final_admission_keeps_pinned_mount_source(sandbox_owner, tmp_path):
    from arvyx_control.local_executor import ExecutionPolicy
    owner, sid, launcher = sandbox_owner
    owner.execution_policy = ExecutionPolicy(host_uid=os.geteuid(), sandbox_launcher=launcher,
                                             sandbox_fd_protocol='arvyx-directory-fd-v1')
    workspace = Path(owner._get(sid)['workspace'])
    original = os.stat(workspace)
    captured = {}
    real_start = owner._start

    def record(*args, **kwargs):
        captured.update(kwargs)
        return real_start(*args, **kwargs)

    def fork_after_replacement():
        # Final owner admission has already run inside _start_locked. Replace the
        # workspace pathname now, before any launcher could resolve a mount source.
        workspace.rename(tmp_path / 'moved-original')
        workspace.mkdir()
        replacement = os.stat(workspace)
        argv = list(captured['argv'])
        source = argv[argv.index('--bind-fd') + 1]
        info = os.fstat(int(source))
        captured['observed'] = (info.st_dev, info.st_ino)
        captured['replacement'] = (replacement.st_dev, replacement.st_ino)
        captured['inherited'] = captured['inherited_fds']
        captured['pathname_args'] = [a for a in argv if str(workspace) in a]
        raise OSError('synthetic fork boundary: no child created')

    with patch.object(owner, '_start', side_effect=record), patch('pty.fork', side_effect=fork_after_replacement):
        with pytest.raises(OSError, match='synthetic fork boundary'):
            owner.start(sid, actor='operator', environment='sandbox')
    assert captured['observed'] == (original.st_dev, original.st_ino)
    assert captured['observed'] != captured['replacement']
    assert captured['pathname_args'] == []  # no pathname --bind source at all
    argv = captured['argv']
    assert argv[argv.index('--bind-fd') + 2] == '/workspace'
    assert captured['inherited'] == (int(argv[argv.index('--bind-fd') + 1]),)
    assert argv[0].startswith('/proc/self/fd/')  # sealed launcher snapshot, not the path
    assert owner._get(sid)['status'] == 'stopped'


# --------------------------------------------------------------------------
# REV-0103: metadata selection never attaches; the separate consent-bound
# native/present operation maps the exact conversation to the exact running owner
# session, focuses its exact pane and fails closed without a mapping.
# --------------------------------------------------------------------------

from test_completion_fix4_C import native_owner  # noqa: E402,F401  (fixture)
from test_session_workspace_journey import journey  # noqa: E402,F401  (fixture)


def _presentation_fixture(owner, ext, connect, tmp_path):
    from arvyx_control.cockpit_native_runtime import NativeRuntime
    from arvyx_control.native_presentation import NativePresentation
    exe = tmp_path / 'hermes-not-executed'
    exe.write_bytes(b'synthetic executable; never executed')
    exe.chmod(0o700)
    owner.native_runtimes['hermes'] = NativeRuntime(tool='hermes', executable=exe, home=connect['path'],
                                                    store=Path(connect['path']) / 'state.db')
    workspace = None
    with sqlite3.connect(Path(connect['path']) / 'state.db') as db:
        workspace = db.execute("SELECT cwd FROM sessions WHERE id='1204'").fetchone()[0]
    sid = 'exact-owner-session'
    owner.db.execute("INSERT INTO sessions VALUES(?,NULL,NULL,'exact',?,'running',NULL,'local')", (sid, workspace))
    owner.db.execute("INSERT INTO native_bindings VALUES(?,'hermes','1204')", (sid,))
    owner.db.execute('INSERT INTO native_organizers VALUES(?,?)', ('agent-a', sid))
    owner.db.commit()
    owner.live[sid] = dict(fd=1, attached=False, process_generation='synthetic-generation')
    frontend = tmp_path / 'frontend'
    frontend.mkdir()
    binary = tmp_path / 'native-not-executed'
    binary.write_bytes(b'synthetic native bytes; never executed')
    binary.chmod(0o700)
    (frontend / 'bindings.json').write_text(json.dumps(dict(
        authority_home=str(owner.root), binary_sha256='f' * 64, bindings=[dict(sid=sid, pane='w_1-1')])))
    ext.native.frontend = NativePresentation(owner.root, frontend, binary, ext.owner.creation.db)
    state = dict(panes=[dict(pane_id='w_1-1', workspace_id='w_1', tab_id='w_1:1', focused=False),
                        dict(pane_id='w_2-1', workspace_id='w_2', tab_id='w_2:1', focused=True)], calls=[])

    class RecordedNative:
        """Native binary process boundary only; the capability request is asserted."""
        digest = 'f' * 64

        def __init__(self, *args, **kwargs):
            assert kwargs['required_capability'] == 'onboarding-v1'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def invoke(self, operation, args, **kwargs):
            state['calls'].append(list(args))
            command = args[2:]
            result = dict(snapshot=dict(panes=state['panes'])) if command == ['api', 'snapshot'] else {}
            return json.dumps(dict(result=result)).encode()

    def focus(_frontend, pane):
        for row in state['panes']:
            row['focused'] = row['pane_id'] == pane
    return sid, state, RecordedNative, focus


def test_rev0103_metadata_select_is_inert_and_present_attaches_exact_running_conversation(native_owner, tmp_path):
    owner, producer, ext, call, target, root, connect = native_owner
    sid, state, RecordedNative, focus = _presentation_fixture(owner, ext, connect, tmp_path)
    route = dict(target=target, session_id='1204')
    with patch('arvyx_control.native_presentation.VerifiedNative', RecordedNative), \
            patch('arvyx_control.native_presentation._focus_pane', side_effect=focus):
        # 1. Exact metadata selection: no native invocation, no attachment.
        status, selected = call('sessions/select', dict(route=route, confirmed=True))
        assert status == 200, selected
        assert state['calls'] == [] and owner.live[sid]['attached'] is False
        # 2. No owner mapping for a persisted but not running conversation: fail closed.
        status, refused = call('native/present', dict(target=target, session_id='1203', confirmed=True))
        assert (status, refused) == (403, {'error': 'destination_not_authorized'}) and state['calls'] == []
        # 3. Separate reviewed presentation of the exact mapped conversation.
        status, result = call('native/present', dict(target=target, session_id='1204', confirmed=True))
        assert status == 200, result
    assert result['owner_session'] == sid and result['conversation'] == '1204'
    assert result['owner_incarnation'] == owner.incarnation
    assert result['process_generation'] == 'synthetic-generation'
    assert result['pane_id'] == 'w_1-1' and result['native_focus_observed'] is True
    assert [p['pane_id'] for p in state['panes'] if p['focused']] == ['w_1-1']
    assert not [c for c in state['calls'] if c[2:4] in (['workspace', 'create'], ['pane', 'run'])]
    assert [tuple(r) for r in owner.db.execute('SELECT session,pane FROM native_frontend_panes')] == [(sid, 'w_1-1')]


def test_rev0103_stale_process_generation_or_admitted_artifact_refuses_presentation(native_owner, tmp_path):
    owner, producer, ext, call, target, root, connect = native_owner
    sid, state, RecordedNative, focus = _presentation_fixture(owner, ext, connect, tmp_path)
    # Real VerifiedNative: synthetic bytes are not the admitted artifact, and the
    # admitted artifact lacks onboarding-v1; review itself fails closed.
    status, refused = call('native/present', dict(target=target, session_id='1204', confirmed=True))
    assert (status, refused['error']) == (409, 'exact_route_unavailable') and state['calls'] == []
    with patch('arvyx_control.native_presentation.VerifiedNative', RecordedNative), \
            patch('arvyx_control.native_presentation._focus_pane', side_effect=focus):
        status, review = call('actions/prepare', dict(action='native/present', request=dict(
            target=target, session_id='1204', confirmed=True)))
        assert status == 200, review
        owner.live[sid]['process_generation'] = 'replacement-generation'  # restarted process
        status, refused = call('actions/commit', dict(consent_id=review['consent_id'],
                                                      consent_sha256=review['sha256'], confirmed=True))
        assert status == 400  # re-resolved owner proof differs from the reviewed one
    assert not [c for c in state['calls'] if c[2:4] in (['workspace', 'focus'], ['tab', 'focus'])]
    assert owner.db.execute('SELECT count(*) FROM native_frontend_panes').fetchone()[0] == 0


def test_rev0103_browser_attach_grants_exact_owner_lease_only_for_mapped_conversation(native_owner, tmp_path):
    """PublicOnboarding.tsx 'Attach existing native session' -> native/attach; no native binary."""
    owner, producer, ext, call, target, root, connect = native_owner
    sid, state, RecordedNative, focus = _presentation_fixture(owner, ext, connect, tmp_path)
    status, refused = call('native/attach', dict(target=target, session_id='1203', confirmed=True))
    assert (status, refused) == (403, {'error': 'destination_not_authorized'})
    assert owner.live[sid]['attached'] is False
    status, result = call('native/attach', dict(target=target, session_id='1204', confirmed=True))
    assert status == 200, result
    assert result['owner_session'] == sid and result['conversation'] == '1204'
    assert owner.live[sid]['attached'] == result['attachment']['attachment']
    assert state['calls'] == []
