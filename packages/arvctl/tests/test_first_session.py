"""Bounded first-session entry; fixture checks are not native acceptance."""
import hashlib
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux" or os.geteuid() == 0, reason="Linux unprivileged isolated setup protocol")


def test_no_tty_no_policy_or_publication(tmp_path):
    from arvyx_control.first_session import first_session
    destination = tmp_path / 'fresh'
    policy = Mock()
    with patch('os.isatty', return_value=False):
        with pytest.raises(ValueError, match='interactive terminal'):
            first_session(destination, python=Path('/usr/bin/python3'), source=tmp_path,
                          python_sha256='0'*64, binary=tmp_path/'arvyx', policy=policy,
                          environment='host', confirmed=True)
    policy.plan.assert_not_called()
    assert not destination.exists()


def test_consent_before_side_effects(tmp_path):
    from arvyx_control.first_session import first_session
    destination = tmp_path / 'fresh'
    with patch('os.isatty', return_value=True):
        with pytest.raises(PermissionError, match='confirmation'):
            first_session(destination, python=Path('/usr/bin/python3'), source=tmp_path,
                          python_sha256='0'*64, binary=tmp_path/'arvyx', policy=Mock(),
                          environment='host', confirmed=False)
    assert not destination.exists()


def test_python_seal_survives_path_replacement(tmp_path, monkeypatch):
    # Fixture location can have writable test-runner ancestors; this unit tests
    # sealing, not ancestry admission. Real acceptance uses protected paths.
    monkeypatch.setattr('arvyx_control.first_session.read_native_bytes', lambda p: Path(p).read_bytes())
    from arvyx_control.first_session import VerifiedPython
    import subprocess
    executable = tmp_path/'python'
    executable.write_bytes(Path('/usr/bin/python3').resolve().read_bytes())
    executable.chmod(0o700)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    with VerifiedPython(executable, digest) as admitted:
        executable.write_bytes(b'changed')
        result = subprocess.check_output([admitted.path, '-I', '-c', 'print(123)'], pass_fds=(admitted.fd,))
        assert result.strip() == b'123'
        assert admitted.digest == digest


def test_digest_mismatch_refuses(tmp_path):
    from arvyx_control.first_session import VerifiedPython
    with pytest.raises(ValueError, match='digest'):
        VerifiedPython(Path('/usr/bin/python3').resolve(), '0'*64)


def test_minimal_environment_drops_identity_and_provider_overrides(monkeypatch):
    from arvyx_control.first_session import setup_environment
    monkeypatch.setenv('OPENAI_API_KEY', 'synthetic-not-a-credential')
    monkeypatch.setenv('HERMES_HOME', '/unrelated-profile')
    env = setup_environment('/isolated')
    assert env['HOME'] == env['HERMES_HOME'] == '/isolated'
    assert env['HERMES_GUEST_ONBOARDING'] == '0'
    assert 'OPENAI_API_KEY' not in env and 'PYTHONPATH' not in env


@pytest.fixture
def short_fixture(tmp_path, monkeypatch):
    """Fixture ancestry only: never label this mocked admission native evidence."""
    import tempfile
    from arvyx_control import first_session as module
    # Reproduce the hosted runner's long, owner-only TMPDIR on every run.
    private_tmp = tmp_path / 'arvyx-private-tmp-with-a-long-ci-prefix'
    private_tmp.mkdir(mode=0o700)
    monkeypatch.setenv('TMPDIR', str(private_tmp))
    # Socket fixtures need a separate explicit short base, not the runner's
    # potentially unbounded TMPDIR. mkdtemp creates only our owner-only tree;
    # never chmod a shared ancestor. Local operators can keep it in scratch.
    base = Path(os.environ.get('ARVYX_TEST_SOCKET_TMPDIR', Path.home()))
    with tempfile.TemporaryDirectory(prefix='fs-', dir=base) as directory:
        root = Path(directory)
        assert root.stat().st_mode & 0o777 == 0o700
        assert len(os.fsencode(root/'existing/frontend/.config/herdr/sessions/amc/herdr.sock')) < 104, (
            'Set ARVYX_TEST_SOCKET_TMPDIR to an existing short private test base')
        monkeypatch.setattr(module, 'open_native_directory', lambda p: os.open(p, os.O_DIRECTORY | os.O_NOFOLLOW))
        monkeypatch.setattr(module.os, 'isatty', lambda fd: True)
        monkeypatch.setattr(module, 'terminal_preflight', lambda: None)
        source = root/'source'
        source.mkdir(mode=0o700)
        (source/'hermes_cli').mkdir()
        (source/'hermes_cli/main.py').touch()
        (source/'hermes_state_registry.py').touch()
        yield root, source


def test_short_fixture_preserves_real_socket_budget_under_long_private_tmpdir(short_fixture):
    import socket
    from arvyx_control.first_session import first_session
    root, source = short_fixture
    long_root = Path(os.environ['TMPDIR']) / 'fresh'
    suffix = 'frontend/.config/herdr/sessions/amc/herdr.sock'
    assert len(os.fsencode(long_root / suffix)) >= 104
    assert Path(os.environ['TMPDIR']).stat().st_mode & 0o777 == 0o700
    # The production preflight must still reject a real over-budget root.
    with pytest.raises(ValueError, match='too long for private native sockets'):
        first_session(long_root, **fixture_arguments(root, source))
    assert not long_root.exists()
    assert root.stat().st_mode & 0o777 == 0o700
    assert not root.is_symlink()
    endpoint = root / 'fresh' / suffix
    assert len(os.fsencode(endpoint)) < 104
    endpoint.parent.mkdir(parents=True, mode=0o700)
    # Exercise AF_UNIX itself, not only a length assertion or a mocked bind.
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(endpoint))
        server.listen(1)
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(str(endpoint))
            peer, _ = server.accept()
            with peer:
                client.sendall(b'private-fixture')
                assert peer.recv(32) == b'private-fixture'
    endpoint.unlink()


def fixture_arguments(root, source):
    from arvyx_control.local_executor import ExecutionPolicy
    return dict(python=Path('/usr/bin/python3').resolve(), source=source,
                python_sha256=hashlib.sha256(Path('/usr/bin/python3').resolve().read_bytes()).hexdigest(),
                binary=root/'unapproved', policy=ExecutionPolicy(host_uid=os.geteuid(), allow_host=True),
                environment='host', confirmed=True)


@pytest.mark.parametrize('timeout', [False, True])
def test_failed_native_init_retains_root_without_placeholder_database(short_fixture, monkeypatch, timeout):
    import subprocess
    from arvyx_control.first_session import first_session
    root, source = short_fixture
    arguments = fixture_arguments(root, source)
    admitted = Mock()
    admitted.__enter__ = Mock(return_value=admitted)
    admitted.__exit__ = Mock(return_value=False)
    monkeypatch.setattr('arvyx_control.native_artifact_policy.VerifiedNative', lambda *a, **k: admitted)
    error = subprocess.TimeoutExpired('fixture', 30) if timeout else subprocess.CalledProcessError(1, 'fixture')
    native = Mock(side_effect=error)
    monkeypatch.setattr(subprocess, 'run', native)
    with pytest.raises(ValueError, match='native initialization failed; state retained'):
        first_session(root/'fresh', **arguments)
    assert (root/'fresh/profile').is_dir() and (root/'fresh/workspace').is_dir()
    assert not (root/'fresh/profile/state.db').exists()
    assert not (root/'fresh/owner').exists()
    assert native.call_count == 1
    argv = native.call_args.args[0]
    assert argv[0].startswith('/proc/self/fd/') and argv[-1] == 'init'
    assert native.call_args.kwargs['stdin'] == subprocess.DEVNULL
    assert native.call_args.kwargs['env']['HERMES_GUEST_ONBOARDING'] == '0'


@pytest.mark.parametrize('failure', ['expiry', 'policy', 'ancestry'])
def test_final_init_dispatch_guard_after_publication(short_fixture, monkeypatch, failure):
    from arvyx_control import first_session as module
    root, source = short_fixture
    arguments = fixture_arguments(root, source)
    admitted = Mock()
    admitted.__enter__ = Mock(return_value=admitted)
    admitted.__exit__ = Mock(return_value=False)
    monkeypatch.setattr('arvyx_control.native_artifact_policy.VerifiedNative', lambda *a, **k: admitted)
    original = module.PinnedDirectory.mkdir
    def mkdir(parent, name):
        child = original(parent, name)
        if name == 'workspace':
            if failure == 'expiry':
                monkeypatch.setattr(module.time, 'time', lambda: 10**12)
            elif failure == 'policy':
                arguments['policy'].allow_host = False
            else:
                (root/'fresh/profile').rename(root/'fresh/retained-profile')
                (root/'fresh/profile').mkdir()
        return child
    monkeypatch.setattr(module.PinnedDirectory, 'mkdir', mkdir)
    dispatch = Mock(side_effect=AssertionError('native init dispatched without final guard'))
    monkeypatch.setattr(module.subprocess, 'run', dispatch)
    with pytest.raises((PermissionError, ValueError)) as refused:
        module.first_session(root/'fresh', **arguments)
    assert (root/'fresh').exists(), str(refused.value)
    dispatch.assert_not_called()
    assert (root/'fresh/workspace').is_dir()
    assert not (root/'fresh/profile/state.db').exists()


def test_owned_cleanup_reports_unresolved_handles():
    import subprocess
    from arvyx_control.cockpit_arvyx import cleanup_owned_frontend
    server = Mock()
    watcher = Mock()
    for process in (server, watcher):
        process.wait.side_effect = subprocess.TimeoutExpired('fixture', 10)
    report = cleanup_owned_frontend(server, watcher, Mock(), {})
    assert report['verified'] is False
    assert set(report['unresolved']) == {'server', 'watcher'}
    server.kill.assert_called_once_with()
    watcher.kill.assert_called_once_with()


def test_owned_cleanup_reaps_real_children_after_stop_failure():
    import subprocess
    from arvyx_control.cockpit_arvyx import cleanup_owned_frontend
    children = [subprocess.Popen(['/usr/bin/python3', '-c', 'import time; time.sleep(60)']) for _ in range(2)]
    native = Mock()
    native.invoke.side_effect = subprocess.CalledProcessError(1, 'fixture-stop')
    try:
        report = cleanup_owned_frontend(*children, native, {})
        assert report == dict(verified=True, unresolved=[])
        assert all(child.poll() is not None for child in children)
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait()


def test_existing_root_is_never_adopted(short_fixture):
    from arvyx_control.first_session import first_session
    root, source = short_fixture
    existing = root/'existing'
    existing.mkdir()
    with pytest.raises(ValueError, match='never adopt'):
        first_session(existing, **fixture_arguments(root, source))
    assert list(existing.iterdir()) == []


def test_policy_denial_precedes_creation(short_fixture):
    from arvyx_control.first_session import first_session
    from arvyx_control.local_executor import ExecutionPolicy
    root, source = short_fixture
    arguments = fixture_arguments(root, source)
    arguments['policy'] = ExecutionPolicy(host_uid=os.geteuid(), allow_host=False)
    with pytest.raises(PermissionError, match='denied'):
        first_session(root/'fresh', **arguments)
    assert not (root/'fresh').exists()


def test_unadmitted_frontend_precedes_creation(short_fixture):
    from arvyx_control.first_session import first_session
    root, source = short_fixture
    (root/'unapproved').write_bytes(b'not-an-admitted-artifact')
    (root/'unapproved').chmod(0o700)
    # The frontend admission module retains its real strict ancestor policy.
    with pytest.raises(ValueError):
        first_session(root/'fresh', **fixture_arguments(root, source))
    assert not (root/'fresh').exists()


def test_pinned_directory_replacement_refuses(short_fixture):
    from arvyx_control.first_session import PinnedDirectory
    root, _ = short_fixture
    with PinnedDirectory(root) as parent:
        with parent.mkdir('child') as child:
            (root/'child').rename(root/'retained')
            (root/'child').mkdir(mode=0o700)
            with pytest.raises(PermissionError, match='replaced'):
                child.check()


def test_cli_first_session_requires_tty_without_creating_onboarding(tmp_path, monkeypatch):
    from arvyx_control.onboarding_cli import main
    monkeypatch.setattr(os, 'isatty', lambda fd: False)
    assert main(['first-session', '--state-dir', str(tmp_path/'state')]) == 2
    assert not (tmp_path/'state').exists()


def test_frontend_socket_budget_checked_before_creation(short_fixture):
    from arvyx_control.first_session import first_session
    root, source = short_fixture
    with pytest.raises(ValueError, match='too long'):
        first_session(root/('a'*90), **fixture_arguments(root, source))
    assert not (root/('a'*90)).exists()


def test_setup_runtime_has_native_api_plan_and_profile_wide_claim(short_fixture, monkeypatch):
    """Synthetic schema is a fixture, not evidence of native initialization."""
    import sqlite3
    from arvyx_control.first_session import SetupRuntime, VerifiedPython, NATIVE_SETUP
    from arvyx_control.hermes_profile import HermesProfile
    root, source = short_fixture
    profile = root/'profile'
    profile.mkdir(mode=0o700)
    with sqlite3.connect(profile/'state.db') as db:
        db.execute('CREATE TABLE sessions(id TEXT,cwd TEXT,end_reason TEXT,title TEXT)')
    args = fixture_arguments(root, source)
    guard = Mock()
    source_fd = os.open(source, os.O_DIRECTORY)
    home_fd = os.open(profile, os.O_DIRECTORY)
    monkeypatch.setattr('arvyx_control.native_artifact_policy.open_native_directory', lambda p: os.open(p, os.O_DIRECTORY | os.O_NOFOLLOW))
    monkeypatch.setattr(HermesProfile, 'assert_idle', Mock(side_effect=AssertionError('cold-profile guard must not be used for an exclusively new home')))
    try:
        with VerifiedPython(args['python'], args['python_sha256']) as admitted:
            runtime = SetupRuntime(admitted=admitted, source=source, home=profile,
                                   guard=guard, source_fd=source_fd, home_fd=home_fd)
            argv, env = runtime.plan_new('arvyx-new-'+'a'*32, root)
            assert argv[0] == admitted.path and argv[3] == NATIVE_SETUP
            assert '--resume' not in argv and '-q' not in argv
            assert env['HOME'] == env['HERMES_HOME'] == '/proc/self/fd/'+str(home_fd)
            assert runtime.execution_fds == (admitted.fd, source_fd, home_fd)
            first = runtime.reserve('arvyx-new-'+'a'*32)
            try:
                with pytest.raises(ValueError, match='reserved'):
                    runtime.profile.reserve('ordinary-cold-resume')
                with pytest.raises(ValueError, match='reserved'):
                    runtime.reserve('arvyx-new-'+'b'*32)
            finally:
                first.release()
            replacement = runtime.reserve('arvyx-new-'+'b'*32)
            replacement.release()
            guard.side_effect = PermissionError('replaced')
            with pytest.raises(PermissionError, match='replaced'):
                runtime.plan_new('arvyx-new-'+'b'*32, root)
    finally:
        os.close(source_fd)
        os.close(home_fd)


def test_atomic_private_receipt_publication(short_fixture):
    import json
    from arvyx_control.first_session import PinnedDirectory
    root, _ = short_fixture
    with PinnedDirectory(root) as pinned:
        pinned.publish_json('receipt.json', {'state': 'initializing'})
        pinned.publish_json('receipt.json', {'state': 'setup_required'})
    assert json.loads((root/'receipt.json').read_text()) == {'state': 'setup_required'}
    assert (root/'receipt.json').stat().st_mode & 0o777 == 0o600
    assert not list(root.glob('.receipt.json-*'))


@pytest.mark.parametrize('cleanup_failure', [None, 'server', 'owner'])
def test_frontend_failure_retains_acknowledged_native_state(short_fixture, monkeypatch, cleanup_failure):
    """Mocked owner boundary failure, explicitly NOT real process acceptance."""
    import sqlite3
    from arvyx_control.first_session import first_session
    root, source = short_fixture
    destination = root/'fresh'
    admitted = Mock()
    admitted.__enter__ = Mock(return_value=admitted)
    admitted.__exit__ = Mock(return_value=False)
    monkeypatch.setattr('arvyx_control.native_artifact_policy.VerifiedNative', lambda *a, **k: admitted)
    def native_init(*args, **kwargs):
        with sqlite3.connect(destination/'profile/state.db') as db:
            db.execute('CREATE TABLE sessions(id TEXT,title TEXT,cwd TEXT,end_reason TEXT)')
    monkeypatch.setattr('subprocess.run', native_init)
    owner = Mock(root=destination/'owner/runtime')
    def lifecycle(**fields):
        if fields['action'] == 'inspect':
            return {'incarnation': 'fixture'}
        if fields['action'] == 'plan':
            return {'native': {}}
        if fields['action'] == 'new':
            with sqlite3.connect(destination/'profile/state.db') as db:
                db.execute('INSERT INTO sessions VALUES(?,?,?,NULL)', ('fixture-native-id','fixture-title',str(destination/'workspace')))
            (destination/'valuable-state').write_text('fixture post-dispatch state')
            return {'owner_session': 'fixture-owner', 'conversation': 'fixture-native-id'}
        return {}
    owner.native_lifecycle.side_effect = lifecycle
    monkeypatch.setattr('arvyx_control.cockpit.LocalCockpit', lambda *a, **k: owner)
    def frontend(home, frontend, native, **kwargs):
        import json
        if cleanup_failure is None:
            raise ValueError('fixture frontend launch failed')
        frontend.mkdir()
        (frontend/'bindings.json').write_text(json.dumps(dict(authority_home=str(home),
            binary_sha256=admitted.digest, bindings=[dict(sid='fixture-owner', pane='fixture-pane')])))
        kwargs['cleanup_report'].update(verified=cleanup_failure != 'server',
            unresolved=['server'] if cleanup_failure == 'server' else [])
        if cleanup_failure == 'owner':
            owner.close.side_effect = ValueError('fixture owner cleanup failed')
        return 0
    monkeypatch.setattr('arvyx_control.cockpit_arvyx._open_frontend', frontend)
    # Fake admission digests must stay JSON scalar values in the fixture receipt.
    admitted.digest = 'f'*64
    with pytest.raises(ValueError, match='cleanup unresolved' if cleanup_failure else 'fixture frontend launch failed'):
        first_session(destination, **fixture_arguments(root, source))
    if cleanup_failure:
        import json
        receipt = json.loads((destination/'first-session.json').read_text())
        assert receipt['owner_status'] == 'cleanup_failed'
        assert receipt['cleanup']['verified'] is False
        assert cleanup_failure in receipt['cleanup']['unresolved']
    assert (destination/'valuable-state').read_text() == 'fixture post-dispatch state'
    with sqlite3.connect(destination/'profile/state.db') as db:
        assert db.execute('SELECT id FROM sessions').fetchall() == [('fixture-native-id',)]
    owner.close.assert_called_once()
    assert not (destination/'owner/runtime/cockpit.sock').exists()
