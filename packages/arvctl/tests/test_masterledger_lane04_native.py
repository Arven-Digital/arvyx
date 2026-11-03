from arvyx_control.local_executor import ExecutionPolicy
"""Lane 04 regression sources; NOT EXECUTED under the static-only contract."""
import json
import pytest
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_primary import PrimaryAgentRegistry
from arvyx_control import native_install
import os

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='the native runtime (Linux x86_64 artifact, host-shell policies) is POSIX-only')


def test_missing_interpreter_never_publishes_primary(tmp_path):
    vault = tmp_path / 'vault'
    for kind, records in {
        'agents': [dict(id='alpha', machine_id='machine', runtime_id='runtime')],
        'machines': [dict(id='machine')],
        'runtimes': [dict(id='runtime', harness='gemini')],
    }.items():
        directory = vault / 'registry' / kind
        directory.mkdir(parents=True)
        for record in records:
            (directory / (record['id'] + '.json')).write_text(json.dumps(record))
    executable = tmp_path / 'missing-interpreter'
    executable.write_text('#!/nonexistent-amc-test-interpreter\n')
    executable.chmod(0o700)
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    class Runtime:
        def reserve(self, conversation): return None  # Disposable test adapter only.
        def plan(self, *args):
            return [str(executable)], dict(PATH='/usr/bin:/bin', HOME=str(tmp_path), TERM='dumb')
    owner = LocalCockpit(tmp_path / 'owner', vault, tmp_path / 'events.jsonl', 'machine',
        native_runtimes={'gemini': Runtime()},
        organizers={'alpha': dict(tool='gemini', conversation='synthetic', workspace=str(workspace))}, execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))
    try:
        sid = owner.open_organizer('alpha', actor='operator')['id']
        with pytest.raises(ValueError, match='exec failed|launch exited'):
            owner.start_native(sid, actor='operator', allow_provider=True, environment='host')
        registry = PrimaryAgentRegistry(owner, tmp_path / 'events.jsonl.primary.sqlite')
        try:
            assert registry.db.execute('SELECT COUNT(*) FROM primary_connections').fetchone()[0] == 0
            assert registry.db.execute('SELECT COUNT(*) FROM primary_events').fetchone()[0] == 0
        finally:
            registry.close()
        assert owner._get(sid)['status'] == 'stopped'
    finally:
        owner.close()


def test_nonhermes_conversation_reservation_excludes_second_writer(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace
    from arvyx_control.cockpit_native_runtime import NativeConversationReservation
    from arvyx_control import native_artifact_policy
    # Isolate reservation behavior from artifact-path ancestry admission here.
    monkeypatch.setattr(native_artifact_policy, 'open_native_directory',
                        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY))
    runtime = SimpleNamespace(home=tmp_path, tool='gemini')
    first = NativeConversationReservation(runtime, 'same-conversation')
    try:
        with pytest.raises(ValueError, match='already reserved'):
            NativeConversationReservation(runtime, 'same-conversation')
        other = NativeConversationReservation(runtime, 'different-conversation')
        other.release()
    finally:
        first.release()
    retry = NativeConversationReservation(runtime, 'same-conversation')
    retry.release()


def test_install_rejects_unsafe_ancestry_before_creating_destination(tmp_path, monkeypatch):
    # Only exercises destination admission; these synthetic bytes are never
    # represented as approved real native bytes or executed.
    receipt = tmp_path / 'receipt.json'
    receipt.write_text('{}')
    monkeypatch.setattr(native_install, 'read_native_bytes', lambda _: b'synthetic')
    monkeypatch.setattr(native_install, 'verify_native_bytes', lambda *a, **kwargs: 'synthetic-not-approved')
    monkeypatch.setattr(native_install, 'native_platform_policy', lambda: {'available': True})
    ancestor = tmp_path / 'unsafe'
    ancestor.mkdir(mode=0o777)
    ancestor.chmod(0o777)
    prefix = ancestor / 'private'
    prefix.mkdir(mode=0o700)
    destination = prefix / 'native'
    with pytest.raises((ValueError, OSError), match='unsafe native artifact ancestor'):
        native_install.install(tmp_path / 'unused', receipt, destination)
    assert not destination.exists()
