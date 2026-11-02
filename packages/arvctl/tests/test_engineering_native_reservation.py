"""Durable native admission without launching any harness or provider."""
import os
from types import SimpleNamespace

import pytest

from arvyx_control import cockpit_native_runtime as native, native_artifact_policy


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    # Isolate the reservation lifecycle from separately tested ancestor policy.
    monkeypatch.setattr(native_artifact_policy, 'open_native_directory',
        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY))
    return SimpleNamespace(home=tmp_path, tool='gemini')


def test_owner_crash_retains_unresolved_native_reservation(runtime):
    pid = os.fork()
    if pid == 0:
        try:
            reservation = native.NativeConversationReservation(runtime, 'exact-conversation')
            os._exit(0)  # Flock closes, but cleanup was never proved.
        except BaseException:
            os._exit(1)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    with pytest.raises(ValueError, match='cleanup unverified'):
        reservation = native.NativeConversationReservation(runtime, 'exact-conversation')
        reservation.release()
    other = native.NativeConversationReservation(runtime, 'different-conversation')
    other.release()


def test_verified_cleanup_allows_reuse_after_reopen(runtime):
    first = native.NativeConversationReservation(runtime, 'exact-conversation')
    with pytest.raises(ValueError, match='already reserved'):
        native.NativeConversationReservation(runtime, 'exact-conversation')
    first.release()
    first.release()
    second = native.NativeConversationReservation(runtime, 'exact-conversation')
    second.release()


def test_failed_reservation_durability_never_admits_launch(runtime, monkeypatch):
    def fail(fd):
        raise OSError('synthetic reservation barrier')
    with monkeypatch.context() as m:
        m.setattr(os, 'fsync', fail)
        with pytest.raises(OSError, match='reservation barrier'):
            native.NativeConversationReservation(runtime, 'exact-conversation')
    with pytest.raises(ValueError, match='cleanup unverified'):
        reservation = native.NativeConversationReservation(runtime, 'exact-conversation')
        reservation.release()


def test_missing_kernel_sealing_api_refuses_execution_without_breaking_import():
    import subprocess
    import sys
    script = '''import fcntl
from pathlib import Path
if hasattr(fcntl, 'F_SEAL_WRITE'):
    del fcntl.F_SEAL_WRITE
from arvyx_control.native_artifact_policy import VerifiedNative
from arvyx_control.agent_sessions import RoutingError
try:
    VerifiedNative(Path('/never-read-or-executed'))
except RoutingError as exc:
    assert 'sealing unavailable' in str(exc), str(exc)
else:
    raise AssertionError('unsealed execution must never be admitted')
'''
    result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr


def test_legacy_empty_reservation_cannot_attest_orphan_cleanup(runtime):
    import hashlib
    import json
    key = hashlib.sha256(json.dumps([runtime.tool, 'legacy'], ensure_ascii=True).encode()).hexdigest()
    path = runtime.home / ('.amc-native-conversation-' + key + '.lock')
    path.touch(mode=0o600)
    with pytest.raises(ValueError, match='cleanup unverified'):
        reservation = native.NativeConversationReservation(runtime, 'legacy')
        reservation.release()


def test_missing_fcntl_module_refuses_native_execution_without_breaking_import():
    import subprocess
    import sys
    script = '''from arvyx_control.agent_sessions import RoutingError
import sys
sys.modules['fcntl'] = None
from arvyx_control.native_artifact_policy import VerifiedNative
try:
    VerifiedNative('/never-read-or-executed')
except RoutingError as exc:
    assert 'sealing unavailable' in str(exc), str(exc)
else:
    raise AssertionError('unsealed execution must never be admitted')
'''
    result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
