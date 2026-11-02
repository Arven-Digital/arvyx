from arvyx_control.replica_authority import authority_context
"""Review regressions use disposable sockets/stores and captured terminal text only."""
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import socket
import threading
import time
from unittest.mock import patch

import pytest

from arvyx_control import api
from arvyx_control.control import recover_torn_final_event
from arvyx_control.shared_onboarding_cli import menu
from safe_mcp_bridge.cli import _post_json, BridgeError


@pytest.mark.parametrize('cross_origin', [False, True])
@pytest.mark.parametrize('code', [301, 302, 303, 307, 308])
@pytest.mark.parametrize('header', ['Authorization', 'X-Bridge-Key'])
def test_bridge_denies_redirects(code, header, monkeypatch, cross_origin):
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', 0)))
            seen.append(self.path)
            self.send_response(code)
            self.send_header('Location', destination)
            self.send_header('Content-Length', '0')
            self.end_headers()
        def do_GET(self):
            seen.append(self.path)
            data = b'{}'
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    sink = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    sink_thread = threading.Thread(target=sink.serve_forever, daemon=True)
    sink_thread.start()
    destination = f'http://127.0.0.1:{sink.server_port}/collector' if cross_origin else '/collector'
    monkeypatch.setenv('SYNTHETIC_BRIDGE_VALUE', 'not-a-real-credential')
    try:
        config = {'target': {'url': f'http://127.0.0.1:{server.server_port}/upstream'},
                  'auth': {'env': 'SYNTHETIC_BRIDGE_VALUE', 'header': header}}
        with pytest.raises(BridgeError):
            _post_json(config, {'jsonrpc': '2.0', 'id': 1, 'method': 'ping'})
        assert seen == ['/upstream']
    finally:
        server.shutdown(); server.server_close(); thread.join()
        sink.shutdown(); sink.server_close(); sink_thread.join()


@pytest.mark.parametrize('drip', [False, True])
def test_core_preheader_worker_lifetime_is_bounded(tmp_path, monkeypatch, drip):
    monkeypatch.setattr(api.BoundedThreadingHTTPServer, 'request_lifetime_seconds', .25, raising=False)
    handler = api.make_handler(tmp_path / 'vault', tmp_path / 'control.jsonl')
    server = api.BoundedThreadingHTTPServer(('127.0.0.1', 0), handler, max_workers=1)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = socket.create_connection(server.server_address, timeout=2)
    try:
        client.settimeout(2)
        start = time.monotonic()
        if drip:
            for byte in b'GET /health HTTP/1.1\r\nX-Slow: never-ending':
                try: client.sendall(bytes([byte]))
                except OSError: break
                if time.monotonic() - start > .6: break
                time.sleep(.025)
        else:
            client.sendall(b'GET /health HTTP/1.1\r\nX-Incomplete: ')
        # Must close even when bytes arrive faster than an idle socket timeout.
        assert client.recv(4096) == b''
        assert time.monotonic() - start < 1.25
        deadline = time.monotonic() + 1
        while not server._worker_slots.acquire(blocking=False):
            assert time.monotonic() < deadline
            time.sleep(.01)
        server._worker_slots.release()
        with socket.create_connection(server.server_address, timeout=2) as healthy:
            healthy.sendall(b'GET /health HTTP/1.0\r\n\r\n')
            assert b'HTTP/1.0 200' in healthy.recv(4096)
    finally:
        client.close(); server.shutdown(); server.server_close(); thread.join()


def test_instruction_preview_escapes_only_display_not_approval():
    content = 'visible\x1b[2J\x1b]52;c;hidden\x07\rspoof\x85\u202ehidden\nnext'
    digest = hashlib.sha256(content.encode()).hexdigest()
    prepared = []
    def call(path, body=None):
        if path == 'capabilities': return {'mode': 'metadata', 'instruction_sources': []}
        if path == 'instructions/preview':
            return {'files': [{'path': 'AGENTS.md\x1b[H', 'content': content, 'approved_sha256': digest, 'next_offset': None}]}
        if path == 'agents/prepare': prepared.append(body); return {'request': body}
        raise AssertionError(path)
    output = io.StringIO()
    with patch('arvyx_control.onboarding_cli.choose', side_effect=['create', 'copy', 'yes', 'skip', 'quit']), patch('builtins.input', side_effect=['name', 'source', 'AGENTS.md\x1b[H']), contextlib.redirect_stdout(output):
        assert menu(call) == 0
    assert not any(c in output.getvalue() for c in ['\x1b', '\x07', '\r', '\x85', '\u202e'])
    assert '\\x1b' in output.getvalue()
    assert digest in output.getvalue()
    assert prepared[0]['identity_files'] == [{'path': 'AGENTS.md\x1b[H', 'approved_sha256': digest}]


def test_session_metadata_is_escaped_in_display_only():
    target = {'agent': 'exact'}
    route = {'session_id': 'id\x1b[H'}
    selected = []
    def call(path, body=None):
        if path == 'capabilities': return {'mode': 'metadata'}
        if path == 'targets': return {'items': [target]}
        if path == 'sessions/recent': return {'items': [{'title': 'title\x1b]0;spoof\x07', 'route': route}]}
        if path == 'sessions/select': selected.append(body); return body
        raise AssertionError(path)
    output = io.StringIO()
    with patch('arvyx_control.onboarding_cli.choose', side_effect=['sessions', 'last5', 'quit']), patch('builtins.input', side_effect=['1', '1']), contextlib.redirect_stdout(output):
        assert menu(call) == 0
    assert '\x1b' not in output.getvalue() and '\x07' not in output.getvalue()
    assert selected == [{'route': route, 'confirmed': True}]


@pytest.mark.parametrize('existing', ['exact', 'partial', 'mismatch', 'symlink'])
def test_torn_recovery_resumes_only_exact_quarantine(tmp_path, existing):
    state = tmp_path / 'control.jsonl'
    # The complete prefix must satisfy the current event schema; otherwise
    # recovery correctly refuses mid-file corruption before reaching the
    # quarantine comparison that this test exercises.
    prefix = (json.dumps(dict(id='event_synthetic', type='synthetic.complete', task_id='task_synthetic',
                              timestamp='2026-01-01T00:00:00Z', payload={}), sort_keys=True) + '\n').encode()
    torn = b'{"torn":'
    state.write_bytes(prefix + torn)
    quarantine = state.with_name(state.name + '.torn-' + hashlib.sha256(torn).hexdigest()[:16] + '.bin')
    expected = torn if existing in ('exact', 'symlink') else torn[:-1] if existing == 'partial' else b'conflict'
    if existing == 'symlink':
        other = tmp_path / 'other'; other.write_bytes(expected); quarantine.symlink_to(other)
    else: quarantine.write_bytes(expected)
    if existing == 'exact':
        with authority_context(tmp_path / "authority-vault", state):
            result = recover_torn_final_event(state)
        assert state.read_bytes() == prefix
        assert result['quarantine_sha256'] == hashlib.sha256(torn).hexdigest()
    else:
        with pytest.raises((ValueError, OSError)):
            with authority_context(tmp_path / "authority-vault", state):
                recover_torn_final_event(state)
        assert state.read_bytes() == prefix + torn
    assert quarantine.read_bytes() == expected


def test_torn_recovery_refuses_schema_invalid_complete_prefix(tmp_path):
    """Negative control for the fixture above: invalid complete lines are corruption."""
    state = tmp_path / 'control.jsonl'
    state.write_bytes(b'{"complete":true}\n{"torn":')
    with pytest.raises(ValueError, match='mid-file corruption on line 1'):
        with authority_context(tmp_path / "authority-vault", state):
            recover_torn_final_event(state)
    assert state.read_bytes() == b'{"complete":true}\n{"torn":'
    assert not list(tmp_path.glob('control.jsonl.torn-*'))


def _first_append_short_by_newline(tmp_path, state):
    """REV-0539: the first append writes complete JSON but omits only the newline."""
    import os
    from arvyx_control import control
    real_write = os.write
    shortened = []
    def short_write(fd, data):
        if not shortened and data.endswith(b'\n') and len(data) > 1 and os.path.samestat(os.fstat(fd), os.stat(state)):
            shortened.append(data)
            return real_write(fd, data[:-1])
        return real_write(fd, data)
    event = control._event('synthetic.created', 'task_synthetic', '2026-01-01T00:00:00Z', {'synthetic': True})
    with authority_context(tmp_path / "authority-vault", state):
        with patch.object(control.os, 'write', short_write):
            with pytest.raises(OSError, match='short event append'):
                control._append_event(state, event)
    assert len(shortened) == 1 and state.read_bytes() == shortened[0][:-1]
    return shortened[0]


def _recording_fsync(state, events, *, fail_directory=False):
    import os
    import stat as stat_module
    real_fsync = os.fsync
    def fsync(fd):
        metadata = os.fstat(fd)
        if stat_module.S_ISDIR(metadata.st_mode) and os.path.samestat(metadata, os.stat(state.parent)):
            events.append('directory')
            if fail_directory:
                raise OSError('synthetic directory barrier failure')
        elif stat_module.S_ISREG(metadata.st_mode) and os.path.samestat(metadata, os.stat(state)):
            events.append(('file', os.stat(state).st_size))
        return real_fsync(fd)
    return fsync


def test_newline_only_recovery_persists_file_then_containing_directory(tmp_path):
    from arvyx_control import control
    state = tmp_path / 'log' / 'control.jsonl'
    record = _first_append_short_by_newline(tmp_path, state)
    events = []
    with authority_context(tmp_path / "authority-vault", state):
        with patch.object(control.os, 'fsync', _recording_fsync(state, events)):
            result = recover_torn_final_event(state)
    assert result['repair'] == 'missing_final_newline' and result['removed_bytes'] == 0
    assert state.read_bytes() == record
    # File contents (including the repaired newline) are synced first, then
    # the directory holding the log's new name, before success is returned.
    assert events == [('file', len(record)), 'directory']
    assert not list(state.parent.glob('control.jsonl.torn-*'))


def test_newline_only_recovery_directory_barrier_failure_is_not_success(tmp_path):
    from arvyx_control import control
    state = tmp_path / 'log' / 'control.jsonl'
    record = _first_append_short_by_newline(tmp_path, state)
    events = []
    with authority_context(tmp_path / "authority-vault", state):
        with patch.object(control.os, 'fsync', _recording_fsync(state, events, fail_directory=True)):
            with pytest.raises(OSError, match='synthetic directory barrier failure'):
                recover_torn_final_event(state)
    assert events == [('file', len(record)), 'directory']
    # The unacknowledged repair never removes the complete record. The next
    # append retries the namespace barrier before acknowledging anything.
    assert state.read_bytes() == record
    retry = []
    with authority_context(tmp_path / "authority-vault", state):
        with patch.object(control.os, 'fsync', _recording_fsync(state, retry)):
            control._append_event(state, control._event('synthetic.next', 'task_synthetic', '2026-01-01T00:00:01Z', {}))
    assert retry[-1] == 'directory'
    assert [event.type for event in control.read_events(state)] == ['synthetic.created', 'synthetic.next']


def test_torn_recovery_retries_after_actual_quarantine_publication(tmp_path):
    state = tmp_path / 'control.jsonl'
    torn = b'{"interrupted":'
    state.write_bytes(torn)
    with patch('arvyx_control.control.os.ftruncate', side_effect=OSError('synthetic crash before truncate')):
        with pytest.raises(OSError, match='synthetic crash'):
            with authority_context(tmp_path / "authority-vault", state):
                recover_torn_final_event(state)
    assert state.read_bytes() == torn
    with authority_context(tmp_path / "authority-vault", state):
        result = recover_torn_final_event(state)
    assert state.read_bytes() == b''
    assert Path(result['quarantine_path']).read_bytes() == torn


def test_current_command_guidance_routes_without_native_start():
    from arvyx_control.onboarding_cli import main
    with patch('arvyx_control.terminal_sessions.history_menu', return_value=0) as history:
        assert main(['history', '--hermes-home', '/synthetic/consented-profile']) == 0
    history.assert_called_once_with(Path('/synthetic/consented-profile'), owner=None,
                                    frontend=None, binary=None, authorize_launch=False,
                                    workspace=None, new_profile=None, authorize_default_resume=False,
                                    # REV-0547: absence of policy/mode is forwarded unchanged so the
                                    # history launch boundary refuses; nothing is defaulted here.
                                    execution_policy=None, environment=None, root_acknowledged=False)
    with patch('arvyx_control.terminal_sessions.terminal_menu', return_value=0) as terminal:
        assert main(['terminal', '--native-owner', '/synthetic/owner',
                     '--frontend-home', '/synthetic/frontend', '--arvyx-binary', '/synthetic/binary']) == 0
    assert terminal.call_args.args == (Path('/synthetic/owner'), Path('/synthetic/frontend'), Path('/synthetic/binary'))
    assert terminal.call_args.kwargs['authorize_launch'] is False


def test_current_terminal_guidance_is_fenced_and_correct():
    doc = Path(__file__).resolve().parents[3] / 'docs/terminal-readiness-final.md'
    if not doc.is_file():
        pytest.skip('private terminal readiness record is not part of this checkout')
    text = doc.read_text()
    assert 'Historical receipt' in text
    assert 'amc history --hermes-home' in text
    assert 'Current attach-only entry' in text
