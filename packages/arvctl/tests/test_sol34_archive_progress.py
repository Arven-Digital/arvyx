"""Synthetic offline regressions for candidate33 findings 2 and 3."""
import json
import sqlite3
from contextlib import closing
from unittest.mock import patch
import pytest
from arvyx_control import cockpit_archive as archive
from arvyx_control.cockpit import LocalCockpit
from test_sol27_archive_pem import owner_at, native_owner


@pytest.mark.parametrize('prefix', ['token=', 'password :', 'api_key\n=', 'Bearer', 'aws_secret_access_key=', 'to\x1b[31mken='])
@pytest.mark.parametrize('fragmented', [False, True])
def test_actual_capture_newline_context(tmp_path, prefix, fragmented):
    owner = owner_at(tmp_path / 'capture.db')
    recorder = archive.WorkCapture(owner, 's')
    value = 'SYNTHETIC_VALUE_123456' if not prefix.startswith('aws') else 'A' * 40
    data = (prefix + '\n' + ' \n' * 300 + value + '\nnearby-public\n').encode()
    for part in ([bytes([byte]) for byte in data] if fragmented else [data]):
        recorder.feed(part)
        assert value not in str(archive.pending_capture(owner))
    recorder.finish()
    assert value not in str(archive.pending_capture(owner))
    assert 'nearby-public' in str(archive.pending_capture(owner))


@pytest.mark.parametrize('padding', [' ' * 20000, '\u2003' * 300])
def test_bounded_overlong_and_unicode_context(tmp_path, padding):
    owner = owner_at(tmp_path / 'capture.db')
    recorder = archive.WorkCapture(owner, 's')
    recorder.feed(('token=' + padding + '\n').encode())
    assert len(recorder.ordinary_context) <= 256
    for byte in b'SYNTHETIC_VALUE_123456':
        recorder.feed(bytes([byte]))
    with patch.object(recorder, '_write', side_effect=BufferError('synthetic finish')):
        with pytest.raises(BufferError):
            recorder.finish()
    recorder.finish()
    assert 'SYNTHETIC_VALUE_123456' not in str(archive.pending_capture(owner))


def test_nearby_canonical_call_exemption_and_plain_lines(tmp_path):
    owner = owner_at(tmp_path / 'capture.db')
    recorder = archive.WorkCapture(owner, 's')
    data = b'token=\nhelper_function()\nplain-output\n'
    for byte in data:
        recorder.feed(bytes([byte]))
    recorder.finish()
    text = str(archive.pending_capture(owner))
    assert 'helper_function()' in text and 'plain-output' in text


def test_context_rollback_and_backpressure(tmp_path):
    owner = owner_at(tmp_path / 'capture.db')
    recorder = archive.WorkCapture(owner, 's')
    recorder.feed(b'token=\n')
    before = archive.pending_capture(owner)
    with patch.object(recorder, '_write', side_effect=BufferError('synthetic')):
        with pytest.raises(BufferError):
            recorder.feed(b'SYNTHETIC_VALUE_123456\n')
    assert archive.pending_capture(owner) == before
    recorder.feed(b'SYNTHETIC_VALUE_123456\npublic\n')
    recorder.finish()
    assert 'SYNTHETIC_VALUE_123456' not in str(archive.pending_capture(owner))
    assert 'public' in str(archive.pending_capture(owner))


@pytest.mark.parametrize('pump', [False, True])
@pytest.mark.parametrize('content', ['x' * 12000, '\u00e9' * 6000], ids=['ascii', 'json-escaped'])
def test_real_native_archive_bounded_pages_progress(tmp_path, pump, content):
    store = tmp_path / 'state.db'
    with closing(sqlite3.connect(store)) as db, db:
        db.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT)')
        db.executemany('INSERT INTO messages VALUES(?,?,?,?)',
                       [(i, 'conversation', 'assistant', content) for i in range(1, 101)])
    owner = native_owner(tmp_path / 'archive.db', store)
    runtime = owner.native_runtimes['hermes']
    if pump:
        import os
        import threading
        from types import MethodType
        owner.db.execute('CREATE TABLE sessions(id,status,pid)')
        owner.db.execute('CREATE TABLE delegations(session,generation,status,pending)')
        owner.db.commit()
        owner.native_archive = MethodType(LocalCockpit.native_archive, owner)
        read_fd, write_fd = os.pipe()
        os.close(write_fd)  # EOF, not a launched native runtime.
        live = dict(fd=read_fd, recorder=archive.WorkCapture(owner, 's'),
                    capture_error=None, input_lock=threading.Lock(), input=bytearray(),
                    discarded_bytes=0, input_error=None)
        # Only the owner's current pump generation may finalize/archive; a
        # retired pump returns without effects. Register this exact one.
        owner.live['s'] = live
        LocalCockpit._pump(owner, 's', live)
        assert live['capture_error'] is None
        assert len(archive.pending_capture(owner)) == 100
        return
    after = 0
    total = 0
    for _ in range(10):
        page = runtime.transcript('conversation', after=after)
        assert len(json.dumps(page).encode()) <= 1024 * 1024
        result = LocalCockpit.native_archive(owner, 's', actor='operator')
        assert result['cursor'] > after
        total += result['imported']
        after = result['cursor']
        if not result['has_more']:
            break
    else:
        pytest.fail('bounded pages did not finish')
    assert total == 100 and after == 100
    assert len(archive.pending_capture(owner)) == 100
    assert LocalCockpit.native_archive(owner, 's', actor='operator')['imported'] == 0
