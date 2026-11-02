"""Offline synthetic regressions for candidate26 findings 1 and 2."""
import sqlite3
import threading
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from arvyx_control import cockpit_archive as archive
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_native_runtime import NativeRuntime


def owner_at(path):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    return SimpleNamespace(db=db, lock=threading.RLock(), _get=lambda sid: {'workspace': '/synthetic'},
                           _human=lambda actor: None, live={}, archive_sync='not configured')


@pytest.mark.parametrize('opening,ending', [
    ('-----begin rsa private key-----', '-----END RSA PRIVATE KEY-----'),
    ('BEGıN\u2003RSA PRIVATE KEY', 'END RSA PRIVATE KEY'),
    ('BEGIN RSA PRİVATE KEY\nEND RSA PRIVATE KEY', 'END RSA PRIVATE KEY'),
    ('BEGIN RSA PRIVATE KEY\nBEGIN EC PRIVATE KEY\nEND EC PRIVATE KEY', 'END RSA PRIVATE KEY'),
    ('BEGIN RSA PRIVATE KEY\nEND EC PRIVATE KEY', 'END RSA PRIVATE KEY'),
])
def test_capture_context_actual_feed_finish(tmp_path, opening, ending):
    owner = owner_at(tmp_path / 'capture.db')
    recorder = archive.WorkCapture(owner, 's')
    for byte in (opening + '\nSYNTHETIC_BODY\n' + ending + '\n').encode():
        recorder.feed(bytes([byte]))
    recorder.finish()
    assert 'SYNTHETIC_BODY' not in str(archive.pending_capture(owner))


def native_owner(path, store):
    owner = owner_at(path)
    owner.root=path.parent/'owner';owner.root.mkdir(mode=0o700,exist_ok=True)
    owner.vault=path.parent/'vault';owner.vault.mkdir(mode=0o700,exist_ok=True)
    from arvyx_control.vault import init_vault
    if not (owner.vault/'.arvyx-vault').exists():init_vault(owner.vault)
    owner.state=path.parent/'events.jsonl';owner.state.touch(exist_ok=True)
    workspace=path.parent/'workspace';workspace.mkdir(mode=0o700,exist_ok=True)
    owner._get=lambda sid: {'workspace': str(workspace)}
    owner.host='fixture-host';owner.incarnation='fixture-owner';owner.team=None
    runtime = NativeRuntime.__new__(NativeRuntime)
    runtime.tool, runtime.store, runtime.home = 'hermes', store, store.parent
    from arvyx_control.hermes_profile import HermesProfile
    runtime.profile = HermesProfile(store.parent, store)
    runtime.plan = lambda *args: None
    owner.native_runtimes = {'hermes': runtime}
    owner.native = lambda *args, **kwargs: {'tool': 'hermes', 'conversation': 'conversation'}
    return owner


def test_native_sql_adapter_page_restart_and_atomic_retry(tmp_path):
    store = tmp_path / 'state.db'
    with sqlite3.connect(store) as db:
        db.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT)')
        db.executemany('INSERT INTO messages VALUES(?,?,?,?)', [(i, 'conversation', 'assistant', 'safe') for i in range(1,100)])
        db.execute('INSERT INTO messages VALUES(100,?,?,?)', ('conversation', 'assistant', 'begin rsa private key'))
        db.execute('INSERT INTO messages VALUES(101,?,?,?)', ('conversation', 'assistant', 'SYNTHETIC_BODY\nEND RSA PRIVATE KEY'))
    path = tmp_path / 'archive.db'
    owner = native_owner(path, store)
    assert LocalCockpit.native_archive(owner, 's', actor='operator')['cursor'] == 100
    owner.db.close()
    owner = native_owner(path, store)
    before = archive.pending_capture(owner)
    owner.db.execute("CREATE TEMP TRIGGER fail_native BEFORE INSERT ON work_capture BEGIN SELECT RAISE(ABORT,'synthetic'); END")
    owner.db.commit()
    with pytest.raises(sqlite3.IntegrityError):
        LocalCockpit.native_archive(owner, 's', actor='operator')
    assert archive.pending_capture(owner) == before
    owner.db.execute('DROP TRIGGER fail_native')
    context_before = [tuple(r) for r in owner.db.execute('SELECT * FROM native_archive_context')]
    owner.db.execute("CREATE TEMP TRIGGER fail_cursor BEFORE INSERT ON native_archive_cursor BEGIN SELECT RAISE(ABORT,'synthetic cursor'); END")
    owner.db.commit()
    with pytest.raises(sqlite3.IntegrityError):
        LocalCockpit.native_archive(owner, 's', actor='operator')
    assert archive.pending_capture(owner) == before
    assert context_before == [tuple(r) for r in owner.db.execute('SELECT * FROM native_archive_context')]
    owner.db.execute('DROP TRIGGER fail_cursor')
    result = LocalCockpit.native_archive(owner, 's', actor='operator')
    assert result['cursor'] == 101
    assert 'SYNTHETIC_BODY' not in str(archive.pending_capture(owner))
    assert LocalCockpit.native_archive(owner, 's', actor='operator')['imported'] == 0


@pytest.mark.parametrize('label', ['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'DSA PRIVATE KEY', 'OPENSSH PRIVATE KEY', 'ENCRYPTED PRIVATE KEY'])
def test_capture_labels_recovery_public_and_unterminated_finish(tmp_path, label):
    owner = owner_at(tmp_path / 'capture.db')
    recorder = archive.WorkCapture(owner, 's')
    recorder.feed(('begin ' + label.lower() + '\nSYNTHETIC_BODY\nend ' + label + '\nsafe-public\nBEGIN PUBLIC KEY\npublic-material\n').encode())
    recorder.feed(('begin ' + label + '\nSYNTHETIC_TAIL').encode())
    with patch.object(recorder, '_write', side_effect=BufferError('synthetic')):
        with pytest.raises(BufferError):
            recorder.finish()
    recorder.finish()
    text = str(archive.pending_capture(owner))
    assert 'SYNTHETIC' not in text
    assert 'safe-public' in text and 'public-material' in text


def test_feed_rollback_preserves_active_label_and_nested_poison(tmp_path):
    owner = owner_at(tmp_path / 'capture.db')
    recorder = archive.WorkCapture(owner, 's')
    recorder.feed(b'BEGIN RSA PRIVATE KEY\n')
    before = archive.pending_capture(owner)
    with patch.object(recorder, '_write', side_effect=BufferError('synthetic')):
        with pytest.raises(BufferError):
            recorder.feed(b'END RSA PRIVATE KEY\n')
    assert archive.pending_capture(owner) == before
    recorder.feed(b'SYNTHETIC_BODY\nBEGIN EC PRIVATE KEY\nEND EC PRIVATE KEY\nEND RSA PRIVATE KEY\nSYNTHETIC_AFTER_NESTED')
    recorder.finish()
    assert 'SYNTHETIC' not in str(archive.pending_capture(owner))


def test_native_context_is_conversation_scoped_and_contains_no_body(tmp_path):
    store = tmp_path / 'state.db'
    with sqlite3.connect(store) as db:
        db.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT)')
        db.executemany('INSERT INTO messages VALUES(?,?,?,?)', [
            (1, 'conversation', 'assistant', 'BEGIN RSA PRIVATE KEY\nSYNTHETIC_BODY'),
            (2, 'other', 'assistant', 'public-conversation'),
        ])
    owner = native_owner(tmp_path / 'archive.db', store)
    conversations = {'s': 'conversation', 't': 'other'}
    owner.native = lambda sid, **kw: {'tool': 'hermes', 'conversation': conversations[sid]}
    LocalCockpit.native_archive(owner, 's', actor='operator')
    assert 'SYNTHETIC' not in str([tuple(r) for r in owner.db.execute('SELECT * FROM native_archive_context')])
    # Rebinding an archived session to another conversation is a source change:
    # its source-bound cursor is refused, never silently reused or reset.
    conversations['s'] = 'other'
    with pytest.raises(archive.ContextProvenanceRequired, match='explicit reimport required'):
        LocalCockpit.native_archive(owner, 's', actor='operator')
    conversations['s'] = 'conversation'
    # A distinct conversation's context starts clear: the open private block of
    # 'conversation' must not suppress it.
    LocalCockpit.native_archive(owner, 't', actor='operator')
    assert 'public-conversation' in str(archive.pending_capture(owner))
    with sqlite3.connect(store) as db:
        db.execute('INSERT INTO messages VALUES(3,?,?,?)', ('conversation', 'assistant', 'SYNTHETIC_LATER\nEND EC PRIVATE KEY\nSYNTHETIC_MISMATCH'))
    before = [tuple(r) for r in owner.db.execute('SELECT * FROM native_archive_context ORDER BY run')]
    with patch.object(archive, 'CAPTURE_CAPACITY', 1):
        with pytest.raises(BufferError):
            LocalCockpit.native_archive(owner, 's', actor='operator')
    assert before == [tuple(r) for r in owner.db.execute('SELECT * FROM native_archive_context ORDER BY run')]
    LocalCockpit.native_archive(owner, 's', actor='operator')
    assert 'SYNTHETIC' not in str(archive.pending_capture(owner))



def test_actual_overlong_delimiter_and_body_screening(tmp_path):
    owner = owner_at(tmp_path / 'capture.db')
    recorder = archive.WorkCapture(owner, 's')
    recorder.feed(b'x' * 20000 + b'begin ' + b' ' * 20000 + b'rsa private key\nSYNTHETIC_BODY\n')
    recorder.feed(b'y' * 20000 + b'end rsa private key\nordinary after block\n')
    recorder.finish()
    text = str(archive.pending_capture(owner))
    assert 'SYNTHETIC_BODY' not in text and 'ordinary after block' in text
