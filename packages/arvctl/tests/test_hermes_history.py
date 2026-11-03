import sqlite3
from contextlib import ExitStack, closing
import pytest
from arvyx_control.agent_sessions import AgentSessions, RoutingError
from arvyx_control.hermes_history import HermesHistory
import os

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='host-shell execution policy (host_uid) and the PTY owner are POSIX-only')

# Synthetic, never-executed provider path: launch plans must not depend on an
# installed Hermes binary on the test host, and no test here dispatches it.
SYNTHETIC_HERMES = '/synthetic/not-executed-hermes'

@pytest.fixture
def history(tmp_path):
    home = tmp_path/'isolated'
    home.mkdir(mode=0o700)
    with closing(sqlite3.connect(home/'state.db')) as db, db:
        db.executescript('CREATE TABLE sessions(id TEXT PRIMARY KEY,title TEXT,started_at REAL,ended_at REAL,end_reason TEXT,cwd TEXT); CREATE TABLE messages(id INTEGER PRIMARY KEY,session_id TEXT,timestamp REAL,content TEXT);')
        db.executemany('INSERT INTO sessions VALUES(?,?,?,?,?,?)',[(f'id-{i}',f'Title {i}',i,None,None,str(tmp_path)) for i in range(8)])
        db.execute("INSERT INTO messages VALUES(1,'id-0',99,'SECRET TRANSCRIPT')")
    return HermesHistory(home, executable=SYNTHETIC_HERMES)


def test_full_history_recent_search_and_readonly(history):
    service = AgentSessions({history.target:history})
    assert [x.route.session_id for x in service.recent(history.target)] == ['id-0','id-7','id-6','id-5','id-4']
    page = service.all(history.target,limit=3)
    assert page.total == 8 and page.next_cursor
    assert service.all(history.target,query='TITLE 1').total == 1
    assert service.all(history.target,query='SECRET').total == 0
    with history.connection() as db:
        with pytest.raises(sqlite3.OperationalError):
            db.execute('DELETE FROM sessions')


def test_corrupt_timestamp_is_not_exposed_or_used(history):
    with closing(sqlite3.connect(history.home/'state.db')) as db, db:
        db.execute("UPDATE messages SET timestamp='SECRET NONNUMERIC' WHERE id=1")
    items = AgentSessions({history.target:history}).recent(history.target)
    assert items[0].route.session_id == 'id-7'


def test_exact_launch_plan_requires_authorization_and_isolation(history,tmp_path):
    with pytest.raises(RoutingError,match='authorization'):
        history.launch_plan(tmp_path)
    argv,env = history.launch_plan(tmp_path,authorized=True)
    assert argv[-3:] == ['--cli','--in',str(tmp_path)]
    assert env['HERMES_HOME'] == str(history.home)
    assert 'HERMES_SESSION_ID' not in env
    assert 'OPENAI_API_KEY' not in env
    argv,_ = history.launch_plan(tmp_path,session_id='id-2',authorized=True)
    assert argv[-2:] == ['--resume','id-2']
    with pytest.raises(RoutingError,match='exact'):
        history.launch_plan(tmp_path,session_id='latest',authorized=True)
    with history.connection() as db:
        assert db.execute('SELECT count(*) FROM sessions').fetchone()[0] == 8


def test_replaced_database_and_compression_never_fallback(history,tmp_path):
    with closing(sqlite3.connect(history.home/'state.db')) as db, db:
        db.execute("UPDATE sessions SET end_reason='compression' WHERE id='id-2'")
    with pytest.raises(RoutingError,match='compression'):
        history.launch_plan(tmp_path,session_id='id-2',authorized=True)
    with ExitStack() as holder:
        if os.name == 'posix':
            # The reviewed database stays open elsewhere (a running Hermes), so its
            # inode stays allocated and the replacement gets a different identity.
            # With nothing holding it the kernel may recycle the inode and the pinned
            # (device, inode) identity cannot see the swap (REV-0623). NTFS file ids
            # carry a sequence number, and Windows cannot unlink an open file.
            holder.enter_context((history.home/'state.db').open('rb'))
        (history.home/'state.db').unlink()
        with closing(sqlite3.connect(history.home/'state.db')) as db, db:
            db.execute('CREATE TABLE replacement(id)')
        with pytest.raises(RoutingError,match='replaced'):
            history.metadata(history.target)


def test_new_clean_isolated_home_has_no_history_and_does_not_create_database(tmp_path):
    home = tmp_path/'clean'; home.mkdir(mode=0o700)
    adapter = HermesHistory(home, executable=SYNTHETIC_HERMES)
    assert adapter.metadata(adapter.target) == ()
    argv,env = adapter.launch_plan(tmp_path,authorized=True)
    assert '--resume' not in argv and env['HERMES_HOME'] == str(home)
    assert not (home/'state.db').exists()


def test_main_rejects_history_only_terminal_without_creating_onboarding_state(history,tmp_path,monkeypatch,capsys):
    from arvyx_control.onboarding_cli import main
    monkeypatch.setattr('builtins.input',lambda _:pytest.fail('must reject before prompting or launching'))
    state = tmp_path/'unused-state'
    assert main(['terminal','--hermes-home',str(history.home),'--state-dir',str(state)]) == 2
    assert 'existing native mouse frontend' in capsys.readouterr().err
    assert not state.exists()


def test_history_helper_reads_fixture_without_native_launch(history,monkeypatch,capsys):
    from arvyx_control.terminal_sessions import history_menu
    answers=iter(['all','back','search','Title 1','back','new','quit'])
    monkeypatch.setattr('builtins.input',lambda _:next(answers))
    assert history_menu(history.home) == 0
    output=capsys.readouterr().out
    assert '8 matching stored' in output and '1 matching stored' in output
    assert 'New requires explicit --workspace' in output


def test_new_confirmation_cancel_does_not_launch(history,tmp_path,monkeypatch):
    from arvyx_control.terminal_sessions import history_menu
    answers = iter(['new','cancel','quit'])
    monkeypatch.setattr('builtins.input',lambda _:next(answers))
    monkeypatch.setattr(HermesHistory,'launch',lambda *a,**k:pytest.fail('cancel must not launch'))
    assert history_menu(history.home,authorize_launch=True,workspace=tmp_path) == 0


def test_named_new_cancel_creates_no_profile(history,tmp_path,monkeypatch):
    from arvyx_control.terminal_sessions import history_menu
    answers = iter(['new','cancel','quit'])
    monkeypatch.setattr('builtins.input',lambda _:next(answers))
    monkeypatch.setattr(HermesHistory,'launch',lambda *a,**k:pytest.fail('cancel must not launch'))
    assert history_menu(history.home,authorize_launch=True,workspace=tmp_path,new_profile='amc-test-cancel') == 0


def test_exact_cold_confirmation_cancel_does_not_launch(history,tmp_path,monkeypatch):
    from arvyx_control.terminal_sessions import history_menu
    answers = iter(['search','id-2','1','cancel','quit'])
    monkeypatch.setattr('builtins.input',lambda _:next(answers))
    monkeypatch.setattr(HermesHistory,'launch',lambda *a,**k:pytest.fail('cancel must not launch'))
    assert history_menu(history.home,authorize_launch=True,workspace=tmp_path) == 0


def test_symlinked_identity_is_not_isolated(history,tmp_path):
    (history.home/'SOUL.md').symlink_to(tmp_path/'other-identity')
    with pytest.raises(RoutingError,match='symlink'):
        history.launch_plan(tmp_path,authorized=True)


def test_default_profile_exact_cold_plan_requires_separate_consent(history,tmp_path):
    history.default_home = history.home
    with pytest.raises(RoutingError, match='isolated'):
        history.launch_plan(tmp_path,authorized=True,session_id='id-2')
    argv,_ = history.launch_plan(tmp_path,authorized=True,session_id='id-2',authorize_default_resume=True)
    assert argv[-2:] == ['--resume','id-2']
    with pytest.raises(RoutingError, match='isolated'):
        history.launch_plan(tmp_path,authorized=True,authorize_default_resume=True)


def test_default_live_profile_guard_never_starts_second_writer(history,tmp_path,monkeypatch):
    import os
    from pathlib import Path
    import arvyx_control.hermes_history as module
    import arvyx_control.hermes_profile as profile_module
    history.default_home = history.home
    proc = tmp_path/'proc'; proc.mkdir()
    entry = proc/str(os.getpid()+1000000); entry.mkdir()
    (entry/'environ').write_bytes(b'HOME=/example\0')
    (entry/'cmdline').write_bytes(b'python\0hermes\0--cli\0')
    monkeypatch.setattr(profile_module,'Path',lambda p:proc if p == '/proc' else Path(p))
    monkeypatch.setattr(os,'isatty',lambda fd:True)
    monkeypatch.setattr(module.subprocess,'call',lambda *a,**k:pytest.fail('live default must not launch'))
    with pytest.raises(RoutingError,match='live or unscoped'):
        history.launch(tmp_path,authorized=True,session_id='id-2',authorize_default_resume=True,execution_policy=__import__('arvyx_control.local_executor',fromlist=['ExecutionPolicy']).ExecutionPolicy(host_uid=os.geteuid(),allow_host=True),environment='host')


def test_default_profile_launch_refused(tmp_path):
    profile = tmp_path/'.hermes'; profile.mkdir()
    with closing(sqlite3.connect(profile/'state.db')) as db, db:
        db.execute('CREATE TABLE sessions(id,title,started_at)')
    adapter = HermesHistory(profile,default_home=profile)
    with pytest.raises(RoutingError,match='isolated'):
        adapter.launch_plan(tmp_path,authorized=True)
