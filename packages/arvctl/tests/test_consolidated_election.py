"""Persistence regressions using real SQLite stores and explicit owner facts."""
import json
import sqlite3
from contextlib import closing
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from arvyx_control.cockpit_primary import PrimaryAgentRegistry, NativePrimaryAuthority
from arvyx_control.cockpit_human_binding import HumanBindings
import os

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='PTY owner, curses surface, fork or pidfd semantics are POSIX-only')

@pytest.fixture
def binding(tmp_path):
    home = tmp_path
    (home/'runtime').mkdir()
    for kind in ('agents', 'machines', 'runtimes'):
        (home/'vault/registry'/kind).mkdir(parents=True)
    for agent in ('alpha', 'beta'):
        (home/'vault/registry/agents'/(agent+'.json')).write_text(json.dumps(dict(id=agent)))
    with closing(sqlite3.connect(home/'runtime/sessions.sqlite')) as db, db:
        db.execute('CREATE TABLE native_organizers(agent TEXT, session TEXT)')
    owner = SimpleNamespace(vault=home/'vault', state=home/'events.jsonl', _human=lambda _: None)
    registry = PrimaryAgentRegistry(owner, home/'primary.sqlite', shared_secret='test-secret')
    authority = NativePrimaryAuthority(registry, lambda: [], authorization='Bearer test-secret')
    bindings = HumanBindings(home, authority)
    sessions = [dict(session='s1', host='machine', tool='hermes', conversation='c1', pid=123)]
    agents = [dict(id='alpha', machine_id='machine', harness='hermes', machine_valid=True)]
    bindings.facts = lambda: (sessions, agents)
    yield bindings, sessions, registry, authority
    registry.close()

def test_bind_disconnect_before_first_read_and_later_native(binding):
    bindings, sessions, registry, authority = binding
    bindings.bind(dict(sessions[0], agent_id='alpha', revision=0))
    sessions.clear()
    authority.source = lambda: ['beta']
    result = authority.read()
    assert result['primary_agent_id'] == 'alpha'
    assert result['primary_connected'] is False
    other = PrimaryAgentRegistry(registry.owner, bindings.home/'primary.sqlite', shared_secret='test-secret')
    try:
        assert other.snapshot()['agent_id'] == 'alpha'
        assert other.db.execute('SELECT actor,reason FROM primary_events').fetchall()[0][0] == 'human-binding'
    finally: other.close()

def test_election_error_rolls_back_both_stores(binding):
    bindings, sessions, registry, _ = binding
    registry.db.execute("CREATE TRIGGER fail_election BEFORE UPDATE ON primary_agent BEGIN SELECT RAISE(ABORT, 'injected disk failure'); END")
    with pytest.raises(sqlite3.Error):
        bindings.bind(dict(sessions[0], agent_id='alpha', revision=0))
    with closing(sqlite3.connect(bindings.path)) as db, db:
        assert db.execute('SELECT COUNT(*) FROM bindings').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM audit').fetchone()[0] == 0
    registry.db.execute('DROP TRIGGER fail_election')
    bindings.bind(dict(sessions[0], agent_id='alpha', revision=0))
    assert registry.snapshot()['agent_id'] == 'alpha'

def test_read_does_not_invent_historical_native_order(binding):
    _, _, registry, authority = binding
    authority.source = lambda: ['beta', 'alpha']
    assert authority.read()['primary_agent_id'] is None


def test_connect_election_has_audit(binding):
    _,_,registry,_=binding
    identity=SimpleNamespace(agent_id='alpha')
    with patch.object(registry,'_identity',return_value=identity): registry.connect(authorization='test-agent')
    assert registry.db.execute('SELECT actor,reason FROM primary_events').fetchone()[0]=='alpha'


def test_process_crash_inside_cross_store_commit_recovers_both(binding):
    import os
    bindings,sessions,registry,_=binding
    child=os.fork()
    if child==0:
        def crash(*args,**kwargs): os._exit(69)
        bindings.primary.registry._elect_locked=crash
        bindings.bind(dict(sessions[0],agent_id='alpha',revision=0))
        os._exit(99)
    _,status=os.waitpid(child,0)
    assert os.waitstatus_to_exitcode(status)==69
    assert registry.snapshot()['agent_id'] is None
    with closing(sqlite3.connect(bindings.path)) as db, db:
        assert db.execute('SELECT COUNT(*) FROM bindings').fetchone()[0]==0
    bindings.bind(dict(sessions[0],agent_id='alpha',revision=0))
    assert registry.snapshot()['agent_id']=='alpha'


def test_presence_source_never_holds_primary_write_lock(binding):
    """Owner connection writes must finish while a reader waits on owner I/O."""
    import threading
    bindings,sessions,registry,authority=binding
    source_entered=threading.Event(); writer_done=threading.Event(); errors=[]
    def source():
        source_entered.set()
        if not writer_done.wait(2):
            raise RuntimeError('owner -> primary / primary -> owner deadlock')
        return ['alpha']
    authority.source=source
    other=PrimaryAgentRegistry(registry.owner,bindings.home/'primary.sqlite',shared_secret='test-secret')
    def write_connection():
        source_entered.wait(2)
        try:
            with other._transaction():
                other._elect_locked('alpha',actor='native-owner',reason='connection')
        except Exception as exc: errors.append(exc)
        finally: writer_done.set()
    worker=threading.Thread(target=write_connection)
    worker.start()
    try:
        result=authority.read()
        assert result['primary_agent_id']=='alpha'
    finally:
        worker.join(4);other.close()
    assert not errors
