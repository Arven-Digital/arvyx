import json
import os
import sqlite3
from contextlib import closing
from unittest.mock import patch
import pytest
from test_consolidated_election import binding
from arvyx_control.cockpit_human_binding import HumanBindings

@pytest.mark.skipif(os.name != 'posix', reason='fork-based crash fixture is POSIX-only')
def test_crash_before_enrollment_audit_recovers_only_its_fresh_files(binding):
    bindings,sessions,registry,_=binding
    vault=bindings.home/'vault/registry'
    (vault/'machines/machine.json').write_text(json.dumps(dict(id='machine')))
    before={p for p in vault.rglob('*.json')}
    payload=dict(sessions[0],display_name='Fresh Agent')
    child=os.fork()
    if child==0:
        count=[0];original=json.dump
        def crash_after_write(record,stream,**kwargs):
            original(record,stream,**kwargs);stream.flush();os.fsync(stream.fileno())
            count[0]+=1
            if count[0]==2: os._exit(67)
        try:
            with patch('json.dump',side_effect=crash_after_write): bindings.enroll(payload)
        finally: os._exit(99)
    _,status=os.waitpid(child,0)
    assert os.waitstatus_to_exitcode(status)==67
    assert len(set(vault.rglob('*.json'))-before)==2
    HumanBindings(bindings.home,bindings.primary)
    assert set(vault.rglob('*.json'))==before
    with closing(sqlite3.connect(bindings.path)) as db, db:
        assert db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]==0
        assert db.execute('SELECT status FROM enrollment_journal').fetchone()[0]=='rolled-back'
