"""Exact registry compatibility must never follow aliases outside its authority."""
from contextlib import closing
import json
import pytest
from arvyx_control.cockpit_primary import compatible_native_identity


def registry(tmp_path):
    vault=tmp_path/'vault'
    for kind,record in [('agents',dict(id='agent',machine_id='machine',runtime_id='runtime')),('machines',dict(id='machine')),('runtimes',dict(id='runtime',harness='hermes'))]:
        root=vault/'registry'/kind;root.mkdir(parents=True);(root/(record['id']+'.json')).write_text(json.dumps(record))
    return vault


def test_symlinked_registry_cannot_attest_native_identity(tmp_path):
    vault=registry(tmp_path)
    assert compatible_native_identity(vault,'agent','machine','hermes')
    record=vault/'registry/runtimes/runtime.json';outside=tmp_path/'outside.json';record.rename(outside);record.symlink_to(outside)
    assert not compatible_native_identity(vault,'agent','machine','hermes')


@pytest.mark.parametrize('payload',['['*1200+'0'+']'*1200,'x'*300000,'[]','null'],ids=['deep','oversize','array','null'])
def test_malformed_registry_is_unavailable_without_crashing_primary(tmp_path,payload):
    vault=registry(tmp_path);(vault/'registry/agents/agent.json').write_text(payload)
    assert compatible_native_identity(vault,'agent','machine','hermes') is False


def test_human_facts_skip_deep_bad_registry_without_losing_valid_agents(tmp_path):
    import sqlite3
    from unittest.mock import patch
    from arvyx_control.cockpit_human_binding import HumanBindings
    home=tmp_path/'home';home.mkdir();vault=registry(home);(home/'runtime').mkdir()
    database=home/'runtime/sessions.sqlite'
    with closing(sqlite3.connect(database)) as db, db:
        db.executescript('CREATE TABLE identity(host TEXT,state TEXT,vault TEXT);CREATE TABLE native_bindings(session TEXT,tool TEXT,conversation TEXT);')
        db.execute('INSERT INTO identity VALUES(?,?,?)',('machine',str(home/'events.jsonl'),str(vault)))
    journal=home/'runtime/bindings.sqlite'
    with closing(sqlite3.connect(journal)) as db, db:db.execute('CREATE TABLE enrollment_journal(agent_id TEXT,status TEXT)')
    (vault/'registry/agents/bad.json').write_text('['*1200+'0'+']'*1200)
    bindings=HumanBindings.__new__(HumanBindings);bindings.home=home;bindings.path=journal
    current=dict(host='machine',state=str(home/'events.jsonl'),sessions=[])
    with patch('arvyx_control.cockpit_human_binding.request',return_value=current):
        sessions,agents=bindings.facts()
    assert sessions==[] and [a['id'] for a in agents]==['agent']
