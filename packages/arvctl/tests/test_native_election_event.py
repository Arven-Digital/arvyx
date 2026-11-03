import os
import pytest
from arvyx_control.local_executor import ExecutionPolicy
import json

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='host-shell execution policy (host_uid) and the PTY owner are POSIX-only')
from types import SimpleNamespace
from arvyx_control.cockpit import LocalCockpit
from arvyx_control.cockpit_primary import PrimaryAgentRegistry


def test_native_connection_elects_before_any_presentation_read(tmp_path):
    vault=tmp_path/'vault'
    for kind, records in {'agents':[dict(id='alpha',machine_id='test-machine',runtime_id='test-runtime')],
                          'machines':[dict(id='test-machine')],
                          'runtimes':[dict(id='test-runtime',harness='gemini')]}.items():
        (vault/'registry'/kind).mkdir(parents=True)
        for record in records:
            (vault/'registry'/kind/(record['id']+'.json')).write_text(json.dumps(record))
    workspace=tmp_path/'workspace'; workspace.mkdir()
    class Harmless:
        def reserve(self, conversation): return None  # Disposable test adapter only.
        def plan(self,*args): return ['/bin/cat'], dict(PATH='/usr/bin:/bin',HOME=str(tmp_path),TERM='dumb')
    owner=LocalCockpit(tmp_path/'runtime',vault,tmp_path/'events.jsonl','test-machine',
        native_runtimes={'gemini':Harmless()},organizers={'alpha':dict(tool='gemini',conversation='test-conversation',workspace=str(workspace))}, execution_policy=ExecutionPolicy(host_uid=__import__("os").geteuid(), allow_host=True))
    try:
        sid=owner.open_organizer('alpha',actor='operator')['id']
        owner.start_native(sid,actor='operator',allow_provider=True, environment='host')
        owner.end(sid,actor='operator')
        registry=PrimaryAgentRegistry(owner,tmp_path/'events.jsonl.primary.sqlite')
        try:
            assert registry.snapshot()['agent_id']=='alpha'
            assert registry.db.execute('SELECT actor,reason FROM primary_events').fetchone()[0]=='native-owner'
        finally: registry.close()
    finally: owner.close()
