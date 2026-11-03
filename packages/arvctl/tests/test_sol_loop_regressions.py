"""Exact Sol review regressions; synthetic data, no provider or owner startup."""
import io
import json
import os
from pathlib import Path
import sqlite3
from contextlib import closing
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch
from email.message import Message
import pytest
from arvyx_control import api, security, cockpit_archive, onboarding_cli
from arvyx_control.agent_sessions import AgentSessions, SessionTarget, SessionRoute, SessionMetadata, RoutingError
from safe_mcp_bridge import cli as bridge


def test_image_magic_does_not_exempt_payload(tmp_path):
    p = tmp_path/'unknown.png'
    p.write_bytes(b'\x89PNG\r\n\x1a\n'+b'\0'*4+('sk-'+'a'*24).encode())
    assert not security.is_verified_image(p)


def test_standalone_bridge_detector_parity():
    assert bridge._FALLBACK_SECRET_RE.pattern == security.SECRET_RE.pattern
    code = "from safe_mcp_bridge.cli import _redact_secret_shapes; import json; print(json.dumps(_redact_secret_shapes(['glpat-'+'a'*24, 'npm_'+'b'*24, 'pypi-'+'c'*24])))"
    env = dict(os.environ, PYTHONPATH=str(Path(bridge.__file__).parents[1]))
    result = subprocess.run([sys.executable, '-S', '-c', code], env=env, capture_output=True, text=True, check=True)
    value, count = json.loads(result.stdout)
    assert count == 3 and all(v == '[REDACTED-SECRET]' for v in value)


def test_suffix_present_scanner_is_bounded():
    code = "from arvyx_control.security import contains_literal_secret; assert not contains_literal_secret('a.'*16000+' (@arven.digital)'); assert contains_literal_secret('a.'*16000+'x@arven.digital')"
    subprocess.run([sys.executable, '-c', code], check=True, timeout=2)


@pytest.mark.parametrize('headers,raw', [([('Content-Length','100')], b'{}'), ([('Content-Length','2'),('Content-Length','3')],b'{}'), ([('Content-Length','2'),('Transfer-Encoding','chunked')],b'{}'), ([('Content-Length','13')],b'{"a":1,"a":2}')])
def test_api_rejects_ambiguous_or_incomplete_intake(headers, raw, tmp_path):
    handler = api.make_handler(tmp_path, tmp_path/'state')
    obj = object.__new__(handler)
    obj.path = '/anything'; obj.headers = Message()
    for k,v in headers: obj.headers[k] = v
    obj.rfile = io.BytesIO(raw); obj.connection = Mock()
    obj._preauthorize = Mock(return_value=True); obj._handle = Mock(); obj._write = Mock()
    obj.do_POST()
    obj._handle.assert_not_called()
    assert obj._write.call_args[0][0].status == 400


def test_bridge_framing_failure_is_per_request():
    config = {'target': {'url':'http://127.0.0.1:1'}, 'policy': {'allow_tools':[]}}
    # The healthy upstream reply must itself be a correlated JSON-RPC 2.0
    # response; the bridge rejects envelope-less/uncorrelated replies.
    with patch.object(bridge._OPENER, 'open', side_effect=[ValueError('incomplete body'), Mock(__enter__=Mock(return_value=SimpleNamespace(read=lambda n:b'{"jsonrpc":"2.0","id":2,"result":{}}')), __exit__=Mock(return_value=False))]) as opener:
        first = bridge._handle_line(config, '{"jsonrpc":"2.0","id":1,"method":"ping"}')
        second = bridge._handle_line(config, '{"jsonrpc":"2.0","id":2,"method":"ping"}')
    assert first == {'jsonrpc':'2.0','id':1,'error':{'code':-32000,
        'message':'upstream transport, framing or decoding failure; nothing retried'}}
    assert second == {'jsonrpc':'2.0','id':2,'result':{}}
    assert opener.call_count == 2


def test_bridge_real_leaf_incomplete_response_survives(monkeypatch):
    from safe_mcp_bridge import http_bounds
    from contextlib import redirect_stdout
    class Response:
        status = 200
        _method = 'POST'
        chunked = False
        length = 100
        headers = Message()
        headers['Content-Length'] = '100'
        def read(self, n): return b'{}'
        def close(self): pass
    class Connection:
        def __init__(self, *a, **k): self.sock = Mock()
        def connect(self): pass
        def request(self, *a, **k): pass
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setattr(http_bounds.http.client, 'HTTPConnection', Connection)
    config = {'target': {'url':'http://127.0.0.1:1'}, 'policy': {'allow_tools':[]}}
    monkeypatch.setattr(sys, 'stdin', io.StringIO('{"jsonrpc":"2.0","id":1,"method":"ping"}\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n'))
    output = io.StringIO()
    with redirect_stdout(output): assert bridge._run(config) == 0
    replies = [json.loads(line) for line in output.getvalue().splitlines()]
    assert [r['id'] for r in replies] == [1,2]
    assert all(r['error']['code'] == -32000 for r in replies)


def test_query_byte_budget_is_visible():
    target = SessionTarget('m','a','w','c')
    adapter = SimpleNamespace(target=target, connected=True, metadata=lambda t:[])
    with pytest.raises(RoutingError, match='incomplete'):
        AgentSessions({target:adapter}).all(target,query='x'*8192)


def test_oversized_adapter_metadata_is_not_retained():
    target = SessionTarget('m','a','w','c')
    item = SessionMetadata(SessionRoute(target,'s'), 'x'*(2*1024*1024), 1)
    adapter = SimpleNamespace(target=target, connected=True, metadata=lambda t:[item])
    sessions = AgentSessions({target:adapter})
    with pytest.raises(RoutingError, match='incomplete'): sessions.all(target)
    assert not sessions._snapshots


def test_sqlite_oversized_title_fails_before_metadata(tmp_path):
    from arvyx_control.hermes_history import HermesHistory
    home = tmp_path/'isolated'; home.mkdir(mode=0o700)
    with closing(sqlite3.connect(home/'state.db')) as db, db:
        db.execute('CREATE TABLE sessions(id TEXT PRIMARY KEY,title TEXT,started_at REAL)')
        db.execute('INSERT INTO sessions VALUES(?,?,?)', ('s','x'*(2*1024*1024),1))
    history = HermesHistory(home)
    with pytest.raises(RoutingError, match='incomplete'): history.metadata(history.target)


def test_query_bytes_are_not_retained():
    target = SessionTarget('m','a','w','c')
    adapter = SimpleNamespace(target=target, connected=True, metadata=lambda t:[])
    service = AgentSessions({target:adapter})
    with pytest.raises(RoutingError, match='incomplete'): service.all(target, query='q'*10000)
    assert not service._snapshots


def test_metadata_page_and_snapshot_byte_budgets():
    target = SessionTarget('m','a','w','c')
    items = [SessionMetadata(SessionRoute(target,str(i)), '\\'*4096, 1) for i in range(500)]
    adapter = SimpleNamespace(target=target, connected=True, metadata=lambda t:items)
    service = AgentSessions({target:adapter})
    page = service.all(target,limit=1000)
    assert len(json.dumps(page.to_dict()).encode()) < 1024*1024
    assert page.next_cursor
    for i in range(6): service.all(target,query='')
    assert sum(v[4] for v in service._snapshots.values()) <= 16*1024*1024


def test_image_exact_pin_rejects_mutation(tmp_path):
    source = Path(security.__file__).parent/'static/brand/favicon.png'
    assert security.is_verified_image(source)
    changed = tmp_path/'changed.png'; changed.write_bytes(source.read_bytes()+b'extra')
    assert not security.is_verified_image(changed)


def test_email_matching_preserves_canonical_semantics():
    import itertools
    alphabet = 'a._-éİ1 '
    for n in range(4):
        for chars in itertools.product(alphabet, repeat=n):
            text = ''.join(chars)+'@arven.digital'
            assert security.contains_literal_secret(text) == bool(security.SECRET_RE.search(text))


def test_idle_archive_pending_uses_index():
    owner = SimpleNamespace(db=sqlite3.connect(':memory:'))
    cockpit_archive._capture_schema(owner)
    owner.db.executemany('INSERT INTO work_capture(event_id,session,run,text,delivered) VALUES(?,?,?,?,1)', ((str(i),'s','r','x') for i in range(20000)))
    steps=[]; owner.db.set_progress_handler(lambda: steps.append(1) or 0, 100)
    assert owner.db.execute('SELECT sequence FROM work_capture WHERE delivered=0 ORDER BY sequence LIMIT 100').fetchall() == []
    assert len(steps) < 10


def test_history_forwards_explicit_options(tmp_path):
    home=tmp_path/'h'; workspace=tmp_path/'w'
    with patch('arvyx_control.terminal_sessions.history_menu', return_value=0) as menu:
        assert onboarding_cli.main(['history','--hermes-home',str(home),'--workspace',str(workspace),'--authorize-native-launch','--authorize-default-resume','--new-hermes-profile','blank']) == 0
    assert menu.call_args.kwargs['workspace'] == workspace
    assert menu.call_args.kwargs['authorize_launch'] is True
    assert menu.call_args.kwargs['authorize_default_resume'] is True
    assert menu.call_args.kwargs['new_profile'] == 'blank'


def test_hot_checkpoint_is_not_curated_memory(tmp_path):
    from arvyx_control.index import load_index
    from arvyx_control.recall import excerpt
    agent = tmp_path/'agents'/'other'; agent.mkdir(parents=True)
    checkpoint = agent/'SESSION-STATE.md'; checkpoint.write_text('Synthetic hot checkpoint uniquecontext')
    assert not any(c.relative_path.endswith('SESSION-STATE.md') for c in load_index(tmp_path))
    with pytest.raises(ValueError, match='forbidden'):
        excerpt(tmp_path,'agents/other/SESSION-STATE.md','1-1')


def test_digest_checkpoint_requires_session_scope(tmp_path):
    from arvyx_control.auth import Identity
    identity = Identity('reader',frozenset({'control.read','memory.read'}),'agent')
    with patch.object(api,'resolve_identity',return_value=identity), patch.object(api,'build_digest') as digest:
        digest.return_value.to_dict.return_value = {}
        result = api._handle_api_request('GET','/digest',{},tmp_path,tmp_path/'state',authorization='Bearer synthetic')
        assert result.status == 200
        assert digest.call_args.kwargs['include_session'] is False


@pytest.mark.parametrize('standalone',[False,True])
def test_redaction_suffix_present_is_bounded(standalone):
    code = "from arvyx_control.security import redact_secrets; assert redact_secrets('a.'*16000+' (@arven.digital)').endswith(' (@arven.digital)')"
    # -S disables site (and with it editable-install .pth paths), so name the
    # source root explicitly; CI's editable install alone cannot satisfy -S.
    env = dict(os.environ, PYTHONPATH=str(Path(security.__file__).parents[1]))
    if standalone:
        code = "from safe_mcp_bridge.cli import _redact_secret_shapes; text='a.'*16000+' (@arven.digital)'; assert _redact_secret_shapes(text)==(text,0)"
        env['PYTHONPATH'] = str(Path(bridge.__file__).parents[1])
    subprocess.run([sys.executable,'-S','-c',code],env=env,check=True,timeout=2)


@pytest.mark.parametrize('payload',[{'id':1,'method':[]},{'id':1,'method':'tools/call','params':{'name':[]}}])
def test_bridge_malformed_envelope_is_per_request(payload):
    config={'target':{'url':'http://127.0.0.1:1'},'policy':{'allow_tools':[]}}
    with patch.object(bridge,'_post_json',return_value={'jsonrpc':'2.0','id':2,'result':{}}) as post:
        first=bridge._handle_line(config,json.dumps(payload))
        second=bridge._handle_line(config,'{"jsonrpc":"2.0","id":2,"method":"ping"}')
    assert first['error']['code'] in {-32600,-32602}
    assert second=={'jsonrpc':'2.0','id':2,'result':{}} and post.call_count==1


def test_bridge_deep_json_is_per_request():
    from unittest.mock import MagicMock
    response=MagicMock(); response.read.return_value=('['*1100+'0'+']'*1100).encode()
    opener=MagicMock();opener.open.return_value.__enter__.return_value=response
    config={'target':{'url':'http://127.0.0.1:1'},'policy':{'allow_tools':[]}}
    with patch.object(bridge,'_OPENER',opener):
        first=bridge._handle_line(config,'{"jsonrpc":"2.0","id":1,"method":"ping"}')
    assert first['error']['code']==-32000


def test_configured_secret_refusal_uses_decoded_strings(monkeypatch,capsys):
    value='synthetic'+chr(34)+'credential'+chr(92)+'tail'
    monkeypatch.setenv('SYNTHETIC_ESCAPED_VALUE',value)
    config={'auth':{'env':'SYNTHETIC_ESCAPED_VALUE'},'redaction':{'fail_on_secret_output':True}}
    withheld = {'jsonrpc':'2.0','id':None,'error':{'code':-32003,
        'message':'response withheld; outcome uncertain; nothing retried'}}
    escaped = json.dumps(value)[1:-1]
    for response in [{'jsonrpc':'2.0','id':7,'result':value},{'jsonrpc':'2.0','id':7,'result':{value:'x'}}]:
        # Control: shape redaction alone does not catch this synthetic value,
        # so withholding below comes from the decoded configured-secret check.
        bridge._emit_response({'auth':config['auth'],'redaction':{'fail_on_secret_output':False}},response)
        assert escaped in capsys.readouterr().out
        bridge._emit_response(config,response)
        out = capsys.readouterr().out
        # Refusal emits one value-free, uncorrelated frame and nothing else.
        assert [json.loads(line) for line in out.splitlines()] == [withheld]
        assert value not in out and escaped not in out
    bridge._emit_response(config,{'jsonrpc':'2.0','id':8,'result':'safe next frame'})
    assert json.loads(capsys.readouterr().out) == {'jsonrpc':'2.0','id':8,'result':'safe next frame'}


def test_private_names_in_sanctioned_pointers_are_scanned(tmp_path,monkeypatch):
    import importlib.util
    import re
    from arvyx_control import audit
    source = Path(__file__).resolve().parents[3]/'scripts/private_context_scan.py'
    spec=importlib.util.spec_from_file_location('sol_scanner',source)
    scanner=importlib.util.module_from_spec(spec);spec.loader.exec_module(scanner)
    p=tmp_path/'public.md';p.write_text('secret://vault/private-agent/key')
    for module in [audit,scanner]:
        monkeypatch.setattr(module,'private_name_patterns',lambda *a,**k:[re.compile('private-agent')])
        monkeypatch.setattr(module,'private_name_exempt_paths',lambda r:None)
    monkeypatch.setattr(audit,'iter_source_files',lambda r:[p])
    monkeypatch.setattr(scanner,'_iter_scan_files',lambda r:[p])
    assert not audit._private_context_check(tmp_path).ok
    assert scanner.scan(tmp_path)[0]


def test_native_transcript_rejects_oversized_source_before_return(tmp_path):
    from arvyx_control.cockpit_native_runtime import NativeRuntime
    from arvyx_control.hermes_profile import HermesProfile
    store=tmp_path/'state.db'
    with closing(sqlite3.connect(store)) as db, db:
        db.execute('CREATE TABLE messages(id INTEGER,role TEXT,content TEXT,session_id TEXT)')
        db.execute('INSERT INTO messages VALUES(1,?,?,?)',('assistant','x'*(2*1024*1024),'s'))
    runtime=object.__new__(NativeRuntime);runtime.tool='hermes';runtime.store=store
    runtime.profile=HermesProfile(store.parent,store)
    with pytest.raises(ValueError,match='byte budget'):runtime.transcript('s')


def test_capture_finish_rechecks_shared_capacity(monkeypatch):
    import threading
    monkeypatch.setattr(cockpit_archive,'CAPTURE_CAPACITY',20000)
    owner=SimpleNamespace(db=sqlite3.connect(':memory:'),lock=threading.RLock(),_get=lambda sid:{})
    first=cockpit_archive.WorkCapture(owner,'s',run='first')
    second=cockpit_archive.WorkCapture(owner,'s',run='second')
    for _ in range(80):first.feed(b'x'*100)
    # Fill the shared quota using persistent text plus per-record metadata.
    while True:
        try:
            second.feed(b'y\n')
        except BufferError:
            break
    with pytest.raises(BufferError):first.finish()
    assert len(first.buffer)==8000
    assert owner.db.execute('SELECT bytes FROM capture_accounting').fetchone()[0]<=20000
    assert owner.db.execute("SELECT status FROM capture_runs WHERE run='first'").fetchone()[0]=='open'
