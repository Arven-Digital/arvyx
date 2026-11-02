import hashlib
from pathlib import Path
import pytest
from arvyx_control.agent_sessions import AgentSessions, RoutingError
from arvyx_control.terminal_sessions import ExistingArvyxAdapter


def test_existing_native_routes_and_revalidates(tmp_path):
    import json
    binding = {'authority_home': str(tmp_path), 'bindings': [{'sid':'exact','pane':'p1'}]}
    (tmp_path/'bindings.json').write_text(json.dumps(binding))
    rows = [{'id':'exact','name':'real Hermes','status':'running','project':'p'}]
    native = {'tool':'hermes','conversation':'native-exact'}
    def request(home, op, **kw):
        return rows if op == 'list' else native
    adapter = ExistingArvyxAdapter(tmp_path, tmp_path, Path('/unused'), request_fn=request)
    service = AgentSessions({adapter.target: adapter})
    item = service.recent(adapter.target)[0]
    assert item.route.session_id == 'native-exact'
    assert service.select(item.route)['pane'] == 'p1'
    native['conversation'] = 'replacement'
    with pytest.raises(RoutingError):
        service.select(item.route)
    with pytest.raises(RoutingError, match='unavailable'):
        service.new(adapter.target)


def test_missing_binding_never_falls_back(tmp_path):
    import json
    (tmp_path/'bindings.json').write_text(json.dumps({'authority_home':str(tmp_path),'bindings':[]}))
    adapter = ExistingArvyxAdapter(tmp_path,tmp_path,Path('/unused'), request_fn=lambda *a,**k: [])
    assert adapter.metadata(adapter.target) == ()


def test_one_binary_trust_policy_for_ui_and_attach(tmp_path):
    from arvyx_control.terminal_sessions import verify_native_binary, NATIVE_MOUSE_BINARY_SHA256
    from unittest.mock import patch
    binary=tmp_path/'native';binary.write_bytes(b'harmless-test-bytes')
    with patch('arvyx_control.native_artifact_policy.read_native_bytes', return_value=b'harmless-test-bytes'), patch('arvyx_control.native_artifact_policy.NATIVE_MOUSE_BINARY_SHA256', NATIVE_MOUSE_BINARY_SHA256), patch('arvyx_control.native_artifact_policy.hashlib.sha256') as digest:
        digest.return_value.hexdigest.return_value=NATIVE_MOUSE_BINARY_SHA256
        assert verify_native_binary(binary,{'binary_sha256':NATIVE_MOUSE_BINARY_SHA256}) == NATIVE_MOUSE_BINARY_SHA256
        with pytest.raises(RoutingError): verify_native_binary(binary,{'binary_sha256':'wrong'})
        with pytest.raises(RoutingError): verify_native_binary(binary,{})


def test_open_and_attach_accept_the_same_bound_mouse_build(tmp_path):
    import json
    from unittest.mock import patch
    from arvyx_control.terminal_sessions import NATIVE_MOUSE_BINARY_SHA256
    (tmp_path/'bindings.json').write_text(json.dumps(dict(authority_home=str(tmp_path),binary_sha256=NATIVE_MOUSE_BINARY_SHA256,bindings=[dict(sid='s',pane='p')])))
    binary=tmp_path/'native';binary.write_bytes(b'harmless')
    def request(home,op,**kwargs):
        return [dict(id='s',name='S',status='running')] if op=='list' else dict(tool='hermes',conversation='c')
    adapter=ExistingArvyxAdapter(tmp_path,tmp_path,binary,request_fn=request)
    route=adapter.metadata(adapter.target)[0].route
    data = b'approved fixture bytes, never executed'
    digest = hashlib.sha256(data).hexdigest()
    adapter.binding['binary_sha256'] = digest
    with patch('arvyx_control.native_artifact_policy.read_native_bytes', return_value=data), patch('arvyx_control.native_artifact_policy.NATIVE_MOUSE_BINARY_SHA256', digest), patch('sys.stdin.isatty',return_value=True),patch('sys.stdout.isatty',return_value=True),patch('arvyx_control.terminal_sessions.frontend_environment',return_value={}),patch('arvyx_control.cockpit_client.exchange', return_value=b'{"id":"amc:pane:focus","result":{"pane":{"pane_id":"p"}}}'),patch('subprocess.call',return_value=0),patch('subprocess.check_output',return_value=json.dumps(dict(result=dict(snapshot=dict(panes=[dict(pane_id='p',workspace_id='w',tab_id='t',focused=True)])))).encode()):
        assert adapter.open_ui()==0
        assert adapter.attach(route)==0
