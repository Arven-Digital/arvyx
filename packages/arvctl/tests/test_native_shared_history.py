"""Native client config uses existing shared authority; process boundary is a recorder."""
import json
from pathlib import Path
from unittest.mock import patch
import pytest
from arvyx_control.terminal_sessions import ExistingArvyxAdapter

@pytest.fixture
def native(tmp_path):
    (tmp_path/'bindings.json').write_text(json.dumps(dict(authority_home=str(tmp_path),binary_sha256='test-digest',bindings=[dict(sid='s',pane='p')])))
    def request(home,op,**kw):return [dict(id='s',name='Running',status='running')] if op=='list' else dict(tool='hermes',conversation='existing')
    return ExistingArvyxAdapter(tmp_path,tmp_path,Path('/unused-test-binary'),request_fn=request)

def test_native_service_config_reaches_only_recorded_client_boundary(native):
    config=dict(origin='http://127.0.0.1:12345',capability='fixture-capability')
    with patch('arvyx_control.terminal_sessions.VerifiedNative') as verify,patch('sys.stdin.isatty',return_value=True),patch('sys.stdout.isatty',return_value=True),patch('arvyx_control.terminal_sessions.frontend_environment',return_value={}),patch('subprocess.call',return_value=0) as process:
        sealed = verify.return_value.__enter__.return_value
        sealed.invoke.side_effect = lambda operation, args, **kwargs: operation(['/proc/self/fd/fixture', *args], pass_fds=(123,), **kwargs)
        assert native.open_ui(onboarding=config)==0
        verify.assert_called_once_with(native.binary,native.binding,required_capability='onboarding-v1')
        assert json.loads(process.call_args.kwargs['env']['AMC_ONBOARDING_RPC'])==config

@pytest.mark.parametrize('origin',['https://127.0.0.1:12345','http://localhost:12345','http://127.0.0.1:12345/private','http://127.0.0.1:12345?redirect=1'])
def test_shared_native_client_refuses_noncanonical_endpoints_before_process(native,origin):
    with patch('subprocess.call') as process:
        with pytest.raises(ValueError):native.open_ui(onboarding=dict(origin=origin,capability='fixture-capability'))
        process.assert_not_called()
