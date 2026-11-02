"""Native pane API recorder only; no native binary, provider or input executes."""
import json,sqlite3
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from arvyx_control.native_presentation import NativePresentation


@pytest.fixture(autouse=True)
def original_review_consent():
    from arvyx_control.reviewed_actions import consent_scope
    import time
    with consent_scope(time.time()+300):yield


def setup(tmp_path):
    home=tmp_path/'owner';home.mkdir();frontend=tmp_path/'frontend';frontend.mkdir()
    binding=dict(authority_home=str(home),binary_sha256='f'*64,bindings=[])
    (frontend/'bindings.json').write_text(json.dumps(binding))
    db=sqlite3.connect(tmp_path/'attempts.db');state=dict(panes=[],calls=[])
    class Native:
        digest='f'*64
        def __init__(self,*args,**kwargs):assert kwargs['required_capability']=='onboarding-v1'
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def invoke(self,operation,args,**kwargs):
            state['calls'].append(args);command=args[2:]
            if command==['api','snapshot']:result=dict(snapshot=dict(panes=state['panes']))
            elif command[:2]==['workspace','create']:
                state['panes']=[dict(pane_id='w_1-1',workspace_id='w_1',tab_id='w_1:1',focused=False)]
                result=dict(root_pane=state['panes'][0],workspace=dict(workspace_id='w_1'),tab=dict(tab_id='w_1:1'))
            else:result={}
            return json.dumps(dict(result=result)).encode()
    proof=dict(owner_session='sid',conversation='native-id',owner_incarnation='owner-boot',epoch=0)
    target=dict(machine_id='m',agent_id='a',workspace_id='profile',connection_id='c')
    producer=SimpleNamespace(verify=lambda observed,route:None,record_pane=lambda *args:None)
    presentation=NativePresentation(home,frontend,tmp_path/'not-executed',db)
    return presentation,state,Native,proof,target,producer


def test_new_pane_has_exact_bridge_then_focus_and_reopen_never_duplicates(tmp_path):
    presentation,state,Native,proof,target,producer=setup(tmp_path)
    def focus(frontend,pane):
        for row in state['panes']:row['focused']=row['pane_id']==pane
    with patch('arvyx_control.native_presentation.VerifiedNative',Native),patch('arvyx_control.native_presentation._focus_pane',side_effect=focus):
        result=presentation.present(proof,target,producer=producer)
        assert result['pane_id']=='w_1-1' and result['native_focus_observed']
        run=[c for c in state['calls'] if c[2:4]==['pane','run']][0]
        assert 'arvyx_control.cockpit_arvyx' in run[-1] and '--native-proof' in run[-1]
        presentation.present(proof,target,producer=producer)
        assert len([c for c in state['calls'] if c[2:4]==['workspace','create']])==1


def test_lost_focus_ack_is_durable_and_never_creates_second_tab(tmp_path):
    presentation,state,Native,proof,target,producer=setup(tmp_path)
    with patch('arvyx_control.native_presentation.VerifiedNative',Native),patch('arvyx_control.native_presentation._focus_pane',side_effect=OSError('lost focus reply')):
        with pytest.raises(OSError):presentation.present(proof,target,producer=producer)
        with pytest.raises(PermissionError):presentation.present(proof,target,producer=producer)
    assert len([c for c in state['calls'] if c[2:4]==['workspace','create']])==1
    assert presentation.db.execute('SELECT status FROM native_presentations').fetchone()[0]=='ambiguous'


def test_original_launch_adapter_accepts_local_sessions_without_fake_tasks():
    from arvyx_control.cockpit_arvyx import launch_plan
    result=launch_plan([dict(id='a'*32,name='local-shell',kind='local',project=None,task=None)])
    assert result[0]['kind']=='local' and result[0]['project'] is None
    with pytest.raises(ValueError):launch_plan([dict(id='a'*32,name='local',kind='local',project='fake',task='fake')])
