"""Full service chain on disposable native metadata; no provider or sockets."""
import hashlib
import json
import sqlite3
from contextlib import closing
import pytest

@pytest.fixture
def services(tmp_path):
    from arvyx_control.local_onboarding import local_composition
    root=tmp_path/'onboarding';root.mkdir(mode=0o700)
    home=tmp_path/'discovery';home.mkdir()
    vault=tmp_path/'vault'
    for kind, record in [('agents',dict(id='agent-a',machine_id='machine-a',runtime_id='runtime-a')),
                          ('machines',dict(id='machine-a')),
                          ('runtimes',dict(id='runtime-a',harness='hermes'))]:
        directory=vault/'registry'/kind;directory.mkdir(parents=True)
        (directory/(record['id']+'.json')).write_text(json.dumps(record))
    profile=tmp_path/'profile';profile.mkdir(mode=0o700)
    (profile/'SOUL.md').write_text('Be careful and cite sources.\n',newline='\n')
    with closing(sqlite3.connect(profile/'state.db')) as db, db:
        db.executescript('CREATE TABLE sessions(id TEXT PRIMARY KEY,title TEXT,started_at REAL); CREATE TABLE messages(session_id TEXT,timestamp REAL);')
        db.executemany('INSERT INTO sessions VALUES(?,?,?)',[(str(i),f'Session {i}',i) for i in range(1205)])
    api=local_composition(root,vault=vault,machine_id='machine-a',capability='browser-test',discovery_home=home)
    def raw(path,body=None,token=None):
        return api.dispatch('GET' if body is None else 'POST','/api/public-onboarding/'+path,'Bearer '+(token or 'browser-test'),{} if body is None else body)
    from reviewed_action_helpers import reviewed_call
    def call(path,body=None,**kwargs):return reviewed_call(raw,path,body,**kwargs)
    yield api,call,profile,root
    api.close()

def test_manual_exact_identity_metadata_history_and_refresh(services):
    api,call,profile,root=services
    assert call('capabilities')[1]['mode']=='real-local'
    assert call('manual/connect',dict(family='hermes',path=str(profile),agent_id='agent-a',confirmed=False))[0]==400
    body=dict(family='hermes',path=str(profile),agent_id='agent-a',confirmed=True)
    assert call('manual/connect',body,token='wrong')[0]==401
    status,result=call('manual/connect',body)
    assert status==200
    target=result['target'];assert target['agent_id']=='agent-a'
    assert result['live_runtime'] is False
    page=call('sessions/all',dict(target=target,limit=97))[1]
    ids=[x['route']['session_id'] for x in page['items']]
    with closing(sqlite3.connect(profile/'state.db')) as db, db: db.execute('INSERT INTO messages VALUES(?,?)',('0',100000))
    while page['next_cursor']:
        page=call('sessions/all',dict(target=target,limit=97,cursor=page['next_cursor']))[1]
        ids.extend(x['route']['session_id'] for x in page['items'])
    assert len(ids)==len(set(ids))==1205
    assert call('sessions/recent',dict(target=target))[1]['items'][0]['route']['session_id']=='0'
    assert call('targets')[1]['items']==[target]
    route=call('sessions/recent',dict(target=target))[1]['items'][0]['route']
    assert call('sessions/select',dict(route=route,confirmed=True))[0]==200
    assert call('manual/connect',dict(body,agent_id='another'))[0]==403
    assert not list(root.rglob('*.key'))

def test_reviewed_instruction_copy_digest_consent_and_environment(services):
    api,call,profile,root=services
    result=call('manual/connect',dict(family='hermes',path=str(profile),agent_id='agent-a',confirmed=True))[1]
    source=result['instruction_source_id']
    preview=call('instructions/preview',dict(source_id=source,paths=['SOUL.md'],confirmed=True))[1]
    assert preview['files'][0]['content']=='Be careful and cite sources.\n'
    body=dict(name='New Agent',harness='hermes',environment='metadata',identity_mode='copy',source_id=source,identity_files=[{k:v for k,v in preview['files'][0].items() if k!='content'}])
    status,prepared=call('agents/prepare',body)
    assert status==200
    assert prepared['environment']=='metadata'
    consent=dict(consent_id=prepared['consent_id'],consent_sha256=prepared['sha256'],confirmed=True)
    assert call('agents/commit',dict(consent,consent_sha256='wrong'))[0]==400
    status,created=call('agents/commit',consent)
    assert status==201
    assert (root/'profiles'/created['agent_id']/'SOUL.md').read_text()==preview['files'][0]['content']
    assert call('agents/commit',consent)[0]==400
    assert call('agents/prepare',dict(body,environment='root'))[0]==501
    assert call('instructions/preview',dict(source_id=source,paths=['auth.json'],confirmed=True))[0]==400

def test_changed_instruction_after_review_cannot_be_committed(services):
    api,call,profile,root=services
    result=call('manual/connect',dict(family='hermes',path=str(profile),agent_id='agent-a',confirmed=True))[1]
    source=result['instruction_source_id']
    preview=call('instructions/preview',dict(source_id=source,paths=['SOUL.md'],confirmed=True))[1]
    prepared=call('agents/prepare',dict(name='Unique',harness='hermes',environment='metadata',identity_mode='copy',source_id=source,identity_files=[{k:v for k,v in preview['files'][0].items() if k!='content'}]))[1]
    (profile/'SOUL.md').write_text('Changed instruction')
    assert call('agents/commit',dict(consent_id=prepared['consent_id'],consent_sha256=prepared['sha256'],confirmed=True))[0]==400
    assert call('agents')[1]['items']==[]


def test_terminal_and_web_share_exact_creation_authority(services):
    from unittest.mock import patch
    from arvyx_control.shared_onboarding_cli import menu
    api,call,profile,root=services
    def shared(path,body=None):
        status,result=call(path,body)
        assert status<300,result
        return result
    choices=iter(['create','clean','yes','quit'])
    with patch('arvyx_control.onboarding_cli.choose',side_effect=lambda *a: next(choices)),patch('builtins.input',return_value='CLI Agent'),patch('builtins.print'):
        assert menu(shared)==0
    assert call('agents')[1]['items'][0]['name']=='CLI Agent'
    with closing(sqlite3.connect(root/'agents.sqlite')) as db, db:
        assert db.execute('SELECT status FROM onboarding_consents').fetchone()[0]=='completed'


def test_control_preview_copies_original_bytes_through_shared_menu(services, capsys):
    from unittest.mock import patch
    from arvyx_control.shared_onboarding_cli import menu
    api,call,profile,root=services
    original = b'Visible\x1b[2J\x1b]52;c;synthetic\x07\rhidden\n'
    (profile/'SOUL.md').write_bytes(original)
    connected=call('manual/connect',dict(family='hermes',path=str(profile),agent_id='agent-a',confirmed=True))[1]
    source=connected['instruction_source_id']
    def shared(path,body=None):
        status,result=call(path,body)
        assert status<300,result
        return result
    with patch('arvyx_control.onboarding_cli.choose',side_effect=['create','copy','yes','yes','yes','quit']), patch('builtins.input',side_effect=['Escaped Agent',source,'SOUL.md']):
        assert menu(shared)==0
    output=capsys.readouterr().out
    assert '\x1b' not in output and '\x07' not in output and '\r' not in output
    assert '\\x1b' in output and hashlib.sha256(original).hexdigest() in output
    created=call('agents')[1]['items'][0]
    assert (root/'profiles'/created['agent_id']/'SOUL.md').read_bytes()==original


def test_pairing_uses_same_store_separate_proof_and_main_confirmation(services):
    import base64
    from arvyx_control.machine_pairing_transport import PairingTransport
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    api,call,profile,root=services
    pairing=PairingTransport(root/'pairing')
    api.owners['local-owner'].extension.pairing=pairing
    assert call('capabilities')[1]['pairing'] is True
    assert call('pairing/issue',dict(confirmed=False))[0]==400
    ticket=call('pairing/issue',dict(confirmed=True))[1]
    key=Ed25519PrivateKey.generate()
    identity=PairingTransport.public(key,'disposable-remote')
    challenge=pairing.challenge(dict(identity,purpose='confirm',code=ticket['code']))
    proof=dict(challenge=challenge['challenge'],signature=base64.b64encode(key.sign(base64.b64decode(challenge['message']))).decode(),code=ticket['code'])
    claimed=pairing.prove(proof)
    assert claimed['status']=='pending_main_approval'
    pending=call('pairing/pending')[1]['claims']
    assert len(pending)==1 and pending[0]['fingerprint']==claimed['fingerprint']
    claim_id=pending[0]['claim_id'];assert isinstance(claim_id,str) and claim_id
    from arvyx_control.machine_pairing import MachineIdentity
    machine=MachineIdentity(**identity)
    assert pairing.store.check(machine).allowed is False
    # Negative control: the stable reviewed claim ID is required; omission is refused before review.
    assert call('pairing/decide',dict(fingerprint=claimed['fingerprint'],approved=True,confirmed=True))[0]==400
    assert pairing.store.check(machine).allowed is False
    decide=dict(fingerprint=claimed['fingerprint'],claim_id=claim_id,approved=True,confirmed=True)
    assert call('pairing/decide',decide)[0]==200
    assert pairing.store.check(machine).allowed is True
    with pytest.raises(ValueError): pairing.prove(proof)
    # Review now rejects an already consumed claim before the decision stage.
    assert call('pairing/decide',decide)[0]==400
