# Provider-free fixture only; no production identity.
import json, os, signal, subprocess, sys, tempfile, time
from pathlib import Path
from arvyx_control.cockpit_client import initialize, request
from arvyx_control.cockpit_team import TeamAuthority
from arvyx_control.cockpit_paperclip import PaperclipServer
ROOT=Path(__file__).resolve().parents[1]
home=Path(tempfile.mkdtemp(prefix='paperclip-'))
initialize(home)
log=(home/'owner.log').open('wb')
owner=subprocess.Popen([sys.executable,'-m','arvyx_control.cockpit_client','--home',str(home),'serve'],stdout=log,stderr=log)
def stop(*args): raise KeyboardInterrupt
signal.signal(signal.SIGTERM,stop)
server=None
try:
    deadline=time.monotonic()+10
    while not (home/'runtime/cockpit.sock').exists():
        if time.monotonic()>deadline or owner.poll() is not None: raise RuntimeError('Owner failed')
        time.sleep(.02)
    import secrets
    fixture_credential = secrets.token_urlsafe(32)
    team=TeamAuthority(home/'vault',home/'events.jsonl',bearer_secret=fixture_credential,authorization='Bearer '+fixture_credential)
    directory=home/'vault/registry/agents'
    directory.mkdir(parents=True,exist_ok=True)
    for agent in ('nova','rowan'):
        (directory/(agent+'.json')).write_text(json.dumps({'id':agent,'display_name':agent.title(),'machine_id':'fixture-machine','runtime_id':'fixture-runtime','scopes':['control.read','control.write']}))
        result=team.action('task-create',{'title':'Paperclip fixture '+agent,'owner':'demobot','idempotency_key':'paperclip-fixture-task-'+agent})
        assert result.status==201, result
        request(home,'open',project='demo-agent',task=result.body['task']['id'],name=agent,actor='operator')
    server=PaperclipServer(home,ROOT/'frontends/paperclip/dist',capability=os.environ['AMC_BROWSER_CAPABILITY'],team=team)
    (ROOT/'receipts/paperclip/fixture.json').write_text(json.dumps({'origin':server.origin,'fixture_only':True,'pid':os.getpid()}))
    print(server.origin,flush=True)
    server.serve_forever()
except KeyboardInterrupt: pass
finally:
    if server: server.server_close()
    owner.send_signal(signal.SIGINT)
    owner.wait(timeout=10)
    log.close()
