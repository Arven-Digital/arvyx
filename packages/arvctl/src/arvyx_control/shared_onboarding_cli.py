"""Terminal client of the same authenticated onboarding service used by the web."""
import getpass
import json
import re
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler


def terminal_text(value, *, multiline=False):
    """Escape controls and invisible format characters only at presentation."""
    return ''.join(c if c.isprintable() or (multiline and c == '\n')
                   else c.encode('unicode_escape').decode('ascii') for c in str(value))


def client(url, credential, *, timeout=10):
    if not 0 < timeout <= 10:
        raise ValueError('bounded request timeout required')
    parts=urlsplit(url)
    if parts.scheme!='http' or parts.hostname!='127.0.0.1' or not parts.port or parts.username or parts.password or parts.path not in ('','/') or parts.query or parts.fragment:
        raise ValueError('literal loopback HTTP endpoint required; use an approved tunnel')
    origin=f'http://127.0.0.1:{parts.port}'
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs): raise ValueError('redirect denied')
    from .http_bounds import BoundedOpener
    opener=BoundedOpener()
    def call(path, body=None, *, deadline=None):
        if path not in {'capabilities','discover','targets','manual/connect','profiles/connect','profiles/register','agents','instructions/preview',
                        'agents/prepare','agents/commit','sessions/recent','sessions/all','sessions/select',
                        'pairing/issue','pairing/pending','pairing/decide',
                        'native/revoke','native/present','native/io','native/attach','native/prepare','native/commit','native/sessions','native/open','sessions/workspaces','sessions/prepare','sessions/commit',
                        'delegations','delegations/prepare','delegations/commit','delegations/fence','delegations/fenced-execute','delegations/leaf-binding',
                        'executor/execute','executor/result','delegations/result','delegations/reconcile','actions/prepare','actions/commit'} \
                and not re.fullmatch(r'actions/attempts/[0-9a-f]{32}',path):
            raise ValueError('unsupported setup operation')
        headers={'Authorization':'Bearer '+credential,'Origin':origin}
        raw=None
        if body is not None:
            headers['Content-Type']='application/json';raw=json.dumps(body).encode()
        request=Request(origin+'/api/public-onboarding/'+path,data=raw,headers=headers)
        remaining = timeout
        if deadline is not None:
            import time
            remaining = min(timeout, deadline - time.monotonic())
            if remaining <= 0:
                raise TimeoutError('operation deadline expired; nothing retried')
        with opener.open(request,timeout=remaining) as response:
            raw = response.read(1024*1024+1)
            if len(raw) > 1024*1024:
                raise ValueError('response byte limit exceeded; nothing retried')
        # Parse only after the transport has proved message completeness and the
        # non-renewable deadline on exit. A deadline shutdown can truncate a
        # close-delimited response; it is a transport failure, never a reply.
        return json.loads(raw)
    return call


def prepare_workspace(call,target):
    from .onboarding_cli import choose
    catalog=call('sessions/workspaces',dict(target=target))
    roots=catalog['roots']
    if not roots:
        print('No workspace roots were authorized by the local operator.');return
    for i,root in enumerate(roots,1):print(f"{i}. {terminal_text(root['label'])}")
    answer=input('Authorized workspace root number, or back: ')
    if not answer.isdecimal() or not 1<=int(answer)<=len(roots):return
    mode=choose('Workspace [current / existing / create]: ',('current','existing','create'))
    selection=dict(mode=mode,root_id=roots[int(answer)-1]['id'])
    if mode=='current':selection['session_id']=input('Exact stored session ID whose workspace to use: ')
    else:selection['path']=input('Folder relative to this root: ')
    print('No native session or process starts for metadata preparation.')
    if catalog.get('native_lifecycle') and choose('Create a local shell instead? yes / skip: ',('yes','skip'))=='yes':
        environment=choose('Permissions [sandbox / host / root]: ',('sandbox','host','root'))
        acknowledged=environment=='root' and input('Type ROOT to acknowledge broad system access: ')=='ROOT'
        harness=choose('Harness [shell / hermes]: ',('shell','hermes'))
        provider_ack=harness=='hermes' and input('Type START HERMES to authorize the configured provider process: ')=='START HERMES'
        review=call('native/prepare',dict(target=target,workspace=selection,environment=environment,harness=harness,root_acknowledged=acknowledged,provider_start_acknowledged=provider_ack))
        print(terminal_text(environment+' shell in '+review['snapshot']['workspace']['path']))
        if choose('Create this exact shell session? yes / skip: ',('yes','skip'))=='yes':
            result=call('native/commit',dict(consent_id=review['consent_id'],consent_sha256=review['sha256'],confirmed=True))
            print('Created exact owner session: '+terminal_text(result['owner_session']))
        return
    preview=call('sessions/prepare',dict(target=target,workspace=selection,environment='metadata'))
    print('Prepare workspace: '+terminal_text(preview['workspace']))
    if choose('Prepare this exact reviewed workspace? yes / skip: ',('yes','skip'))=='yes':
        result=call('sessions/commit',dict(consent_id=preview['consent_id'],consent_sha256=preview['sha256'],confirmed=True))
        print('Workspace ready: '+terminal_text(result['workspace'])+'. No native session was created.')


def menu(call):
    """Explicit individual choices; no provider execution or native input."""
    from .onboarding_cli import choose
    caps=call('capabilities')
    if caps.get('reviewed_actions'):
        original=call
        def call(path,body=None):
            from .reviewed_actions import ACTIONS
            if path not in ACTIONS:return original(path,body)
            review=original('actions/prepare',dict(action=path,request=body))
            print(terminal_text(json.dumps(dict(request=review['request'],execution_binding=review.get('execution_binding')),indent=2),multiline=True))
            if choose('Confirm this exact reviewed action? yes / skip: ',('yes','skip'))!='yes':
                raise ValueError('review cancelled; no action committed')
            try:
                return original('actions/commit',dict(consent_id=review['consent_id'],consent_sha256=review['sha256'],confirmed=True))
            except HTTPError as exc:
                # An uncertain outcome is not something to retry: show the durable attempt,
                # including what the effect planned to publish (REV-0568).
                try:failure=json.loads(exc.read(65536) or b'{}')
                except ValueError:failure={}
                if isinstance(failure,dict) and failure.get('reconcile_required') is True:
                    print('Outcome uncertain; recorded attempt '+terminal_text(review['consent_id'])+':')
                    print(terminal_text(json.dumps(original('actions/attempts/'+review['consent_id']),indent=2),multiline=True))
                raise
    print('Shared AMC setup | '+terminal_text(caps['mode']))
    print('Metadata connections and reviewed profile creation. Runtime execution is unavailable.')
    while True:
        action=choose('Setup [discover / manual / create / sessions / pair / delegate / quit]: ',('discover','manual','create','sessions','pair','delegate','quit'))
        if action=='quit': return 0
        if action=='delegate':
            targets=call('capabilities').get('delegation_targets',[])
            for i,t in enumerate(targets,1):print(f"{i}. {terminal_text(t['machine'])} | {terminal_text(t['executing_agent'])} | {terminal_text(t['session'])}")
            index=input('Exact executor number, or back: ')
            if not index.isdecimal() or not 1<=int(index)<=len(targets):continue
            target=targets[int(index)-1]
            environment=choose('Environment: '+', '.join(target['environments'])+': ',tuple(target['environments']))
            goal=input('Requested work: ')
            review=call('delegations/prepare',dict(machine=target['machine'],executing_agent=target['executing_agent'],session=target['session'],environment=environment,operation='manage_agent' if environment=='metadata' else 'invoke_'+environment,goal=goal))
            print(terminal_text(json.dumps(dict(request=review['request'],execution_binding=review.get('execution_binding')),indent=2),multiline=True))
            acknowledged=environment=='root' and input('Administrator access on this exact machine. Type ROOT to acknowledge: ')=='ROOT'
            if environment=='root' and not acknowledged:continue
            if choose('Confirm this exact delegation? yes / skip: ',('yes','skip'))=='yes':
                print(json.dumps(call('delegations/commit',dict(consent_id=review['consent_id'],consent_sha256=review['sha256'],confirmed=True,root_acknowledged=acknowledged)),indent=2))
            continue
        if action=='discover':
            result=call('discover',{})
            if result.get('incomplete') or result.get('truncated'):
                print('Discovery incomplete; results are not exhaustive.')
            for candidate in result['candidates']:
                print(terminal_text(candidate['label'])+' | '+terminal_text(candidate['location'])+' | '+terminal_text(candidate['reason']))
                if candidate.get('requires_agent_id') and choose('Connect / Skip: ',('connect','skip'))=='connect':
                    agent=input('Exact registered immutable agent ID for this profile (empty to register a new identity): ').strip()
                    if not agent:
                        name=input('New identity display name: ').strip()
                        registered=call('profiles/register',dict(candidate_id=candidate['id'],display_name=name,confirmed=True))
                        print(json.dumps(registered,indent=2))
                        agent=registered['agent_id']
                    print(json.dumps(call('profiles/connect',dict(candidate_id=candidate['id'],agent_id=agent,confirmed=True)),indent=2))
            print('Use manual connection to confirm an exact registered identity and profile.')
        elif action=='manual':
            adapters=[a for a in call('capabilities').get('metadata_adapters',[])
                      if isinstance(a,dict) and isinstance(a.get('id'),str) and a['id']] or [dict(id='hermes',label='Hermes')]
            for a in adapters:print(terminal_text(a['id'])+' | '+terminal_text(a.get('label',a['id']))+' | '+terminal_text(a.get('store','read-only session metadata')))
            family=choose('Harness ['+' / '.join(a['id'] for a in adapters)+']: ',tuple(a['id'] for a in adapters))
            agent=input('Immutable registered agent ID: ')
            path=input('Absolute profile directory (Hermes profile, or the Claude Code / Codex state root): ')
            if choose('Allow metadata access to this exact profile? yes / skip: ',('yes','skip'))=='yes':
                print(json.dumps(call('manual/connect',dict(family=family,agent_id=agent,path=path,confirmed=True)),indent=2))
        elif action=='create':
            body=dict(name=input('Unique agent name: '),harness='hermes',environment='metadata',identity_mode='clean',identity_files=[])
            print('Sandbox, host and root execution unavailable. Metadata profile creation only.')
            if choose('Instructions [clean / copy]: ',('clean','copy'))=='copy':
                sources=call('capabilities').get('instruction_sources',[])
                print(json.dumps(sources,indent=2))
                source=input('Exact source ID: ')
                paths=[p.strip() for p in input('Selected instruction filenames, comma separated: ').split(',')]
                files=[]
                if not paths or len(set(paths))!=len(paths):
                    raise ValueError('explicit distinct instruction selection required')
                for path in paths:
                    import hashlib
                    offset=0;chunks=[];digest=None
                    while True:
                        reviewed=call('instructions/preview',dict(source_id=source,paths=[path],confirmed=True,offset=offset))
                        item=reviewed['files'][0]
                        if item['path']!=path or (digest is not None and digest!=item['approved_sha256']):
                            raise ValueError('instruction changed; review again')
                        digest=item['approved_sha256'];chunks.append(item['content'])
                        next_offset=item['next_offset']
                        if next_offset is None:break
                        if next_offset!=offset+len(item['content']) or next_offset<=offset:
                            raise ValueError('invalid instruction page')
                        offset=next_offset
                    content=''.join(chunks)
                    if hashlib.sha256(content.encode()).hexdigest()!=digest:
                        raise ValueError('instruction digest mismatch; review again')
                    print(terminal_text(path)+'\n'+terminal_text(content,multiline=True)+'\nSHA256: '+terminal_text(digest))
                    if choose('Approve this exact instruction? yes / skip: ',('yes','skip'))=='yes':
                        files.append(dict(path=path,approved_sha256=digest))
                body.update(identity_mode='copy',source_id=source,identity_files=files)
            preview=call('agents/prepare',body)
            print(json.dumps(preview['request'],indent=2))
            if choose('Create this exact reviewed profile? yes / skip: ',('yes','skip'))=='yes':
                print(json.dumps(call('agents/commit',dict(consent_id=preview['consent_id'],consent_sha256=preview['sha256'],confirmed=True)),indent=2))
        elif action=='sessions':
            targets=call('targets')['items'];print(json.dumps(targets,indent=2))
            index=input('Destination number (starting at 1), or back: ')
            if not index.isdecimal() or not 1<=int(index)<=len(targets): continue
            target=targets[int(index)-1]
            mode=choose('History [last5 / all / search / new]: ',('last5','all','search','new'))
            if mode=='new':
                prepare_workspace(call,target)
                continue
            query=input('Title or exact ID search: ') if mode=='search' else ''
            cursor=None
            while True:
                page=call('sessions/recent',dict(target=target)) if mode=='last5' else call('sessions/all',dict(target=target,query=query,limit=20,cursor=cursor))
                for i,item in enumerate(page['items'],1): print(f"{i}. {terminal_text(item['title'])} | {terminal_text(item['route']['session_id'])}")
                answer=input('Inspect number / next / back: ')
                if answer=='next' and page.get('next_cursor'):
                    cursor=page['next_cursor'];continue
                if answer.isdecimal() and 1<=int(answer)<=len(page['items']):
                    route=page['items'][int(answer)-1]['route']
                    print(json.dumps(call('sessions/select',dict(route=route,confirmed=True)),indent=2))
                break
        elif action=='pair':
            if not caps.get('pairing'):
                print('Pairing unavailable; explicitly enable pairing on the main listener.');continue
            decision=choose('Pairing [issue / pending / approve / deny / back]: ',('issue','pending','approve','deny','back'))
            if decision=='issue': print(json.dumps(call('pairing/issue',dict(confirmed=True)),indent=2))
            if decision=='pending': print(json.dumps(call('pairing/pending'),indent=2))
            if decision in ('approve','deny'):
                claims=call('pairing/pending')['claims']
                for i,claim in enumerate(claims,1):
                    print(f"{i}. {terminal_text(claim['name'])} | {terminal_text(claim['fingerprint'])} | claim {terminal_text(claim['claim_id'])} | expires {claim['expires']}")
                selected=input('Exact claim number after comparing the intended remote fingerprint, or back: ')
                if not selected.isdecimal() or not 1<=int(selected)<=len(claims):continue
                claim=claims[int(selected)-1]
                if choose('Confirm this decision? yes / skip: ',('yes','skip'))=='yes':
                    print(json.dumps(call('pairing/decide',dict(claim_id=claim['claim_id'],fingerprint=claim['fingerprint'],approved=decision=='approve',confirmed=True)),indent=2))


def main(url):
    return menu(client(url,getpass.getpass('Existing browser setup capability (kept in memory): ')))
