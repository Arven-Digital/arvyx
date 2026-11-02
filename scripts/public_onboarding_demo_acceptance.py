"""Real HTTP composition regression; no credentials printed."""
import http.client
import json
import threading
from public_onboarding_demo import make_demo

server=make_demo()
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
origin=f'http://127.0.0.1:{server.server_port}'
cookie=''
receipts=[]
def call(path,body=None,authenticated=True,override=None):
    conn=http.client.HTTPConnection('127.0.0.1',server.server_port)
    headers={'Origin':origin,'Content-Type':'application/json'}
    if authenticated:headers['Cookie']=cookie
    headers.update(override or {})
    conn.request('GET' if body is None else 'POST',path,None if body is None else json.dumps(body),headers)
    r=conn.getresponse();data=r.read();result=json.loads(data);conn.close()
    return r,result
try:
    assert call('/api/public-onboarding/agents',authenticated=False)[0].status==401
    r,_=call('/fixture-session',{});cookie=r.getheader('Set-Cookie').split(';')[0]
    assert 'HttpOnly' in r.getheader('Set-Cookie')
    assert call('/api/public-onboarding/discover',{},override={'Origin':'http://evil.invalid'})[0].status==403
    r,catalog=call('/api/public-onboarding/discover',{});assert r.status==200
    assert call('/api/public-onboarding/connect',{'candidate_id':catalog['candidates'][0]['id']})[0].status==400
    targets=[]
    for candidate in catalog['candidates']:
        r,value=call('/api/public-onboarding/connect',{'candidate_id':candidate['id'],'confirmed':True});assert r.status==200;targets.append(value['target'])
    target=targets[0]
    r,value=call('/api/public-onboarding/sessions/recent',{'target':target});assert r.status==200 and len(value['items'])==5
    items=[];cursor=None
    while True:
        r,page=call('/api/public-onboarding/sessions/all',{'target':target,'cursor':cursor,'limit':100});assert r.status==200
        items.extend(page['items']);cursor=page['next_cursor']
        if cursor is None:break
    assert len(items)==1205 and len({i['route']['session_id'] for i in items})==1205
    r,page=call('/api/public-onboarding/sessions/search',{'target':target,'query':'session-1204'});assert len(page['items'])==1
    route=page['items'][0]['route']
    r,selected=call('/api/public-onboarding/sessions/select',{'route':route,'confirmed':True});assert r.status==200 and selected['route']==route
    assert server.adapter.actions[-1][2]=='session-1204'
    r,created=call('/api/public-onboarding/agents/create',{'name':'Unique HTTP proof','harness':'fixture','confirmed':True});assert r.status==201
    r,readback=call('/api/public-onboarding/agents');assert created in readback['items']
    assert call('/api/public-onboarding/agents/create',{'name':'Unique HTTP proof','harness':'fixture','confirmed':True})[0].status==400
    print(json.dumps({'discovered':len(catalog['candidates']),'explicit_connections':len(targets),'recent':5,'all_unique':len(items),'selected':selected,'created_readback':created,'security_checks':'passed'},indent=2))
finally:
    server.shutdown();server.server_close();server.api.close()
