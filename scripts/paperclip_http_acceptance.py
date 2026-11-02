# Exercise the running disposable Paperclip fixture, never production.
import argparse, hashlib, json, os, re, urllib.request, urllib.error
from urllib.parse import urlsplit
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description='Explicit disposable loopback fixture only; never production.')
parser.add_argument('--fixture-origin',required=True)
args=parser.parse_args()
fixture=json.loads((ROOT/'receipts/paperclip/fixture.json').read_text())
origin=args.fixture_origin
parts=urlsplit(origin)
if fixture.get('fixture_only') is not True or fixture.get('origin') != origin or parts.scheme != 'http' or parts.hostname != '127.0.0.1' or not parts.port or parts.username or parts.password or parts.path or parts.query or parts.fragment:
    parser.error('explicit origin must match the disposable loopback fixture receipt')
key=os.environ.get('AMC_BROWSER_CAPABILITY','')
if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}',key):
    parser.error('supply the disposable fixture browser capability via AMC_BROWSER_CAPABILITY')
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl): return None
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
def call(path,auth=True,method='GET'):
    request=urllib.request.Request(origin+path,method=method,headers={'Authorization':'Bearer '+key} if auth else {})
    try:
        with opener.open(request,timeout=10) as r: return r.status,r.read(1024*1024+1),dict(r.headers)
    except urllib.error.HTTPError as r:
        with r: return r.code,r.read(1024*1024+1),dict(r.headers)
checks=[]
assert call('/api/snapshot',False)[0]==403
checks.append('Unauthorized snapshot refused')
status,body,_=call('/api/snapshot')
assert status==200
snapshot=json.loads(body)
assert len(snapshot['team']['tasks']['tasks'])==2
assert len(snapshot['local']['sessions'])==2
checks.append('Snapshot reads two fixture tasks and two exact owner sessions')
for asset in ('arvyx-wordmark.png','favicon.png'):
    status,body,_=call('/assets/'+asset,False)
    expected=(ROOT/'packages/arvctl/src/arvyx_control/static/brand'/asset).read_bytes()
    assert status==200 and body==expected
    checks.append('Original '+asset+' bytes preserved')
for path in ('/api/select','/api/team/action','/api/end'):
    assert call(path,method='POST')[0]==405
checks.append('Mutation endpoints refused')
assert call('/../package.json')[0]==404
checks.append('Non-distribution path refused')
status,body,headers=call('/',False)
assert status==200 and b'type="module"' in body
assert "script-src 'self'" in headers['Content-Security-Policy']
checks.append('Built React entrypoint served with same-origin-only script CSP')
(ROOT/'receipts/paperclip/http-checks.json').write_text(json.dumps({'fixture_only':True,'passed':len(checks),'checks':checks},indent=2)+'\n')
print(json.dumps({'passed':len(checks),'checks':checks},indent=2))
