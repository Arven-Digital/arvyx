"""Isolated same-origin onboarding fixture. No workspace owner or provider access."""
import argparse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
from arvyx_control.cockpit_paperclip import asset_content_type
import tempfile
from arvyx_control.public_onboarding_api import fixture_composition, PREFIX

ROOT = Path(__file__).resolve().parents[1]

def make_demo(port=0):
    state = Path(tempfile.mkdtemp(prefix='onboarding-demo-', dir=os.environ.get('TMPDIR', str(Path.home()/'.hermes/cache/scratch'))))
    state.chmod(0o700)
    api, token, adapter = fixture_composition(state)
    session = secrets.token_urlsafe(32)
    assets = ROOT/'frontends/paperclip/dist-onboarding'
    allowed = {('/'+str(p.relative_to(assets))):p.read_bytes() for p in assets.rglob('*') if p.is_file()}
    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, value, cookie=False, content_type='application/json'):
            data = value if isinstance(value, bytes) else json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            if cookie:self.send_header('Set-Cookie',f'amc_onboarding={session}; HttpOnly; SameSite=Strict; Path=/')
            self.end_headers();self.wfile.write(data)
        def run_request(self):
            origin=f'http://127.0.0.1:{self.server.server_port}'
            if self.headers.get_all('Host',[])!=[origin[7:]] or self.headers.get('Origin',origin)!=origin or (self.command=='POST' and self.headers.get('Origin')!=origin):
                return self.reply(403,{'error':'same_origin_required'})
            if self.command=='GET' and not self.path.startswith(PREFIX):
                path='/onboarding-demo.html' if self.path=='/' else self.path
                if path not in allowed:return self.reply(404,{'error':'not_found'})
                return self.reply(200,allowed[path],content_type=asset_content_type(path))
            try:
                size=int(self.headers.get('Content-Length','0'))
                if self.headers.get('Transfer-Encoding') or not 0<=size<=16384:raise ValueError
                body=json.loads(self.rfile.read(size)) if size else {}
                if type(body)!=dict:raise ValueError
            except (ValueError,UnicodeError):return self.reply(400,{'error':'invalid_request'})
            if self.path=='/fixture-session' and self.command=='POST':
                return self.reply(200,{'mode':'fixture_only'},cookie=True)
            cookies=SimpleCookie();cookies.load(self.headers.get('Cookie',''))
            if self.headers.get('Authorization') or 'amc_onboarding' not in cookies or not secrets.compare_digest(cookies['amc_onboarding'].value,session):
                return self.reply(401,{'error':'private_fixture_session_required'})
            status,value=api.dispatch(self.command,self.path,'Bearer '+token,body)
            return self.reply(status,value)
        do_GET=run_request
        do_POST=run_request
        def log_message(self,*args):pass
    server=HTTPServer(('127.0.0.1',port),Handler)
    server.api,server.adapter,server.state=api,adapter,state
    return server

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=0)
    args=parser.parse_args();server=make_demo(args.port)
    print(json.dumps({'url':f'http://127.0.0.1:{server.server_port}/','fixture_only':True,'pid':os.getpid()}),flush=True)
    try:server.serve_forever()
    finally:server.server_close();server.api.close()
