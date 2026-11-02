"""Clean-machine read-only entry. Explore and skip without a native owner.

No registry, fixture sessions, primary, credential, provider or process is created.
Enrollment is a distinct explicit local command. This listener exposes only the
pinned frontend asset snapshot, service capabilities and bounded discovery.
"""
import argparse,json,secrets
from pathlib import Path
from .cockpit_paperclip import PaperclipServer,PaperclipHandler
from .public_onboarding_api import PREFIX

class ExplorationHandler(PaperclipHandler):
    def do_GET(self):
        if self.headers.get_all('Host',[])!=[self.server.origin.removeprefix('http://')]:return self.reply(403,dict(error='same_origin_required'))
        if self.path=='/api/presentation-mode':return self.reply(200,dict(mode='explore'))
        if self.path==PREFIX+'capabilities':return self.reply(200,dict(mode='explore',owner_connected=False,organizer=None,can_skip=True,enrollment_required=True))
        if self.path.startswith('/api/') or self.path.startswith('/external/'):return self.reply(409,dict(error='explicit_local_enrollment_required'))
        return super().do_GET()
    def do_POST(self):
        return self.reply(409,dict(error='read_only_exploration; explicit_local_enrollment_required'))

def build_exploration_server(frontend,*,port=0):
    server=PaperclipServer(Path('/nonexistent-arvyx-exploration-owner'),frontend,port,capability=secrets.token_urlsafe(32))
    server.RequestHandlerClass=ExplorationHandler
    return server

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--frontend',type=Path,required=True);p.add_argument('--port',type=int,default=0)
    args=p.parse_args(argv);server=build_exploration_server(args.frontend,port=args.port)
    print(json.dumps(dict(origin=server.origin,mode='explore',owner_started=False)),flush=True)
    try:server.serve_forever()
    finally:server.server_close()
if __name__=='__main__':main()
