def test_terminal_help_explains_attach_only_scope():
    import subprocess,sys
    result=subprocess.run([sys.executable,'-m','arvyx_control.onboarding_cli','--help'],capture_output=True,text=True,check=True)
    assert 'Terminal mode is attach-only' in result.stdout


def test_metadata_picker_wording_is_not_runtime_open():
    source=(Path(__file__).resolve().parents[3]/'frontends/paperclip/PublicOnboarding.tsx').read_text()
    assert '>Inspect session metadata<' in source
    assert 'setInspection(result)' in source
    assert 'JSON.stringify(inspection,null,2)' in source
    assert 'Execution requires a separately configured local owner policy.' in source


def test_text_client_rejects_truncated_oversize_json():
    from arvyx_control.shared_onboarding_cli import client
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            data=b'{}'+b' '*(1024*1024)
            self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers()
            try:self.wfile.write(data)
            except OSError:pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
    try:
        with pytest.raises(ValueError,match='limit'):
            client(f'http://127.0.0.1:{server.server_port}','synthetic',timeout=1)('capabilities')
    finally:server.shutdown();server.server_close();thread.join(2)

def test_text_client_enforces_elapsed_deadline():
    from arvyx_control.shared_onboarding_cli import client
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            self.send_response(200);self.send_header('Content-Length','100');self.end_headers()
            for _ in range(100):
                try:self.wfile.write(b' ');self.wfile.flush()
                except OSError:break
                time.sleep(.02)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
    start=time.monotonic()
    try:
        with pytest.raises((ValueError,OSError,TimeoutError)):
            client(f'http://127.0.0.1:{server.server_port}','synthetic',timeout=.15)('capabilities')
        assert time.monotonic()-start<.6
    finally:server.shutdown();server.server_close();thread.join(2)

def test_shipped_fonts_are_verified_and_spoof_is_rejected(tmp_path):
    root=Path(__file__).resolve()
    repo=Path(__file__).resolve().parents[3]
    for font in (repo/'frontends/paperclip/public/fonts').glob('*.woff2'):
        assert security.is_verified_font(font)
    fake=tmp_path/'fake.woff2'
    fake.write_bytes(b'wOF2'+b'\0'*60)
    assert not security.is_verified_font(fake)

def test_scanner_resource_exhaustion_is_structured(tmp_path):
    from arvyx_control.audit import _private_context_check
    source=tmp_path/'bounded.py'
    source.write_text('value = '+' + '.join([repr('a'*10000)]*100))
    result=_private_context_check(tmp_path)
    assert not result.ok
    assert any('resource' in hit for hit in result.findings)

import ast
import socket
import time
import sqlite3
from contextlib import closing
from pathlib import Path
from arvyx_control import cockpit_web, cockpit_archive, hermes_history
from arvyx_control.public_onboarding_api import BoundedWorkers

def test_legacy_dashboard_has_bounded_worker_admission(tmp_path):
    server = cockpit_web.DashboardServer(tmp_path)
    try:
        assert isinstance(server, BoundedWorkers)
    finally:
        server.server_close()

def test_metadata_aggregates_activity_once(tmp_path):
    with closing(sqlite3.connect(tmp_path/'state.db')) as db, db:
        db.execute('CREATE TABLE sessions(id TEXT,title TEXT,started_at REAL)')
        db.execute('CREATE TABLE messages(session_id TEXT,timestamp REAL)')
        db.executemany('INSERT INTO sessions VALUES (?,?,?)',[(str(i),'title',1) for i in range(400)])
        db.executemany('INSERT INTO messages VALUES (?,?)',[(str(i),2) for i in range(400) for j in range(10)])
    history=hermes_history.HermesHistory(tmp_path)
    target=history.target
    result=history.metadata(target)
    assert 0 < history.last_query_steps < 300000
    assert len(result)==400
    history.query_budget_steps=1
    with pytest.raises(hermes_history.RoutingError,match='budget'):
        history.metadata(target)

def test_capture_feed_avoids_retained_history_rescan():
    class Owner:
        lock=threading.RLock()
        db=sqlite3.connect(':memory:')
        def _get(self,sid):return {}
    owner=Owner();capture=cockpit_archive.WorkCapture(owner,'session')
    owner.db.executemany('INSERT INTO work_capture(event_id,session,run,text) VALUES (?,?,?,?)',[(str(i),'session','run','text') for i in range(4000)])
    owner.db.commit()
    steps=[0]
    def progress():steps[0]+=100;return 0
    owner.db.set_progress_handler(progress,100)
    capture.feed(b'')
    assert steps[0]<1000

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import pytest
from arvyx_control import health, notifiers, security

@contextmanager
def pair():
    seen=[]
    class Destination(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            seen.append(self.command)
            self.send_response(200);self.end_headers();self.wfile.write(b'{}')
    destination=ThreadingHTTPServer(('127.0.0.1',0),Destination)
    class Redirect(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def respond(self):
            self.send_response(302)
            self.send_header('Location',f'http://127.0.0.1:{destination.server_port}/landing');self.end_headers()
        def do_GET(self):self.respond()
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length',0)));self.respond()
    origin=ThreadingHTTPServer(('127.0.0.1',0),Redirect)
    threads=[threading.Thread(target=s.serve_forever,kwargs={'poll_interval':.01},daemon=True) for s in (origin,destination)]
    for t in threads:t.start()
    try:yield f'http://127.0.0.1:{origin.server_port}/source',seen
    finally:
        for s in (origin,destination):s.shutdown();s.server_close()
        for t in threads:t.join(2)

def test_health_refuses_cross_origin_redirect():
    with pair() as (url,seen):
        with pytest.raises(ValueError,match='HTTP 302'):
            health._get_json(url,'synthetic-marker',2)
    assert not seen

def test_notifier_does_not_report_redirect_as_delivery():
    with pair() as (url,seen):
        result=notifiers._post_json(url,{'message':'synthetic notification'},2)
    assert result is not None
    assert not seen

def test_scanner_handles_valid_deep_constant_without_recursion_crash():
    text='value = '+' + '.join([repr('a')]*1200)
    ast.parse(text);compile(text,'<synthetic>','exec')
    assert security.python_constant_shape_spans(text)==set()
