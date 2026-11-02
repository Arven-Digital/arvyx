from arvyx_control.replica_authority import authority_context
"""Behavioral reproductions for Grok candidate02 findings."""
from contextlib import contextmanager
from pathlib import Path
import importlib.util
import shutil
import sqlite3
import threading
from types import SimpleNamespace
import pytest
from arvyx_control import cockpit_archive, dogfood, health_ops, replica, embeddings, notifiers
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

@pytest.mark.parametrize('client', ['replica', 'embeddings', 'notifiers'])
def test_remaining_clients_have_total_deadline(client):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def respond(self):
            self.send_response(200); self.send_header('Content-Length','100');self.end_headers()
            for _ in range(100):
                try: self.wfile.write(b' ');self.wfile.flush()
                except OSError: break
                time.sleep(.02)
        def do_GET(self): self.respond()
        def do_POST(self): self.rfile.read(int(self.headers.get('Content-Length',0)));self.respond()
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
    url=f'http://127.0.0.1:{server.server_port}'
    start=time.monotonic()
    try:
        if client == 'notifiers':
            assert notifiers._post_json(url,{},.15) is not None
        else:
            with pytest.raises((ValueError,OSError,embeddings.EmbeddingError)):
                if client=='replica': replica._get_json(url,None,.15)
                else: embeddings._embed_batch(embeddings.EmbeddingConfig('http',url,'fixture',None,.15,1),['fixture'])
        assert time.monotonic()-start < .7
    finally: server.shutdown();server.server_close();thread.join(2)

from test_round5_review_fixes import pair

@pytest.mark.parametrize('client', ['agent', 'canary', 'deadman'])
def test_final_credential_clients_have_total_deadline(client, tmp_path):
    with authority_context(tmp_path / "vault"):
        from arvyx_control import agent_delivery, delivery_canary, liveness
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length',0)))
                self.send_response(200);self.send_header('Content-Length','100');self.end_headers()
                # Drip headers/body would renew urllib timeouts indefinitely.
                for _ in range(100):
                    try:self.wfile.write(b' ');self.wfile.flush()
                    except OSError:break
                    time.sleep(.02)
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
        url=f'http://127.0.0.1:{server.server_port}/synthetic'
        start=time.monotonic()
        try:
            if client=='canary':
                with pytest.raises((OSError,ValueError)):
                    delivery_canary.http_json('POST',url,{}, {},.15)
            elif client=='deadman':
                assert liveness.ping_deadman(url,fail=False,timeout=.15)['status']=='failed'
            else:
                item=SimpleNamespace(id='synthetic',target='synthetic',subject_id='synthetic',payload={})
                route=agent_delivery.AgentRoute('synthetic','hermes-webhook','URL','KEY',timeout_seconds=.15)
                result=agent_delivery.deliver_outbox_item(item,route,environ={'URL':url,'KEY':'synthetic'})
                assert not result.accepted
            assert time.monotonic()-start < .7
        finally:server.shutdown();server.server_close();thread.join(2)



@pytest.mark.parametrize('client', ['agent', 'canary', 'deadman'])
def test_credential_clients_never_follow_redirect(client, tmp_path):
    with authority_context(tmp_path / "vault"):
        from arvyx_control import agent_delivery, delivery_canary, liveness
        with pair() as (url,seen):
            if client=='canary':
                assert delivery_canary.http_json('POST',url,{}, {},1)[0]==302
            elif client=='deadman':
                assert liveness.ping_deadman(url,fail=False,timeout=1)['status']=='failed'
            else:
                item=SimpleNamespace(id='synthetic',target='synthetic',subject_id='synthetic',payload={})
                route=agent_delivery.AgentRoute('synthetic','hermes-webhook','URL','KEY',timeout_seconds=1)
                assert not agent_delivery.deliver_outbox_item(item,route,environ={'URL':url,'KEY':'synthetic'}).accepted
            assert not seen


def test_health_ops_does_not_follow_redirect():
    with pair() as (url, seen):
        probe = health_ops._probe_endpoint({'name': 'test', 'url': url}, 'synthetic', 2)
        assert probe.status != 'OK'
        assert not seen


@pytest.mark.parametrize('method', ['get', 'post'])
def test_dogfood_rejects_redirect_without_forwarding(method):
    with pair() as (url, seen):
        with pytest.raises(Exception):
            if method == 'get': dogfood._get_text(url, authorized=True)
            else: dogfood._post_json(url, {})
        assert not seen


def test_native_import_uses_incremental_counter(tmp_path):
    db = sqlite3.connect(':memory:')
    # Synthetic exact native source (profile home + store inode); import binds
    # its cursor provenance to these, never to transcript content.
    (tmp_path / 'home').mkdir(); (tmp_path / 'home' / 'state.db').write_bytes(b'')
    owner = SimpleNamespace(db=db, lock=threading.RLock(), _human=lambda _: None,
        native=lambda *a, **kw: {'tool': 'synthetic', 'conversation': 'conversation'},
        _get=lambda _: {'workspace': '/synthetic'}, native_runtimes={})
    owner.native_runtimes['synthetic'] = SimpleNamespace(plan=lambda *a: None,
        home=tmp_path / 'home', store=tmp_path / 'home' / 'state.db',
        transcript=lambda *a, **kw: [{'id': 1, 'role': 'user', 'content': 'hello'}])
    cockpit_archive._capture_schema(owner)
    db.executemany('INSERT INTO work_capture(event_id,session,run,text) VALUES(?,?,?,?)',
        [(str(i), 'session', 'run', 'retained') for i in range(4000)])
    db.commit()
    queries=[]
    db.set_trace_callback(queries.append)
    cockpit_archive.import_native(owner, 'session', actor='synthetic')
    assert not any('SUM(' in q.upper() and 'WORK_CAPTURE' in q.upper() for q in queries)
    expected=db.execute('SELECT SUM(LENGTH(CAST(text AS BLOB))) FROM work_capture').fetchone()[0]
    assert db.execute('SELECT bytes FROM capture_accounting').fetchone()[0] == expected
    db.close()


def test_picker_regression_reads_its_own_tree(tmp_path):
    original=Path(__file__).with_name('test_round5_review_fixes.py')
    target=tmp_path/'packages/arvctl/tests/test_round5_review_fixes.py'
    target.parent.mkdir(parents=True)
    shutil.copy2(original,target)
    frontend=tmp_path/'frontends/paperclip/PublicOnboarding.tsx'
    frontend.parent.mkdir(parents=True)
    frontend.write_text('regressed synthetic UI')
    spec=importlib.util.spec_from_file_location('isolated_picker_regression',target)
    assert spec is not None and spec.loader is not None
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    with pytest.raises(AssertionError): module.test_metadata_picker_wording_is_not_runtime_open()
