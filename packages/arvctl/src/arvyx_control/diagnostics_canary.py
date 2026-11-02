"""Deterministic scenario, disposable local state only; no production target option."""
import argparse
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def run():
    from . import api, cli, diagnostics
    with tempfile.TemporaryDirectory(prefix='amc-diagnostics-synthetic-') as tmp:
        root = Path(tmp)
        reporter = diagnostics.Reporter(root / 'errors.sqlite')
        server = ThreadingHTTPServer(('127.0.0.1', 0), api.make_handler(
            vault=root, state=root/'state.jsonl', bearer_secret='synthetic-local-only'))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def request(path, body=None):
            req = Request(f'http://127.0.0.1:{server.server_port}{path}',
                          data=json.dumps(body).encode() if body is not None else None,
                          headers={'Authorization': 'Bearer synthetic-local-only'})
            try:
                response = urlopen(req, timeout=5)
            except HTTPError as exc:
                response = exc
            with response:
                return response.status, json.loads(response.read())['body']
        def injected_failure(*args, **kwargs):
            raise RuntimeError('synthetic omitted message')
        try:
            with patch.object(diagnostics, '_reporter', reporter):
                with patch.object(api, '_operator_summary', side_effect=injected_failure):
                    api_status = [request('/summary')[0] for _ in range(2)]
                with patch.object(cli, '_execution_worker_tick', side_effect=RuntimeError('synthetic omitted message')), patch.object(cli, 'write_tick_record'):
                    try:
                        cli._run_execution_worker(argparse.Namespace(state=root/'state.jsonl'))
                    except RuntimeError:
                        pass
                client_status, _ = request('/diagnostics/client', {'kind': 'error', 'message': 'synthetic omitted message'})
                flushed = reporter.flush()
                status, result = request('/diagnostics')
                _, feed = request('/diagnostics/feed?after=0')
                components = sorted({g['component'] for g in result['groups']})
                counts = {g['component']: g['count'] for g in result['groups']}
                ok = (flushed and status == 200 and api_status == [500, 500] and client_status == 202
                      and components == ['api', 'browser', 'worker'] and counts.get('api') == 2
                      and len(feed['events']) == 3)
                return {'ok': ok, 'synthetic_only': True, 'components': components, 'counts': counts,
                        'feed': feed, 'groups': result['groups'], 'status': result['status'],
                        'operator_retrieval_status': status, 'external_alert_delivered': False}
        finally:
            server.shutdown()
            server.server_close()
            reporter.close()
