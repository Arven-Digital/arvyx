"""Provider-free browser fixture; use installed wheel, never the existing pilot.

Run with --receipts outside source. Stop with SIGTERM/KeyboardInterrupt.
Browser capability is supplied via environment, never printed or written.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

from arvyx_control.cockpit_client import initialize, request
from arvyx_control.cockpit_team import TeamAuthority
from arvyx_control.cockpit_web import DashboardServer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipts', type=Path, required=True)
    args = parser.parse_args()
    args.receipts.mkdir(parents=True, exist_ok=True)
    # AF_UNIX paths are bounded; runtime stays in managed scratch, not long receipt paths.
    home = Path(tempfile.mkdtemp(prefix='web-team-'))
    initialize(home)
    log = (home / 'owner.log').open('wb')
    owner = subprocess.Popen([sys.executable, '-m', 'arvyx_control.cockpit_client', '--home', str(home), 'serve'], stdout=log, stderr=log)
    server = None
    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        deadline = time.monotonic() + 10
        while not (home / 'runtime/cockpit.sock').exists():
            if owner.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('fixture owner did not become ready')
            time.sleep(.02)
        # Synthetic fixture-only identity, never ambient credentials or anonymous demo.
        identity = 'fixture-only-web-operator'
        team = TeamAuthority(home / 'vault', home / 'events.jsonl',
                             bearer_secret=identity, authorization='Bearer ' + identity)
        for agent in ('nova', 'rowan'):
            directory = home / 'vault/registry/agents'
            directory.mkdir(parents=True, exist_ok=True)
            (directory / (agent + '.json')).write_text(json.dumps({
                'id': agent, 'display_name': agent.title(), 'machine_id': 'fixture-machine',
                'runtime_id': 'fixture-runtime', 'scopes': ['control.read', 'control.write']}))
        result = team.action('task-create', {'title': 'Provider-free browser fixture', 'owner': 'demobot',
                                             'idempotency_key': 'fixture-browser-task-1'})
        if result.status != 201:
            raise RuntimeError('fixture task creation refused')
        task = result.body['task']
        session = request(home, 'open', project='demo-agent', task=task['id'], name='browser', actor='operator')
        team.action('approval-request', {'command': 'printf fixture-only', 'requester': 'nova',
                                        'reason': 'Provider-free fixture; never executes',
                                        'idempotency_key': 'fixture-browser-approval-1'})
        server = DashboardServer(home, capability=os.environ['AMC_BROWSER_CAPABILITY'], team=team)
        info = {'origin': server.origin, 'home': str(home), 'pid': os.getpid(), 'session': session,
                'fixture_only': True, 'source_module': __import__('arvyx_control.cockpit_web', fromlist=['x']).__file__}
        (args.receipts / 'web-browser-info.json').write_text(json.dumps(info, indent=2) + '\n')
        print(json.dumps({'origin': server.origin, 'fixture_only': True}), flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if server is not None:
            server.server_close()
        owner.send_signal(signal.SIGINT)
        owner.wait(timeout=10)
        log.close()


if __name__ == '__main__':
    main()
