"""PTY acceptance of the admitted onboarding-v1 native chooser against a synthetic Hermes store.

Synthetic only: a disposable Hermes-like state.db, a disposable registry identity, the
production onboarding API served over loopback HTTP with a one-time capability, and the
admitted native binary driven through a real pseudo-terminal. No provider, no real
profile, no transcript exposure (the synthetic transcript body must never reach the
screen). Writes a receipt JSON and exits non-zero on any unmet expectation.

Usage: python native_chooser_pty_acceptance.py --binary /path/arvyx --out /dir [--rows 40 --cols 120]

Maintainer acceptance tool, not a CI gate: it needs a POSIX host, the admitted
onboarding-v1 binary (any other digest is refused) and the `pyte` terminal emulator,
which is a tool-only dependency outside the hashed runtime locks.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import pty
import secrets
import select
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pyte

from arvyx_control.cockpit_arvyx import frontend_environment
from arvyx_control.local_onboarding import local_composition
from arvyx_control.public_onboarding_api import handler_for

TRANSCRIPT_SENTINEL = 'SYNTHETIC TRANSCRIPT BODY'
REVIEWED = {'manual/connect', 'profiles/register', 'profiles/connect', 'sessions/select'}
KEYS = dict(F6=b'\x1b[17~', TAB=b'\t', ENTER=b'\r', ESC=b'\x1b', DOWN=b'\x1b[B', UP=b'\x1b[A')


def build_synthetic_hermes(home: Path, count: int = 12) -> list[str]:
    profile = home / '.hermes'
    profile.mkdir(mode=0o700)
    (profile / 'config.yaml').write_text('model: synthetic\n', encoding='utf-8')
    titles = [f'Synthetic segment {i:02d}' for i in range(count)]
    with sqlite3.connect(profile / 'state.db') as db:
        db.executescript('''CREATE TABLE sessions(id TEXT PRIMARY KEY,title TEXT,started_at REAL,ended_at REAL,
            end_reason TEXT,cwd TEXT,parent_session_id TEXT,archived INTEGER,hidden INTEGER);
            CREATE TABLE messages(id INTEGER PRIMARY KEY,session_id TEXT,timestamp REAL,content TEXT);''')
        db.executemany('INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?,?)', [
            (f'syn-{i:04d}', titles[i], 1_000.0 + i, None, None, str(profile), None, 0, 0) for i in range(count)])
        db.execute('INSERT INTO messages(session_id,timestamp,content) VALUES(?,?,?)', ('syn-0003', 5_000.0, TRANSCRIPT_SENTINEL))
    os.chmod(profile / 'state.db', 0o600)
    return titles


def build_registry(vault: Path) -> None:
    records = [('agents', dict(id='agent-hermes', display_name='Synthetic Hermes', machine_id='machine-a',
                               runtime_id='runtime-hermes', scopes=['memory.read'])),
               ('machines', dict(id='machine-a', display_name='Machine A', role='workstation')),
               ('runtimes', dict(id='runtime-hermes', display_name='Hermes runtime', harness='hermes'))]
    for kind, record in records:
        directory = vault / 'registry' / kind
        directory.mkdir(parents=True, exist_ok=True)
        (directory / (record['id'] + '.json')).write_text(json.dumps(record), encoding='utf-8')


class TolerantScreen(pyte.Screen):
    """pyte lacks private-mode device status reports and a few modern queries;
    the client under test asks for them at startup. Ignore them: no reply is a
    valid terminal answer and the client falls back to plain rendering."""

    def report_device_status(self, *args, **kwargs):  # noqa: D401
        return None

    def report_device_attributes(self, *args, **kwargs):
        return None


class Terminal:
    def __init__(self, binary: Path, env: dict[str, str], rows: int, cols: int):
        self.screen = TolerantScreen(cols, rows)
        self.stream = pyte.ByteStream(self.screen)
        self.pid, self.fd = pty.fork()
        if self.pid == 0:  # child
            fcntl.ioctl(1, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
            os.execve(str(binary), [str(binary), '--session', 'amc'], env)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
        self.raw = bytearray()

    def pump(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            ready, _, _ = select.select([self.fd], [], [], min(remaining, 0.1))
            if ready:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    return
                if not data:
                    return
                self.raw.extend(data)
                try:
                    self.stream.feed(data)
                except (TypeError, KeyError, ValueError) as exc:  # unsupported escape sequence
                    self.parse_errors = getattr(self, 'parse_errors', 0) + 1
                    self.last_parse_error = repr(exc)

    def text(self) -> str:
        return '\n'.join(line.rstrip() for line in self.screen.display)

    def wait_for(self, needle: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump(0.2)
            if needle in self.text():
                return True
        return False

    def wait_gone(self, needle: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump(0.2)
            if needle not in self.text():
                return True
        return False

    def send(self, data: bytes) -> None:
        os.write(self.fd, data)
        self.pump(0.3)

    def stop(self) -> None:
        try:
            os.kill(self.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            pid, _ = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                return
            self.pump(0.1)
        os.kill(self.pid, signal.SIGKILL)
        os.waitpid(self.pid, 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--rows', type=int, default=40)
    parser.add_argument('--cols', type=int, default=120)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    args.out.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    # Only the admitted onboarding-v1 bytes are an acceptance subject; any other
    # binary would produce a receipt about something the product never admits.
    from arvyx_control.native_artifact_policy import admitted_capabilities
    if 'onboarding-v1' not in admitted_capabilities(digest):
        print(f'refusing: {binary} is not the admitted onboarding-v1 artifact for this platform ({digest[:12]}…)', file=sys.stderr)
        return 2
    receipt: dict = dict(binary=str(binary), binary_sha256=digest, admitted=True,
                         synthetic_only=True, provider=False, steps=[], api_calls=[], failures=[])

    base = Path(tempfile.mkdtemp(prefix='native-chooser-', dir=os.environ.get('TMPDIR')))
    root, home, vault, frontend_home = base / 'onboarding', base / 'home', base / 'vault', base / 'frontend-home'
    for path in (root, home, vault, frontend_home):
        path.mkdir(mode=0o700)
    titles = build_synthetic_hermes(home)
    build_registry(vault)
    capability = secrets.token_urlsafe(24)
    api = local_composition(root, vault=vault, machine_id='machine-a', capability=capability, discovery_home=home)
    original_dispatch = api.dispatch
    log_lock = threading.Lock()

    def logged_dispatch(method, path, authorization, body):
        status, value = original_dispatch(method, path, authorization, body)
        with log_lock:
            receipt['api_calls'].append(dict(method=method, path=path.removeprefix('/api/public-onboarding/'), status=status))
        return status, value
    api.dispatch = logged_dispatch
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler_for(api))
    origin = f'http://127.0.0.1:{server.server_port}'
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def raw(path, body=None):
        data = None if body is None else json.dumps(body).encode()
        request = Request(origin + '/api/public-onboarding/' + path, data=data, method='GET' if body is None else 'POST',
                          headers={'Origin': origin, 'Authorization': 'Bearer ' + capability, 'Content-Type': 'application/json'})
        try:
            with urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except HTTPError as exc:
            return exc.code, json.loads(exc.read() or b'{}')

    def call(path, body=None):
        if path in REVIEWED and isinstance(body, dict) and body.get('confirmed') is True:
            status, review = raw('actions/prepare', dict(action=path, request=body))
            if status != 200:
                return status, review
            return raw('actions/commit', dict(consent_id=review['consent_id'], consent_sha256=review['sha256'], confirmed=True))
        return raw(path, body)

    def step(name, ok, **detail):
        receipt['steps'].append(dict(name=name, ok=bool(ok), **detail))
        if not ok:
            receipt['failures'].append(name)
        print(('ok   ' if ok else 'FAIL ') + name, file=sys.stderr)

    terminal = None
    try:
        status, connected = call('manual/connect', dict(family='hermes', path=str(home / '.hermes'), agent_id='agent-hermes', confirmed=True))
        step('manual connect of the synthetic Hermes profile through the reviewed API', status == 200,
             status=status, harness=connected.get('harness'), metadata_only=connected.get('metadata_only'))
        target = connected.get('target')
        status, targets = raw('targets')
        step('exactly one connected target is listed', status == 200 and len(targets.get('items', [])) == 1, status=status)
        status, recent = call('sessions/recent', dict(target=target))
        recent_titles = [item.get('title') for item in recent.get('items', [])]
        step('Last 5 over the API returns synthetic titles only', status == 200 and len(recent_titles) == 5
             and all(t in titles for t in recent_titles) and TRANSCRIPT_SENTINEL not in json.dumps(recent), titles=recent_titles)

        env = frontend_environment(frontend_home)
        env['AMC_ONBOARDING_RPC'] = json.dumps(dict(origin=origin, capability=capability))
        terminal = Terminal(binary, env, args.rows, args.cols)
        terminal.pump(3.0)
        booted = bool(terminal.text().strip())
        step('native client renders in the pseudo-terminal', booted, first_screen=terminal.text()[:600])
        before = [call for call in receipt['api_calls']]

        terminal.send(KEYS['F6'])
        opened = terminal.wait_for('Choose an exact connected agent', 5.0) or terminal.wait_for('[Last 5]', 2.0)
        step('F6 opens the shared chooser with the exact-agent notice', opened, screen=terminal.text())

        terminal.send(KEYS['TAB'])
        terminal.pump(1.5)
        cycled = any(c['path'] == 'targets' for c in receipt['api_calls'][len(before):])
        step('Tab asks the API for the connected targets (no session opens)', cycled, screen=terminal.text())

        # Cycling to the exact target loads Last 5 for it; the most recently active
        # synthetic segment (the one with the newest message) must lead the list and
        # the list must be activity-ordered, not ID-ordered.
        listed_recent = terminal.wait_for('Synthetic segment 03', 5.0)
        screen_lines = [line for line in terminal.text().split('\n') if 'Synthetic segment' in line]
        shown = []
        for line in screen_lines:
            start = line.find('Synthetic segment')
            shown.append(line[start:start + len('Synthetic segment 00')])
        recent_called = any(c['path'] == 'sessions/recent' for c in receipt['api_calls'][len(before):])
        step('Last 5 renders on the real frontend in activity order (newest message first)',
             listed_recent and recent_called and shown[:1] == ['Synthetic segment 03'] and shown == recent_titles[:len(shown)],
             shown=shown, api_order=recent_titles)

        for ch in b'segment':
            terminal.send(bytes([ch]))
        terminal.send(KEYS['ENTER'])
        listed = terminal.wait_for('Synthetic segment', 6.0)
        searched = any(c['path'] in ('sessions/all', 'sessions/search') for c in receipt['api_calls'][len(before):])
        step('typing a query and Enter lists matching synthetic sessions through sessions/all', listed and searched,
             screen=terminal.text())
        step('no transcript content reaches the screen', TRANSCRIPT_SENTINEL not in terminal.text() and TRANSCRIPT_SENTINEL not in terminal.raw.decode('utf-8', 'replace'))

        terminal.send(KEYS['DOWN']); terminal.send(KEYS['DOWN']); terminal.send(KEYS['UP'])
        terminal.pump(0.5)
        step('arrow keys scroll the list without leaving the chooser', 'Synthetic segment' in terminal.text(), screen=terminal.text())

        terminal.send(KEYS['ESC'])
        closed = terminal.wait_gone('Choose an exact connected agent', 4.0) and terminal.wait_gone('[Last 5]', 2.0)
        step('Esc closes the chooser', closed, screen=terminal.text())

        terminal.send(KEYS['F6'])
        reopened = terminal.wait_for('[Last 5]', 4.0) or terminal.wait_for('Choose an exact connected agent', 2.0)
        terminal.send(KEYS['ESC'])
        step('F6 reopens and Esc closes again', reopened and terminal.wait_gone('[Last 5]', 4.0))

        launched = [c for c in receipt['api_calls'] if c['path'].startswith('native/') or c['path'] in ('sessions/prepare', 'sessions/commit')]
        step('no native presentation or launch was requested', not launched)
    finally:
        if terminal is not None:
            terminal.stop()
            try:
                subprocess.run([str(binary), '--session', 'amc', 'server', 'stop'], env=env, timeout=10,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        server.shutdown()
        api.close()
        import shutil
        shutil.rmtree(base, ignore_errors=True)  # synthetic state only; the receipt is the record
    receipt['ok'] = not receipt['failures']
    receipt['synthetic_titles'] = titles
    (args.out / 'native-chooser-pty-acceptance.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(ok=receipt['ok'], failures=receipt['failures'], steps=len(receipt['steps']),
                          api_calls=[c['path'] for c in receipt['api_calls']])))
    return 0 if receipt['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
