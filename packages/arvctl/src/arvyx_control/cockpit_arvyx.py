"""Private-only experimental adapter for the upstream terminal frontend for Arvyx.

The upstream renderer provides mouse/terminal emulation only. Existing AMC attachment
leases and byte transport remain authoritative. This does not confer product
acceptance, shared-selection synchronization, or provider-launch permission.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shlex
import subprocess
import sys
import time


def frontend_environment(home: Path) -> dict[str, str]:
    """Do not copy the caller's credentials, SSH agent or plugin environment."""
    return {
        'HOME': str(home), 'XDG_CONFIG_HOME': str(home / '.config'),
        'XDG_STATE_HOME': str(home / '.local/state'),
        'PATH': '/usr/bin:/bin', 'SHELL': '/bin/sh',
        'TERM': 'xterm-256color', 'LANG': 'C.UTF-8',
    }


def launch_plan(sessions: list[dict], host: str = 'local') -> list[dict]:
    plan = []
    seen = set()
    for session in sessions:
        kind = session.get('kind', 'work')
        if kind not in ('work', 'organizer', 'local'):
            raise ValueError('unknown AMC session kind')
        # Organizer is global coordination, not synthetic task-bound work.
        required = ('id', 'name') if kind in ('organizer','local') else ('id', 'name', 'project', 'task')
        if kind in ('organizer','local') and (session.get('project') is not None or session.get('task') is not None):
            raise ValueError('organizer/local session must not have a project/task binding')
        if any(not isinstance(session.get(key), str) or not session[key] for key in required):
            raise ValueError('session requires an exact AMC project/task/host binding')
        if session['id'] in seen:
            raise ValueError('duplicate session binding')
        seen.add(session['id'])
        session_host = session.get('host', host)
        if not isinstance(session_host, str) or not session_host:
            raise ValueError('exact host binding required')
        if ':' in session['id']:
            qualified_host, local_id = session['id'].split(':', 1)
            if qualified_host != session_host or not re.fullmatch(r'[a-f0-9]{32}', local_id):
                raise ValueError('fleet session identity does not match host')
        plan.append({key: session[key] for key in required} |
                    {'sid': session['id'], 'label': session['name'], 'host': session_host,
                     'kind': kind, 'project': session.get('project'), 'task': session.get('task')})
    return plan


def pane_binding(sid: str, sessions: list[dict]) -> dict:
    for binding in launch_plan(sessions):
        if binding['sid'] == sid:
            return binding
    raise ValueError('unknown exact AMC session ID')


class FocusBridge:
    """Choose one revision-fenced focus change; never infer task lifecycle."""
    def __init__(self, bindings):
        self.bindings = dict(bindings)
        self.revision = None
        self.focused = None
        self.pending_focus = None

    def decide(self, focused, view, *, available=None):
        previous_revision, previous_focus = self.revision, self.focused
        self.revision, self.focused = view['revision'], focused
        selected = view['selected']
        available = set(self.bindings) if available is None else set(available)
        if previous_revision is None or previous_revision != self.revision:
            self.pending_focus = None
            target = next((pane for pane, sid in self.bindings.items()
                           if sid == selected and pane in available), None)
            if target is not None and target != focused:
                self.pending_focus = target
                return 'frontend', target
        elif self.pending_focus is not None:
            # An RPC acknowledgement is not an observed rendered focus. Do not
            # mistake the previous frame for human input and reverse authority.
            if focused == self.pending_focus or self.pending_focus not in available:
                self.pending_focus = None
            return None
        elif focused != previous_focus and focused in self.bindings and focused in available:
            sid = self.bindings[focused]
            if selected != sid:
                return 'authority', sid
        return None


def watch_focus(binding_file: Path, binary: Path, *, native_fd=None):
    from .native_artifact_policy import VerifiedNative
    record = json.loads(binding_file.read_text())
    with VerifiedNative(binary, record, inherited_fd=native_fd) as native:
        return _watch_focus(binding_file, native, record=record)


def _focus_pane(frontend_home: Path, pane_id: str):
    """Focus an exact existing pane after the verified native snapshot probe."""
    from .cockpit_client import exchange
    # The pinned CLI's `pane focus` selects a direction, not an exact pane.
    # Use its newline-delimited API with the same bounded, no-retry transport.
    identifier = 'amc:pane:focus'
    payload = json.dumps({'id': identifier, 'method': 'pane.focus',
                          'params': {'pane_id': pane_id}}).encode() + b'\n'
    endpoint = frontend_home / '.config/herdr/sessions/amc/herdr.sock'
    # Exact PaneFocus request: bounded by the same deadline, no AMC metadata.
    response = json.loads(exchange(endpoint, payload, owner_budget=False))
    if not isinstance(response, dict) or response.get('id') != identifier or 'error' in response:
        raise ValueError('exact pane focus failed; no retry')
    result = response.get('result')
    pane = result.get('pane') if isinstance(result, dict) else None
    if not isinstance(pane, dict) or pane.get('pane_id') != pane_id:
        raise ValueError('exact pane focus acknowledgement mismatch; no retry')
    # FocusBridge waits for a subsequent snapshot; this RPC is not observation.


def _watch_focus(binding_file: Path, native, *, record):
    """Use the same binding document that authorized the sealed native object."""
    from .cockpit_client import request
    home = Path(record['authority_home'])
    environment = frontend_environment(binding_file.parent)
    bindings = {item['pane']: item['sid'] for item in record['bindings']}
    bridge = FocusBridge(bindings)
    focus_deadline = None
    while True:
        try:
            output = native.invoke(subprocess.check_output, ['--session', 'amc', 'api', 'snapshot'], env=environment, timeout=5, stderr=subprocess.DEVNULL)
            panes = json.loads(output)['result']['snapshot']['panes']
            focused_ids = [pane['pane_id'] for pane in panes if pane.get('focused') is True]
            if len(focused_ids) > 1:
                raise ValueError('ambiguous native focus snapshot; no retry')
            focused = focused_ids[0] if focused_ids else None
            if (bridge.pending_focus is not None and focused != bridge.pending_focus
                    and focus_deadline is not None and time.monotonic() >= focus_deadline):
                raise ValueError('exact native focus not observed before deadline; no retry')
            view = request(home, 'view')
            current=request(home,'native_lifecycle',action='inspect',actor='operator')
            dynamic=request(home,'native_lifecycle',action='panes',actor='operator',expected=current,confirmed=True,
                            frontend=hashlib.sha256(binding_file.read_bytes()).hexdigest())
            refreshed=dict(bindings)
            for row in dynamic:
                if row['pane'] in refreshed and refreshed[row['pane']]!=row['session']:
                    raise ValueError('native pane identity conflicts; no focus fallback')
                refreshed[row['pane']]=row['session']
            bridge.bindings=refreshed
            change = bridge.decide(focused, view, available={pane['pane_id'] for pane in panes})
            if change is not None:
                kind, target = change
                if kind == 'authority':
                    panels = list(view['panels'])
                    if target not in panels:
                        panels.append(target)
                    request(home, 'layout', panels=panels, selected=target, revision=view['revision'], actor='operator')
                else:
                    pane = next(pane for pane in panes if pane['pane_id'] == target)
                    for args in [('workspace', 'focus', pane['workspace_id']), ('tab', 'focus', pane['tab_id'])]:
                        native.invoke(subprocess.check_output, ['--session', 'amc', *args], env=environment, timeout=5, stderr=subprocess.DEVNULL)
                    _focus_pane(binding_file.parent, target)
                    focus_deadline = time.monotonic() + 5
            time.sleep(.1)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            # No reconnect resends, focus overwrite after conflict or provider launch.
            # Exiting is visible in the isolated log and requires explicit reopening.
            print('Focus synchronization stopped; no selection write retried.', flush=True)
            return


def bridge(home: Path, sid: str, *, proof=None,target=None,consent_expires_at=None):
    from .cockpit_client import attach, request
    # Listing does not start processes, grant leases or infer a takeover.
    pane_binding(sid, request(home, 'list'))
    if proof is None:
        attach(home, sid, takeover=False)
    else:
        from .reviewed_actions import assert_consent_active
        if consent_expires_at is None:raise ValueError('native bridge requires original reviewed consent expiry')
        assert_consent_active(consent_expires_at)
        if proof.get('owner_session')!=sid:raise ValueError('exact native bridge identity required')
        expected=request(home,'native_lifecycle',action='inspect',actor='operator')
        if expected['incarnation']!=proof['owner_incarnation'] or expected['epoch']!=proof['epoch']:
            raise ValueError('native bridge lease revoked or owner changed')
        # Inspection can block; retain the original absolute expiry at dispatch.
        assert_consent_active(consent_expires_at)
        lease=request(home,'native_lifecycle',action='attach',actor='operator',expected=expected,confirmed=True,result=proof,target=target,consent_expires_at=consent_expires_at)
        attach(home,sid,takeover=False,existing_lease=lease)


def open_frontend(home: Path, frontend_home: Path, binary: Path):
    from .native_artifact_policy import VerifiedNative
    with VerifiedNative(binary) as native:
        return _open_frontend(home, frontend_home, native)


def _open_frontend(home: Path, frontend_home: Path, native):
    """Explicitly attach existing AMC sessions through the actual released UI.

    No provider/process start, task creation, native-session inference or lease
    takeover is performed. A fresh frontend home avoids adopting external Arvyx
    persistence, plugins, SSH endpoints, automatic restart or configuration.
    """
    from .cockpit_client import request
    digest = native.digest
    sessions = request(home, 'list')
    snapshot = request(home, 'snapshot', actor='operator')
    plan = launch_plan(sessions, snapshot['host'])
    if not plan:
        raise ValueError('create an explicitly bound AMC session first')
    frontend_home.mkdir(mode=0o700, parents=False, exist_ok=False)
    config = frontend_home / '.config/herdr/config.toml'
    config.parent.mkdir(mode=0o700, parents=True)
    config.write_text('onboarding = false\n[update]\nversion_check = false\nmanifest_check = false\n[terminal]\nshell_mode = "non_login"\n')
    environment = frontend_environment(frontend_home)
    environment['PYTHONPATH'] = str(Path(__file__).resolve().parents[1])
    log = (frontend_home / 'frontend.log').open('wb')
    process = None
    watcher = None
    attach_status = None

    def command(*args):
        output = native.invoke(subprocess.check_output, ['--session', 'amc', *args], env=environment, timeout=10)
        return json.loads(output) if output.strip().startswith(b'{') else None

    try:
        process = native.invoke(subprocess.Popen, ['--session', 'amc', 'server'], env=environment, stdout=log, stderr=log)
        endpoint = frontend_home / '.config/herdr/sessions/amc/herdr.sock'
        deadline = time.monotonic() + 10
        while not endpoint.exists():
            if process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError('Arvyx did not start; inspect the isolated frontend log')
            time.sleep(.05)
        workspaces = {}
        bindings = []
        for item in plan:
            # Keep the global organizer distinct even from a project named Organizer.
            project = (item['host'], item['kind'], item['project'])
            if project not in workspaces:
                scope_label = 'Organizer' if item['kind'] == 'organizer' else 'Local sessions' if item['kind']=='local' else item['project']
                result = command('workspace', 'create', '--cwd', str(home), '--label', item['host'] + ' / ' + scope_label, '--no-focus')['result']
                workspaces[project] = result['workspace']['workspace_id']
            else:
                result = command('tab', 'create', '--workspace', workspaces[project], '--cwd', str(home), '--label', item['name'], '--no-focus')['result']
            pane = result['root_pane']['pane_id']
            argv = [sys.executable, '-m', 'arvyx_control.cockpit_arvyx', '--home', str(home), '--sid', item['sid']]
            command('pane', 'run', pane, shlex.join(argv))
            identity = request(home, 'native', sid=item['sid'], actor='operator')
            if identity is not None:
                # Exact remembered identity, not guessed foreground liveness.
                # No cold-resume argv is given and no provider is launched.
                command('pane', 'report-agent', pane, '--source', 'amc:binding',
                        '--agent', identity['tool'], '--state', 'unknown',
                        '--message', 'AMC-bound identity; current liveness is not inferred')
                # Arvyx only accepts native-resume references from official
                # integrations. Do not impersonate one: these are display tokens.
                for label, value in (('amc-session', item['sid']), ('amc-conversation', identity['conversation'])):
                    command('pane', 'report-metadata', pane, '--source', 'amc:binding',
                            '--token', f'{label}={value}')
            bindings.append(item | {'pane': pane})
        binding_file = frontend_home / 'bindings.json'
        binding_file.write_text(json.dumps({'authority_home': str(home), 'binary_sha256': digest, 'bindings': bindings}, indent=2) + '\n')
        watcher = subprocess.Popen([sys.executable, '-m', 'arvyx_control.cockpit_arvyx', '--home', str(home), '--watch-bindings', str(binding_file), '--native-fd', str(native.fd)], pass_fds=(native.fd,), env=environment, stdout=log, stderr=log, start_new_session=True)
        (frontend_home / 'focus-watcher.pid').write_text(str(watcher.pid) + '\n')
        attach_status = native.invoke(subprocess.call, ['session', 'attach', 'amc'], env=environment)
        return attach_status
    finally:
        # A failed attach/setup must not leave a focus writer running. Preserve
        # both exceptions and nonzero exit statuses if best-effort shutdown fails.
        # Only a successful detach deliberately preserves the server and watcher.
        if attach_status != 0:
            if watcher is not None:
                try:
                    watcher.terminate()
                    watcher.wait(timeout=10)
                except (OSError, subprocess.SubprocessError):
                    try:
                        watcher.kill()
                        watcher.wait(timeout=10)
                    except (OSError, subprocess.SubprocessError):
                        pass
            if process is not None:
                try:
                    native.invoke(subprocess.run, ['--session', 'amc', 'server', 'stop'], env=environment, timeout=10, capture_output=True)
                    process.wait(timeout=10)
                except (OSError, subprocess.SubprocessError):
                    pass
        log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--sid')
    parser.add_argument('--frontend-home', type=Path)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--watch-bindings', type=Path)
    parser.add_argument('--native-fd', type=int)
    parser.add_argument('--native-proof',help='Explicit public route/incarnation proof; never a bearer')
    parser.add_argument('--native-target',help='Exact public profile target for the reviewed bridge')
    parser.add_argument('--native-consent-expires',type=float,help='Original absolute review expiry; never renewed by the bridge')
    args = parser.parse_args()
    if args.watch_bindings is not None:
        if (args.binary is None) == (args.native_fd is None) or args.sid is not None or args.frontend_home is not None:
            parser.error('watcher mode requires exactly one of --binary/--native-fd and forbids frontend/bridge modes')
        try:
            watch_focus(args.watch_bindings, args.binary, native_fd=args.native_fd)
        finally:
            if args.native_fd is not None:
                os.close(args.native_fd)
        return
    if args.native_fd is not None:
        parser.error('--native-fd is restricted to watcher mode')
    if args.frontend_home is not None:
        if args.binary is None or args.sid is not None:
            parser.error('frontend mode requires --binary and forbids --sid')
        raise SystemExit(open_frontend(args.home.resolve(), args.frontend_home.absolute(), args.binary.absolute()))
    if args.sid is None or args.binary is not None:
        parser.error('bridge mode requires --sid')
    if bool(args.native_proof)!=bool(args.native_target):parser.error('native proof and target must be supplied together')
    bridge(args.home.resolve(), args.sid,proof=json.loads(args.native_proof) if args.native_proof else None,target=json.loads(args.native_target) if args.native_target else None,consent_expires_at=args.native_consent_expires)


if __name__ == '__main__':
    main()
