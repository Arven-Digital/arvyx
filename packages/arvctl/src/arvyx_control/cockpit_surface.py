"""Local terminal session navigator and read-only AMC team snapshot.

Lifecycle semantics adapted from Herdr's server-owned pane/focus separation;
team grouping follows Paperclip's dashboard, without its second authority.
No upstream executable code or dependencies are imported.
"""
from __future__ import annotations

try:
    import curses
except ImportError:  # Windows: the standard library has no curses
    curses = None

from html import escape
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import webbrowser

from . import safe_open
from .cockpit_client import attach, request
from .cockpit_terminal_panels import read_panels, draw_panels, ordered_sessions

_PRIVATE_SHELL = object()


def private_shell():
    """Client-local interactive shell; never registered, streamed or archived by AMC."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError('private shell requires an interactive local terminal')
    print('PRIVATE LOCAL SHELL — this client machine only; not shared or recorded by AMC. Exit returns to cockpit.')
    subprocess.run(['/bin/sh', '-i'], cwd=Path.cwd(), env={
        'PATH': '/usr/bin:/bin', 'HOME': str(Path.home()),
        'TERM': os.environ.get('TERM', 'xterm-256color'), 'ENV': '/dev/null', 'PS1': 'private-local $ ',
    }, check=False)


def label(value):
    """Never interpret registry fields as terminal control sequences."""
    return ''.join(char if char.isprintable() else '?' for char in str(value))


def snapshot(root):
    return request(root, 'snapshot', actor='operator')


def operator_summary(model):
    status = model.get('operator_status', {})
    counts = status.get('delegations', {})
    authority = ', '.join(f'{key}: {value}' for key, value in sorted(counts.items())) if counts else 'none recorded'
    return ('Delegated authority: ' + authority + ' · Runner: ' + status.get('runner', 'unknown') +
            ' · Provider activity: ' + status.get('provider_activity', 'unknown'))


def capture_summary(model):
    status = model.get('capture')
    if status is None:
        return 'Recording status unavailable'
    return (f"Recording: {status['pending']} pending · {status['interrupted_runs']} interrupted runs · "
            f"AMC archive sync: {status['sync']} · no automatic deletion")


def dashboard_availability(model):
    """Allowlist boolean availability only; never forward private error details."""
    availability = model.get('availability', {})
    return {key: value for key, value in availability.items()
            if key in {'amc_authority', 'machine', 'amc_memory'}
            and (type(value) is bool or (key == 'amc_memory' and value is None))}


def task_authority_warning(model):
    if dashboard_availability(model).get('amc_authority') is False:
        return 'Task authority unavailable — task counts and ledger are unknown. Local session controls remain usable.'
    return ''


def render_dashboard(model):
    def text(value):
        return escape(str(value), quote=True)

    sessions = model['sessions']
    warning = task_authority_warning(model)
    tasks = [] if warning else model['tasks']
    selected = model['view']['selected']
    cards = []
    for session in sessions:
        cards.append('<article class="session"><div class="eyebrow">' + text(session['project']) +
                     '</div><h3>' + text(('@' + session['host'] + ' ' if session.get('host') else '') + session['name']) + '</h3><p>' + text(session['status']) +
                     (' · selected in cockpit' if session['id'] == selected else '') +
                     '</p><p>' + text(session.get('capture_error') or '') + '</p><dl><dt>Task</dt><dd>' + text(session['task']) +
                     '</dd><dt>Workspace</dt><dd>' + text(session['workspace']) +
                     '</dd><dt>Session</dt><dd>' + text(session['id']) + '</dd></dl></article>')
    rows = ''.join('<tr><td>' + text(task['title']) + '</td><td>' + text(task['owner']) +
                   '</td><td>' + text(task['status']) + '</td><td><code>' + text(task['id']) +
                   '</code></td></tr>' for task in tasks)
    owners = sorted({str(task['owner']) for task in tasks})
    return '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>AMC · Local team cockpit</title><style>
*{box-sizing:border-box}body{margin:0;background:#101715;color:#e5ece6;font:15px system-ui,sans-serif}
main{max-width:1200px;margin:auto;padding:48px 28px}header{border-bottom:1px solid #35453c;padding-bottom:28px}
.eyebrow{color:#a9cc9a;font:12px monospace;letter-spacing:2px;text-transform:uppercase}h1{font-size:42px;letter-spacing:-2px;margin:14px 0}
p{color:#b3c0b6;line-height:1.6}h2{margin-top:40px;font-size:22px}.metrics,.sessions{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px}
.metric,.session{background:#19231d;border:1px solid #35453c;border-radius:10px;padding:22px}.metric strong{font-size:32px;display:block;margin-bottom:8px}
.metrics{margin-top:28px}h3{font-size:24px;margin:12px 0}dt{color:#8ba394;font-size:12px;margin-top:14px}dd{margin:4px 0;overflow-wrap:anywhere;font:12px monospace}
.table{overflow:auto}table{width:100%;border-collapse:collapse;text-align:left}th,td{padding:14px 12px;border-bottom:1px solid #35453c}th{color:#a9cc9a;font-size:12px;text-transform:uppercase}code{font-size:11px}footer{margin-top:40px;border-top:1px solid #35453c;padding-top:20px;color:#8ba394}
</style><main><header><div class="eyebrow">AMC / Local pilot / ''' + text(model['host']) + '''</div>
<h1>The team, without a second control plane.</h1><p>Read-only snapshot of the same AMC tasks and cockpit sessions. Refresh from the terminal navigator with r or w. No terminal contents are exported.</p></header>
<div class="metrics"><div class="metric"><strong>''' + ('Unknown' if warning else str(len(tasks))) + '''</strong>AMC tasks</div><div class="metric"><strong>''' + str(len(sessions)) + '''</strong>Work sessions</div><div class="metric"><strong>''' + ('Unknown' if warning else str(len(owners))) + '''</strong>Task owners</div></div>
<h2>Work sessions</h2><div class="sessions">''' + (''.join(cards) or '<p>No sessions</p>') + '''</div>
<h2>Task ledger</h2>''' + ('<p class="task-authority-warning" role="status">' + text(warning) + '</p>' if warning else '') + '''<div class="table"><table><thead><tr><th>Task</th><th>Owner</th><th>Status</th><th>AMC identity</th></tr></thead><tbody>''' + (rows or ('<tr><td colspan="4">Task ledger unknown</td></tr>' if warning else '<tr><td colspan="4">No tasks</td></tr>')) + '''</tbody></table></div>
<footer>Local pilot · Single human operator<br>''' + text(operator_summary(model)) + '''<br>''' + text(capture_summary(model)) + '''<br>Snapshot captured: ''' + text(model.get('captured_at', 'timestamp unavailable')) + '''<br>Selection revision ''' + text(model['view']['revision']) + ''' · A stopped process is not a resumed conversation. Task status remains AMC-authoritative.</footer></main></html>'''


def export_dashboard(root, model=None):
    """Owner-private atomic snapshot; no TCP listener or browser input endpoint."""
    model = snapshot(root) if model is None else model
    fd, name = tempfile.mkstemp(prefix='.team-', suffix='.html', dir=root)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline="\n") as stream:
            stream.write(render_dashboard(model))
        target = root / 'team.html'
        safe_open.replace_path(name, target)
        return target
    finally:
        Path(name).unlink(missing_ok=True)


def navigator(root):
    """Navigation and PTY attachment are separate modes; output cannot run commands."""
    if curses is None:
        raise RuntimeError("the terminal surface needs curses, which this platform's Python does not provide; use 'arvyx web' instead")
    while True:
        action = curses.wrapper(lambda screen: _navigate(screen, root))
        if action is None:
            return
        if action is _PRIVATE_SHELL:
            private_shell()
            continue
        attach(root, action)


def _navigate(screen, root):
    curses.curs_set(0)
    attention_attr = curses.A_BOLD
    try:
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_GREEN, -1)
            attention_attr |= curses.color_pair(1)
    except curses.error:
        pass
    screen.timeout(500)
    index = 0
    notice = ''
    while True:
        model = {'sessions': [], 'view': {'selected': None, 'panels': [], 'revision': 0}}
        selected = None
        try:
            model = snapshot(root)
            export_dashboard(root, model)
            sessions = ordered_sessions(model['sessions'])
            selected = model['view']['selected']
            if selected:
                index = next((i for i, item in enumerate(sessions) if item['id'] == selected), index)
            index = min(index, max(0, len(sessions) - 1))
            online = True
            if model.get('availability', {}).get('amc_authority') is False:
                notice = 'AMC unavailable — long-term memory unavailable. Local terminals remain usable; drafts never auto-send.'
        except (OSError, ValueError) as exc:
            sessions = []
            online = False
            notice = 'Arvyx unreachable; no input queued: ' + str(exc)
        screen.erase()
        height, width = screen.getmaxyx()

        def line(y, value, attr=0):
            if 0 <= y < height - 1 and width > 1:
                screen.addnstr(y, 0, label(value), width - 1, attr)

        line(0, ' AMC  /  ' + str(model.get('host', 'unavailable')) + '  /  WORKSPACE', curses.A_BOLD)
        line(1, ' Shared selection · read-only previews · Enter opens native terminal', curses.A_DIM)
        line(2, ' ' + operator_summary(model), curses.A_DIM)
        capacity = max(1, (height - 10) // 2)
        start = max(0, index - capacity + 1)
        sidebar = min(40, max(20, width // 3)) if width >= 70 else width
        line(3, ' SESSIONS  ' + str(len(sessions)), curses.A_DIM)
        for position, item in enumerate(sessions[start:start + capacity], start=start):
            attention = item.get('attention') in {'human', 'review'}
            title = ('› ' if position == index else '  ') + item['name']
            attr = (attention_attr if attention else 0) | (curses.A_REVERSE if position == index else 0)
            y = (position - start) * 2 + 4
            if y + 1 < height - 5:
                screen.addnstr(y, 0, label(title.ljust(sidebar - 2)), max(1, sidebar - 2), attr)
                detail = '  ' + ('@' + item['host'] + ' · ' if item.get('host') else '') + (item['attention'] if attention else item['status'])
                screen.addnstr(y + 1, 0, label(detail), max(1, sidebar - 2), attention_attr if attention else curses.A_DIM)
        if online and width >= 70:
            for y in range(3, max(3, height - 5)):
                screen.addnstr(y, sidebar - 1, '│', 1, curses.A_DIM)
            draw_panels(screen, read_panels(root, model), top=4, left=sidebar,
                        height=max(0, height - 9), width=width - sidebar - 1)
        if sessions:
            line(height - 5, str(model.get('host', 'owner')) + ' / ' + str(sessions[index]['project'] or 'organizer') + ' / ' + str(sessions[index]['task'] or 'coordination, not a work task'))
            line(height - 4, 'Workspace: ' + sessions[index]['workspace'])
        line(height - 3, notice or (capture_summary(model) if online else 'Offline'))
        line(height - 2, ' j/k select   Enter attach   x hide   t all   e End   w web   p private   q detach', curses.A_REVERSE)
        screen.refresh()
        key = screen.getch()
        if key == ord('q'):
            return None
        if key == ord('p'):
            return _PRIVATE_SHELL
        if not online:
            continue
        if key in (ord('j'), curses.KEY_DOWN, ord('k'), curses.KEY_UP) and sessions:
            step = 1 if key in (ord('j'), curses.KEY_DOWN) else -1
            target = sessions[(index + step) % len(sessions)]
            try:
                request(root, 'select', sid=target['id'], revision=model['view']['revision'], actor='operator')
            except (ValueError, OSError) as exc:
                notice = str(exc)
        elif key in (ord('x'), ord('t')) and sessions:
            panels = list(model['view'].get('panels', []))
            target = sessions[index]['id']
            if key == ord('t'):
                panels = [item['id'] for item in sessions[:16]]
                focus = selected if selected in panels else panels[0]
            else:
                panels = [sid for sid in panels if sid != target]
                focus = selected if selected in panels else (panels[0] if panels else None)
            try:
                request(root, 'layout', panels=panels, selected=focus,
                        revision=model['view']['revision'], actor='operator')
            except (OSError, ValueError) as exc:
                notice = str(exc)
        elif key in (10, 13) and sessions:
            if sessions[index]['status'] == 'running':
                target = sessions[index]['id']
                # Even an unchanged focus must pass the revision fence: another
                # client may have selected a pane while getch was waiting.
                try:
                    request(root, 'select', sid=target, revision=model['view']['revision'], actor='operator')
                except (OSError, ValueError) as exc:
                    notice = str(exc)
                    continue
                return target
            notice = 'Stopped/ended: use explicit start from the CLI; never auto-resume.'
        elif key == ord('e') and sessions:
            target = sessions[index]
            line(height - 2, 'End ' + target['name'] + '? Press Y to stop process; files remain.')
            screen.refresh()
            screen.timeout(-1)
            confirm = screen.getch()
            screen.timeout(500)
            if confirm == ord('Y'):
                try:
                    request(root, 'end', sid=target['id'], actor='operator')
                    notice = 'Ended ' + target['name'] + '; workspace preserved.'
                except (OSError, ValueError) as exc:
                    notice = str(exc)
        elif key == ord('w'):
            try:
                endpoint = request(root, 'dashboard', actor='operator')
                webbrowser.open(endpoint['url'])
                notice = 'Opened the owner-managed live local team dashboard.'
            except (OSError, ValueError) as exc:
                notice = 'Web unavailable: ' + str(exc)
