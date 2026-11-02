"""Capability-protected loopback cockpit and explicitly configured AMC team UI.

Business actions remain governed by the existing API. No terminal input,
approval consumption, provider execution or replacement authority is exposed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from .security import bounded_json_loads
from pathlib import Path
import re
import secrets
import webbrowser

from .cockpit_client import request, exchange_deadline, remaining
from .cockpit_surface import render_dashboard, snapshot, operator_summary, dashboard_availability
from .cockpit_team import render_team


SCRIPT = r'''
const fragment = location.hash.slice(1);
if (/^[A-Za-z0-9_-]{32,128}$/.test(fragment)) sessionStorage.setItem('amc-local-capability', fragment);
if (fragment) history.replaceState(null, '', '/');
const capability = sessionStorage.getItem('amc-local-capability') || '';
const status = document.getElementById('status');
const content = document.getElementById('content');
let busy = false;
let actionNotice = '';
let renderedProjection = '';
const pages = {overview: 'Overview', sessions: 'Work sessions', tasks: 'Tasks', projects: 'Projects', agents: 'Agents', approvals: 'Approval inbox', organizer: 'Organizer & handoffs', memory: 'Project memory', history: 'History & evidence'};
let currentPage = 'overview';
function showPage(page, focus = false) {
  currentPage = Object.hasOwn(pages, page) ? page : 'overview';
  document.querySelectorAll('[data-page]').forEach(section => {
    section.hidden = section.dataset.page !== currentPage;
  });
  document.querySelectorAll('[data-route]').forEach(link => {
    if (link.dataset.route === currentPage) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
  document.getElementById('page-title').textContent = pages[currentPage];
  content.hidden = !['overview', 'sessions'].includes(currentPage);
  document.getElementById('team').hidden = ['overview', 'sessions'].includes(currentPage);
  if (focus) {
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('navigation-toggle').setAttribute('aria-expanded', 'false');
    document.getElementById('page-title').focus();
  }
}
document.querySelectorAll('[data-route]').forEach(link => {
  link.onclick = event => { event.preventDefault(); showPage(link.dataset.route, true); };
});
document.getElementById('navigation-toggle').onclick = () => {
  const open = document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('navigation-toggle').setAttribute('aria-expanded', String(open));
};
document.addEventListener('keydown', event => {
  if (event.key === 'Escape') {
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('navigation-toggle').setAttribute('aria-expanded', 'false');
    document.getElementById('navigation-toggle').focus();
  }
});
async function api(path, body) {
  const options = {headers: {'Authorization': 'Bearer ' + capability}, cache: 'no-store'};
  if (body !== undefined) {
    options.method = 'POST'; options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request refused');
  return result;
}
async function update() {
  if (busy) return;
  busy = true;
  try {
    const model = await api('/api/dashboard');
    const authorityNotice = model.availability.amc_authority === false ? 'Task authority unavailable — task counts and ledger are unknown. Local session controls remain usable. · ' : '';
    status.textContent = (actionNotice ? actionNotice + ' · ' : '') + authorityNotice + 'Connected to local AMC owner · ' + model.operator_summary;
    const projection = JSON.stringify([model.sessions, model.tasks, model.capture, model.view, model.operator_status, model.operator_summary, model.availability]);
    // An unchanged poll must not replace focused session actions. Team forms
    // already have an independent, explicitly refreshed replacement boundary.
    if (projection === renderedProjection) return;

    const doc = new DOMParser().parseFromString(model.html, 'text/html');
    content.replaceChildren(doc.querySelector('main'));
    content.querySelector('header p').textContent = 'Shared terminal selection and existing AMC tasks. Local owner refreshes every 2 seconds.';
    const main = content.querySelector('main');
    main.querySelector('header').hidden = true;
    const overview = document.createElement('section'); overview.dataset.page = 'overview';
    overview.append(main.querySelector('.metrics'));
    const sessionPage = document.createElement('section'); sessionPage.dataset.page = 'sessions';
    const headings = main.querySelectorAll('h2');
    sessionPage.append(headings[0], main.querySelector('.sessions'));
    overview.append(headings[1]);
    const authorityWarning = main.querySelector('.task-authority-warning');
    if (authorityWarning) overview.append(authorityWarning);
    overview.append(main.querySelector('.table'), main.querySelector('footer'));
    main.append(overview, sessionPage);
    showPage(currentPage);
    const cards = content.querySelectorAll('article.session');
    model.sessions.forEach((session, index) => {
      const select = document.createElement('button'); select.textContent = 'Select in cockpit';
      select.onclick = async () => {
        try { await api('/api/select', {sid: session.id, revision: model.view.revision}); actionNotice = 'Shared selection updated.'; }
        catch (error) { actionNotice = error.message + ' · No automatic retry.'; }
        update();
      };
      cards[index].append(select);
      const take = document.createElement('button'); take.textContent = 'Take control · stop operator';
      take.onclick = async () => {
        take.disabled = true;
        try {
          const result = await api('/api/take-control', {sid: session.id});
          if (result === null) {
            actionNotice = 'No active operator delegation; child process not interrupted.';
            take.disabled = false;
          } else {
            actionNotice = result.acknowledged === false ? 'Cancellation recorded; remote owner has NOT acknowledged. Inspect host before assuming operator stopped.' : 'Operator revoked; child process not interrupted.';
          }
        }
        catch (error) { actionNotice = 'Revocation delivery unconfirmed. Inspect owner state; no automatic retry.'; }
        update();
      };
      cards[index].append(take);
      if (session.status !== 'ended') {
        const end = document.createElement('button'); end.textContent = 'End session…';
        end.onclick = async () => {
          if (prompt('Stop the process and preserve files? Type the exact session name: ' + session.name) !== session.name) return;
          try { await api('/api/end', {sid: session.id, confirm: session.id}); actionNotice = 'Session ended; workspace preserved.'; }
          catch (error) { actionNotice = error.message + ' · Delivery may be uncertain; inspect state before another action.'; }
          update();
        };
        cards[index].append(end);
      }
    });
    renderedProjection = projection;
  } catch (error) {
    status.textContent = 'Disconnected or unauthorized: ' + error.message + '. View may be stale. No input is queued or resent.';
  } finally { busy = false; }
}
let teamBusy = false;
async function refreshTeam() {
  if (teamBusy) return;
  teamBusy = true;
  const target = document.getElementById('team');
  try {
    const model = await api('/api/team');
    const doc = new DOMParser().parseFromString(model.html, 'text/html');
    target.replaceChildren(doc.querySelector('section'));
    showPage(currentPage);
    document.getElementById('team-status').textContent = 'Team snapshot refreshed ' + new Date().toLocaleTimeString() + ' · refresh explicitly; drafts never auto-send.';
    const filter = target.querySelector('#task-filter');
    filter.oninput = () => target.querySelectorAll('[data-task-row]').forEach(row => { row.hidden = !row.textContent.toLowerCase().includes(filter.value.toLowerCase()); });
    const approvalFilter = target.querySelector('#approval-filter');
    approvalFilter.onchange = () => target.querySelectorAll('[data-approval-status]').forEach(card => { card.hidden = approvalFilter.value === 'pending' && card.dataset.approvalStatus !== 'requested'; });
    approvalFilter.onchange();
    target.querySelectorAll('form[data-team-action]').forEach(form => {
      form.onsubmit = async event => {
        event.preventDefault();
        if (form.dataset.pending) return;
        const body = Object.fromEntries(new FormData(form));
        if (form.dataset.teamAction === 'memory-recall') body.consent = form.elements.consent.checked;
        else body.idempotency_key = 'web-' + crypto.randomUUID();
        const button = form.querySelector('button');
        const output = form.querySelector('output');
        form.dataset.pending = 'true'; button.disabled = true;
        output.textContent = 'Submitting once…';
        try {
          const result = await api('/api/team/action', {action: form.dataset.teamAction, payload: body});
          if (form.dataset.teamAction === 'memory-recall') {
            target.querySelector('#memory-preview').textContent = JSON.stringify(result, null, 2);
            output.textContent = 'Recall preview only. Not injected into any conversation.';
            delete form.dataset.pending; button.disabled = false;
          } else {
            output.textContent = 'AMC accepted. Refresh to verify authoritative state; this submission remains disabled.';
          }
        } catch (error) {
          output.textContent = error.message + ' · Delivery may be uncertain. Retain draft and inspect AMC state before any new submission. No retry.';
        }
      };
    });
    target.querySelectorAll('[data-approve]').forEach(button => {
      button.onclick = async () => {
        const id = button.dataset.approve;
        if (prompt('Approve recorded request only; no execution. Type exact approval ID: ' + id) !== id) return;
        button.disabled = true;
        try {
          await api('/api/team/action', {action: 'approval-approve', payload: {id, confirm: id, idempotency_key: 'web-' + crypto.randomUUID()}});
          button.textContent = 'Accepted · refresh to verify';
        } catch (error) { button.textContent = 'Uncertain/refused · inspect before retry'; }
      };
    });
  } catch (error) {
    document.getElementById('team-status').textContent = 'AMC team unavailable or unauthorized. Last view may be stale. Drafts remain local; no retry.';
  } finally { teamBusy = false; }
}
document.getElementById('team-refresh').onclick = () => {
  if (document.querySelector('#team form[data-pending]')) {
    if (!confirm('Discard the submitted/uncertain form view and refresh authoritative state? Nothing will be resent.')) return;
  } else if ([...document.querySelectorAll('#team input')].some(input => input.value && input.type !== 'checkbox')) {
    if (!confirm('Discard local unsent drafts and refresh? Nothing will be sent.')) return;
  }
  refreshTeam();
};
update(); refreshTeam(); setInterval(update, 2000);
'''

SCRIPT_HASH = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode('ascii')
CSP = "default-src 'none'; script-src 'sha256-" + SCRIPT_HASH + "'; style-src 'unsafe-inline'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"



# Adapted from Paperclip Sidebar.tsx / primary-sidebar-styles.ts at
# efce9356b553a08f77a5877bb0ceac68d2cc4ad8, MIT (see licenses/Paperclip-MIT.txt).
# Keep navigation and drafts outside the owner polling replacement boundary.
STYLE = '''
:root{color-scheme:light;--ink:#202124;--muted:#737579;--line:#e5e5e5;--paper:#fff;--rail:#f5f5f4;--active:#e6e6e4}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:13px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
button,input,select{font:inherit}button,a,input,select,summary{outline-offset:3px}:focus-visible{outline:2px solid #28714b}
button{border:1px solid var(--line);background:white;border-radius:6px;padding:7px 12px;color:var(--ink);cursor:pointer}
button:hover{background:#f1f1ef}button:disabled{opacity:.55;cursor:default}button+button{margin-left:7px}
a{color:inherit;text-decoration:none}.skip{position:fixed;top:-60px;z-index:20;background:white;padding:12px}.skip:focus{top:0}
#sidebar{width:240px;position:fixed;inset:0 auto 0 0;background:var(--rail);border-right:1px solid var(--line);padding:0 16px 16px;display:flex;flex-direction:column;z-index:5;overflow-y:auto}
.brand{height:60px;display:flex;align-items:center;padding-left:12px}.brand img{width:100px;height:auto;display:block}.mobile-brand{display:none;width:70px;height:auto}
.nav-group{font-size:10px;letter-spacing:1.2px;color:#8a8b8b;margin:26px 12px 8px}nav a{display:flex;align-items:center;gap:11px;padding:8px 12px;margin:2px 0;border-radius:7px;min-height:34px}nav a:hover{background:#ebebe9}nav a[aria-current=page]{background:var(--active);font-weight:600}.nav-icon{width:16px;text-align:center;font-size:16px;color:#626663}.rail-footer{margin-top:auto;padding:20px 12px 0;color:var(--muted);font-size:11px;border-top:1px solid var(--line)}
#workspace{margin-left:240px;min-width:0}.topbar{height:60px;display:flex;align-items:center;gap:16px;border-bottom:1px solid var(--line);padding:0 26px;position:sticky;top:0;background:white;z-index:2}#page-title{font-size:13px;font-weight:600;letter-spacing:.6px;text-transform:uppercase;margin:0}.scope{margin-left:auto;color:var(--muted);font-size:11px}#navigation-toggle{display:none}
#status{padding:9px 26px;border-bottom:1px solid var(--line);color:#616864;background:#fafbf9;font-size:11px;overflow-wrap:anywhere}
#content main{padding:24px 26px 0;max-width:none;margin:0}h2{font-size:15px;font-weight:600;margin:0 0 20px}h3{font-size:14px;font-weight:600;margin:0 0 8px}p{color:var(--muted);line-height:1.6}pre,code{font:11px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}dl{font-size:12px}dt{color:var(--muted);margin-top:12px}dd{margin:2px 0;overflow-wrap:anywhere}
.metrics{display:grid;grid-template-columns:repeat(3,1fr);border:1px solid var(--line);border-radius:7px;margin-bottom:28px}.metric{padding:18px 22px;color:var(--muted);border-right:1px solid var(--line)}.metric:last-child{border:0}.metric strong{display:block;font-size:27px;line-height:1.4;font-weight:600;color:var(--ink)}
.sessions,.team-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));gap:14px}article.session,#team article{border:1px solid var(--line);border-radius:7px;padding:18px;min-width:0;overflow-wrap:anywhere}.eyebrow{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}.session button{margin:10px 6px 0 0;font-size:11px}.attention{border-left:3px solid #35885a!important}
.table{overflow:auto}table{border-collapse:collapse;width:100%;text-align:left}th{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);font-weight:500}th,td{padding:11px 12px;border-bottom:1px solid var(--line)}tbody tr:hover{background:#fafafa}td:first-child{min-width:180px}td:nth-child(3){font-size:11px}footer{border-top:1px solid var(--line);padding:20px 0;margin-top:30px;font-size:11px;color:var(--muted)}
.team-controls{display:flex;align-items:center;gap:14px;margin:20px 26px 0;border-top:1px solid var(--line);padding-top:16px}#team-status{font-size:11px}#team{padding:20px 26px 40px}#team-panel>h2,#team-panel>p{display:none}.availability{font-size:11px;color:var(--muted);margin-bottom:24px;border-bottom:1px solid var(--line);padding-bottom:12px}
#team fieldset{min-inline-size:0;border:1px solid var(--line);border-radius:6px;padding:18px;max-width:620px;margin:18px 0}legend{padding:0 6px;font-weight:500;max-width:100%}label{display:block;font-size:12px;color:#555;margin:12px 0}input:not([type=checkbox]),select{display:block;width:100%;max-width:440px;min-width:0;border:1px solid #d8d9d7;border-radius:5px;padding:9px 10px;background:white;color:var(--ink);margin-top:6px}input[type=search]{margin-bottom:20px}select{width:auto;min-width:140px}input[type=checkbox]{accent-color:#28714b}output{display:block;margin-top:12px;color:#5b645d}details{border-bottom:1px solid var(--line);padding:12px 0}summary{cursor:pointer;font-weight:500}.composer{margin-top:20px}#team [data-page]>h2:not(:first-child){margin-top:30px}[hidden]{display:none!important}
@media(max-width:760px){#sidebar{display:none;width:240px;top:60px;box-shadow:8px 0 30px #0002}#sidebar.open{display:flex}#workspace{margin-left:0}.topbar{padding:0 16px}#navigation-toggle{display:block}.scope{font-size:10px}#status{padding:9px 16px}#content main,#team{padding-left:16px;padding-right:16px}.team-controls{margin-left:16px;margin-right:16px;flex-wrap:wrap;gap:2px}.metrics{grid-template-columns:repeat(3,1fr)}.metric{padding:12px 10px;font-size:11px}.metric strong{font-size:24px}.sessions,.team-grid{grid-template-columns:1fr}table,tbody{display:block}thead{display:none}tbody tr{display:grid;grid-template-columns:1fr auto;padding:12px 0;border-bottom:1px solid var(--line);gap:4px 12px}td{border:0;padding:0;min-width:0!important}td:first-child,td:last-child{grid-column:1/-1}td:nth-child(2){color:var(--muted)}td:last-child{color:var(--muted);font-size:10px}td code{overflow-wrap:anywhere}}
'''

SHELL = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Arvyx · Team workspace</title><link rel="icon" type="image/png" href="/assets/favicon.png"><style>''' + STYLE + '''@media(max-width:760px){.mobile-brand{display:block}.scope{display:none}.topbar{gap:12px}#page-title{font-size:11px;margin-left:auto}}</style>
<a class="skip" href="#workspace">Skip to workspace</a>
<aside id="sidebar"><div class="brand"><img src="/assets/arvyx-wordmark.png" alt="Arvyx" width="100"></div>
<nav aria-label="Main navigation">
<a href="#workspace" data-route="overview" aria-current="page"><span class="nav-icon" aria-hidden="true">◫</span>Overview</a>
<a href="#workspace" data-route="approvals"><span class="nav-icon" aria-hidden="true">▱</span>Inbox</a>
<div class="nav-group">WORK</div>
<a href="#workspace" data-route="tasks"><span class="nav-icon" aria-hidden="true">◎</span>Tasks</a>
<a href="#workspace" data-route="projects"><span class="nav-icon" aria-hidden="true">▱</span>Projects</a>
<a href="#workspace" data-route="sessions"><span class="nav-icon" aria-hidden="true">▣</span>Work sessions</a>
<div class="nav-group">TEAM</div>
<a href="#workspace" data-route="agents"><span class="nav-icon" aria-hidden="true">♧</span>Agents</a>
<a href="#workspace" data-route="organizer"><span class="nav-icon" aria-hidden="true">▤</span>Organizer</a>
<a href="#workspace" data-route="memory"><span class="nav-icon" aria-hidden="true">◇</span>Memory</a>
<a href="#workspace" data-route="history"><span class="nav-icon" aria-hidden="true">◷</span>History &amp; evidence</a>
</nav><div class="rail-footer">Single human · existing AMC authority<br>Local-only workspace</div></aside>
<div id="workspace" tabindex="-1"><header class="topbar"><button id="navigation-toggle" aria-controls="sidebar" aria-expanded="false" aria-label="Toggle navigation">☰</button><img class="mobile-brand" src="/assets/arvyx-wordmark.png" alt="Arvyx" width="70"><h1 id="page-title" tabindex="-1">Overview</h1><span class="scope">Local AMC · private pilot</span></header>
<div id="status" role="status">Local AMC · capability required · no provider calls</div><div id="content"></div>
<div id="team"></div><div class="team-controls"><button id="team-refresh">Refresh team authority</button><p id="team-status" role="status">Team authority not loaded</p></div>
</div><script>''' + SCRIPT + '</script></html>'


from .public_onboarding_api import BoundedWorkers


class DashboardServer(BoundedWorkers, ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, root: Path, port=0, *, capability=None, team=None):
        self.root = root
        self.team = team
        self.capability = secrets.token_urlsafe(32) if capability is None else capability
        if not isinstance(self.capability, str) or not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', self.capability):
            raise ValueError('invalid dashboard capability')
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError('invalid loopback port')
        super().__init__(('127.0.0.1', port), DashboardHandler)
        self.origin = 'http://127.0.0.1:' + str(self.server_address[1])

    def get_request(self):
        client, address = super().get_request()
        client.settimeout(3)
        return client, address


class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Never persist capability headers, browser paths or registry content.

    def reply(self, code, value, *, html=False, content_type=None):
        data = value if content_type else (value.encode() if html else json.dumps(value).encode())
        self.send_response(code)
        self.send_header('Content-Type', content_type or ('text/html; charset=utf-8' if html else 'application/json'))
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', CSP)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()
        self.wfile.write(data)

    def authorized(self, *, mutation=False):
        hosts = self.headers.get_all('Host', [])
        headers = self.headers.get_all('Authorization', [])
        expected_host = self.server.origin.removeprefix('http://')
        if hosts != [expected_host] or len(headers) != 1:
            return False
        expected = 'Bearer ' + self.server.capability
        if not hmac.compare_digest(headers[0].encode(), expected.encode()):
            return False
        return not mutation or self.headers.get_all('Origin', []) == [self.server.origin]

    def do_GET(self):
        assets = {'/assets/arvyx-wordmark.png': ('arvyx-wordmark.png', 'image/png'),
                  '/assets/favicon.png': ('favicon.png', 'image/png')}
        if self.path in assets:
            name, mime = assets[self.path]
            data = (Path(__file__).parent / 'static' / 'brand' / name).read_bytes()
            self.reply(200, data, content_type=mime)
            return
        if self.path == '/':
            self.reply(200, SHELL, html=True)
            return
        if not self.authorized():
            self.reply(403, {'error': 'Local capability required'})
            return
        if self.path == '/api/team':
            try:
                with exchange_deadline(2.5) as team_end:
                    try:
                        local = snapshot(self.server.root)
                        local['machine_available'] = True
                    except (ValueError, OSError):
                        local = {'sessions': [], 'host': 'unavailable', 'machine_available': False}
                    local['delegations'] = {}
                    for session in local.get('sessions', []):
                        if session.get('online') is False or str(session.get('status', '')).startswith('offline'):
                            local['delegations'][session['id']] = {'status': 'unavailable'}
                            continue
                        # Owner snapshots already include delegation, including None.
                        # Do not fan out another identity snapshot/read for each row.
                        if 'delegation' in session:
                            local['delegations'][session['id']] = session['delegation']
                            continue
                        try:
                            remaining(team_end)
                            local['delegations'][session['id']] = request(self.server.root, 'delegation', sid=session['id'], actor='operator')
                        except (ValueError, OSError):
                            local['delegations'][session['id']] = {'status': 'unavailable'}
                    remaining(team_end)
                    model = self.server.team.read() if self.server.team is not None else {'availability': {}}
                    remaining(team_end)
                    self.reply(200, {'html': render_team(model, local)})
            except (ValueError, OSError, RuntimeError):
                self.reply(503, {'error': 'Team authority unavailable; no requests queued'})
            return
        if self.path != '/api/dashboard':
            self.reply(404, {'error': 'Unknown endpoint'})
            return
        try:
            model = snapshot(self.server.root)
            self.reply(200, dict(html=render_dashboard(model), sessions=model['sessions'], tasks=model['tasks'],
                                 capture=model.get('capture'), view=model['view'],
                                 availability=dashboard_availability(model),
                                 operator_status=model.get('operator_status', {}), operator_summary=operator_summary(model)))
        except (ValueError, OSError):
            self.reply(503, {'error': 'Local AMC owner unavailable; no input queued'})

    def do_POST(self):
        if not self.authorized(mutation=True):
            self.reply(403, {'error': 'Local capability and exact origin required'})
            return
        if self.path not in {'/api/select', '/api/end', '/api/take-control', '/api/team/action'}:
            self.reply(404, {'error': 'Unknown endpoint'})
            return
        try:
            if self.headers.get_all('Content-Type', []) != ['application/json']:
                raise ValueError('JSON content type required')
            sizes = self.headers.get_all('Content-Length', [])
            if len(sizes) != 1 or self.headers.get('Transfer-Encoding') is not None:
                raise ValueError('One bounded content length required')
            size = int(sizes[0])
            if not 0 < size <= 4096:
                raise ValueError('Request size rejected')
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError('Incomplete request; not dispatched')
            def unique_fields(pairs):
                result = dict(pairs)
                if len(result) != len(pairs):
                    raise ValueError('Duplicate JSON fields rejected')
                return result
            data = bounded_json_loads(raw, object_pairs_hook=unique_fields)
            if self.path == '/api/team/action':
                if not isinstance(data, dict) or set(data) != {'action', 'payload'} or not isinstance(data['action'], str):
                    raise ValueError('Exact action envelope required')
                if self.server.team is None:
                    self.reply(503, {'error': 'AMC identity not configured; no mutation attempted'})
                    return
                result = self.server.team.action(data['action'], data['payload'])
                # Never reflect private paths, credential errors or raw command content.
                if result.status >= 400:
                    self.reply(result.status, {'error': 'AMC refused or outcome requires reconciliation; refresh authority before any new action'})
                else:
                    self.reply(result.status, result.body)
                return
            if not isinstance(data, dict) or not isinstance(data.get('sid'), str):
                raise ValueError('Exact session ID required')
            if self.path == '/api/take-control':
                if set(data) != {'sid'}:
                    raise ValueError('Exact revocation target required')
                result = request(self.server.root, 'take_control', sid=data['sid'], actor='operator')
            elif self.path == '/api/end':
                if set(data) != {'sid', 'confirm'} or data['confirm'] != data['sid']:
                    raise ValueError('Explicit target confirmation required')
                result = request(self.server.root, 'end', sid=data['sid'], actor='operator')
            else:
                if set(data) != {'sid', 'revision'} or type(data['revision']) is not int:
                    raise ValueError('Exact view revision required')
                result = request(self.server.root, 'select', sid=data['sid'], revision=data['revision'], actor='operator')
            self.reply(200, result)
        except (ValueError, OSError) as exc:
            # Do not echo arbitrary request content or a private workspace path.
            self.reply(400, {'error': 'Request refused or delivery uncertain; refresh and reconcile, do not blindly retry'})


def serve(root, port=0):
    server = DashboardServer(root, port)
    print(server.origin + ' (local-only; capability opens in your browser, not printed)', flush=True)
    webbrowser.open(server.origin + '/#' + server.capability)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
