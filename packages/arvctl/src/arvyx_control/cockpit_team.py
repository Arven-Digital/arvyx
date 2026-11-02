"""AMC team panel over the governed API, never a second persistence authority.

Modified interaction adaptations of Paperclip Approvals.tsx / ApprovalCard.tsx
and Dashboard.tsx at efce9356b553a08f77a5877bb0ceac68d2cc4ad8.
Copyright (c) 2025 Paperclip AI. MIT notice retained in TEAM_ATTRIBUTION below.
No React code, company identity, billing, or database layer imported.
"""
from __future__ import annotations

from html import escape
from pathlib import Path
import re

from .api import handle_api_request
from .cockpit_client import checkpoint, exchange_deadline

TEAM_ATTRIBUTION = '''MIT License

Copyright (c) 2025 Paperclip AI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.'''


class TeamAuthority:
    """Explicit server-held AMC credentials; browser capability is NOT AMC identity.

    Callers configure existing identity; this class never issues tokens, enables
    demo mode, or reads ambient credential files. API permissions are rechecked
    on every call. No credentials are serialized into a response or HTML.
    """

    def __init__(self, vault: Path, state: Path, *, authorization=None, bearer_secret=None):
        self.vault = Path(vault)
        self.state = Path(state)
        self._authorization = authorization
        self._bearer_secret = bearer_secret

    def _call(self, method, path, body=None):
        checkpoint()
        return handle_api_request(method, path, body, vault=self.vault, state=self.state,
                                  authorization=self._authorization, bearer_secret=self._bearer_secret,
                                  allow_unauthenticated_demo=False)

    def read(self):
        # In-process API, not HTTP: checkpoints prevent further dispatch but
        # cannot interrupt a filesystem syscall or the API's own lock wait.
        with exchange_deadline(2.5):
            return self._read()

    def _read(self):
        model: dict = {'availability': {}}
        for name, route in [('control', '/control-plane'), ('tasks', '/tasks'),
                            ('approvals', '/approvals'), ('handoffs', '/handoffs'),
                            ('threads', '/threads')]:
            checkpoint()
            try:
                result = self._call('GET', route)
                checkpoint()
                available = result.status == 200 and isinstance(result.body, dict)
                model['availability'][name] = available
                if available:
                    model[name] = result.body
            except (OSError, ValueError, RuntimeError):
                model['availability'][name] = False
        checkpoint()
        return model

    def action(self, name, payload):
        schemas = {
            'task-create': ({'title', 'owner', 'idempotency_key'}, '/tasks'),
            'approval-request': ({'command', 'requester', 'reason', 'idempotency_key'}, '/approvals/request'),
            'approval-approve': ({'id', 'confirm', 'idempotency_key'}, None),
            'handoff-create': ({'title', 'from_agent', 'to_agent', 'summary', 'idempotency_key'}, '/handoffs'),
            'organizer-post': ({'title', 'body', 'actor', 'target', 'idempotency_key'}, '/threads'),
            'memory-recall': ({'question', 'project', 'consent'}, '/memory/recall'),
        }
        if name not in schemas or not isinstance(payload, dict):
            raise ValueError('Unsupported team action')
        fields, route = schemas[name]
        if set(payload) != fields:
            raise ValueError('Exact action fields required')
        body = dict(payload)
        if name == 'memory-recall':
            if body.pop('consent') is not True:
                raise ValueError('Explicit project-memory consent required')
        if any(not isinstance(value, str) or not value.strip() or len(value) > 3000
                 for value in body.values()):
            raise ValueError('Bounded nonempty action fields required')
        if name == 'approval-approve':
            identifier = body.pop('id')
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', identifier) or body.pop('confirm') != identifier:
                raise ValueError('Exact approval confirmation required')
            route = '/approvals/' + identifier + '/approve'
        if name == 'organizer-post':
            body.update(type='update', channel='ops', severity='notice')
        return self._call('POST', route, body)


def _text(value):
    return escape(str(value), quote=True)


def _collection(model, key, collection):
    value = model.get(key, {}).get(collection, [])
    return value if isinstance(value, list) else []


def render_team(model, local):
    """Pure escaped rendering; availability is not inferred from empty lists.

    Paperclip adaptations: pending/all filters, explicit details and decisions,
    disabled pending actions, separate query/mutation errors and empty states.
    AMC has no reject route: deliberately do not port Paperclip's reject button.
    """
    control = model.get('control', {})
    agents = control.get('agents', [])
    tasks = _collection(model, 'tasks', 'tasks')
    approvals = _collection(model, 'approvals', 'approvals')
    threads = _collection(model, 'threads', 'threads')
    sessions = local.get('sessions', [])
    available = model.get('availability', {})
    parts = ['<section id="team-panel"><h2>Team control room</h2>',
             '<p>AMC permissions, audit and idempotency remain authoritative. No command execution or automatic task acceptance.</p>',
             '<div class="availability" role="status">Machine: ' + _text(local.get('host', 'unknown')) +
             ' · AMC control: ' + ('available' if available.get('control') else 'unavailable or unauthorized') +
             ' · Operators: registry presence only, not live reachability</div>',
             '<section data-page="agents"><h2 id="team-agents">Registered agents</h2><div class="team-grid">']
    for agent in agents:
        parts.append('<article><h3>' + _text(agent.get('display_name', agent.get('id'))) + '</h3><p>' +
                     _text(agent.get('id')) + ' · ' + _text(agent.get('status')) + '</p><pre>' +
                     _text(agent.get('machine')) + '</pre><p>Presence: registered (not a heartbeat)</p><p>Scopes: ' +
                     _text(', '.join(agent.get('scopes', []))) + '</p></article>')
    parts.append('</div>' + ('' if agents else '<p>No registered agents returned. This is not proof of an empty fleet.</p>'))
    parts.append('</section><section data-page="projects"><h2 id="team-projects">Project workspaces</h2><div class="team-grid">')
    projects = sorted({str(item.get('project', '')) for item in sessions})
    for project in projects:
        linked = [item for item in sessions if item.get('project') == project]
        parts.append('<article><h3>' + _text(project) + '</h3><p>Existing cockpit binding · ' + str(len(linked)) +
                     ' sessions</p><p>' + _text(', '.join(str(item.get('task')) for item in linked)) + '</p></article>')
    parts.append('</div><p>Projects shown from existing session bindings; no separate web project database.</p>')
    parts.append('</section><section data-page="tasks"><h2 id="team-tasks">Task ledger &amp; assignment</h2><label>Filter tasks <input id="task-filter" type="search" placeholder="Title, owner or ID"></label><div class="table"><table><thead><tr><th>Task</th><th>Owner</th><th>Status</th><th>Identity</th></tr></thead><tbody>')
    for task in tasks:
        parts.append('<tr data-task-row><td>' + _text(task.get('title')) + '</td><td>' + _text(task.get('owner')) +
                     '</td><td>' + _text(task.get('status')) + '</td><td><code>' + _text(task.get('id')) + '</code></td></tr>')
    parts.append('</tbody></table></div>')
    if not available.get('tasks'):
        parts.append('<p>Task authority unavailable or unauthorized. Nothing will be queued.</p>')
    parts.append('<details class="composer"><summary>+ New task</summary>' + _form('task-create', 'Create AMC task', [('title', 'Task title'), ('owner', 'Assigned owner')]) + '</details>')
    parts.append('</section><section data-page="approvals"><h2 id="team-approvals">Approval inbox</h2><label>Show <select id="approval-filter"><option value="pending">Pending</option><option value="all">All</option></select></label><div class="team-grid">')
    for approval in approvals:
        status = str(approval.get('status'))
        identifier = str(approval.get('id'))
        parts.append('<article data-approval-status="' + _text(status) + '"><h3>' + _text(identifier) +
                     '</h3><p>' + _text(status) + ' · requested by ' + _text(approval.get('requester')) +
                     '</p><details><summary>Command-bound decision details</summary><pre>' + _text(approval.get('command', 'Command text not retained; verify hash')) +
                     '</pre><p>Hash: ' + _text(approval.get('command_sha256', approval.get('command_hash', 'unavailable'))) +
                     '</p><p>' + _text(approval.get('reason')) + '</p><p>Expires: ' + _text(approval.get('expires_at')) + '</p></details>')
        if status == 'requested':
            parts.append('<button type="button" data-approve="' + _text(identifier) + '">Approve exact request…</button>')
        parts.append('</article>')
    parts.append('</div><p>Approval authorizes only the recorded command. Approving here never executes or consumes it.</p>')
    parts.append(_form('approval-request', 'Request command approval', [('command', 'Exact command'), ('requester', 'Requester'), ('reason', 'Reason')]))
    parts.append('<h2>Attention &amp; review evidence</h2><div class="team-grid">')
    for card in control.get('cards', []):
        if card.get('lane') not in {'review', 'active'} and not card.get('pending'):
            continue
        parts.append('<article class="attention"><h3>' + _text(card.get('title')) + '</h3><p>' +
                     _text(card.get('kind')) + ' · ' + _text(card.get('lane')) + ' · ' + _text(card.get('owner')) +
                     '</p><pre>' + _text(card.get('evidence', {})) + '</pre></article>')
    parts.append('</div><p>Attention never changes shared selection. Evidence references are inert text, not trusted executable links.</p>')
    parts.append('<h2>Session operators</h2><p>Take control on a session revokes delegation without interrupting its child process. No provider runner is implied. Assign explicitly with the existing arvyx-cockpit autopilot assign command; see arvyx-cockpit autopilot --help. No slash command is installed by this panel.</p>')
    for session in sessions:
        delegation = local.get('delegations', {}).get(session['id'], {'status': 'unavailable'})
        parts.append('<details><summary>' + _text(session.get('name')) + ' · ' + _text(session['id']) +
                     '</summary><pre>' + _text(delegation) + '</pre></details>')
    organizers = [session for session in sessions if session.get('kind') == 'organizer']
    parts.append('</section><section data-page="organizer"><h2 id="team-organizer">Organizer &amp; handoffs</h2>')
    if organizers:
        parts.append('<p>Persistent native organizer records are available in the shared terminal session list. A stopped record is not a running conversation; resume explicitly. Provider compatibility remains a separately verified gate.</p>')
        for session in organizers:
            parts.append('<p>' + _text(session['name']) + ' · ' + _text(session['status']) + ' · ' + _text(session['id']) + '</p>')
    else:
        parts.append('<p>No native organizer conversation connected.</p>')
    parts.append('<p>The following are existing AMC coordination threads, not a substitute agent conversation.</p>')
    parts.append(_form('organizer-post', 'Post coordination note', [('title', 'Subject'), ('body', 'Note'), ('actor', 'Sender'), ('target', 'Target agent')]))
    for thread in threads:
        parts.append('<details><summary>' + _text(thread.get('title')) + ' · ' + _text(thread.get('target')) +
                     '</summary><pre>' + _text(thread.get('body', thread.get('latest_text', ''))) + '</pre></details>')
    parts.append(_form('handoff-create', 'Create governed handoff', [('title', 'Title'), ('from_agent', 'From'), ('to_agent', 'To'), ('summary', 'Handoff summary')]))
    for handoff in _collection(model, 'handoffs', 'handoffs'):
        parts.append('<p>' + _text(handoff.get('id')) + ' · ' + _text(handoff.get('title')) + ' · ' + _text(handoff.get('status')) + '</p>')
    parts.append('</section><section data-page="memory"><h2 id="team-memory">Long-term memory</h2><p>Recall only after explicit consent. Results remain a preview, never injected into a native conversation or promoted to truth.</p>')
    parts.append(_form('memory-recall', 'Recall project memory', [('project', 'Existing project ID'), ('question', 'Question')], consent=True))
    parts.append('<pre id="memory-preview" aria-live="polite"></pre></section><section data-page="history"><h2>Recent AMC history</h2>')
    for event in control.get('events', []):
        parts.append('<details><summary>' + _text(event.get('type', event.get('event_type', 'Control event'))) +
                     ' · ' + _text(event.get('timestamp', '')) + '</summary><pre>' + _text(event) + '</pre></details>')
    parts.append('<details><summary>Paperclip interaction attribution · MIT</summary><pre>' + _text(TEAM_ATTRIBUTION) + '</pre></details></section></section>')
    return ''.join(parts)


def _form(action, title, fields, *, consent=False):
    result = '<form data-team-action="' + action + '"><fieldset><legend>' + title + '</legend>'
    for name, label in fields:
        result += '<label>' + label + '<input name="' + name + '" required maxlength="2000" autocomplete="off"></label>'
    if consent:
        result += '<label><input name="consent" type="checkbox" required> I consent to read this project’s memory now</label>'
    return result + '<button type="submit">' + title + '</button><output aria-live="polite"></output></fieldset></form>'
