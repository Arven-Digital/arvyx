"""One local fleet view coordinator; host owners retain their task/process authority.

Endpoints are explicit existing same-UID Unix sockets (or separately approved
SSH forwards). No discovery, enrollment token, credential copy or write retry.
"""
import json
import re
import uuid
import time
from typing import Any
from .cockpit_client import reserved_deadline, absolute_deadline, deadline_lock, checkpoint


# One fleet read: the local snapshot plus the sequential fan-out to every remote host
# must finish inside this budget; a host that does not answer in time is reported
# offline with its cached sessions. Tests on slow hosted runners widen it.
SNAPSHOT_BUDGET_SECONDS = 1.0
SNAPSHOT_RESERVE_SECONDS = 0.5


class FleetCockpit:
    def __init__(self, owner, endpoints):
        self.owner = owner
        self.endpoints = dict(endpoints)
        if owner.host in self.endpoints or any(not re.fullmatch(r'[a-z0-9-]{1,64}', host) for host in self.endpoints):
            raise ValueError('unique explicit fleet host names required')
        with owner.lock:
            owner.db.execute('''CREATE TABLE IF NOT EXISTS fleet_cache (
                host TEXT PRIMARY KEY, snapshot TEXT NOT NULL)''')
            owner.db.execute('''CREATE TABLE IF NOT EXISTS fleet_view (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1), revision INTEGER NOT NULL,
                selected TEXT, panels TEXT NOT NULL)''')
            owner.db.execute("INSERT OR IGNORE INTO fleet_view VALUES(1,0,NULL,'[]')")
            owner.db.execute('''CREATE TABLE IF NOT EXISTS fleet_cancellations (
                id TEXT PRIMARY KEY, target TEXT NOT NULL, status TEXT NOT NULL)''')
            owner.db.commit()

    @staticmethod
    def reference(host, sid):
        if not re.fullmatch(r'[a-z0-9-]{1,64}', host) or not re.fullmatch(r'[a-f0-9]{32}', sid):
            raise ValueError('invalid exact fleet session identity')
        return host + ':' + sid

    def _target(self, reference):
        if not isinstance(reference, str) or reference.count(':') != 1:
            raise ValueError('host-qualified session required')
        host, sid = reference.split(':')
        self.reference(host, sid)
        if host != self.owner.host and host not in self.endpoints:
            raise ValueError('host not explicitly configured')
        return host, sid

    def _call(self, host, operation, **fields):
        if host == self.owner.host:
            return getattr(self.owner, operation)(**fields)
        return self.endpoints[host].call(operation, **fields)

    def view(self):
        with deadline_lock(self.owner.lock):
            row = dict(self.owner.db.execute('SELECT revision,selected,panels FROM fleet_view WHERE singleton=1').fetchone())
            row['panels'] = json.loads(row['panels'])
            return row

    def snapshot(self, *, actor):
        self.owner._human(actor)
        # Anchor before the local snapshot too. Fanout is sequential: there is
        # no executor backlog or timed-out worker continuing in the background.
        try:
            with reserved_deadline(SNAPSHOT_BUDGET_SECONDS, SNAPSHOT_RESERVE_SECONDS) as fanout_end:
                pass
        except TimeoutError:
            fanout_end = time.monotonic()
        result = self.owner.snapshot(actor=actor)
        checkpoint()
        sessions, hosts, delegations, runners = [], [], {}, []
        for host in [self.owner.host, *sorted(self.endpoints)]:
            online = True
            try:
                if host == self.owner.host:
                    current = result
                else:
                    budget = fanout_end - time.monotonic()
                    if budget <= 0:
                        raise TimeoutError('fleet read budget exhausted; using stale cache')
                    with absolute_deadline(fanout_end):
                        current = self._call(host, 'snapshot', actor=actor)
                if current['host'] != host:
                    raise ValueError('fleet endpoint identity mismatch')
                with deadline_lock(self.owner.lock):
                    self.owner.db.execute('INSERT OR REPLACE INTO fleet_cache VALUES(?,?)', (host, json.dumps(current)))
                    self.owner.db.commit()
            except (OSError, ValueError):
                online = False
                with deadline_lock(self.owner.lock):
                    row = self.owner.db.execute('SELECT snapshot FROM fleet_cache WHERE host=?', (host,)).fetchone()
                current = json.loads(row['snapshot']) if row else {'sessions': []}
            hosts.append({'host': host, 'online': online, 'captured_at': current.get('captured_at')})
            runners.append(host + ': ' + current.get('operator_status', {}).get('runner', 'unknown') + ('' if online else ' (stale)'))
            for session in current['sessions']:
                item = self._session(host, session)
                item['online'] = online
                if not online:
                    item['status'] = 'offline; last known ' + session['status']
                sessions.append(item)
            for state, count in current.get('operator_status', {}).get('delegations', {}).items():
                delegations[state] = delegations.get(state, 0) + count
        result.update(sessions=sessions, view=self.view(), hosts=hosts)
        result['operator_status']['delegations'] = delegations
        result['operator_status']['runner'] = '; '.join(runners)
        result['operator_status']['provider_activity'] = 'per-host observations unavailable; offline authority counts may be stale'
        return result

    def layout(self, panels, *, selected, revision, actor):
        self.owner._human(actor)
        if (type(revision) is not int or not isinstance(panels, list) or len(panels) > 16
                or len(set(panels)) != len(panels) or (selected is not None and selected not in panels)
                or (panels and selected is None)):
            raise ValueError('invalid fleet layout')
        for reference in panels:
            self._target(reference)
        available = {session['id'] for session in self.snapshot(actor=actor)['sessions']}
        if not set(panels) <= available:
            raise ValueError('unknown fleet session; refresh host snapshot')
        with self.owner.lock:
            cursor = self.owner.db.execute('UPDATE fleet_view SET revision=revision+1,selected=?,panels=? WHERE singleton=1 AND revision=?',
                                           (selected, json.dumps(panels), revision))
            if cursor.rowcount != 1:
                self.owner.db.rollback()
                raise ValueError('stale fleet view; refresh before changing layout')
            self.owner.db.commit()
            return self.view()

    def select(self, sid, *, revision, actor):
        self._target(sid)
        panels = self.view()['panels']
        if sid not in panels:
            panels.append(sid)
        return self.layout(panels, selected=sid, revision=revision, actor=actor)

    def take_control(self, sid, *, actor):
        self.owner._human(actor)
        host, local_sid = self._target(sid)
        identifier = uuid.uuid4().hex
        with self.owner.lock:
            self.owner.db.execute('INSERT INTO fleet_cancellations VALUES(?,?,?)', (identifier, sid, 'recorded; not acknowledged'))
            self.owner.db.commit()
        try:
            result = self._call(host, 'take_control', sid=local_sid, actor=actor)
            observed = self._call(host, 'delegation', sid=local_sid, actor=actor)
            acknowledged = observed is None or observed['status'] == 'revoked'
        except (OSError, ValueError):
            acknowledged = False
        if acknowledged:
            with self.owner.lock:
                self.owner.db.execute("UPDATE fleet_cancellations SET status='acknowledged' WHERE id=?", (identifier,))
                self.owner.db.commit()
        return {'cancellation': identifier, 'target': sid, 'acknowledged': acknowledged,
                'status': 'acknowledged' if acknowledged else 'recorded; not acknowledged'}

    def take_control_scope(self, scope, *, target=None, actor):
        self.owner._human(actor)
        if scope not in {'session', 'host', 'operator', 'fleet'} or (scope != 'fleet' and not isinstance(target, str)):
            raise ValueError('explicit stop scope and target required')
        if scope == 'session':
            return self.take_control(target, actor=actor)
        model = self.snapshot(actor=actor)
        if scope == 'host' and target not in [self.owner.host, *self.endpoints]:
            raise ValueError('host not explicitly configured')
        sessions = [session for session in model['sessions']
                    if scope == 'fleet' or (scope == 'host' and session['host'] == target)
                    or (scope == 'operator' and (session.get('delegation') or {}).get('operator') == target)]
        results = [self.take_control(session['id'], actor=actor) for session in sessions]
        missing = [host['host'] for host in model['hosts'] if not host['online'] and (scope != 'host' or host['host'] == target)]
        return {'scope': scope, 'target': target, 'results': results, 'unreachable_hosts': missing,
                'acknowledged': not missing and all(result['acknowledged'] for result in results),
                'child_processes_interrupted': False}

    def _embedded_sessions(self, host, value: Any) -> Any:
        """Qualify schema session references, never opaque text or unrelated IDs."""
        if isinstance(value, list):
            return [self._embedded_sessions(host, item) for item in value]
        if not isinstance(value, dict):
            return value
        result = {key: self._embedded_sessions(host, item) for key, item in value.items()}
        if 'session' in result and result['session'] is not None:
            result['session'] = self.reference(host, result['session'])
        return result

    def _session(self, host, session):
        return dict(self._embedded_sessions(host, session),
                    id=self.reference(host, session['id']), host=host)

    def open(self, *, project, task, name, actor, workspace=None):
        session = self.owner.open(project=project, task=task, name=name,
                                  actor=actor, workspace=workspace)
        return self._session(self.owner.host, session)

    def open_organizer(self, agent, *, actor, host=None):
        host = self.owner.host if host is None else host
        if host != self.owner.host and host not in self.endpoints:
            raise ValueError('host not explicitly configured')
        session = self._call(host, 'open_organizer', agent=agent, actor=actor)
        return self._session(host, session)

    def send_draft(self, sid, *, identifier, consent, attachment, actor):
        self.owner._human(actor)
        host, local_sid = self._target(sid)
        # One attempt only. Receiver checks the exact session and draft under
        # its lock before persisting ambiguity; no full-history preflight.
        result = self._call(host, 'send_draft', identifier=identifier, consent=consent,
                            attachment=attachment, actor=actor, sid=local_sid)
        return self._embedded_sessions(host, result)

    def __getattr__(self, operation):
        if operation == 'list':
            return lambda: self.snapshot(actor='operator')['sessions']
        if operation == 'organizer':
            return getattr(self.owner, operation)
        if operation == 'dashboard':
            return self.owner.dashboard
        if operation == 'capabilities':
            return self.owner.capabilities
        allowed = {'start', 'native', 'native_archive', 'bind_native', 'start_native', 'drafts', 'stage_draft',
                   'archive', 'reconcile_input', 'attach', 'detach', 'resize', 'write', 'read', 'end', 'delegate', 'delegation'}
        if operation not in allowed:
            raise AttributeError(operation)
        def forward(sid, **fields):
            host, local_sid = self._target(sid)
            # Never queue or retry input on reconnect; caller keeps its own draft.
            result = self._call(host, operation, sid=local_sid, **fields)
            if operation in {'start', 'start_native', 'attach', 'detach', 'end'}:
                return self._session(host, result)
            return self._embedded_sessions(host, result)
        return forward
