"""Local human-only cockpit. Never exposed through agent HTTP/MCP permissions."""
from __future__ import annotations

import hashlib
import argparse
import base64
import binascii
import json
from . import private_paths
from .security import bounded_json_loads
import os
from pathlib import Path
import re
import select
import signal
import socket
import sqlite3
import threading
import uuid
from contextlib import ExitStack

from .control import list_tasks, _locked_state


from .replica_authority import owner_entry
from .cockpit_client import checkpoint, deadline_lock
from .locks import try_exclusive_lock
from . import owner_endpoint

class LocalCockpit:
    """One same-UID PTY owner per private state directory, not a sandbox."""

    def __init__(self, root: Path, vault: Path, state: Path, host: str, *, team=None, native_runtimes=None, driver=None, organizers=None, execution_policy=None,delegation_authority_database=None):
        from .replica_authority import assert_mutation_authority
        assert_mutation_authority(vault)
        self.delegation_remote_fence=None
        self.delegation_remote_recovery=None
        self.delegation_authority_database=(None if delegation_authority_database is None else Path(delegation_authority_database).absolute())
        self.root = root.resolve()
        self.root.parent.mkdir(parents=True, exist_ok=True)
        private_paths.ensure_private_directory(self.root, mode=0o700)
        if root.is_symlink() or not private_paths.is_private(self.root.stat(), path=self.root):
            raise ValueError("cockpit directory must be private and not a symlink")
        authority = state.resolve()
        authority.parent.mkdir(parents=True, exist_ok=True)
        self.owner = authority.with_name(authority.name + ".cockpit-owner.lock").open("a+", newline="\n")
        if not try_exclusive_lock(self.owner):
            self.owner.close()
            raise ValueError("cockpit directory already owned")
        self.vault, self.state, self.host = vault.resolve(), state.resolve(), host
        self.lock = threading.RLock()
        self.live = {}
        self.starting = set()
        self.closed = False
        self.incarnation = uuid.uuid4().hex
        self.execution_policy = execution_policy
        self.web_server = None
        self.web_thread = None
        # Optional already-authenticated business adapter, supplied explicitly
        # by the integrator; never mint identity from the local socket actor.
        self.team = team
        self.native_runtimes = dict(native_runtimes or {})
        self.operator_drivers = dict(driver or {})
        self.organizer_bindings = dict(organizers or {})
        self.db = sqlite3.connect(self.root / "sessions.sqlite", check_same_thread=False)
        private_paths.apply_mode(path=self.root / "sessions.sqlite", mode=0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute("CREATE TABLE IF NOT EXISTS identity (host TEXT, state TEXT, vault TEXT)")
        identity = self.db.execute("SELECT * FROM identity").fetchone()
        expected = (host, str(self.state), str(self.vault))
        if identity and tuple(identity) != expected:
            self.db.close()
            self.owner.close()
            raise ValueError("fixed host/state/vault binding mismatch")
        if not identity:
            self.db.execute("INSERT INTO identity VALUES (?, ?, ?)", expected)
        self.db.execute("""CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY, project TEXT, task TEXT, name TEXT, workspace TEXT,
            status TEXT, pid INTEGER)""")
        if 'kind' not in {row[1] for row in self.db.execute('PRAGMA table_info(sessions)')}:
            self.db.execute("ALTER TABLE sessions ADD COLUMN kind TEXT NOT NULL DEFAULT 'work'")
        self.db.execute('CREATE TABLE IF NOT EXISTS native_organizers(agent TEXT PRIMARY KEY, session TEXT UNIQUE NOT NULL)')
        self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS active_task ON sessions(task) WHERE status != 'ended'")
        self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS active_name ON sessions(name) WHERE status != 'ended'")
        self.db.execute('CREATE TABLE IF NOT EXISTS cleanup_ownership(session TEXT PRIMARY KEY, pid INTEGER NOT NULL)')
        self.db.execute("INSERT OR IGNORE INTO cleanup_ownership SELECT id,pid FROM sessions WHERE pid IS NOT NULL")
        self.db.execute("UPDATE sessions SET status='stopped', pid=NULL WHERE status != 'ended'")
        self.db.execute("CREATE TABLE IF NOT EXISTS shared_view (singleton INTEGER PRIMARY KEY CHECK(singleton=1), selected TEXT, revision INTEGER NOT NULL)")
        self.db.execute("INSERT OR IGNORE INTO shared_view (singleton, selected, revision) VALUES (1, NULL, 0)")
        self.db.execute('''CREATE TABLE IF NOT EXISTS delegations (
            session TEXT PRIMARY KEY REFERENCES sessions(id), operator TEXT NOT NULL,
            goal TEXT NOT NULL, limits TEXT NOT NULL, generation INTEGER NOT NULL,
            cursor INTEGER NOT NULL, status TEXT NOT NULL, pending TEXT)''')
        self.db.execute('CREATE TABLE IF NOT EXISTS delegation_expiries(session TEXT PRIMARY KEY,expires REAL NOT NULL,incarnation TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS staged_input(session TEXT PRIMARY KEY, delivery TEXT NOT NULL)')
        self.db.execute('INSERT OR IGNORE INTO staged_input SELECT session,pending FROM delegations WHERE pending IS NOT NULL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS native_bindings (
            session TEXT PRIMARY KEY, tool TEXT NOT NULL, conversation TEXT NOT NULL)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS session_attention (
            session TEXT PRIMARY KEY, kind TEXT NOT NULL, reason TEXT NOT NULL)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS lifecycle_bindings (
            attempt TEXT PRIMARY KEY, session TEXT UNIQUE NOT NULL, target TEXT NOT NULL,
            incarnation TEXT NOT NULL, epoch INTEGER NOT NULL, environment TEXT NOT NULL)''')
        self.db.execute('CREATE TABLE IF NOT EXISTS lifecycle_policy (singleton INTEGER PRIMARY KEY, epoch INTEGER NOT NULL)')
        self.db.execute('INSERT OR IGNORE INTO lifecycle_policy VALUES(1,0)')
        self.db.execute('''CREATE TABLE IF NOT EXISTS native_frontend_panes(
            session TEXT PRIMARY KEY,frontend TEXT NOT NULL,pane TEXT NOT NULL,
            workspace TEXT NOT NULL,tab TEXT NOT NULL,incarnation TEXT NOT NULL,epoch INTEGER NOT NULL)''')
        # A crashed owner cannot know whether a reserved prompt reached the tool.
        self.db.execute("UPDATE delegations SET status=CASE WHEN pending IS NULL THEN 'paused' ELSE 'ambiguous' END WHERE status='active'")
        columns = {row[1] for row in self.db.execute('PRAGMA table_info(shared_view)')}
        if 'panels' not in columns:
            self.db.execute("ALTER TABLE shared_view ADD COLUMN panels TEXT NOT NULL DEFAULT '[]'")
            selected = self.db.execute('SELECT selected FROM shared_view WHERE singleton=1').fetchone()[0]
            self.db.execute('UPDATE shared_view SET panels=? WHERE singleton=1',
                            (json.dumps([selected] if selected else []),))
        self.db.commit()

        self.archive_stop = threading.Event()
        self.archive_sync = 'not configured' if team is None else 'waiting'
        self.archive_thread = None
        if team is not None:
            self.archive_thread = threading.Thread(target=self._sync_archive, daemon=True)
            self.archive_thread.start()
        self.operator_stop = threading.Event()
        self.operator_thread = None
        if self.operator_drivers:
            from .cockpit_terminal_runner import run_configured
            self.operator_thread = threading.Thread(target=run_configured, args=(self, self.operator_stop), daemon=True)
            self.operator_thread.start()

    @owner_entry
    def _sync_archive(self):
        from .cockpit_archive import sync_capture
        from .cockpit_archive_authority import governed_sink
        sink = governed_sink(self)
        while not self.archive_stop.wait(1):
            try:
                count = sync_capture(self, sink)
                self.archive_sync = 'configured; acknowledgment checked' if count else 'configured; pending or idle'
            except (OSError, ValueError, RuntimeError, sqlite3.Error):
                self.archive_sync = 'unavailable; records retained locally'

    @owner_entry
    def raise_capture_capacity(self, *, actor, expected_bytes, capacity_bytes, reason):
        from .cockpit_archive import raise_capture_capacity
        return raise_capture_capacity(self, actor=actor, expected_bytes=expected_bytes,
                                      capacity_bytes=capacity_bytes, reason=reason)

    @owner_entry
    def export_capture(self, *, actor, after=0, limit=100):
        from .cockpit_archive import export_capture
        return export_capture(self, actor=actor, after=after, limit=limit)

    @owner_entry
    def prepare_capture_offload(self, directory, *, actor, acknowledgement='delivery', verification_limit=None):
        from .capture_offload import prepare_offload
        return prepare_offload(self,directory,actor=actor,acknowledgement=acknowledgement,verification_limit=verification_limit)

    @owner_entry
    def acknowledge_capture_offload(self, directory, sha256, *, actor, confirmed=False, verification_limit=None, retention_receipt=None):
        from .capture_offload import acknowledge_offload
        return acknowledge_offload(self,directory,sha256,actor=actor,confirmed=confirmed,verification_limit=verification_limit,retention_receipt=retention_receipt)

    @owner_entry
    def relocate_capture_offload(self, directory, *, actor, expected_head, confirmed=False, copy_from_bound=False, verification_limit=None, retention_receipt=None):
        from .capture_offload import relocate_offload_storage
        return relocate_offload_storage(self, directory, actor=actor, expected_head=expected_head,
                                        confirmed=confirmed, copy_from_bound=copy_from_bound,verification_limit=verification_limit,retention_receipt=retention_receipt)

    @owner_entry
    def trust_capture_retention(self, storage, public_key, qualification, *, actor, confirmed=False):
        from .capture_retention import trust
        return trust(self,storage,public_key,qualification,actor=actor,confirmed=confirmed)

    @owner_entry
    def revoke_capture_retention(self, key_id, *, actor, confirmed=False):
        from .capture_retention import revoke
        return revoke(self,key_id,actor=actor,confirmed=confirmed)

    @owner_entry
    def request_capture_retention(self, storage, sha256, through, kind, *, actor):
        from .capture_retention import request
        return request(self,storage,sha256,through,kind,actor=actor)

    @owner_entry
    def reset_capture_offload_verification(self, *, actor, expected_head, confirmed=False):
        from .capture_offload import schema,head
        from .capture_offload_verify import clear
        self._human(actor)
        if confirmed is not True:raise ValueError('explicit verification progress reset confirmation required')
        with self.lock,self.db:
            schema(self)
            if head(self)[0]!=expected_head:raise ValueError('exact current offload head required')
            clear(self)
        return dict(progress_reset=True,released=0,history_retained=True)

    @owner_entry
    def read_capture_offload_page(self, directory, *, actor, sha256, through=None, limit=16):
        self._human(actor)
        from .capture_offload import read_offload_page,storage_identity,require_storage,schema
        with self.lock:
            schema(self);require_storage(self,storage_identity(directory))
            return read_offload_page(directory,sha256,through=through,limit=limit)

    @owner_entry
    def inspect_capture_context(self, sid, *, actor, kind):
        from .cockpit_archive import inspect_context_recovery
        return inspect_context_recovery(self, sid, actor=actor, kind=kind)

    @owner_entry
    def reconcile_capture_context(self, sid, *, actor, kind, expected, confirmed=False, clean_boundary_confirmed=False):
        from .cockpit_archive import reconcile_context
        return reconcile_context(self, sid, actor=actor, kind=kind, expected=expected,
            confirmed=confirmed, clean_boundary_confirmed=clean_boundary_confirmed)

    @owner_entry
    def configure_remote_delegation(self, config, *, actor, expected, confirmed=False, recovery_only=False):
        """Private operator provisioning; never a task/onboarding request field."""
        self._human(actor)
        if confirmed is not True:raise PermissionError('explicit remote fence provisioning confirmation required')
        if type(recovery_only) is not bool:raise ValueError('explicit recovery-only mode required')
        with self.lock:
            if self.delegation_remote_fence is not None:raise PermissionError('remote fence already provisioned; no automatic rebind')
            if expected!=self._native_lifecycle_identity():raise PermissionError('exact inspected owner identity required')
            from .remote_effect_fence import load_client
            client=load_client(config)
            binding=client.binding
            if recovery_only:
                if self.delegation_remote_recovery is not None:
                    client.close();raise PermissionError('recovery configuration already installed')
                if binding['target']['machine_id']!=self.host:
                    client.close();raise PermissionError('recovery configuration names another machine')
                self.delegation_remote_recovery=client
                return dict(configured=True,recovery_only=True,configuration_sha256=client.configuration_sha256)
            if (binding['incarnation'],binding['epoch'],binding['target']['machine_id'])!=(self.incarnation,expected['epoch'],self.host):
                client.close();raise PermissionError('trusted configuration names another owner incarnation')
            self.delegation_remote_fence=client
            return dict(configured=True,configuration_sha256=client.configuration_sha256)

    @owner_entry
    def reconcile_remote_delegation(self, attempt, *, actor, expected_sha256, outcome, evidence_sha256, confirmed=False):
        self._human(actor)
        with self.lock:
            remote=self.delegation_remote_recovery or self.delegation_remote_fence
            if remote is None:raise PermissionError('trusted remote fence configuration required')
            row=self.db.execute('SELECT session FROM lifecycle_bindings WHERE attempt=?',(attempt,)).fetchone()
            if row is None:raise PermissionError('exact retained owner attempt required')
            sid=row[0]
            if sid in self.starting or (sid in self.live and self.live[sid].get('thread') is None):
                raise PermissionError('final effect admission still active; cannot settle')
            if outcome=='no-effect-proven' and (sid in self.live or self._get(sid).get('pid') is not None
                    or self.db.execute('SELECT 1 FROM cleanup_ownership WHERE session=?',(sid,)).fetchone()):
                raise PermissionError('no-effect proof conflicts with retained process/cleanup evidence')
            remote.reconcile(attempt,expected_sha256=expected_sha256,outcome=outcome,
                evidence_sha256=evidence_sha256,confirmed=confirmed)
            return dict(settled=True,attempt=attempt,outcome=outcome)

    @staticmethod
    def _human(actor):
        if actor != "operator":
            raise PermissionError("local cockpit requires human operator")

    @owner_entry
    def _get(self, sid):
        row = self.db.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if row is None:
            raise ValueError("unknown session")
        return dict(row)

    @owner_entry
    def list(self):
        with self.lock:
            return [dict(row) for row in self.db.execute("SELECT * FROM sessions ORDER BY rowid")]

    @owner_entry
    def view(self):
        with self.lock:
            row = dict(self.db.execute("SELECT selected, revision, panels FROM shared_view WHERE singleton=1").fetchone())
            row['panels'] = json.loads(row['panels'])
            return row

    @owner_entry
    def layout(self, panels, *, selected, revision, actor):
        """Stable pane IDs and shared focus; never starts/stops a process."""
        self._human(actor)
        if type(revision) is not int or revision < 0:
            raise ValueError('invalid view revision')
        if (not isinstance(panels, list) or len(panels) > 16
                or any(not isinstance(sid, str) for sid in panels)
                or len(set(panels)) != len(panels)
                or (selected is not None and selected not in panels)
                or (panels and selected is None)):
            raise ValueError('invalid shared layout')
        with self.lock:
            for sid in panels:
                self._get(sid)
            if self.view()['revision'] != revision:
                raise ValueError('stale shared view; refresh before changing layout')
            self.db.execute('UPDATE shared_view SET selected=?, panels=?, revision=revision+1 WHERE singleton=1',
                            (selected, json.dumps(panels)))
            self.db.commit()
            return self.view()

    @owner_entry
    def capabilities(self):
        return {"protocol": 2, "binary_frames": True, "attachment_tokens": True,
                "max_input_bytes": 4096, "replay_bytes": 65536}

    @owner_entry
    def drafts(self, sid, *, actor, after=0, limit=50, identifier=None):
        from .cockpit_consent import drafts
        return drafts(self, sid, actor=actor, after=after, limit=limit, identifier=identifier)

    @owner_entry
    def stage_draft(self, sid, text, *, actor, context='', context_consent=False):
        from .cockpit_consent import stage_draft
        return stage_draft(self, sid, text, actor=actor, context=context, context_consent=context_consent)

    @owner_entry
    def send_draft(self, identifier, *, consent, attachment, actor, sid=None):
        from .cockpit_consent import send_draft
        return send_draft(self, identifier, consent=consent, attachment=attachment, actor=actor, sid=sid)

    @owner_entry
    def archive(self, sid, *, actor, event_id=None, source=None, text=None, after=0):
        from .cockpit_archive import records, append_record
        if event_id is None and source is None and text is None:
            return records(self, sid, actor=actor, after=after)
        return append_record(self, sid, actor=actor, event_id=event_id, source=source, text=text)

    @owner_entry
    def organizer(self, agent, *, actor, content=None, consent=False, idempotency_key=None):
        from .cockpit_adapters_organizer import OrganizerContext
        self._human(actor)
        if self.team is None:
            raise ValueError('organizer AMC identity unavailable; nothing queued or sent')
        adapter = OrganizerContext(self.team._call)
        response = (adapter.read(agent) if content is None else
                    adapter.write(agent, content, consent=consent, idempotency_key=idempotency_key))
        return {'status': response.status, 'body': response.body,
                'kind': 'AMC session context, not native live chat'}

    @owner_entry
    def snapshot(self, *, actor):
        """Read the bound authority, never a path guessed by a connected client."""
        from dataclasses import asdict
        from datetime import datetime, timezone
        self._human(actor)
        with deadline_lock(self.lock):
            authority_error = ''
            checkpoint()
            try:
                tasks = [asdict(task) for task in list_tasks(self.state).tasks]
            except (OSError, ValueError) as exc:
                tasks = []
                authority_error = str(exc)
            checkpoint()
            sessions = self.list()
            for session in sessions:
                checkpoint()
                attention = self.db.execute('SELECT kind, reason FROM session_attention WHERE session=?', (session['id'],)).fetchone()
                session['attention'] = attention['kind'] if attention else None
                session['attention_reason'] = attention['reason'] if attention else ''
                session['human_attached'] = bool(self.live.get(session['id'], {}).get('attached'))
                session['capture_error'] = self.live.get(session['id'], {}).get('capture_error')
                session['delegation'] = self.delegation(session['id'], actor='operator')
            operator_status = {
                'delegations': {row['status']: row['count'] for row in self.db.execute(
                    'SELECT status, COUNT(*) AS count FROM delegations GROUP BY status')},
                'runner': 'configured: ' + ', '.join(sorted(self.operator_drivers)) if self.operator_drivers else 'not configured',
                'provider_activity': 'not observed' if not self.operator_drivers else 'not measured; configured driver controls execution',
            }
            from .cockpit_archive import capture_status
            return {'sessions': sessions, 'view': self.view(), 'operator_status': operator_status,
                    'capture': capture_status(self),
                    'tasks': tasks, 'authority_error': authority_error,
                    'availability': {'machine': True, 'amc_authority': not bool(authority_error),
                                     'amc_memory': False if authority_error else None,
                                     'operator': 'not-checked'},
                    'host': self.host, 'state': str(self.state),
                    'captured_at': datetime.now(timezone.utc).isoformat()}

    @owner_entry
    def delegation(self, sid, *, actor):
        """Control metadata only, not a provider runner or authorization bypass."""
        with deadline_lock(self.lock):
            self._get(sid)
            row = self.db.execute('SELECT * FROM delegations WHERE session=?', (sid,)).fetchone()
            if actor != 'operator' and (row is None or row['operator'] != actor):
                raise PermissionError('not the delegated operator')
            return dict(row) if row else None

    @owner_entry
    def delegate(self, sid, *, operator, goal, limits, actor):
        self._human(actor)
        if (not isinstance(operator, str) or not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', operator)
                or operator == 'operator'
                or any(not isinstance(text, str) or not text.strip() or len(text) > 4096 for text in (goal, limits))):
            raise ValueError('explicit operator, goal and limits required')
        with self.lock:
            if self._get(sid)['status'] == 'ended':
                raise ValueError('cannot delegate ended session')
            if self.db.execute('SELECT 1 FROM staged_input WHERE session=?', (sid,)).fetchone():
                raise ValueError('staged input requires explicit human reconciliation')
            previous = self.delegation(sid, actor=actor)
            if previous and previous['status'] in {'active', 'ambiguous'}:
                raise ValueError('take control before reassignment or reconciliation')
            generation = previous['generation'] + 1 if previous else 1
            cursor = previous['cursor'] if previous else 0
            self.db.execute('INSERT OR REPLACE INTO delegations VALUES (?, ?, ?, ?, ?, ?, ?, NULL)',
                            (sid, operator, goal, limits, generation, cursor, 'active'))
            self.db.execute('DELETE FROM delegation_expiries WHERE session=?',(sid,))
            self.db.commit()
            return self.delegation(sid, actor=actor)

    @owner_entry
    def reconcile_input(self, sid, *, actor, attachment, confirmed_clean=False):
        """Human attests the native editor was reconciled; never inject keys."""
        self._human(actor)
        with self.lock:
            live = self.live.get(sid)
            if live is None:
                raise ValueError('attach a running native session first')
            self._attachment(live, attachment)
            row = self.delegation(sid, actor=actor)
            if confirmed_clean is not True or not row or row['status'] != 'revoked':
                raise ValueError('take control and explicitly confirm clean native input first')
            with live['input_lock']:
                if live['input'] or live['input_error'] or live['fd'] is None:
                    raise ValueError('native input is not drained and healthy')
                self.db.execute('DELETE FROM staged_input WHERE session=?', (sid,))
                self.db.commit()
            return {'reconciled': True, 'session': sid}

    @owner_entry
    def take_control(self, sid, *, actor):
        self._human(actor)
        with self.lock:
            self._get(sid)
            self.db.execute("UPDATE delegations SET generation=generation+1, status='revoked', pending=NULL WHERE session=?", (sid,))
            self.db.commit()
            # Deliberately no signal, PTY write, or interruption of the native tool.
            return self.delegation(sid, actor=actor)

    @owner_entry
    def _delegated(self, sid, generation, actor):
        row = self.delegation(sid, actor=actor)
        if (type(generation) is not int or row is None or row['generation'] != generation
                or row['status'] != 'active'):
            raise ValueError('stale or inactive delegation')
        if actor != row['operator']:
            raise PermissionError('not the delegated operator')
        import time
        expiry=self.db.execute('SELECT expires,incarnation FROM delegation_expiries WHERE session=?',(sid,)).fetchone()
        if expiry and (expiry[0]<=time.time() or expiry[1]!=self.incarnation):
            raise ValueError('restart delegation expired or belongs to a previous owner incarnation')
        return row

    @owner_entry
    def authorize_native_restart(self,sid,*,actor,confirmed=False,allow_provider_restart=False,ttl=300):
        from .cockpit_restart import grant
        return grant(self,sid,actor=actor,confirmed=confirmed,allow_provider_restart=allow_provider_restart,ttl=ttl)

    @owner_entry
    def resume_native_restart(self,identifier,*,actor):
        from .cockpit_restart import resume
        return resume(self,identifier,actor=actor)

    @owner_entry
    def take_control_scope(self, scope, *, target=None, actor):
        self._human(actor)
        if scope not in {'session', 'host', 'operator', 'fleet'} or (scope != 'fleet' and not isinstance(target, str)):
            raise ValueError('explicit stop scope/target required')
        if scope == 'session':
            return self.take_control(target, actor=actor)
        if scope == 'host' and target != self.host:
            raise ValueError('host not configured on this owner')
        with self.lock:
            rows = [dict(row) for row in self.db.execute('SELECT * FROM delegations')]
            results = [self.take_control(row['session'], actor=actor) for row in rows
                       if scope != 'operator' or row['operator'] == target]
            return {'scope': scope, 'target': target, 'results': results, 'acknowledged': True,
                    'child_processes_interrupted': False}

    @owner_entry
    def reserve_prompt(self, sid, *, generation, cursor, actor):
        """Persist an intent BEFORE delivery; never send or automatically retry it."""
        with self.lock:
            row = self._delegated(sid, generation, actor)
            if type(cursor) is not int or cursor < row['cursor'] or row['pending'] is not None:
                raise ValueError('invalid cursor or unresolved prompt delivery')
            self.db.execute('UPDATE delegations SET cursor=?, pending=? WHERE session=?',
                            (cursor, uuid.uuid4().hex, sid))
            self.db.commit()
            return self.delegation(sid, actor=actor)

    @owner_entry
    def settle_prompt(self, sid, *, generation, delivery, outcome, actor):
        with self.lock:
            row = self._delegated(sid, generation, actor)
            if (not isinstance(delivery, str) or delivery != row['pending']
                    or outcome not in {'delivered', 'not-delivered', 'ambiguous'}):
                raise ValueError('invalid delivery settlement')
            self.db.execute('UPDATE delegations SET status=?, pending=? WHERE session=?',
                            ('ambiguous' if outcome == 'ambiguous' else 'active',
                             delivery if outcome == 'ambiguous' else None, sid))
            self.db.commit()
            return self.delegation(sid, actor=actor)

    @owner_entry
    def dashboard(self, *, actor):
        self._human(actor)
        with self.lock:
            home = self.root.parent
            if self.root.name != 'runtime' or self.state != home / 'events.jsonl' or self.vault != home / 'vault':
                raise ValueError('owner web button requires the explicit local pilot layout')
            if self.web_server is None:
                from .cockpit_web import DashboardServer
                self.web_server = DashboardServer(home, **({'team': self.team} if self.team is not None else {}))
                self.web_thread = threading.Thread(target=self.web_server.serve_forever, daemon=True)
                self.web_thread.start()
            # Capability travels only to the same-UID UI, never into terminal output/logs.
            return {'url': self.web_server.origin + '/#' + self.web_server.capability}

    @owner_entry
    def select(self, sid, *, revision, actor):
        self._human(actor)
        if type(revision) is not int or revision < 0:
            raise ValueError("invalid view revision")
        with self.lock:
            self._get(sid)
            if self.view()["revision"] != revision:
                raise ValueError("stale shared view; refresh before selecting")
            panels = self.view()['panels']
            if sid not in panels:
                panels.append(sid)
            return self.layout(panels, selected=sid, revision=revision, actor=actor)

    @owner_entry
    def open(self, *, project, task, name, actor, workspace=None):
        self._human(actor)
        for value in (project, name):
            if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", value):
                raise ValueError("invalid exact short name")
        with self.lock, _locked_state(self.state):
            project_file = self.vault / "registry/projects" / (project + ".json")
            if not project_file.is_file():
                raise ValueError("unknown project")
            registry = json.loads(project_file.read_text())
            tasks = {item.id: item for item in list_tasks(self.state).tasks}
            bound = tasks.get(task)
            if bound is None or bound.status in {"done", "retired"}:
                raise ValueError("unknown or terminal task")
            if bound.owner != registry["owner_agent_id"]:
                raise ValueError("task owner does not match project owner")
            if self.db.execute("SELECT 1 FROM sessions WHERE (task=? OR name=?) AND status!='ended'", (task, name)).fetchone():
                raise ValueError("active session already binds task or name")
            previous = self.db.execute("SELECT * FROM sessions WHERE task=? LIMIT 1", (task,)).fetchone()
            sid = uuid.uuid4().hex
            target = Path(workspace).resolve(strict=True) if workspace else self.root / "workspaces" / sid / name
            if previous and (previous["project"] != project or previous["workspace"] != str(target)):
                raise ValueError("task workspace/project is fixed; select previous workspace explicitly")
            if workspace:
                if not target.is_dir():
                    raise ValueError("workspace must be a directory")
            else:
                target.mkdir(mode=0o700, parents=True)
            self.db.execute("INSERT INTO sessions(id,project,task,name,workspace,status,pid) VALUES (?, ?, ?, ?, ?, 'stopped', NULL)",
                            (sid, project, task, name, str(target)))
            self.db.commit()
            return self._get(sid)

    @staticmethod
    def _native_new_identity(runtime,workspace):
        argv,_=runtime.plan_new('arvyx-new-'+'0'*32,workspace)
        return dict(argv=argv,executable_sha256=(runtime.executable_digest if getattr(runtime, 'setup_only', False) else hashlib.sha256(runtime.executable.read_bytes()).hexdigest()),
                    protocol=runtime.new_protocol,profile=str(runtime.home),
                    profile_identity=list(runtime.profile.identity),home_identity=list(runtime.profile.home_identity))

    def _native_lifecycle_identity(self, *, guarded_authority_id=None):
        """Caller holds owner.lock; a held policy guard supplies its checked ID."""
        epoch = self.db.execute('SELECT epoch FROM lifecycle_policy WHERE singleton=1').fetchone()[0]
        current = dict(incarnation=self.incarnation, epoch=epoch, machine=self.host)
        authority_database=self.delegation_authority_database
        current['organizer_effect_fence']=authority_database is not None
        current['organizer_authority_id']=None
        if authority_database is not None:
            from .organizer_durable import authority_fence_identity
            current['organizer_authority_id']=(authority_fence_identity(authority_database) if guarded_authority_id is None else guarded_authority_id)
        remote=self.delegation_remote_fence
        if remote is not None:
            current['remote_organizer_authority_id']=remote.authority_id
            current['remote_fence_configuration']=remote.configuration_sha256
        policy=self.execution_policy
        current['environments']=([] if policy is None else
            [mode for mode,available in (
                ('sandbox',policy.sandbox_launcher is not None and policy.sandbox_fd_protocol=='arvyx-directory-fd-v1' and not private_paths.is_root()),
                ('host',policy.allow_host and private_paths.effective_user()==policy.host_uid and not private_paths.is_root()),
                ('root',policy.allow_root and private_paths.is_root())) if available])
        current['native_protocols']=[name for name,runtime in self.native_runtimes.items() if getattr(runtime,'new_protocol',None) in ('hermes-titled-create-v1', 'hermes-isolated-setup-v1')]
        return current

    @owner_entry
    def native_lifecycle(self, *, action, actor, expected=None, attempt=None, target=None,
                         workspace=None, environment=None, root_acknowledged=False, confirmed=False,
                         result=None, workspace_identity=None, reviewed_native=None, harness='shell', provider_start_acknowledged=False,
                         conversation=None, io_operation=None, fields=None, attachment=None,frontend=None,presentation=None,
                         consent_expires_at=None,delegation_fence=None):
        """Explicit shell producer with durable pre-effect binding and no retry.

        Native provider New protocols are not guessed. Existing Hermes resumes
        continue through bind_native/start_native and their profile reservation.
        """
        self._human(actor)
        with self.lock:
            from .reviewed_actions import assert_consent_active
            assert_consent_active(consent_expires_at)
            current=self._native_lifecycle_identity()
            epoch=current['epoch'];policy=self.execution_policy
            authority_database=self.delegation_authority_database
            remote_fence=self.delegation_remote_fence
            if action == 'inspect':
                return current
            if expected != current or confirmed is not True:
                raise PermissionError('current owner incarnation, revocation epoch and explicit confirmation required')
            if action == 'revoke':
                assert_consent_active(consent_expires_at)
                self.db.execute('UPDATE lifecycle_policy SET epoch=epoch+1 WHERE singleton=1');self.db.commit()
                for live in self.live.values():
                    if 'attachment_authority_epoch' in live:live['attached']=False
                return dict(revoked=True)
            if action=='panes':
                rows=self.db.execute('SELECT session,pane,workspace,tab FROM native_frontend_panes WHERE frontend=? AND incarnation=? AND epoch=? ORDER BY session LIMIT 257',(frontend,self.incarnation,epoch)).fetchall()
                if len(rows)>256:raise ValueError('native pane map budget exceeded; no partial focus map')
                return [dict(session=r[0],pane=r[1],workspace=r[2],tab=r[3]) for r in rows]
            if action=='resolve':
                if type(target) is not dict or target.get('machine_id')!=self.host:
                    raise PermissionError('exact local metadata identity required')
                runtime=self.native_runtimes.get('hermes')
                if runtime is None or str(runtime.home)!=target.get('workspace_id'):
                    raise PermissionError('configured exact profile runtime required')
                rows=self.db.execute('''SELECT b.session FROM native_bindings b
                    LEFT JOIN native_organizers o ON o.session=b.session
                    LEFT JOIN lifecycle_bindings l ON l.session=b.session
                    WHERE b.tool='hermes' AND b.conversation=? AND
                    (o.agent=? OR (l.target=? AND l.incarnation=? AND l.epoch=?))''',
                    (conversation,target['agent_id'],json.dumps(target,sort_keys=True),self.incarnation,epoch)).fetchall()
                if len(rows)!=1:raise PermissionError('exact configured organizer conversation unavailable')
                sid=rows[0][0];row=self._get(sid)
                runtime.profile.resolve(conversation,row['workspace'])
                if row['status']!='running' or sid not in self.live:raise PermissionError('exact native process unavailable; no cold fallback')
                return dict(owner_session=sid,conversation=conversation,tool='hermes',owner_incarnation=self.incarnation,epoch=epoch,
                            process_generation=self.live[sid]['process_generation'],
                            configured_organizer=True,native_session_created=False,status='running')
            if action in ('verify','attach','io','register_pane'):
                if type(result) is not dict or result.get('owner_incarnation')!=self.incarnation or result.get('epoch')!=epoch:
                    raise PermissionError('stale native incarnation or revocation')
                sid=result['owner_session']
                live=self.live.get(sid)
                if not live or not live.get('process_generation') or result.get('process_generation')!=live['process_generation']:
                    raise PermissionError('running native process generation changed; prepare new consent')
                binding=self.db.execute('SELECT target,incarnation,epoch FROM lifecycle_bindings WHERE session=?',(sid,)).fetchone()
                if not binding or json.loads(binding[0])!=target or tuple(binding[1:])!=(self.incarnation,epoch):
                    observed=self.native_lifecycle(action='resolve',actor=actor,expected=current,confirmed=True,target=target,conversation=result.get('conversation')) if result.get('configured_organizer') is True else None
                    if observed is None or any(result.get(k)!=v for k,v in observed.items()):
                        raise PermissionError('exact owner binding unavailable')
                row=self._get(sid);native=self.native(sid,actor=actor)
                if row['status']!='running' or not native or native['conversation']!=result['conversation']:
                    raise PermissionError('exact running conversation unavailable')
                if action=='register_pane':
                    if not isinstance(frontend,str) or not re.fullmatch('[a-f0-9]{64}',frontend) or type(presentation) is not dict or set(presentation)!={'pane','workspace','tab'} or any(not isinstance(v,str) or not re.fullmatch('[A-Za-z0-9_:-]{1,256}',v) for v in presentation.values()):
                        raise ValueError('exact bounded native pane identity required')
                    assert_consent_active(consent_expires_at)
                    self.db.execute('INSERT OR REPLACE INTO native_frontend_panes VALUES(?,?,?,?,?,?,?)',(sid,frontend,presentation['pane'],presentation['workspace'],presentation['tab'],self.incarnation,epoch));self.db.commit()
                    self.select(sid,revision=self.view()['revision'],actor=actor)
                    return dict(registered=True)
                if action=='io':
                    self._attachment(self.live.get(sid),attachment)
                    if type(fields) is not dict:raise ValueError('closed native input fields required')
                    if io_operation=='read' and set(fields)=={'cursor'}:
                        return self.read(sid,actor=actor,cursor=fields['cursor'],binary=True,attachment=attachment)
                    if io_operation=='stage' and set(fields)=={'text'}:
                        return self.stage_draft(sid,fields['text'],actor=actor)
                    if io_operation=='send' and set(fields)=={'draft_id','sha256'}:
                        return self.send_draft(fields['draft_id'],consent=fields['sha256'],attachment=attachment,actor=actor,sid=sid)
                    if io_operation=='detach' and not fields:return self.detach(sid,actor=actor,attachment=attachment)
                    raise ValueError('explicit supported native IO operation required')
                if action=='attach':
                    import time
                    assert_consent_active(consent_expires_at)
                    attached=self.attach(sid,actor=actor,consent_expires_at=consent_expires_at)
                    self.live[sid]['attachment_deadline']=time.monotonic()+300
                    self.live[sid]['attachment_authority_epoch']=epoch
                    return dict(attached,lease_expires_at=time.time()+300)
                return row
            if action == 'plan' and self.execution_policy is not None:
                from dataclasses import asdict
                plan=dict(owner=current,**asdict(self.execution_policy.plan(environment,workspace,root_acknowledged=root_acknowledged)))
                if harness=='hermes':
                    runtime=self.native_runtimes.get('hermes')
                    if runtime is None or type(target) is not dict or str(runtime.home)!=target.get('workspace_id') or (provider_start_acknowledged is not True and not getattr(runtime, 'setup_only', False)) or environment!='host':
                        raise PermissionError('configured exact Hermes host producer and provider-start acknowledgement required')
                    plan['native']=self._native_new_identity(runtime,workspace)
                elif harness!='shell':raise PermissionError('unsupported native producer')
                return plan
            if action != 'new' or self.execution_policy is None:
                raise PermissionError('configured shell producer required')
            if not isinstance(attempt,str) or not re.fullmatch('[a-f0-9]{32}',attempt):
                raise ValueError('exact single-use attempt required')
            if type(target) is not dict or target.get('machine_id') != self.host:
                raise PermissionError('exact local identity required')
            effect_guard=None
            if delegation_fence is not None:
                if type(delegation_fence) is not dict:
                    raise PermissionError('authenticated original delegated ticket required')
                if remote_fence is not None and delegation_fence.get('authority_id')==remote_fence.authority_id:
                    if (target!=remote_fence.binding['target'] or workspace_identity!=remote_fence.binding['workspace_identity']
                            or environment not in remote_fence.binding['environments']):
                        raise PermissionError('exact independently provisioned remote target/workspace/mode required')
                    def effect_guard():
                        return remote_fence.guard(delegation_fence,attempt=attempt,machine=self.host,agent=target['agent_id'],
                            environment=environment,root_acknowledged=root_acknowledged,owner=self)
                else:
                    if authority_database is None or delegation_fence.get('authority_id')!=current['organizer_authority_id']:
                        raise PermissionError('delegated effect authority is unconfigured or changed; explicit provisioning required')
                    from .organizer_durable import delegated_effect_guard
                    def effect_guard():
                        if self.delegation_authority_database!=authority_database:
                            raise PermissionError('delegated effect authority changed')
                        return delegated_effect_guard(authority_database,delegation_fence,attempt=attempt,
                            machine=self.host,agent=target['agent_id'],environment=environment,root_acknowledged=root_acknowledged)
            if self.db.execute('SELECT 1 FROM lifecycle_bindings WHERE attempt=?',(attempt,)).fetchone():
                raise ValueError('owner attempt already recorded; reconcile without replay')
            plan = self.execution_policy.plan(environment,workspace,root_acknowledged=root_acknowledged)
            runtime=None;conversation=None
            if harness=='hermes':
                runtime=self.native_runtimes.get('hermes')
                if runtime is None or str(runtime.home)!=target['workspace_id'] or (provider_start_acknowledged is not True and not getattr(runtime, 'setup_only', False)) or environment!='host':
                    raise PermissionError('explicit configured Hermes producer and provider launch acknowledgement required')
                conversation='arvyx-new-'+attempt
                argv,native_environment=runtime.plan_new(conversation,workspace)
            elif harness!='shell':raise PermissionError('native New protocol unavailable')
            assert_consent_active(consent_expires_at)
            sid = uuid.uuid4().hex
            self.db.execute("INSERT INTO sessions VALUES(?,NULL,NULL,?,?,'stopped',NULL,'local')",
                            (sid,'local-'+sid,str(Path(workspace).resolve(strict=True))))
            # A shell conversation is identified by the owner's actual session,
            # never an invented provider ID or ID inferred from terminal output.
            self.db.execute('INSERT INTO native_bindings VALUES(?,?,?)',(sid,harness,conversation or sid))
            self.db.execute('INSERT INTO lifecycle_bindings VALUES(?,?,?,?,?,?)',
                            (attempt,sid,json.dumps(target,sort_keys=True),self.incarnation,epoch,environment))
            self.db.commit()
            native_binding=self.native(sid,actor=actor)
        # The durable attempt precedes admission, but no outer owner lock may
        # survive into _start's process/pump retirement.
        def admission():
            if self.delegation_authority_database!=authority_database or self.delegation_remote_fence is not remote_fence:
                raise PermissionError('delegated effect authority changed')
            assert_consent_active(consent_expires_at)
            if self._native_lifecycle_identity(guarded_authority_id=current['organizer_authority_id'] if delegation_fence is not None else None)!=current or self.native(sid,actor=actor)!=native_binding:
                raise PermissionError('owner incarnation, epoch or native binding changed before launch')
            if self.execution_policy is not policy or policy.plan(environment,workspace,root_acknowledged=root_acknowledged)!=plan:
                raise PermissionError('execution policy changed before launch')
            if runtime is not None and (self.native_runtimes.get('hermes') is not runtime or self._native_new_identity(runtime,workspace)!=reviewed_native):
                raise PermissionError('reviewed native executable or profile changed before launch')
            from .external_workspace import _open_root
            with _open_root(Path(workspace)) as current_workspace:
                info=os.fstat(current_workspace)
                if workspace_identity!=[info.st_dev,info.st_ino]:
                    raise PermissionError('reviewed workspace incarnation changed before launch')
            assert_consent_active(consent_expires_at)
        from .external_workspace import _open_root
        with _open_root(Path(workspace)) as workspace_fd, policy.sealed_launcher(plan,workspace_fd=workspace_fd) as argv:
            info=os.fstat(workspace_fd)
            if workspace_identity!=[info.st_dev,info.st_ino]:raise PermissionError('reviewed workspace incarnation changed')
            native_environment=None
            if runtime is not None:argv,native_environment=runtime.plan_new(conversation,workspace)
            self._start(sid,actor=actor,argv=argv,environment=native_environment if runtime is not None else plan.environment,
                        expected_native=native_binding,workspace_fd=workspace_fd,admission=admission,
                        inherited_fds=((workspace_fd,) if plan.mode=='sandbox' else ()) + (runtime.execution_fds if runtime is not None and getattr(runtime, 'setup_only', False) else ()),
                        consent_expires_at=consent_expires_at,
                        **({} if effect_guard is None else dict(effect_guard=effect_guard)))
        with self.lock:
            admission()
            if runtime is not None:
                conversation=runtime.created_session(conversation,workspace)
                assert_consent_active(consent_expires_at)
                self.db.execute('UPDATE native_bindings SET conversation=? WHERE session=?',(conversation,sid));self.db.commit()
            return dict(owner_session=sid,conversation=conversation or sid,tool=harness,owner_incarnation=self.incarnation,
                        process_generation=self.live[sid]['process_generation'],
                        epoch=epoch,native_session_created=True,environment=environment,status='running',
                        **(dict(setup_required=True) if runtime is not None and getattr(runtime, 'setup_only', False) else {}))

    @owner_entry
    def open_organizer(self, agent=None, *, actor):
        self._human(actor)
        from_primary = agent is None
        if agent is None:
            # Default to the persisted global selection, never a registry/model
            # role or the first listed organizer. This does not start a process.
            from .cockpit_primary import PrimaryAgentRegistry
            primary = PrimaryAgentRegistry(self, self.state.with_name(self.state.name + '.primary.sqlite'))
            try:
                agent = primary.snapshot()['agent_id']
            finally:
                primary.close()
            if agent is None:
                raise ValueError('no validated primary agent connected yet')
        if not isinstance(agent, str) or not re.fullmatch(r'[a-z0-9-]{1,64}', agent):
            raise ValueError('existing organizer identity/configuration unavailable')
        if agent not in self.organizer_bindings:
            if from_primary:
                raise ValueError('selected primary has no configured native organizer binding; explicit owner configuration required')
            raise ValueError('existing organizer identity/configuration unavailable')
        binding = self.organizer_bindings[agent]
        if (not isinstance(binding, dict) or set(binding) != {'tool', 'conversation', 'workspace'}
                or any(not isinstance(value, str) or not value for value in binding.values())):
            raise ValueError('exact organizer tool/conversation/workspace references required')
        from .cockpit_adapters import resume_plan
        resume_plan(binding['tool'], binding['conversation'])
        workspace = Path(binding['workspace']).resolve(strict=True)
        if binding['tool'] != 'fixture':
            runtime = self.native_runtimes.get(binding['tool'])
            if runtime is None:
                raise ValueError('existing organizer native runtime unavailable')
            runtime.plan(binding['conversation'], workspace)
        with self.lock:
            previous = self.db.execute('SELECT session FROM native_organizers WHERE agent=?', (agent,)).fetchone()
            if previous:
                session = self._get(previous[0])
                native = self.native(previous[0], actor=actor)
                if native['tool'] != binding['tool'] or native['conversation'] != binding['conversation'] or session['workspace'] != str(workspace):
                    raise ValueError('persistent organizer binding changed; explicit reconciliation required')
                if session['status'] == 'ended':
                    self.db.execute("UPDATE sessions SET status='stopped' WHERE id=?", (session['id'],))
                    self.db.commit()
                return self._get(session['id'])
            sid = uuid.uuid4().hex
            self.db.execute("INSERT INTO sessions VALUES(?,NULL,NULL,?,?,'stopped',NULL,'organizer')",
                            (sid, 'organizer-' + agent, str(workspace)))
            self.db.execute('INSERT INTO native_organizers VALUES(?,?)', (agent, sid))
            self.db.execute('INSERT INTO native_bindings VALUES(?,?,?)', (sid, binding['tool'], binding['conversation']))
            self.db.commit()
            return self._get(sid)

    @owner_entry
    def native(self, sid, *, actor):
        self._human(actor)
        with self.lock:
            self._get(sid)
            row = self.db.execute('SELECT * FROM native_bindings WHERE session=?', (sid,)).fetchone()
            return dict(row) if row else None

    @owner_entry
    def native_archive(self, sid, *, actor):
        from .cockpit_archive import import_native
        return import_native(self, sid, actor=actor)

    @owner_entry
    def bind_native(self, sid, *, tool, conversation, actor):
        from .cockpit_adapters import resume_plan
        self._human(actor)
        resume_plan(tool, conversation)
        with self.lock:
            if sid in self.starting:
                raise ValueError('session startup/cleanup in progress; binding refused')
            if self._get(sid)['status'] != 'stopped':
                raise ValueError('native binding requires stopped session')
            previous = self.native(sid, actor=actor)
            binding = dict(session=sid, tool=tool, conversation=conversation)
            if previous and previous != binding:
                raise ValueError('native conversation is fixed; create a new session explicitly')
            self.db.execute('INSERT OR IGNORE INTO native_bindings VALUES (?, ?, ?)', (sid, tool, conversation))
            self.db.commit()
            return binding

    @owner_entry
    def start_native(self, sid, *, actor, fixture=False, allow_provider=False, environment=None, root_acknowledged=False, _restart_admission=None):
        import shutil
        from .cockpit_adapters import resume_plan
        self._human(actor)
        if type(fixture) is not bool or type(allow_provider) is not bool:
            raise ValueError('explicit Boolean launch flags required')
        binding = self.native(sid, actor=actor)
        if binding is None:
            raise ValueError('no verified native conversation binding')
        if binding['tool'] == 'fixture':
            if not fixture:
                raise ValueError('explicit fixture flag required')
        elif not allow_provider:
            raise ValueError('provider launch requires fresh explicit authorization')
        if binding['tool'] != 'fixture':
            if fixture:raise PermissionError('fixture exemption is restricted to fixture bindings')
            plan,policy=self._execution_plan(sid,environment,root_acknowledged)
            if environment=='sandbox':raise PermissionError('provider sandbox profile admission unavailable')
            runtime = self.native_runtimes.get(binding['tool'])
            if runtime is None:
                raise ValueError('native executable/configuration unavailable; no replacement conversation launched')
            argv, native_environment = runtime.plan(binding['conversation'], self._get(sid)['workspace'])
            if _restart_admission is not None:
                from .cockpit_restart import RestartAdmission
                if type(_restart_admission) is not RestartAdmission or _restart_admission.owner is not self or _restart_admission.sid!=sid:
                    raise PermissionError('internal exact restart admission required')
            incarnation=self.incarnation
            epoch=self.db.execute('SELECT epoch FROM lifecycle_policy WHERE singleton=1').fetchone()[0]
            def admission():
                if self.incarnation!=incarnation or self.db.execute('SELECT epoch FROM lifecycle_policy WHERE singleton=1').fetchone()[0]!=epoch:
                    raise PermissionError('native launch authority changed')
                if self.native(sid,actor=actor)!=binding or self.execution_policy is not policy or policy.plan(environment,self._get(sid)['workspace'],root_acknowledged=root_acknowledged)!=plan:
                    raise PermissionError('native binding or execution policy changed')
                if runtime.plan(binding['conversation'],self._get(sid)['workspace'])!=(argv,native_environment):raise PermissionError('native launch plan changed')
                if _restart_admission is not None:_restart_admission()
            # Keep the exact trusted reboot object available to cleanup admission;
            # the ordinary policy guard still runs at the final effect boundary.
            return self._start(sid, actor=actor, argv=argv, environment=native_environment, expected_native=binding,
                               admission=admission,restart_admission=_restart_admission,
                               **({} if _restart_admission is None else dict(consent_expires_at=_restart_admission.expires)))
        argv = resume_plan(binding['tool'], binding['conversation'])
        executable = shutil.which(argv[0], path='/usr/bin:/bin')
        if executable is None:
            raise ValueError('native executable unavailable; no replacement conversation launched')
        argv[0] = executable
        return self._start(sid, actor=actor, argv=argv, expected_native=binding)

    def _execution_plan(self,sid,environment,root_acknowledged):
        policy=self.execution_policy
        if policy is None or environment is None:raise PermissionError('configured execution policy and explicit execution mode required')
        return policy.plan(environment,self._get(sid)['workspace'],root_acknowledged=root_acknowledged),policy

    @owner_entry
    def start(self, sid, *, actor, environment=None, root_acknowledged=False):
        self._human(actor)
        if self.native(sid, actor=actor):
            raise ValueError('native binding requires explicit native resume')
        plan,policy=self._execution_plan(sid,environment,root_acknowledged)
        workspace_identity=None
        def admission():
            if self.execution_policy is not policy or policy.plan(environment,self._get(sid)['workspace'],root_acknowledged=root_acknowledged)!=plan:
                raise PermissionError('execution policy changed before launch')
            with _open_root(Path(self._get(sid)['workspace'])) as current_fd:
                if (os.fstat(current_fd).st_dev,os.fstat(current_fd).st_ino)!=workspace_identity:
                    raise PermissionError('workspace incarnation changed before launch')
        from .external_workspace import _open_root
        with _open_root(Path(self._get(sid)['workspace'])) as workspace_fd, policy.sealed_launcher(plan,workspace_fd=workspace_fd) as argv:
            workspace_identity=(os.fstat(workspace_fd).st_dev,os.fstat(workspace_fd).st_ino)
            return self._start(sid,actor=actor,argv=argv,environment=plan.environment,admission=admission,workspace_fd=workspace_fd,
                               **({} if plan.mode!='sandbox' else dict(inherited_fds=(workspace_fd,))))

    def _retire_live(self, sid, live):
        """Join without owner.lock; retries stay excluded until retirement."""
        thread = live.get('thread')
        if thread is not None and thread.ident is not None:
            thread.join(timeout=5)
            if thread.is_alive():
                raise ValueError('previous pump cleanup incomplete; retry refused')
        with self.lock:
            if not live.get('terminated'):
                raise ValueError('previous process cleanup unverified; retry refused')
            if live.get('fd') is not None:
                os.close(live['fd'])
                live['fd'] = None
            if live.get('reservation') is not None:
                live['reservation'].release()
                live['reservation'] = None
            if self.live.get(sid) is live:
                live['retired'] = True
                self.db.execute('DELETE FROM cleanup_ownership WHERE session=?', (sid,))
                self.db.commit()

    @owner_entry
    def _start(self, sid, *, actor, argv, environment=None, expected_native=None, workspace_fd=None, admission=None, restart_admission=None,effect_guard=None,consent_expires_at=None,inherited_fds=()):
        self._human(actor)
        with self.lock:
            if sid in self.starting:
                raise ValueError('session startup/cleanup in progress; retry refused')
            if self._get(sid)['status'] != 'stopped':
                raise ValueError('session must be stopped')
            if self.native(sid, actor=actor) != expected_native:
                raise ValueError('native binding changed during launch planning; retry explicitly')
            if admission is not None:admission()
            self.starting.add(sid)
            previous = self.live.get(sid)
        try:
            if previous is not None:
                self._terminate(previous)
                self._retire_live(sid, previous)
            return self._start_locked(sid, actor=actor, argv=argv, environment=environment, **({} if workspace_fd is None else dict(workspace_fd=workspace_fd)),
                                      **({} if admission is None else dict(admission=admission)),
                                      **({} if effect_guard is None else dict(effect_guard=effect_guard)),
                                      **({} if consent_expires_at is None else dict(consent_expires_at=consent_expires_at)),
                                      **({} if not inherited_fds else dict(inherited_fds=inherited_fds)),
                                      **({} if restart_admission is None else dict(restart_admission=restart_admission)))
        except BaseException:
            with self.lock:
                failed = self.live.get(sid)
            if failed is not None and failed is not previous:
                self._terminate(failed)
                self._retire_live(sid, failed)
            raise
        finally:
            with self.lock:
                self.starting.discard(sid)

    @owner_entry
    def _start_locked(self, sid, *, actor, argv, environment=None, workspace_fd=None, admission=None, restart_admission=None,effect_guard=None,consent_expires_at=None,inherited_fds=()):
        self._human(actor)
        with self.lock, _locked_state(self.state), ExitStack() as effects:
            row = self._get(sid)
            if row["status"] != "stopped":
                raise ValueError("session must be stopped")
            if admission is not None:admission()
            previous_cleanup=self.db.execute('SELECT pid FROM cleanup_ownership WHERE session=?',(sid,)).fetchone()
            if previous_cleanup:
                from .cockpit_restart import RestartAdmission
                if type(restart_admission) is not RestartAdmission or restart_admission.owner is not self or restart_admission.sid!=sid:
                    raise ValueError('previous owner cleanup unverified; explicit host reconciliation required')
                restart_admission()
            tasks = {item.id: item for item in list_tasks(self.state).tasks}
            if row['kind'] == 'work' and (row["task"] not in tasks or tasks[row["task"]].status in {"done", "retired"}):
                raise ValueError("task is no longer active")
            # fork supplies a controlling terminal; argv and cwd never enter shell text.
            import pty
            from .cockpit_archive import WorkCapture
            native = self.native(sid, actor=actor)
            runtime = self.native_runtimes.get(native['tool']) if native else None
            reservation = runtime.reserve(native['conversation']) if runtime and native else None
            recorder = None
            fork_attempted = False
            # Durable pre-fork uncertainty: a crash can never erase launch intent.
            try:
                recorder = WorkCapture(self, sid)
                if admission is not None:admission()
                self.db.execute('INSERT OR REPLACE INTO cleanup_ownership VALUES(?,0)', (sid,))
                # A byte cursor belongs to exactly one PTY stream. New launches never
                # inherit active authority or silently skip bytes from a new stream.
                self.db.execute("UPDATE delegations SET cursor=0, generation=generation+1, status=CASE WHEN pending IS NOT NULL THEN 'ambiguous' WHEN status='active' THEN 'paused' ELSE status END WHERE session=?", (sid,))
                self.db.commit()
                if restart_admission is not None:restart_admission.launch_prepared=True
                from .posix_support import cloexec_pipe
                exec_read, exec_write = cloexec_pipe()
                try:
                    # The authenticated policy fence spans fork, exec ACK and
                    # publication. Sender timeouts cannot release this guard.
                    effect_check=effects.enter_context(effect_guard()) if effect_guard is not None else None
                    checkpoint()
                    if admission is not None:admission()
                    if effect_check is not None:effect_check()
                    from .reviewed_actions import assert_consent_active
                    assert_consent_active(consent_expires_at)
                    fork_attempted = True
                    try:
                        pid, fd = pty.fork()
                    except OSError:
                        # fork() returning an OS error created no child. Keep
                        # the charged run, classified as pre-process evidence.
                        fork_attempted = False
                        raise
                except BaseException:
                    os.close(exec_read)
                    os.close(exec_write)
                    raise
            except BaseException:
                self.db.rollback()
                if recorder is not None and not fork_attempted:
                    recorder.abort_before_process()
                if previous_cleanup:
                    # Restore the reboot's original cleanup evidence even if
                    # releasing the new reservation itself fails durability.
                    self.db.execute('INSERT OR REPLACE INTO cleanup_ownership VALUES(?,?)',(sid,previous_cleanup[0]))
                    self.db.commit()
                if reservation is not None:
                    reservation.release()
                if not previous_cleanup:
                    self.db.execute('DELETE FROM cleanup_ownership WHERE session=?', (sid,))
                    self.db.commit()
                raise
            if pid == 0:
                os.close(exec_read)
                try:
                    if workspace_fd is None:os.chdir(row["workspace"])
                    else:os.fchdir(workspace_fd)
                    for descriptor in inherited_fds:os.set_inheritable(descriptor,True)
                    os.write(exec_write, b'X')
                    os.execve(argv[0], argv, environment if environment is not None else {
                        "PATH": "/usr/bin:/bin", "TERM": "xterm-256color",
                        "HOME": row["workspace"], "ENV": "/dev/null", "PS1": "$ ",
                    })
                except BaseException:
                    # Never include argv/environment or exception text (credentials).
                    try:
                        os.write(exec_write, b'E')
                    finally:
                        os._exit(127)
            os.close(exec_write)
            live = dict(pid=pid, fd=fd, output=bytearray(), offset=0, attached=False,
                        process_generation=uuid.uuid4().hex,
                        recorder=recorder, reservation=reservation,
                        stop=threading.Event(), capture_error=None,
                        input=bytearray(), input_lock=threading.Lock(), written_bytes=0,
                        discarded_bytes=0, input_error=None)
            self.live[sid] = live
            thread = None
            live['thread'] = None
            try:
                # CLOEXEC closes only after successful exec; an error byte or
                # missing pre-exec marker refuses publication. One total budget.
                import time
                deadline = time.monotonic() + 5.0
                handshake = bytearray()
                try:
                    while True:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0 or not select.select([exec_read], [], [], remaining)[0]:
                            raise ValueError('native exec confirmation timed out')
                        chunk = os.read(exec_read, 16)
                        if not chunk:
                            break
                        handshake.extend(chunk)
                        if handshake != b'X':
                            raise ValueError('native chdir/exec failed; no connection published')
                    from .posix_support import exited_unreaped
                    if handshake != b'X' or exited_unreaped(pid):
                        raise ValueError('native launch exited before connection publication')
                finally:
                    os.close(exec_read)
                thread = threading.Thread(target=self._pump, args=(sid, live), daemon=True)
                live['thread'] = thread
                os.set_blocking(fd, False)
                thread.start()
                from .cockpit_primary import PrimaryAgentRegistry, compatible_native_identity
                organizer = self.db.execute('SELECT agent FROM native_organizers WHERE session=?', (sid,)).fetchone()
                native = self.native(sid, actor=actor)
                if (organizer and native and native['tool'] != 'fixture'
                        and compatible_native_identity(self.vault, organizer[0], self.host, native['tool'])):
                    primary = PrimaryAgentRegistry(self, self.state.with_name(self.state.name + '.primary.sqlite'))
                    try:
                        primary.attach_store(self.root / 'sessions.sqlite', 'native_owner')
                        with primary._transaction():
                            assert_consent_active(consent_expires_at)
                            primary.db.execute('INSERT OR REPLACE INTO native_owner.cleanup_ownership VALUES(?,?)', (sid, pid))
                            primary.db.execute("UPDATE native_owner.sessions SET status='running',pid=? WHERE id=?", (pid, sid))
                            primary.db.execute('INSERT OR REPLACE INTO primary_connections VALUES(?,?,1)', ('native:'+organizer[0], organizer[0]))
                            primary._elect_locked(organizer[0], actor='native-owner', reason='first validated native connection')
                    finally:
                        primary.close()
                else:
                    assert_consent_active(consent_expires_at)
                    self.db.execute('INSERT OR REPLACE INTO cleanup_ownership VALUES(?,?)', (sid, pid))
                    self.db.execute("UPDATE sessions SET status='running', pid=? WHERE id=?", (pid, sid))
                    self.db.commit()
            except BaseException:
                self.db.rollback()
                if thread is None or thread.ident is None:
                    os.close(fd)
                    live['fd'] = None
                raise
            return self._get(sid)

    @owner_entry
    def _pump(self, sid, live):
        try:
            while True:
                with live["input_lock"]:
                    pending = bool(live["input"])
                readable, writable, _ = select.select([live["fd"]], [live["fd"]] if pending else [], [], .02)
                if writable:
                    self._flush_input(live)
                if not readable:
                    continue
                try:
                    data = os.read(live["fd"], 4096)
                except (BlockingIOError, InterruptedError):
                    continue
                if not data:
                    break
                while True:
                    try:
                        live['recorder'].feed(data)
                        live['capture_error'] = None
                        break
                    except (sqlite3.Error, OSError, BufferError):
                        live['capture_error'] = 'Recording blocked; output backpressured. End may leave an incomplete run.'
                        if live['stop'].wait(.25):
                            return
                with self.lock:
                    live["output"].extend(data)
                    excess = max(0, len(live["output"]) - 65536)
                    del live["output"][:excess]
                    live["offset"] += excess
        except OSError:
            pass
        finally:
            # Keep the unreaped leader identity reserved until verified cleanup.
            # Reaping here would permit PID/SID reuse before End's member sweep.
            if not live['capture_error']:
                while True:
                    try:
                        live['recorder'].finish()
                        live['capture_error'] = None
                        break
                    except (sqlite3.Error, OSError, BufferError):
                        live['capture_error'] = 'Final recording blocked; tail retained, run incomplete until storage recovery.'
                        if live['stop'].wait(.25):
                            break
            with live["input_lock"]:
                live["discarded_bytes"] += len(live["input"])
                live["input"].clear()
                live["input_error"] = live["input_error"] or "PTY closed"
            with self.lock:
                if live['fd'] is not None:
                    os.close(live["fd"])
                    live["fd"] = None
                if self.live.get(sid) is not live:
                    return
                self.db.execute("UPDATE sessions SET status='stopped', pid=NULL WHERE id=? AND status!='ended'", (sid,))
                self.db.execute("UPDATE delegations SET generation=generation+1, status=CASE WHEN pending IS NOT NULL THEN 'ambiguous' ELSE 'paused' END WHERE session=? AND status='active'", (sid,))
                self.db.commit()
            binding = self.native(sid, actor='operator')
            if binding and binding['tool'] == 'hermes' and 'hermes' in self.native_runtimes:
                try:
                    while self.native_archive(sid, actor='operator')['has_more']:
                        pass
                except (sqlite3.Error, OSError, ValueError, BufferError):
                    live['capture_error'] = 'Structured native archive unavailable; inspect source; nothing promoted to memory.'

    @staticmethod
    def _flush_input(live):
        # Only the pump writes/closes this nonblocking fd. Never take the owner lock.
        with live["input_lock"]:
            if not live["input"]:
                return
            try:
                count = os.write(live["fd"], bytes(live["input"][:4096]))
                if count <= 0:
                    raise OSError("zero-byte PTY write")
            except (BlockingIOError, InterruptedError):
                return
            except OSError as exc:
                live["input_error"] = str(exc)
                live["discarded_bytes"] += len(live["input"])
                live["input"].clear()
                return
            del live["input"][:count]
            live["written_bytes"] += count

    @owner_entry
    def attach(self, sid, *, actor, takeover=False, consent_expires_at=None):
        self._human(actor)
        if type(takeover) is not bool:
            raise ValueError("takeover must be Boolean")
        with self.lock:
            self._get(sid)
            if sid not in self.live or self.live[sid]["fd"] is None:
                raise ValueError("session is not running; explicit start required")
            import time
            if self.live[sid].get('attachment_deadline',float('inf'))<=time.monotonic():
                self.live[sid]['attached']=False
            if self.live[sid]["attached"] and not takeover:
                raise ValueError("already attached; explicit takeover required")
            token = uuid.uuid4().hex
            from .reviewed_actions import assert_consent_active
            assert_consent_active(consent_expires_at)
            self.live[sid]['attachment_epoch'] = self.live[sid].get('attachment_epoch', 0) + 1
            self.live[sid].pop('attachment_deadline',None)
            self.live[sid]["attached"] = token
            return dict(self._get(sid), attachment=token)

    @staticmethod
    def _attachment(live, attachment):
        if not live or not attachment or live["attached"] != attachment:
            raise ValueError("stale attachment; explicitly attach or take over")
        import time
        if live.get('attachment_deadline',float('inf'))<=time.monotonic():
            raise ValueError('attachment lease expired; explicit new attachment required')

    @owner_entry
    def detach(self, sid, *, actor, attachment=None):
        self._human(actor)
        with self.lock:
            self._get(sid)
            self._attachment(self.live.get(sid), attachment)
            self.live[sid]["attached"] = False
            return self._get(sid)

    @owner_entry
    def resize(self, sid, *, rows, columns, actor, attachment=None):
        self._human(actor)
        if any(type(value) is not int or not 1 <= value <= 1000 for value in (rows, columns)):
            raise ValueError("terminal dimensions must be integers from 1 to 1000")
        import fcntl
        import struct
        import termios
        with self.lock:
            self._get(sid)
            live = self.live.get(sid)
            if not live or live["fd"] is None:
                raise ValueError("session is not running")
            self._attachment(live, attachment)
            fcntl.ioctl(live["fd"], termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
            return {"rows": rows, "columns": columns}

    @owner_entry
    def write(self, sid, text=None, *, actor, attachment=None, data=None):
        self._human(actor)
        if data is not None:
            if text is not None or not isinstance(data, str) or len(data) > 5464:
                raise ValueError("invalid binary input frame")
            try:
                payload = base64.b64decode(data, validate=True)
            except (ValueError, binascii.Error):
                raise ValueError("invalid base64 input") from None
        elif isinstance(text, str):
            payload = text.encode()
        else:
            raise ValueError("input requires text or base64 data")
        if len(payload) > 4096:
            raise ValueError("input must be at most 4096 bytes")
        with self.lock:
            row = self._get(sid)
            live = self.live.get(sid)
            self._attachment(live, attachment)
            if row["status"] != "running" or not live or live["fd"] is None or not live["attached"]:
                raise ValueError("attach a running session before input")
            data = payload
            with live["input_lock"]:
                accepted = not live["input_error"] and len(live["input"]) + len(data) <= 65536
                if accepted:
                    live['human_input_revision'] = live.get('human_input_revision', 0) + 1
                    live["input"].extend(data)
                return {"accepted": bool(accepted), "accepted_bytes": len(data) if accepted else 0,
                        "queued_bytes": len(live["input"]), "written_bytes": live["written_bytes"],
                        "discarded_bytes": live["discarded_bytes"], "input_error": live["input_error"],
                        "reason": None if accepted else ("input_failed" if live["input_error"] else "backpressure")}

    @owner_entry
    def read(self, sid, *, actor, cursor=0, binary=False, attachment=None):
        self._human(actor)
        if type(cursor) is not int or cursor < 0 or type(binary) is not bool:
            raise ValueError("invalid cursor")
        with self.lock:
            self._get(sid)
            live = self.live.get(sid)
            if not live:
                return {"output": "", "data": "", "cursor": 0, "truncated": False}
            if attachment is not None or 'attachment_authority_epoch' in live:
                self._attachment(live,attachment)
            offset = live["offset"]
            if cursor > offset + len(live["output"]):
                raise ValueError("cursor ahead of terminal stream")
            payload = bytes(live["output"][max(0, cursor - offset):])
            output = "" if binary else payload.decode("utf-8", errors="replace")
            with live["input_lock"]:
                input_status = {"queued_bytes": len(live["input"]), "written_bytes": live["written_bytes"],
                                "discarded_bytes": live["discarded_bytes"], "input_error": live["input_error"]}
            return {"output": output, "cursor": offset + len(live["output"]), "truncated": cursor < offset,
                    "data": base64.b64encode(payload).decode("ascii") if binary else "",
                    "input_status": input_status}

    @staticmethod
    def _terminate(live):
        live['stop'].set()
        if live.get('terminated'):
            return
        # Stop the leader first, even if enumeration cannot fork under load.
        leader_denied = False
        try:
            os.killpg(live["pid"], signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            leader_denied = True
        # Include separate shell job groups, rechecking for concurrent forks.
        # A failed/bounded enumeration never becomes an acknowledged End.
        import subprocess
        import time
        for attempt in range(3):
            leader_zombie = False
            try:
                try:
                    candidates = []
                    for entry in Path('/proc').iterdir():
                        if entry.name.isdigit():
                            try:
                                state = (entry / 'stat').read_bytes().rsplit(b')', 1)[1].split()[0]
                            except (FileNotFoundError, ProcessLookupError):
                                continue
                            except PermissionError:
                                candidates.append(entry.name)
                                continue
                            except (IndexError, ValueError):
                                candidates.append(entry.name)
                                continue
                            if int(entry.name) == live['pid'] and state == b'Z':
                                leader_zombie = True
                            if state != b'Z':
                                candidates.append(entry.name)
                except FileNotFoundError:
                    # PID/state only, never process arguments or environment.
                    rows = subprocess.check_output(['/bin/ps', '-axo', 'pid=,stat='], text=True, timeout=5)
                    leader_zombie = any(parts[0] == str(live['pid']) and len(parts) > 1 and parts[1].startswith('Z')
                                        for line in rows.splitlines() if (parts := line.split()))
                    candidates = [parts[0] for line in rows.splitlines()
                                  if (parts := line.split()) and not (len(parts) > 1 and parts[1].startswith('Z'))]
            except (OSError, subprocess.SubprocessError) as exc:
                raise ValueError('termination incomplete; process enumeration unavailable') from exc
            found = False
            denied = False
            for candidate in candidates:
                if candidate.isdigit() and int(candidate) != live['pid']:
                    try:
                        pid = int(candidate)
                        pidfd_open = getattr(os, 'pidfd_open', None)
                        pidfd_send = getattr(signal, 'pidfd_send_signal', None)
                        if pidfd_open is not None and pidfd_send is not None:
                            handle = pidfd_open(pid)
                            try:
                                if os.getsid(pid) == live['pid']:
                                    found = True
                                    pidfd_send(handle, signal.SIGKILL)
                            finally:
                                os.close(handle)
                        else:
                            # macOS has no pidfd. Match the process group, which
                            # setsid made equal to the leader, and skip a pid
                            # that disappeared between the snapshot and the check.
                            try:
                                if os.getpgid(pid) != live['pid']:
                                    continue
                            except ProcessLookupError:
                                continue
                            found = True
                            os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except PermissionError:
                        denied = True
            if denied or (leader_denied and not leader_zombie):
                raise ValueError('termination incomplete; session member permission denied')
            if not found:
                reaped = 0
                for _ in range(25):
                    reaped, _ = os.waitpid(live['pid'], os.WNOHANG)
                    if reaped == live['pid']:
                        break
                    time.sleep(.02)
                if reaped != live['pid']:
                    raise ValueError('termination incomplete; leader has not exited')
                live['terminated'] = True
                return
            if attempt < 2:
                time.sleep(.02)
        raise ValueError('termination incomplete; session members require reconciliation')

    @owner_entry
    def end(self, sid, *, actor):
        self._human(actor)
        with self.lock:
            if sid in self.starting:
                raise ValueError('session startup/cleanup in progress; End refused')
            self._get(sid)
            self.starting.add(sid)
        try:
            with self.lock:
                self.take_control(sid, actor=actor)
                live = self.live.get(sid)
                if live is None and self.db.execute('SELECT 1 FROM cleanup_ownership WHERE session=?', (sid,)).fetchone():
                    raise ValueError('previous owner cleanup unverified; End not acknowledged; explicit host reconciliation required')
                if live:
                    self._terminate(live)
                self.db.execute("UPDATE sessions SET status='ended', pid=NULL WHERE id=?", (sid,))
                self.db.commit()
            if live:
                self._retire_live(sid, live)
            return self._get(sid)
        finally:
            with self.lock:
                self.starting.discard(sid)

    def close(self):
        if self.closed:
            return
        failures = []

        def cleanup(action):
            try:
                action()
            except Exception as exc:
                # Local cleanup must continue for all sessions. Never expose
                # storage exception text, command arguments or credentials.
                failures.append(type(exc).__name__)

        self.archive_stop.set()
        self.operator_stop.set()
        for thread in (self.archive_thread, self.operator_thread):
            if thread is not None:
                cleanup(lambda: thread.join(timeout=5))
                if thread.is_alive():
                    failures.append('background cleanup incomplete')
        if self.web_server is not None:
            cleanup(self.web_server.shutdown)
            cleanup(self.web_server.server_close)
            cleanup(lambda: self.web_thread.join(timeout=5))
            if self.web_thread.is_alive():
                failures.append('web cleanup incomplete')
        for sid, live in list(self.live.items()):
            cleanup(lambda: self._terminate(live))
            if live.get('terminated'):
                cleanup(lambda: self._retire_live(sid, live))
        cleanup(self.db.close)
        for remote in (self.delegation_remote_recovery,self.delegation_remote_fence):
            if remote is not None:cleanup(remote.close)
        cleanup(self.owner.close)
        self.closed = True
        if failures:
            raise ValueError(f'termination incomplete; {len(failures)} cleanup failures; '
                             'failed sessions retained for explicit host reconciliation')


def configured_team(vault, state, operator_credential_file=None):
    """Use an explicitly supplied existing AMC credential, never a new operator identity.

    Two explicit forms exist: an existing agent token in AMC_COCKPIT_AUTHORIZATION,
    or the owner's private operator credential file (the same file cockpit_local
    takes; REV-0572). Absent configuration leaves team/organizer unavailable.
    Validation of identity and permissions remains the existing API's job on every
    request. No shared-secret fallback or credential discovery is performed.
    """
    from .cockpit_team import TeamAuthority
    authorization = os.environ.get('AMC_COCKPIT_AUTHORIZATION')
    if authorization is not None and operator_credential_file is not None:
        raise ValueError('choose one explicit team credential: AMC_COCKPIT_AUTHORIZATION or --operator-credential-file')
    if operator_credential_file is not None:
        from .external_workspace import _read
        path = Path(operator_credential_file)
        if not path.is_absolute():
            raise ValueError('operator credential file must be an absolute path')
        raw, identity, _ = _read(path.parent, (path.name,), 4096)
        if not private_paths.is_private_mode(identity[2], path=path):
            raise ValueError('operator credential must be private')
        secret = raw.decode('utf-8').strip()
        if not secret or any(ord(c) < 32 or ord(c) == 127 for c in secret):
            raise ValueError('operator credential file must hold one printable secret')
        return TeamAuthority(vault, state, bearer_secret=secret, authorization='Bearer ' + secret)
    if authorization is None:
        return None
    if (not authorization.startswith('Bearer ') or not authorization[7:].strip()
            or len(authorization) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in authorization)):
        raise ValueError('invalid explicit AMC authorization configuration')
    return TeamAuthority(vault, state, authorization=authorization)


OWNER_TIMEOUT = 2


def handle_connection(client, service, dispatcher, *, listener=None):
    """One bounded exchange; forwarded sockets inherit the same total budget.

    Synchronous local operations are not forcibly cancelled or replayed after
    timeout: a lost acknowledgement always requires explicit reconciliation.
    ``listener`` (the owner's endpoint) checks the endpoint token on Windows.
    """
    import time
    from .cockpit_client import (exchange_deadline, absolute_deadline, validate_budget,
                                 receive_frame, send_frame, remaining, REQUEST_CAP, RESPONSE_CAP)
    started = time.monotonic()
    with exchange_deadline(OWNER_TIMEOUT) as end:
        try:
            raw = receive_frame(client, end, REQUEST_CAP)
            request = bounded_json_loads(raw)
            if not isinstance(request, dict):
                raise ValueError("request must be an object")
            if listener is not None:
                listener.authorize(request)
            else:
                request.pop(owner_endpoint.TOKEN_FIELD, None)
            budget = validate_budget(request.pop('_budget_seconds', OWNER_TIMEOUT))
            # Charge frame receipt too; old clients get the existing owner cap.
            end = min(end, started + budget)
            endpoint_identity = request.pop('_endpoint_identity', None)
            if endpoint_identity is not None and endpoint_identity != {'host': service.host, 'state': str(service.state)}:
                raise ValueError('endpoint identity mismatch; operation not delivered')
            operation = request.pop("operation")
            retention_operation = operation in {'trust_capture_retention', 'revoke_capture_retention', 'request_capture_retention'}
            if not retention_operation and operation not in {"authorize_native_restart", "resume_native_restart", "prepare_capture_offload", "acknowledge_capture_offload", "relocate_capture_offload", "reset_capture_offload_verification", "read_capture_offload_page", "configure_remote_delegation", "reconcile_remote_delegation", "inspect_capture_context", "reconcile_capture_context", "native_lifecycle", "raise_capture_capacity", "export_capture", "open", "open_organizer", "start", "bind_native", "native", "native_archive", "start_native", "drafts", "stage_draft", "send_draft", "archive", "organizer", "attach", "detach", "resize", "write", "read", "end", "list", "view", "select", "layout", "capabilities", "snapshot", "dashboard", "delegate", "delegation", "take_control", "take_control_scope", "reconcile_input"}:
                raise ValueError("unknown operation")
            remaining(end)
            # Storage policy belongs to this authenticated local owner, not a
            # session-selected remote host. Remote owners use their own socket.
            target = service if retention_operation or operation in {"authorize_native_restart", "resume_native_restart", "prepare_capture_offload", "acknowledge_capture_offload", "relocate_capture_offload", "reset_capture_offload_verification", "read_capture_offload_page", "configure_remote_delegation", "reconcile_remote_delegation", "inspect_capture_context", "reconcile_capture_context", "native_lifecycle", "raise_capture_capacity", "export_capture"} else dispatcher
            with absolute_deadline(end):
                result = getattr(target, operation)(**request)
            response = {"ok": True, "result": result}
            remaining(end)
        except (ValueError, TypeError, KeyError, OSError, sqlite3.Error, RuntimeError, BufferError) as exc:
            response = {"ok": False, "error": str(exc)}
        try:
            send_frame(client, json.dumps(response).encode() + b"\n", end, RESPONSE_CAP)
        except (OSError, ValueError):
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--vault", type=Path)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--host")
    parser.add_argument('--fleet-config', type=Path, help='Explicit private local endpoint map; no discovery or SSH launch')
    parser.add_argument('--runtime-config', type=Path, help='Explicit private executable/home/store and approved operator-driver references')
    parser.add_argument('--resume-delegated',action='append',default=[],metavar='LEASE_ID',help='Consume an existing unexpired exact native restart lease after verified kernel reboot; no consent renewal')
    parser.add_argument('--execution-policy', type=Path, help='Private JSON local-shell executor policy; no automatic host/root grant')
    parser.add_argument('--remote-delegation-config',type=Path,help='Private exact remote fence trust; pin the current owner through configure_remote_delegation after startup')
    parser.add_argument('--delegation-authority-database',type=Path,help='Trusted local organizer authority database for authenticated final effect fencing')
    parser.add_argument('--operator-credential-file',type=Path,help='Explicit private operator credential (as cockpit_local takes) so team controls of the live dashboard act as this operator; never sent to the browser')
    parser.add_argument("action", choices=["serve", "request"])
    parser.add_argument("--body", default="{}", help="Local JSON request, never a network endpoint")
    args = parser.parse_args()
    endpoint = str(args.root / "cockpit.sock")
    if args.action == "request":
        from .cockpit_client import exchange
        print(exchange(endpoint, args.body.encode() + b"\n").decode(), end="")
        return
    if not args.vault or not args.state or not args.host:
        parser.error("serve requires --vault --state --host")
    team = configured_team(args.vault, args.state, args.operator_credential_file)
    native_runtimes, drivers, organizers = {}, {}, {}
    if args.runtime_config is not None:
        from .cockpit_native_runtime import NativeRuntime
        from .cockpit_terminal_runner import JsonOperator
        config = args.runtime_config
        if config.is_symlink() or not private_paths.is_private(config.stat(), path=config) or config.stat().st_size > 65536:
            raise ValueError('runtime configuration must be private, bounded and not a symlink')
        specification = json.loads(config.read_text())
        if set(specification) not in ({'native', 'operators'}, {'native', 'operators', 'organizers'}):
            raise ValueError('exact native/operators and optional organizers configuration required')
        organizers = specification.get('organizers', {})
        native_runtimes = {tool: NativeRuntime(tool=tool, **fields) for tool, fields in specification['native'].items()}
        for operator, fields in specification['operators'].items():
            if not re.fullmatch(r'[a-z0-9-]{1,64}', operator) or operator == 'operator':
                raise ValueError('explicit named agent operator required')
            drivers[operator] = JsonOperator(**fields)
    policy=None
    if args.execution_policy:
        from .local_executor import ExecutionPolicy
        config=args.execution_policy
        if config.is_symlink() or not private_paths.is_private(config.stat(), path=config) or config.stat().st_size>4096:
            raise ValueError('private bounded executor policy required')
        policy=ExecutionPolicy(**json.loads(config.read_text()))
    service = LocalCockpit(args.root, args.vault, args.state, args.host, team=team,
                           native_runtimes=native_runtimes, driver=drivers, organizers=organizers,execution_policy=policy,
                           delegation_authority_database=args.delegation_authority_database)
    if args.remote_delegation_config is not None:
        service.configure_remote_delegation(args.remote_delegation_config,actor='operator',expected=service.native_lifecycle(action='inspect',actor='operator'),confirmed=True)
    try:
        for identifier in args.resume_delegated:
            service.resume_native_restart(identifier,actor='operator')
    except BaseException:
        service.close();raise
    dispatcher = service
    if args.fleet_config is not None:
        from .cockpit_fleet import FleetCockpit
        from .cockpit_transport import Endpoint
        config = args.fleet_config
        if config.is_symlink() or not private_paths.is_private(config.stat(), path=config) or config.stat().st_size > 65536:
            service.close()
            raise ValueError('fleet endpoint configuration must be private, bounded and not a symlink')
        mapping = json.loads(config.read_text())
        endpoints = {}
        for host, record in mapping.items():
            if set(record) != {'root', 'state'}:
                raise ValueError('exact fleet root/state endpoint fields required')
            endpoints[host] = Endpoint(Path(record['root']), host, record['state'])
        dispatcher = FleetCockpit(service, endpoints)
    listener = owner_endpoint.listen(endpoint)
    try:
        while True:
            client, _ = listener.accept()
            with client:
                handle_connection(client, service, dispatcher, listener=listener)
    finally:
        listener.close()
        service.close()


if __name__ == "__main__":
    main()
