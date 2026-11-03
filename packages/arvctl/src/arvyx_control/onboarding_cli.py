"""Owner-operated onboarding and explicit local terminal routing.

Onboarding alone never launches a runtime. Terminal history is read-only; native
startup requires explicit launch approval, workspace and profile safeguards.
The private state directory is the local trust boundary; never expose this API to
untrusted request payloads. Organizer assignment is a local provisioning action.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import sqlite3
import sys
import unicodedata
import uuid

from . import private_paths
from .agent_creation import AgentCreation, CreationRequest
from .harness_discovery import discover_harnesses
from .organizer_authority import OrganizerAuthority


class Onboarding:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.parent.mkdir(parents=True, exist_ok=True)
        private_paths.ensure_private_directory(self.directory, mode=0o700)
        info = self.directory.lstat()
        if self.directory.is_symlink() or not private_paths.owner_private(info, path=self.directory):
            raise ValueError('state directory must be private, owned by the current user, and not a symlink')
        self.db = sqlite3.connect(self.directory / 'onboarding.sqlite3')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS connections (
                id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS setup (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        ''')
        profiles = self.directory / 'profiles'
        private_paths.ensure_private_directory(profiles, mode=0o700)
        self.creation = AgentCreation(self.db, profiles, workspace_id='local',
                                      local_host='local', isolated_harnesses=frozenset({'hermes'}))

    def close(self):
        self.db.close()

    def status(self) -> dict:
        row = self.db.execute("SELECT value FROM setup WHERE key='organizer'").fetchone()
        return dict(connections=[dict(json.loads(r[1]), connection_row_id=r[0]) for r in self.db.execute(
            'SELECT id, record FROM connections ORDER BY name')],
            organizer=self._organizer_reference(row[0]) if row else None,
            agents=[asdict(a) for a in self.creation.list_agents()])

    def _name(self, name):
        if not isinstance(name, str) or not name.strip() or name != name.strip() or len(name) > 128 or any(unicodedata.category(c).startswith('C') for c in name):
            raise ValueError('a nonempty canonical name is required')
        names = [r['name'] for r in self.status()['connections']] + [a['name'] for a in self.status()['agents']]
        key = lambda n: unicodedata.normalize('NFKC', n).casefold()
        if key(name) in {key(n) for n in names}:
            raise ValueError('name already exists')

    def connect(self, candidate, name):
        self._name(name)
        record = dict(connection_id='connection:' + uuid.uuid4().hex,
                      name=name, candidate=candidate, machine='local',
                      status='consented_unverified', native_attach_available=False)
        with self.db:
            self.db.execute('INSERT INTO connections VALUES(?,?,?)',
                            (candidate['id'], name, json.dumps(record)))
        return record

    @staticmethod
    def _organizer_reference(value):
        try:
            ref = json.loads(value)
        except (ValueError, TypeError):
            ref = None
        if (not isinstance(ref, dict) or ref.get('version') != 2
                or set(ref) != {'version', 'connection_id'}
                or not isinstance(ref['connection_id'], str)):
            return {'migration_required': True, 'legacy_value': value}
        return ref

    def _connection(self, connection_id):
        if (not isinstance(connection_id, str) or not connection_id.startswith('connection:')
                or len(connection_id) != len('connection:') + 32
                or any(c not in '0123456789abcdef' for c in connection_id[len('connection:'):])):
            raise ValueError('canonical immutable connected identity required')
        matches = [c for c in self.status()['connections']
                   if c.get('connection_id') == connection_id]
        if len(matches) != 1:
            raise ValueError('select an exact immutable connected identity')
        return matches[0]

    def organizer(self, connection_id):
        # This is owner provisioning, never authentication by a display name.
        self._connection(connection_id)
        if (self.status()['organizer'] or {}).get('migration_required'):
            raise ValueError('explicit legacy organizer migration required')
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO setup VALUES('organizer',?)",
                            (json.dumps(dict(version=2, connection_id=connection_id)),))

    def migrate_legacy_organizer(self, *, expected_legacy, connection_row_id, confirmed=False):
        """Explicit owner reconciliation; never match a legacy name to a target.

        The caller supplies the exact old value and exact SQL connection row ID.
        A UUID is assigned only to that selected row; no runtime is enrolled.
        """
        if confirmed is not True:
            raise ValueError('explicit migration confirmation required')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.db.execute("SELECT value FROM setup WHERE key='organizer'").fetchone()
            if (not row or row[0] != expected_legacy or
                    not self._organizer_reference(row[0]).get('migration_required')):
                raise ValueError('legacy organizer changed or is not legacy')
            target = self.db.execute('SELECT record FROM connections WHERE id=?',
                                     (connection_row_id,)).fetchone()
            if not target:
                raise ValueError('exact connected row required')
            record = json.loads(target[0])
            connection_id = record.get('connection_id')
            if connection_id is None:
                connection_id = 'connection:' + uuid.uuid4().hex
                record['connection_id'] = connection_id
                self.db.execute('UPDATE connections SET record=? WHERE id=?',
                                (json.dumps(record), connection_row_id))
            self._connection(connection_id)
            self.db.execute("UPDATE setup SET value=? WHERE key='organizer'",
                            (json.dumps(dict(version=2, connection_id=connection_id)),))
        return connection_id

    def authority(self):
        """Restore only exact owner-provisioned connected identities, not names."""
        authority = OrganizerAuthority()
        organizer = self.status()['organizer']
        actor = None
        if organizer is not None:
            if organizer.get('migration_required'):
                raise ValueError('legacy organizer is untrusted; explicit migration required')
            connection_id = organizer['connection_id']
            self._connection(connection_id)
            actor = authority.provision_identity(connection_id, kind='internal', organizer=True)
        authority.enroll_machine('local')
        return authority, actor

    def create(self, name):
        self._name(name)
        authority, actor = self.authority()
        if actor is not None:
            decision = authority.authorize(actor, operation='create_agent', machine='local')
            if not decision.allowed:
                raise PermissionError(decision.reason)
        # Skipping organizer retains the interactive local owner's provisioning
        # ability; it does not grant an agent an organizer identity.
        return self.creation.create(CreationRequest(name=name, harness='hermes', owner_host='local'))


def choose(prompt, options):
    while True:
        answer = input(prompt).strip().lower()
        if answer in options:
            return answer
        print('Choose: ' + ', '.join(options))


def menu(store, home):
    print('AMC local onboarding — no provider calls or runtime changes')
    scan = discover_harnesses(home)
    if scan['truncated']:
        print('Discovery truncated; results are not exhaustive.')
    if scan.get('incomplete_reasons'):
        print('Some known locations were unreadable; results are incomplete.')
    if not scan['candidates']:
        print('No known profiles found. Custom locations and remote machines require an adapter; unavailable here.')
    for candidate in scan['candidates']:
        print(f"{candidate['label']} | local | {candidate['local_id']} | {candidate['path']}")
        if choose('Connect / Skip: ', ('connect', 'skip')) == 'connect':
            store.connect(candidate, input('Agent display name: ').strip())
            print('Consent saved. Native session attachment unavailable; no files imported.')
    print('Organizer is the supreme AMC role; no OS privilege or remote execution is granted here.')
    if choose('Set organizer? yes / skip: ', ('yes', 'skip')) == 'yes':
        print('Connected identities: ' + ', '.join(
            c.get('connection_id', '[legacy row requires migration]') + ' (' + c['name'] + ')'
            for c in store.status()['connections']))
        store.organizer(input('Exact organizer connection_id: ').strip())
    action = choose('Named agent: create / attach / skip: ', ('create', 'attach', 'skip'))
    if action == 'create':
        print('Clean isolated Hermes profile only. No identity/auth/history copied; no runtime launch.')
        agent = store.create(input('New unique agent name: ').strip())
        print(f'Created {agent.name}: {agent.agent_id} (metadata_only; native setup/launch unavailable)')
    elif action == 'attach':
        print('Existing named connections: ' + ', '.join(c['name'] for c in store.status()['connections']))
        name = input('Exact connected name: ').strip()
        if name not in {c['name'] for c in store.status()['connections']}:
            raise ValueError('unknown connected name')
        print('Connection retained. Native session attachment unavailable; no substitute session opened.')
    print('Saved. Run amc status to inspect persisted state.')


def main(argv=None):
    parser = argparse.ArgumentParser(prog='amc', description=__doc__, epilog='Terminal mode is attach-only: requires an existing verified live native owner/frontend and accepted mouse-existing binary. No New, cold resume or provider startup. Native launch/profile/workspace flags apply only to the separately authorized history command, never terminal.')
    parser.add_argument('--state-dir', type=Path, default=Path.home() / '.local/share/amc')
    parser.add_argument('--home', type=Path, default=Path.home(), help='explicit discovery root (metadata only)')
    parser.add_argument('-confirm', metavar='CODE')
    parser.add_argument('--legacy-organizer', help='exact persisted legacy value for explicit migration')
    parser.add_argument('--connection-row-id', help='exact persisted connection row ID; never a display-name match')
    parser.add_argument('--confirm-identity-migration', action='store_true')
    parser.add_argument('--url', help='MAIN loopback pairing endpoint, optionally through an approved SSH tunnel')
    parser.add_argument('--name', help='remote machine display name')
    parser.add_argument('--native-owner', type=Path, help='explicit existing local native owner; never launches a provider')
    parser.add_argument('--frontend-home', type=Path, help='existing verified Arvyx frontend home')
    parser.add_argument('--arvyx-binary', type=Path, help='existing verified absolute Arvyx executable')
    parser.add_argument('--hermes-home', type=Path, help='explicit consented Hermes profile home; read-only native history, no automatic discovery')
    parser.add_argument('--authorize-native-launch', action='store_true', help='authorize native startup only in the specified isolated Hermes home; still requires interactive confirmation')
    parser.add_argument('--workspace', type=Path, help='existing workspace for explicit New/cold resume')
    parser.add_argument('--new-hermes-profile', metavar='NAME', help='blank non-default named profile for New; still requires native launch authorization and NEW NAME confirmation')
    parser.add_argument('--execution-policy',type=Path,help='Private operator provisioned ExecutionPolicy JSON; required for history process launch')
    parser.add_argument('--execution-mode',choices=('sandbox','host','root'),help='Explicit effective launch mode; sandbox native profile currently refuses')
    parser.add_argument('--root-risk-acknowledged',action='store_true',help='Explicit administrator risk acknowledgement for root history launch')
    parser.add_argument('--authorize-default-resume', action='store_true', help='separately authorize default-profile cold resume; still requires native launch authorization, idle profile and exact RESUME confirmation')
    parser.add_argument('command', nargs='?', choices=('explore','onboard', 'status', 'terminal', 'setup', 'history', 'migrate-organizer'), default='onboard')
    args = parser.parse_args(argv)
    if args.confirm is not None:
        if not args.url or not args.name:
            parser.error('-confirm requires --url and --name on REMOTE')
        from .machine_pairing_cli import main as pairing_main
        return pairing_main(['confirm', args.confirm, '--state-dir', str(args.state_dir),
                             '--url', args.url, '--name', args.name])
    store = None
    try:
        if args.command=='explore':
            print('Arvyx | Explore before enrollment. Organizer setup can be skipped. No owner or provider is started.')
            print('When ready, explicitly enroll a new machine home with python3 -m arvyx_control.machine_enrollment. Existing pilot state is never adopted automatically.')
            return 0
        if args.command == 'setup':
            if not args.url:
                raise ValueError('setup requires the exact --url of the authenticated local listener')
            from .shared_onboarding_cli import main as shared_main
            return shared_main(args.url)
        if args.command == 'history':
            if not args.hermes_home:
                raise ValueError('history requires an explicit --hermes-home')
            from .terminal_sessions import history_menu
            from .local_executor import ExecutionPolicy
            from .remote_effect_fence import private_config
            policy=ExecutionPolicy(**private_config(args.execution_policy)) if args.execution_policy else None
            return history_menu(args.hermes_home, owner=args.native_owner,
                                frontend=args.frontend_home, binary=args.arvyx_binary,
                                authorize_launch=args.authorize_native_launch, workspace=args.workspace,
                                new_profile=args.new_hermes_profile,
                                authorize_default_resume=args.authorize_default_resume,execution_policy=policy,environment=args.execution_mode,root_acknowledged=args.root_risk_acknowledged)
        if args.command == 'terminal':
            if not all((args.native_owner, args.frontend_home, args.arvyx_binary)):
                raise ValueError('terminal requires --native-owner, --frontend-home and --arvyx-binary for the existing native mouse frontend; history-only numbered menus are not supported')
            from .terminal_sessions import terminal_menu
            onboarding=None
            if args.url:
                import getpass
                onboarding=dict(origin=args.url,capability=getpass.getpass('Existing setup capability (memory only): '))
            return terminal_menu(args.native_owner, args.frontend_home, args.arvyx_binary,
                                 hermes_home=args.hermes_home, authorize_launch=args.authorize_native_launch,
                                 workspace=args.workspace, new_profile=args.new_hermes_profile,
                                 authorize_default_resume=args.authorize_default_resume, onboarding=onboarding)
        store = Onboarding(args.state_dir)
        if args.command == 'migrate-organizer':
            if args.legacy_organizer is None or not args.connection_row_id:
                raise ValueError('migration requires --legacy-organizer and --connection-row-id')
            print(store.migrate_legacy_organizer(expected_legacy=args.legacy_organizer,
                connection_row_id=args.connection_row_id, confirmed=args.confirm_identity_migration))
        elif args.command == 'status':
            print(json.dumps(store.status(), indent=2))
        else:
            menu(store, args.home)
        return 0
    except (ValueError, OSError, sqlite3.Error, EOFError, KeyboardInterrupt) as exc:
        print(f'Onboarding stopped: {exc}. Prior explicit choices remain saved.', file=sys.stderr)
        return 2
    finally:
        if store is not None:
            store.close()


if __name__ == '__main__':
    raise SystemExit(main())
