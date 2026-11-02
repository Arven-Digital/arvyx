"""Exact attachment to an explicitly supplied, already running native Arvyx owner.

No provider launch, cold resume, session creation, input injection or takeover.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from .agent_sessions import AgentSessions, RoutingError, SessionMetadata, SessionRoute, SessionTarget
from .cockpit_client import request
from .cockpit_arvyx import frontend_environment, _focus_pane

from .native_artifact_policy import NATIVE_MOUSE_BINARY_SHA256, verify_native_artifact, VerifiedNative


def verify_native_binary(binary, binding, *, required_capability=None):
    return verify_native_artifact(binary, binding, required_capability=required_capability)


class ExistingArvyxAdapter:
    connected = True

    def __init__(self, owner, frontend, binary, *, request_fn=request):
        self.owner, self.frontend, self.binary = Path(owner).resolve(), Path(frontend).resolve(), Path(binary).absolute()
        self.request = request_fn
        self.binding_bytes = (self.frontend / 'bindings.json').read_bytes()
        self.binding = json.loads(self.binding_bytes)
        if Path(self.binding['authority_home']).resolve() != self.owner:
            raise RoutingError('frontend belongs to a different exact owner')
        incarnation = hashlib.sha256(self.binding_bytes).hexdigest()
        self.target = SessionTarget('local:' + str(self.owner), 'hermes', str(self.owner), incarnation)

    def _routes(self, target):
        if target != self.target or (self.frontend/'bindings.json').read_bytes() != self.binding_bytes:
            raise RoutingError('stale exact frontend binding')
        rows = {r['id']: r for r in self.request(self.owner, 'list')}
        result = {}
        for binding in self.binding['bindings']:
            sid = binding['sid']
            row = rows.get(sid)
            if not row or row['status'] != 'running':
                continue
            native = self.request(self.owner, 'native', sid=sid, actor='operator')
            if not native or native.get('tool') != 'hermes':
                continue
            conversation = native['conversation']
            if conversation in result:
                raise RoutingError('ambiguous native conversation binding')
            result[conversation] = dict(binding, title=row['name'])
        return result

    def metadata(self, target):
        return tuple(SessionMetadata(SessionRoute(target, sid), row['title'], 0.)
                     for sid, row in self._routes(target).items())

    def perform(self, target, action, session_id=None, *, publication_guard=None):
        if action != 'select':
            raise RoutingError('New unavailable: provider/native launch not authorized in attach-only mode')
        row = self._routes(target).get(session_id)
        if row is None:
            raise RoutingError('exact native session unavailable; no fallback')
        if publication_guard is not None:publication_guard()
        return row

    def open_ui(self, *, onboarding=None):
        """Enter the source-built native client; no textual routing gate."""
        if onboarding is not None:
            from urllib.parse import urlsplit
            if type(onboarding) is not dict or set(onboarding) != {'origin','capability'}:
                raise RoutingError('explicit shared onboarding configuration required')
            parts=urlsplit(onboarding['origin'])
            credential=onboarding['capability']
            if (parts.scheme!='http' or parts.hostname!='127.0.0.1' or not parts.port or parts.username or parts.password or parts.path not in ('','/') or parts.query or parts.fragment or not isinstance(credential,str) or not 1<=len(credential)<=256 or any(ord(c)<33 or ord(c)>126 for c in credential)):
                raise RoutingError('literal loopback origin and private capability required')
            onboarding=dict(origin=f'http://127.0.0.1:{parts.port}',capability=credential)
        routes = self._routes(self.target)
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise RoutingError('interactive terminal required; use ssh -t')
        capability = None if onboarding is None else 'onboarding-v1'
        with VerifiedNative(self.binary, self.binding, required_capability=capability) as native:
            env = frontend_environment(self.frontend)
            if onboarding is not None:
                env['AMC_ONBOARDING_RPC']=json.dumps(onboarding)
            # Presentation metadata only. PaneFocus uses the server API and never
            # injects input, resumes a provider, creates a pane or changes ownership.
            env['AMC_NATIVE_SESSIONS'] = json.dumps([
                {'pane': row['pane'], 'title': row['title'], 'conversation': sid}
                for sid, row in routes.items()])
            return native.invoke(subprocess.call, ['session', 'attach', 'amc'], env=env)

    def attach(self, route):
        row = self.perform(route.target, 'select', route.session_id)
        with VerifiedNative(self.binary, self.binding) as native:
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                raise RoutingError('interactive terminal required; use ssh -t')
            env = frontend_environment(self.frontend)
            def command(*args):
                return json.loads(native.invoke(subprocess.check_output, ['--session','amc',*args],env=env,timeout=5))
            panes = command('api','snapshot')['result']['snapshot']['panes']
            pane = next((p for p in panes if p['pane_id'] == row['pane']), None)
            if pane is None:
                raise RoutingError('exact native pane unavailable; no recreation')
            command('workspace','focus',pane['workspace_id'])
            command('tab','focus',pane['tab_id'])
            _focus_pane(self.frontend, row['pane'])
            observed = command('api','snapshot')['result']['snapshot']['panes']
            exact = [p for p in observed if p.get('pane_id') == row['pane']]
            if (len(exact) != 1 or exact[0].get('focused') is not True
                    or exact[0].get('workspace_id') != pane['workspace_id']
                    or exact[0].get('tab_id') != pane['tab_id']
                    or [p.get('pane_id') for p in observed if p.get('focused') is True] != [row['pane']]):
                raise RoutingError('exact native pane focus not observed; no retry')
            if self.perform(route.target, 'select', route.session_id) != row:
                raise RoutingError('exact native route changed during focus; no retry')
            return native.invoke(subprocess.call, ['session','attach','amc'],env=env)


def terminal_menu(owner, frontend, binary, *, hermes_home=None, authorize_launch=False, workspace=None,
                  new_profile=None, authorize_default_resume=False, onboarding=None):
    if not all((owner, frontend, binary)):
        raise RoutingError('terminal requires an existing exact owner, frontend and source-built native mouse binary; cold history is not a terminal entry screen')
    if authorize_launch or new_profile or authorize_default_resume:
        raise RoutingError('native terminal is attach-only; New and cold resume are unavailable')
    return ExistingArvyxAdapter(owner, frontend, binary).open_ui(onboarding=onboarding)


def history_menu(home, *, owner=None, frontend=None, binary=None, authorize_launch=False, workspace=None,
                 new_profile=None, authorize_default_resume=False, execution_policy=None, environment=None, root_acknowledged=False):
    from .hermes_history import HermesHistory
    history = HermesHistory(home)
    launch_policy=dict(execution_policy=execution_policy,environment=environment,root_acknowledged=root_acknowledged)
    service = AgentSessions({history.target: history})
    print('AMC | Hermes native HISTORY | explicit profile: ' + str(history.home))
    print('All = every stored segment, including archived/hidden/child rows. Search = title/ID metadata only.')
    print('Listing never starts a runtime. New named profiles require NEW <name>; cold resume requires RESUME <exact ID>.')
    print('Default-profile resume also requires separate authorization and an idle profile; live conversations are protected.')
    while True:
        action = input('History [last5 / all / search / new / attached / quit]: ').strip().lower()
        if action == 'quit':
            return 0
        try:
            if action == 'attached':
                if not all((owner,frontend,binary)):
                    raise RoutingError('exact existing owner/frontend/binary required for attachment')
                return terminal_menu(owner,frontend,binary)
            if action == 'new':
                if not workspace:
                    raise RoutingError('New requires explicit --workspace')
                if new_profile:
                    if not authorize_launch:
                        raise RoutingError('explicit native launch authorization required')
                    from .hermes_profile_launch import NewHermesProfile
                    fresh = NewHermesProfile(new_profile)
                    print('Create blank named profile; reuse root provider login by native reference, never copy identity/auth. No initial message.')
                    if input('Type NEW '+new_profile+' to launch: ') != 'NEW '+new_profile:
                        continue
                    # Do not publish a new identity before execution admission.
                    if execution_policy is None or environment is None:
                        raise RoutingError('explicit execution policy and mode required for native history launch')
                    execution_policy.plan(environment,workspace,root_acknowledged=root_acknowledged)
                    if environment=='sandbox':
                        raise PermissionError('native provider sandbox profile admission unavailable; no host fallback')
                    isolated = fresh.prepare(workspace, confirmed=True)
                    return isolated.launch(workspace, authorized=True,**launch_policy)
                history.launch_plan(workspace,authorized=authorize_launch)
                print('Launch clean conversation in this profile; no initial message. Existing conversations remain untouched.')
                if input('Type NEW to launch: ') != 'NEW':
                    continue
                return history.launch(workspace,authorized=authorize_launch,**launch_policy)
            query = input('Search title or ID: ') if action == 'search' else ''
            if action in ('last5','recent5'):
                items = service.recent(history.target)
                page = None
            elif action in ('all','search'):
                page = service.all(history.target,query=query,limit=20)
                items = page.items
            else:
                continue
            while True:
                if page:
                    print(f'{page.total} matching stored native session segments.')
                for i,item in enumerate(items,1):
                    label = ''.join(c if c.isprintable() else '?' for c in item.title)
                    sid = ''.join(c if c.isprintable() else '?' for c in item.route.session_id)
                    print(f'{i}. {label} | {sid}')
                answer = input('Cold resume number / next / back: ').strip()
                if answer == 'next' and page and page.next_cursor:
                    page = service.all(history.target,query=query,limit=20,cursor=page.next_cursor)
                    items = page.items
                    continue
                if answer.isdecimal() and 1 <= int(answer) <= len(items):
                    route = items[int(answer)-1].route
                    row = service.select(route)
                    selected_workspace = workspace or row.get('cwd')
                    if not selected_workspace:
                        raise RoutingError('Cold resume requires explicit --workspace')
                    history.launch_plan(selected_workspace,authorized=authorize_launch,session_id=route.session_id,
                                        authorize_default_resume=authorize_default_resume)
                    print('Cold resume starts installed Hermes and may update session lifecycle; not a running-owner attachment.')
                    if input('Type RESUME '+route.session_id+' to confirm: ') == 'RESUME '+route.session_id:
                        return history.launch(selected_workspace,authorized=authorize_launch,session_id=route.session_id,
                                        authorize_default_resume=authorize_default_resume,**launch_policy)
                break
        except (RoutingError,OSError) as exc:
            print('Unavailable: '+str(exc))
