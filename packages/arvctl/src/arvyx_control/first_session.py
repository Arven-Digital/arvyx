"""Explicit isolated first-run: native schema API -> owner New -> admitted UI.

This setup-only protocol never constructs an agent or resolves a provider. The
installed Hermes source and Python standard library remain trusted dependencies;
only the approved interpreter executable is sealed, not that dependency closure.
"""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import uuid

from .cockpit_native_runtime import NativeRuntime
from .native_artifact_policy import open_native_directory, read_native_bytes


class VerifiedPython:
    """Explicit digest admission, deliberately separate from Arvyx admission."""
    def __init__(self, path, digest):
        from .native_artifact_policy import fcntl, _SEALS
        self.fd = None
        if not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest):
            raise ValueError('explicit Python SHA-256 digest required')
        if _SEALS is None or not hasattr(os, 'memfd_create'):
            raise ValueError('Python executable sealing unavailable')
        data = read_native_bytes(path)
        if not data.startswith(b'\x7fELF'):
            raise ValueError('native ELF Python interpreter required, not a launcher script')
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('Python executable digest mismatch')
        fd = os.memfd_create('arvyx-approved-python', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError('short executable snapshot')
                view = view[written:]
            os.fchmod(fd, 0o500)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, _SEALS)
            if hashlib.sha256(os.pread(fd, len(data) + 1, 0)).hexdigest() != digest:
                raise ValueError('sealed Python digest mismatch')
            self.fd, self.digest = fd, digest
            self.source_path = Path(path)
            info = os.fstat(fd)
            self.identity = (info.st_dev, info.st_ino)
        except BaseException:
            os.close(fd)
            raise

    @property
    def path(self):
        if self.fd is None:
            raise ValueError('approved Python already closed')
        from .native_artifact_policy import fcntl, _SEALS
        info = os.fstat(self.fd)
        if (info.st_dev, info.st_ino) != self.identity or fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) & _SEALS != _SEALS:
            raise ValueError('approved Python descriptor changed')
        return '/proc/self/fd/' + str(self.fd)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# Executed by the admitted interpreter, not a shell. Hermes alone initializes
# and writes its schema/session provenance. Construct no provider/agent runtime.
NATIVE_SETUP = '''import os, sys
sys.path.insert(0, sys.argv[1])
from hermes_state_registry import acquire
mode = sys.argv[2]
db = acquire()
try:
    if mode == "new":
        from hermes_state_ids import new_session_id
        identifier = new_session_id()
        db.create_session(identifier, source="cli", cwd=os.getcwd())
        db.set_session_title(identifier, sys.argv[3])
finally:
    db.close()
if mode == "new":
    print("Arvyx isolated native session: SETUP REQUIRED; no provider started.", flush=True)
    print("This is a native setup surface, not an authenticated chat. Detach to retain state.", flush=True)
    from argparse import Namespace
    from hermes_cli.main import _first_run_setup_guard
    _first_run_setup_guard(Namespace())
'''


class SetupRuntime(NativeRuntime):
    """Native API handshake for an intentionally credential-free first session."""
    setup_only = True

    def __init__(self, *, admitted, source, home, guard, source_fd, home_fd):
        self.admitted = admitted
        self.source = Path(source)
        self.guard = guard
        self.source_fd, self.home_fd = source_fd, home_fd
        super().__init__(tool='hermes', executable=admitted.source_path, home=home,
                         store=Path(home)/'state.db', new_protocol='hermes-isolated-setup-v1')
        # Preserve executable identity; /proc/self/fd resolution is not exec authority.
        self.executable = Path(admitted.path)
        self.guard()
        if any((self.home/name).exists() for name in ('.env', 'auth.json', 'config.yaml')):
            raise ValueError('fresh credential-free setup profile required')
        with self.profile.connection() as db:
            if db.execute('SELECT 1 FROM sessions LIMIT 1').fetchone():
                raise ValueError('fresh empty native profile required; no existing session adoption')

    def plan_new(self, marker, workspace):
        if not re.fullmatch('arvyx-new-[a-f0-9]{32}', marker):
            raise ValueError('exact native New marker required')
        self.guard()
        self.profile.validate()
        with self.profile.connection() as db:
            if db.execute('SELECT 1 FROM sessions WHERE title COLLATE BINARY=? LIMIT 1', (marker,)).fetchone():
                raise ValueError('native New marker exists; never resume')
        return [self.admitted.path, '-I', '-c', NATIVE_SETUP, '/proc/self/fd/'+str(self.source_fd), 'new', marker], setup_environment('/proc/self/fd/'+str(self.home_fd), canonical_home=self.home)

    def reserve(self, conversation):
        # This runtime is admitted only inside an exclusively created fresh
        # root; it never accepts cold existing profiles. Global /proc scans of
        # unrelated, possibly unreadable processes cannot establish ownership.
        # Retain a durable profile-wide claim across all conversation markers.
        self.guard()
        self.profile.validate()
        return FreshSetupReservation(self)

    @property
    def executable_digest(self):
        return self.admitted.digest

    @property
    def execution_fds(self):
        return (self.admitted.fd, self.source_fd, self.home_fd)


class FreshSetupReservation:
    """Share the ordinary profile lock, plus a durable fresh-launch claim."""
    def __init__(self, runtime):
        from . import safe_open, private_paths
        from .locks import try_exclusive_lock
        from .hermes_profile import inode
        from .cockpit_native_runtime import NativeConversationReservation
        import stat
        path = runtime.home/'.amc-native-writer.lock'
        fd = safe_open.open_file(path, write=True, create=True, mode=0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or not private_paths.owner_private(info, fd=fd)
                    or info.st_nlink != 1):
                raise ValueError('unsafe fresh native profile reservation')
            if not try_exclusive_lock(fd):
                raise ValueError('native profile already reserved; attach instead')
            if inode(path) != (info.st_dev, info.st_ino):
                raise ValueError('fresh native profile reservation replaced')
            self.claim = NativeConversationReservation(runtime, 'isolated-setup-profile-v1')
            self.fd = fd
        except BaseException:
            os.close(fd)
            raise

    def release(self):
        if self.fd is not None:
            self.claim.release()
            os.close(self.fd)
            self.fd = None


def setup_environment(home, *, canonical_home=None):
    # HOME as well as HERMES_HOME is isolated: named-profile OAuth fallback must
    # never find the real user's auth store. Do not inherit PATH/provider keys.
    return dict(HOME=str(home), HERMES_HOME=str(home), PATH='/usr/bin:/bin',
                TERM='xterm-256color', LANG='C.UTF-8', HERMES_GUEST_ONBOARDING='0',
                ARVYX_NATIVE_PROFILE=str(canonical_home or home),
                HERMES_NO_UPDATE_CHECK='1', ENV='/dev/null')


class PinnedDirectory:
    """Protected ancestry plus an inode checked before each publication/dispatch."""
    def __init__(self, path):
        self.path = Path(os.path.abspath(path))
        self.fd = open_native_directory(self.path)
        info = os.fstat(self.fd)
        self.identity = (info.st_dev, info.st_ino)

    def check(self):
        fd = open_native_directory(self.path)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != self.identity:
                raise PermissionError('first-session directory replaced')
        finally:
            os.close(fd)

    def mkdir(self, name):
        self.check()
        os.mkdir(name, 0o700, dir_fd=self.fd)
        os.fsync(self.fd)
        child = PinnedDirectory(self.path/name)
        self.check()
        return child

    def publish_json(self, name, document):
        from . import safe_open
        self.check()
        staging = '.'+name+'-'+uuid.uuid4().hex
        fd = safe_open.open_file_at(self.fd, staging, write=True, create=True,
                                   exclusive=True, mode=0o600)
        try:
            data = memoryview((json.dumps(document, indent=2)+'\n').encode())
            while data:
                count = os.write(fd, data)
                if count <= 0:
                    raise OSError('short first-session receipt write')
                data = data[count:]
            os.fsync(fd)
        finally:
            os.close(fd)
        self.check()
        os.replace(staging, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)
        self.check()

    def close(self):
        os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def terminal_preflight():
    """Require the foreground controlling terminal, not merely two TTY fds."""
    if sys.platform != 'linux':
        raise ValueError('isolated first-session setup currently requires Linux executable sealing')
    import termios
    if not os.isatty(0) or not os.isatty(1):
        raise ValueError('interactive terminal required; use ssh -t')
    try:
        termios.tcgetattr(0)
        termios.tcgetattr(1)
        if os.tcgetpgrp(0) != os.getpgrp() or os.tcgetpgrp(1) != os.getpgrp():
            raise ValueError('foreground controlling terminal required')
        tty = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
        os.close(tty)
    except OSError:
        raise ValueError('foreground controlling terminal required; use ssh -t') from None


def first_session(root, *, python, source, python_sha256, binary, policy,
                  environment, confirmed=False):
    """A foreground, bounded owner lifetime; detach preserves files, not a daemon.

    Policy and real controlling-terminal checks precede filesystem creation.
    The destination MUST be absent. Failed/interrupted launches retain all state.
    No existing owner/profile/frontend is adopted or resumed.
    """
    if not os.isatty(0) or not os.isatty(1):
        raise ValueError('interactive terminal required; use ssh -t')
    if confirmed is not True:
        raise PermissionError('explicit first-session confirmation required')
    terminal_preflight()
    consent_expires = time.time()+300
    from .reviewed_actions import assert_consent_active
    if policy is None or environment != 'host':
        raise PermissionError('explicit unprivileged host execution policy required')
    from .native_artifact_policy import VerifiedNative
    from .cockpit import LocalCockpit, handle_connection
    from .machine_enrollment import enroll
    from . import owner_endpoint
    from .cockpit_arvyx import _open_frontend
    root = Path(os.path.abspath(root))
    source = Path(os.path.abspath(source))
    if any(len(os.fsencode(root/suffix)) >= 104 for suffix in
           ('owner/runtime/cockpit.sock', 'frontend/.config/herdr/sessions/amc/herdr.sock')):
        raise ValueError('first-session root too long for private native sockets')
    with ExitStack() as stack:
        parent = stack.enter_context(PinnedDirectory(root.parent))
        source_pin = stack.enter_context(PinnedDirectory(source))
        policy_plan = policy.plan(environment, root.parent)
        if root.exists() or root.is_symlink():
            raise ValueError('new absent first-session root required; never adopt existing state')
        if not all((source/name).is_file() for name in ('hermes_state_registry.py', 'hermes_cli/main.py')):
            raise ValueError('explicit installed Hermes native API source required')
        admitted = stack.enter_context(VerifiedPython(Path(python).resolve(strict=True), python_sha256))
        native = stack.enter_context(VerifiedNative(binary, required_capability='mouse-existing'))
        # Admission above is read-only; creation starts only after all preflights.
        assert_consent_active(consent_expires)
        parent.check(); source_pin.check()
        if policy.plan(environment, root.parent) != policy_plan:
            raise PermissionError('execution policy changed')
        destination = stack.enter_context(parent.mkdir(root.name))
        print('First-session state retained at: ' + str(root), flush=True)
        home = stack.enter_context(destination.mkdir('profile'))
        workspace = stack.enter_context(destination.mkdir('workspace'))
        def guard():
            parent.check(); destination.check(); home.check(); workspace.check(); source_pin.check()
            if policy.plan(environment, root.parent) != policy_plan:
                raise PermissionError('execution policy changed before native dispatch')
            assert_consent_active(consent_expires)
        # All publication/fsync work is complete. Revalidate at the dispatch
        # boundary, not just before creating the retained directories.
        guard()
        # Invoke the installed native registry API, not SQLite DDL or placeholder DB.
        try:
            subprocess.run([admitted.path, '-I', '-c', NATIVE_SETUP, '/proc/self/fd/'+str(source_pin.fd), 'init'],
                           pass_fds=(admitted.fd, source_pin.fd, home.fd, workspace.fd),
                           env=setup_environment('/proc/self/fd/'+str(home.fd), canonical_home=home.path),
                           cwd='/proc/self/fd/'+str(workspace.fd), check=True, timeout=30,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        except subprocess.SubprocessError:
            raise ValueError('native initialization failed; state retained at '+str(root)+
                             '; provision compatible Hermes API dependencies for the selected Python; no automatic retry') from None
        runtime = SetupRuntime(admitted=admitted, source=source, home=home.path, guard=guard,
                               source_fd=source_pin.fd, home_fd=home.fd)
        destination.check(); home.check(); workspace.check(); source_pin.check()
        owner_home = root/'owner'
        enroll(owner_home, 'local', confirmed=True)
        owner = LocalCockpit(owner_home/'runtime', owner_home/'vault', owner_home/'events.jsonl',
                             'local', native_runtimes={'hermes': runtime}, execution_policy=policy)
        listener = None
        thread = None
        stop = threading.Event()
        frontend = root/'frontend'
        receipt = None
        frontend_cleanup = dict(verified=True, unresolved=[])
        try:
            target = dict(machine_id='local', agent_id='hermes:'+str(home.path),
                          workspace_id=str(home.path), connection_id=uuid.uuid4().hex)
            current = owner.native_lifecycle(action='inspect', actor='operator')
            plan = owner.native_lifecycle(action='plan', actor='operator', expected=current,
                confirmed=True, target=target, workspace=str(workspace.path), environment=environment,
                harness='hermes', provider_start_acknowledged=False)
            destination.check(); home.check(); workspace.check(); source_pin.check()
            if policy.plan(environment, root.parent) != policy_plan:
                raise PermissionError('execution policy changed before owner launch')
            proof = owner.native_lifecycle(action='new', actor='operator', expected=current,
                confirmed=True, attempt=uuid.uuid4().hex, target=target, workspace=str(workspace.path),
                workspace_identity=list(workspace.identity), environment=environment, harness='hermes',
                reviewed_native=plan['native'], provider_start_acknowledged=False,
                consent_expires_at=consent_expires)
            owner.native_lifecycle(action='verify', actor='operator', expected=current,
                                   confirmed=True, target=target, result=proof)
            # A real owner socket is required by the existing admitted frontend/bridge.
            listener = owner_endpoint.listen(str(owner.root/'cockpit.sock'))
            listener.server.settimeout(.2)
            def serve():
                import socket
                while not stop.is_set():
                    try:
                        client, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with client:
                        handle_connection(client, owner, owner, listener=listener)
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            receipt = dict(version=1, state='setup_required', owner_lifetime='foreground',
                           owner_status='running', authenticated=False,
                           provider_started=False, target=target, proof=proof,
                           python_sha256=admitted.digest, binary_sha256=native.digest)
            destination.publish_json('first-session.json', receipt)
            destination.check(); home.check(); workspace.check(); source_pin.check()
            def bound(binding_file, admitted_frontend, frontend_env):
                guard()
                document = json.loads(binding_file.read_text())
                rows = [r for r in document['bindings'] if r['sid'] == proof['owner_session']]
                if len(rows) != 1 or document['authority_home'] != str(owner_home) or document['binary_sha256'] != native.digest:
                    raise ValueError('exact first-session binding required')
                observed = json.loads(admitted_frontend.invoke(subprocess.check_output,
                    ['--session', 'amc', 'api', 'snapshot'], env=frontend_env, timeout=5))['result']['snapshot']
                panes = [r for r in observed['panes'] if r['pane_id'] == rows[0]['pane']]
                if len(panes) != 1:
                    raise ValueError('exact native pane not observed')
                presentation = dict(pane=panes[0]['pane_id'], workspace=panes[0]['workspace_id'], tab=panes[0]['tab_id'])
                fingerprint = hashlib.sha256(binding_file.read_bytes()).hexdigest()
                owner.native_lifecycle(action='register_pane', actor='operator', expected=current,
                    confirmed=True, target=target, result=proof, frontend=fingerprint,
                    presentation=presentation, consent_expires_at=consent_expires)
                readback = owner.native_lifecycle(action='panes', actor='operator', expected=current,
                    confirmed=True, frontend=fingerprint)
                if readback != [dict(session=proof['owner_session'], **presentation)]:
                    raise ValueError('owner native pane binding readback mismatch')
                receipt.update(presentation=presentation, frontend_fingerprint=fingerprint,
                               binding_verified=True)
                destination.publish_json('first-session.json', receipt)
            frontend_cleanup.update(verified=False, unresolved=['frontend_cleanup_not_completed'])
            status = _open_frontend(owner_home, frontend, native, preserve_on_detach=False, on_bound=bound,
                cleanup_report=frontend_cleanup,
                native_attachment=dict(proof=proof, target=target, expires=consent_expires))
            binding = json.loads((frontend/'bindings.json').read_text())
            exact = [row for row in binding['bindings'] if row['sid'] == proof['owner_session']]
            if (binding['authority_home'] != str(owner_home) or binding['binary_sha256'] != native.digest
                    or len(exact) != 1):
                raise ValueError('first-session exact frontend binding mismatch')
            receipt.update(frontend=exact[0], attach_exit=status, detached=status == 0)
            destination.publish_json('first-session.json', receipt)
            print('Native setup surface detached; retained state: ' + str(root), flush=True)
            return status
        finally:
            # The scoped first-run owns these processes, never discovered PIDs.
            # Unlike existing attach-only mode, its owner lifetime ends on detach.
            active_error = sys.exc_info()[0] is not None
            unresolved = list(frontend_cleanup['unresolved'])
            stop.set()
            if thread is not None:
                thread.join(timeout=5)
                if thread.is_alive():
                    unresolved.append('owner_listener_thread')
            for name, resource in (('owner_listener', listener), ('owner', owner)):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        unresolved.append(name)
            if receipt is not None:
                destination.check()
                receipt['cleanup'] = dict(verified=not unresolved, unresolved=unresolved,
                                          frontend=frontend_cleanup)
                receipt['owner_status'] = 'cleanup_failed' if unresolved else 'closed'
                if any((home.path/name).exists() for name in ('.env', 'auth.json', 'config.yaml')):
                    # Human setup may have changed authentication after our
                    # credential-free launch observation. Do not infer success.
                    receipt.update(state='setup_outcome_unverified', authenticated=None, provider_started=None)
                destination.publish_json('first-session.json', receipt)
            if unresolved and not active_error:
                raise ValueError('first-session cleanup unresolved: '+', '.join(unresolved)+
                                 '; state retained at '+str(root))
