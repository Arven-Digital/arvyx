"""Explicit profile-scoped Hermes metadata, without importing its writer runtime.

All means every stored session segment, including archived/hidden/child rows;
no transcripts, prompts, credentials, or profile discovery are read. Resume uses
only the installed CLI's full-ID interface; compression parents are refused
because that interface intentionally redirects them to their continuation.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import time
from .agent_sessions import RoutingError, SessionMetadata, SessionRoute, SessionTarget


class HermesHistory:
    connected = True
    query_budget_steps = 10_000_000

    def __init__(self, home, *, executable=None, default_home=None, review_snapshot=None):
        from .hermes_profile import HermesProfile
        self.profile = HermesProfile(home)
        self.home = self.profile.home
        self.default_home = Path(default_home or Path.home()/'.hermes').resolve()
        self.store = self.home/'state.db'
        self.identity = self.profile.identity
        self.review_snapshot = review_snapshot
        self.validate_review()
        self.executable = executable or shutil.which('hermes')
        incarnation = hashlib.sha256(repr(self.identity).encode()).hexdigest()
        self.target = SessionTarget('local', 'hermes:'+str(self.home), str(self.home), incarnation)

    def validate_review(self):
        self.profile.validate()
        expected = self.review_snapshot
        if expected is not None:
            if (not isinstance(expected, dict) or expected.get('profile') != str(self.home)
                    or expected.get('identity') != list(self.identity or ())
                    or expected.get('home_identity') != list(self.profile.home_identity)):
                raise RoutingError('reviewed Hermes profile or database identity changed')

    def _identity(self):
        stat = self.store.stat()
        return stat.st_dev, stat.st_ino

    @contextmanager
    def connection(self):
        self.validate_review()
        with self.profile.connection() as db:
            yield db
            self.validate_review()

    def metadata(self, target):
        if target != self.target:
            raise RoutingError('wrong exact profile target')
        # Even an empty collection is an assertion about the reviewed profile.
        # Missing state.db must not bypass the pinned directory/review identity.
        self.validate_review()
        if self.identity is None and not self.store.exists():
            return ()
        with self.connection() as db:
            columns = {r[1] for r in db.execute('PRAGMA table_info(sessions)')}
            if not {'id','title','started_at'} <= columns:
                raise RoutingError('unsupported installed Hermes sessions schema')
            ended = 's.ended_at' if 'ended_at' in columns else 'NULL'
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            activity = 'NULL'
            join = ''
            if 'messages' in tables:
                mcols = {r[1] for r in db.execute('PRAGMA table_info(messages)')}
                if {'timestamp','session_id'} <= mcols:
                    activity = 'a.latest'
                    join = " LEFT JOIN (SELECT session_id, MAX(timestamp) AS latest FROM messages WHERE typeof(timestamp) IN ('integer','real') GROUP BY session_id COLLATE BINARY) a ON a.session_id COLLATE BINARY=s.id COLLATE BINARY"
            def numeric(expr):
                return f"CASE WHEN typeof({expr}) IN ('integer','real') THEN {expr} ELSE 0 END"
            deadline = time.monotonic() + 2
            steps = 0
            def progress():
                nonlocal steps
                steps += 1000
                return int(steps > self.query_budget_steps or time.monotonic() >= deadline)
            db.set_progress_handler(progress, 1000)
            try:
                from .agent_sessions import MAX_METADATA_FIELD_BYTES, MAX_METADATA_BYTES, metadata_bytes
                # SQLite evaluates the byte lengths before returning any field.
                # Oversized values never cross the Python materialization boundary.
                cap = MAX_METADATA_FIELD_BYTES
                cursor = db.execute(f"SELECT CASE WHEN length(CAST(s.id AS BLOB))<={cap} THEN s.id END,CASE WHEN length(CAST(COALESCE(s.title,'') AS BLOB))<={cap} THEN COALESCE(s.title,'') END,MAX({numeric('s.started_at')},{numeric(ended)},COALESCE({activity},0)) FROM sessions s{join}")
                result = []
                size = 0
                for row in cursor:
                    if row[0] is None or row[1] is None:
                        raise RoutingError('metadata field byte budget exceeded; enumeration incomplete')
                    item = SessionMetadata(SessionRoute(target,row[0]),row[1],float(row[2]))
                    size += metadata_bytes(item)
                    if size > MAX_METADATA_BYTES or time.monotonic() >= deadline:
                        raise RoutingError('metadata collection byte/time budget exceeded; enumeration incomplete')
                    result.append(item)
            except sqlite3.OperationalError as exc:
                if 'interrupted' not in str(exc).lower():
                    raise
                raise RoutingError('metadata query work/time budget exceeded; enumeration incomplete') from None
            finally:
                self.last_query_steps = steps
                db.set_progress_handler(None, 0)
        return tuple(result)

    def perform(self, target, action, session_id=None, *, publication_guard=None):
        if target != self.target or action != 'select':
            raise RoutingError('launch requires separate explicit authorization')
        result = self.exact(session_id)
        if publication_guard is not None:publication_guard()
        return result

    def exact(self, session_id):
        from dataclasses import asdict
        import json
        from .agent_sessions import MAX_METADATA_FIELD_BYTES
        cap = MAX_METADATA_FIELD_BYTES
        if (not isinstance(session_id, str) or not session_id or
                len(session_id) > cap or len(session_id.encode('utf-8')) > cap):
            raise RoutingError('selection identifier byte/type budget exceeded')
        # Include the complete public selection envelope, not just the DB row.
        # Six bytes per UTF-8 byte bounds ensure_ascii JSON escaping (including
        # embedded NULs and astral Unicode). Conservative rejection is intentional.
        response_cap = 64 * 1024
        route = SessionRoute(self.target, session_id)
        overhead = len(json.dumps({'route': asdict(route), 'result':
                       dict.fromkeys(('id', 'cwd', 'end_reason')), 'queued': False}).encode())
        with self.connection() as db:
            db.row_factory = sqlite3.Row
            # Deliberately exclude all prompt/config/transcript fields.
            columns = {r[1] for r in db.execute('PRAGMA table_info(sessions)')}
            if 'id' not in columns:
                raise RoutingError('unsupported installed Hermes sessions schema')
            fields = ['id'] + [c for c in ('cwd','end_reason') if c in columns]
            checks = ["typeof(id)='text'"]
            for field in fields:
                checks.append(f"(typeof({field})='null' OR (typeof({field})='text' AND length(CAST({field} AS BLOB))<={cap}))")
            total = '+'.join(f'6*COALESCE(length(CAST({field} AS BLOB)),0)' for field in fields)
            valid = ' AND '.join(checks) + f' AND ({total})+{overhead}<={response_cap}'
            # A separate validity flag distinguishes rejected rows from legal NULLs.
            # Every projection is guarded by the entire field + aggregate predicate,
            # so even individually small strings in an over-budget row stay in SQL.
            projection = ','.join(f'CASE WHEN {valid} THEN {field} END AS {field}' for field in fields)
            deadline = time.monotonic() + 2
            steps = 0
            def progress():
                nonlocal steps
                steps += 1000
                return int(steps > self.query_budget_steps or time.monotonic() >= deadline)
            db.set_progress_handler(progress, 1000)
            try:
                # Do not inherit a schema's NOCASE/RTRIM identity semantics or
                # assume that a discovered sessions table enforces uniqueness.
                rows = db.execute(f'SELECT ({valid}) AS selection_valid,{projection} FROM sessions WHERE id COLLATE BINARY=? LIMIT 2', (session_id,)).fetchall()
                if time.monotonic() >= deadline:
                    raise RoutingError('selection query time budget exceeded')
            except sqlite3.OperationalError as exc:
                if 'interrupted' not in str(exc).lower():
                    raise
                raise RoutingError('selection query work/time budget exceeded') from None
            finally:
                self.last_query_steps = steps
                db.set_progress_handler(None, 0)
        if not rows:
            raise RoutingError('exact existing session ID unavailable; no fallback')
        if len(rows) != 1:
            raise RoutingError('ambiguous exact session ID; no fallback')
        row = rows[0]
        if row['selection_valid'] != 1:
            raise RoutingError('selection metadata field/type or response byte budget exceeded')
        return {field: row[field] for field in fields}

    def launch_plan(self, workspace, *, authorized=False, session_id=None, authorize_default_resume=False):
        if not authorized:
            raise RoutingError('explicit native launch authorization required')
        self.validate_review()
        if self.home == self.default_home or self.default_home.is_relative_to(self.home):
            if not (self.home == self.default_home and session_id is not None and authorize_default_resume):
                raise RoutingError('launch requires an explicitly authorized isolated Hermes home, not default identity')
        info = self.home.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise RoutingError('isolated home must be owned by current user and not writable by others')
        for name in ('state.db','config.yaml','.env','SOUL.md','USER.md','AGENTS.md','auth.json','memories','memory','skills'):
            if (self.home/name).is_symlink():
                raise RoutingError('isolated identity may not symlink another profile')
        workspace = Path(workspace).resolve(strict=True)
        if not workspace.is_dir():
            raise RoutingError('existing workspace directory required')
        if not self.executable:
            raise RoutingError('installed Hermes executable unavailable')
        argv = [str(self.executable),'--cli','--in',str(workspace)]
        if session_id is not None:
            self.exact(session_id)  # Byte-exact, unique ID before native resolver semantics.
            self.profile.resolve(session_id, workspace)
            argv += ['--resume',session_id]
        # Never inherit this agent's turn/session/identity/provider overrides.
        env = {k:os.environ[k] for k in ('PATH','HOME','TERM','LANG','LC_ALL','COLORTERM','USER','SHELL','TMPDIR') if k in os.environ}
        env = self.profile.environment(env)
        return argv,env

    def launch(self, workspace, *, authorized=False, session_id=None, authorize_default_resume=False,
               execution_policy=None,environment=None,root_acknowledged=False):
        if not os.isatty(0) or not os.isatty(1):
            raise RoutingError('interactive terminal required; use ssh -t')
        from .external_workspace import _open_root
        with _open_root(Path(workspace)) as workspace_fd:
            workspace_identity=(os.fstat(workspace_fd).st_dev,os.fstat(workspace_fd).st_ino)
            argv,env = self.launch_plan(workspace,authorized=authorized,session_id=session_id,
                                        authorize_default_resume=authorize_default_resume)
            if execution_policy is None or environment is None:
                raise RoutingError('explicit execution policy and mode required for native history launch')
            plan=execution_policy.plan(environment,workspace,root_acknowledged=root_acknowledged)
            if environment=='sandbox':raise PermissionError('native provider sandbox profile admission unavailable; no host fallback')
            reservation = self.profile.reserve(session_id, default_home=self.default_home)
            # Retain uncertain reservations explicitly; never kill a PID discovered
            # by the idle scan, and never infer descendant cleanup from leader exit.
            if not hasattr(self, '_writer_reservations'):
                self._writer_reservations = []
            self._writer_reservations.append(reservation)
            try:
                # Idle-process/reservation inspection may take time. Recheck the
                # reviewed metadata boundary after admission, before any dispatch.
                self.validate_review()
                if session_id is not None:
                    self.exact(session_id)
                    self.profile.resolve(session_id, workspace)
                with _open_root(Path(workspace)) as check_fd:
                    if (os.fstat(check_fd).st_dev,os.fstat(check_fd).st_ino)!=workspace_identity:
                        raise PermissionError('native history workspace incarnation changed')
                    if execution_policy.plan(environment,workspace,root_acknowledged=root_acknowledged)!=plan:
                        raise PermissionError('execution policy changed after native history admission')
                    pinned='/proc/self/fd/'+str(workspace_fd)
                    argv=list(argv);argv[argv.index('--in')+1]=pinned
                    result = subprocess.call(argv, env=env, cwd=pinned, pass_fds=(workspace_fd,))
                self.profile.assert_idle(default_home=self.default_home, validate_metadata=False)
            except BaseException:
                raise
            else:
                reservation.release()
                self._writer_reservations.remove(reservation)
                return result
