"""Explicit native runtime references; never discover or copy credentials.

Only metadata identities are inspected. Fixture tests do not establish real
provider compatibility. Real launches still require explicit provider approval.
"""
import json
import os
from pathlib import Path

from .locks import try_exclusive_lock
from . import private_paths, safe_open
from .cockpit_adapters import resume_plan


class TranscriptPage(list):
    """List-compatible bounded page with explicit continuation metadata."""
    def __init__(self):
        super().__init__()
        self.has_more = False


class NativeRuntime:
    def __init__(self, *, tool, executable, home, store, new_protocol=None):
        if tool not in {'claude', 'codex', 'hermes', 'gemini'}:
            raise ValueError('explicit supported native tool required')
        self.tool = tool
        if new_protocol is not None and (tool!='hermes' or new_protocol not in ('hermes-titled-create-v1', 'hermes-isolated-setup-v1')):
            raise ValueError('unsupported explicitly attested native New protocol')
        self.new_protocol=new_protocol
        from .hermes_profile import HermesProfile
        self.profile = HermesProfile(home, store) if tool == 'hermes' else None
        self.executable = Path(executable).resolve(strict=True)
        self.home = Path(home).resolve(strict=True)
        self.store = Path(store).resolve(strict=True)
        if (not self.home.is_dir() or not self.executable.is_file() or not os.access(self.executable, os.X_OK)
                or not private_paths.not_writable_by_others(self.executable.stat(), path=self.executable)):
            raise ValueError('native executable/home references invalid or writable by others')
        if not self.store.is_relative_to(self.home):
            raise ValueError('native metadata store must belong to explicitly approved home')

    def plan(self, conversation, workspace):
        argv = resume_plan(self.tool, conversation)
        workspace = str(Path(workspace).resolve(strict=True))
        if self.tool == 'hermes':
            self.profile.resolve(conversation, workspace)
        elif self.tool == 'gemini':
            if self.store.stat().st_size > 16 * 1024 * 1024:
                raise ValueError('native conversation metadata exceeds cap')
            data = json.loads(self.store.read_text())
            if type(data) is not dict:
                raise ValueError('native conversation metadata must be an object')
            if data.get('sessionId') != conversation:
                raise ValueError('exact Gemini conversation mismatch')
            cwd = data.get('cwd')
            if (not isinstance(cwd, str) or not Path(cwd).is_absolute()
                    or not Path(cwd).is_dir() or str(Path(cwd).resolve(strict=True)) != workspace):
                raise ValueError('exact Gemini conversation/workspace mismatch')
        else:
            # Claude rows carry sessionId; Codex session_meta carries payload.id/cwd.
            with self.store.open() as stream:
                first = stream.readline(65537)
            if len(first) > 65536:
                raise ValueError('native metadata record exceeds cap')
            data = json.loads(first)
            if type(data) is not dict:
                raise ValueError('native conversation metadata must be an object')
            if self.tool == 'codex':
                if data.get('type') != 'session_meta':
                    raise ValueError('Codex session metadata required')
                data = data.get('payload', {})
                if type(data) is not dict:
                    raise ValueError('Codex session metadata payload must be an object')
                identifier = data.get('id')
            else:
                identifier = data.get('sessionId')
            cwd=data.get('cwd')
            if cwd is not None and (not isinstance(cwd,str) or not Path(cwd).is_absolute()):
                raise ValueError('native metadata cwd must be an absolute string')
            if identifier != conversation or (cwd and str(Path(cwd).resolve()) != workspace):
                raise ValueError('exact native conversation/workspace mismatch')
        argv[0] = str(self.executable)
        env = {'PATH': str(self.executable.parent) + ':/usr/bin:/bin', 'TERM': 'xterm-256color',
               'HOME': str(self.home), 'ENV': '/dev/null'}
        if self.profile is not None:
            env = self.profile.environment(env)
        return argv, env

    def reserve(self, conversation):
        """Admission is separate from read-only planning, held until cleanup."""
        if self.profile is not None:
            return self.profile.reserve(conversation)
        return NativeConversationReservation(self, conversation)

    def plan_new(self, marker, workspace):
        """Installed Hermes chat -c <title> --create-if-missing protocol.

        Integrator must explicitly attest this protocol for its installed CLI.
        Source witness: hermes_cli/main.py:_create_titled_session and
        _resolve_continue_flag; _parser.py:--create-if-missing. No initial
        prompt, native DB write or terminal-output identity inference is used.
        """
        import re
        if self.new_protocol!='hermes-titled-create-v1' or not re.fullmatch('arvyx-new-[a-f0-9]{32}',marker):
            raise ValueError('attested Hermes New protocol required')
        from .hermes_history import HermesHistory
        history=HermesHistory(self.home,executable=self.executable)
        argv,env=history.launch_plan(workspace,authorized=True)
        from .hermes_profile import query_budget
        with self.profile.connection() as db, query_budget(db, self.profile):
            if db.execute('SELECT 1 FROM sessions WHERE id COLLATE BINARY=? OR title COLLATE BINARY=? LIMIT 1',(marker,marker)).fetchone():
                raise ValueError('native New correlation marker already exists; no resume fallback')
        return [*argv,'-c',marker,'--create-if-missing'],env

    def created_session(self,marker,workspace):
        from .hermes_profile import query_budget
        import time
        from .public_onboarding_api import assert_request_active
        from .agent_sessions import MAX_METADATA_FIELD_BYTES
        cap = MAX_METADATA_FIELD_BYTES
        deadline=time.monotonic()+1.0
        while True:
            assert_request_active()
            with self.profile.connection() as db,query_budget(db,self.profile):
                rows=db.execute("SELECT CASE WHEN typeof(id)='text' AND length(CAST(id AS BLOB)) BETWEEN 1 AND ? THEN id END FROM sessions WHERE title COLLATE BINARY=? LIMIT 2",(cap,marker)).fetchall()
            if rows or time.monotonic()>=deadline:break
            time.sleep(0.025) # read-only acknowledgement polling; never launch retry
        if len(rows)!=1 or not isinstance(rows[0][0],str):
            raise ValueError('exact native New ID not acknowledged; do not retry')
        self.profile.resolve(rows[0][0],workspace)
        return rows[0][0]

    def transcript(self, conversation, *, after=0):
        """Hermes existing messages schema; no reasoning or credential fields.

        Other tool transcript formats are deliberately not guessed. This reads
        only the explicitly bound store and exact session, never adjacent chats.
        """
        if self.tool != 'hermes' or type(after) is not int or after < 0:
            raise ValueError('structured transcript adapter unavailable')
        from .hermes_profile import query_budget
        from .agent_sessions import MAX_METADATA_FIELD_BYTES
        if (not isinstance(conversation, str) or not conversation or
                len(conversation) > MAX_METADATA_FIELD_BYTES or
                len(conversation.encode()) > MAX_METADATA_FIELD_BYTES or after > 2**63 - 1):
            raise ValueError('native transcript identifier/cursor budget exceeded')
        with self.profile.connection() as db, query_budget(db, self.profile):
            cursor = db.execute('''SELECT CASE WHEN typeof(id)='integer' AND id>=0 THEN id END,
                CASE WHEN typeof(role)='text' AND length(CAST(role AS BLOB))<=1024 THEN role END,
                CASE WHEN typeof(content) IN ('text','null') AND length(CAST(COALESCE(content,'') AS BLOB))<=65536 THEN COALESCE(content,'') END
                FROM messages WHERE session_id COLLATE BINARY=? AND id>? ORDER BY id LIMIT 100''',
                (conversation, after))
            records = TranscriptPage()
            size = 2
            for row in cursor:
                if row[0] is None or row[1] is None or row[2] is None:
                    raise ValueError('native transcript field byte budget exceeded; source cursor unchanged')
                record = {'id': row[0], 'role': row[1], 'content': row[2]}
                charge = len(json.dumps(record).encode()) + 2
                if size + charge > 1024 * 1024:
                    records.has_more = True
                    break
                size += charge
                records.append(record)
            else:
                # The bounded SQL query may have stopped at its row limit. An
                # extra empty page is safe; never infer EOF from imported count.
                records.has_more = len(records) == 100
        return records


class NativeConversationReservation:
    """Cooperative cross-owner exclusion, retained through verified cleanup.

    The persistent claim survives an owner crash after flock is released. Only
    verified cleanup clears it; uncertain prior launches require explicit host
    reconciliation instead of assuming that a free flock proves idleness.
    This does not attest to processes launched outside AMC. Hermes retains its
    stricter profile-wide reservation and independent idle-process checks.
    """
    _IDLE = b'amc-native-idle-v1\n'

    def __init__(self, runtime, conversation):
        import hashlib
        import stat
        from .native_artifact_policy import open_native_directory
        self.fd = None
        directory = open_native_directory(runtime.home)
        try:
            home_info = os.fstat(directory)
            if not private_paths.owned_by_current_user(home_info, fd=directory):
                raise ValueError('native home must be owned by current user')
            key = hashlib.sha256(json.dumps([runtime.tool, conversation], ensure_ascii=True).encode()).hexdigest()
            name = '.amc-native-conversation-' + key + '.lock'
            try:
                fd = safe_open.open_file_at(directory, name, write=True, create=True, exclusive=True, mode=0o600)
                created = True
            except FileExistsError:
                fd = safe_open.open_file_at(directory, name, write=True)
                created = False
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or not private_paths.owner_private(info, fd=fd) or info.st_nlink != 1:
                    raise ValueError('unsafe native conversation reservation')
                if not try_exclusive_lock(fd):
                    raise ValueError('native conversation already reserved; attach instead')
                current = safe_open.stat_at(directory, name)
                if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                    raise ValueError('native conversation reservation replaced')
                # Legacy empty lock files prove only that their owner exited,
                # not that its child processes exited. Refuse them as uncertain.
                if not created and os.pread(fd, len(self._IDLE) + 1, 0) != self._IDLE:
                    raise ValueError('previous native process cleanup unverified; explicit host reconciliation required')
                marker = b'amc-native-reservation-v1\n'
                if os.write(fd, marker) != len(marker):
                    raise OSError('short native reservation write')
                os.fsync(fd)
                os.fsync(directory)
                self.fd = fd
            except BaseException:
                os.close(fd)
                raise
        finally:
            os.close(directory)

    def release(self):
        if self.fd is not None:
            # The owner calls this only after process and pump cleanup, or
            # before a fork was possible. Keep the flock if the barrier fails.
            os.ftruncate(self.fd, 0)
            if os.pwrite(self.fd, self._IDLE, 0) != len(self._IDLE):
                raise OSError('short native cleanup receipt write')
            os.fsync(self.fd)
            os.close(self.fd)
            self.fd = None
        # Do not unlink: another owner must lock the same persistent inode.
