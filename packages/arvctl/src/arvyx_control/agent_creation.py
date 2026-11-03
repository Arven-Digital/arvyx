"""Public, local metadata transaction for creation, not installation or launch.

The caller owns authorization and supplies a trusted isolated-harness capability
set (never take it from a public request). Remote ownership is metadata only;
no remote filesystem is touched. A profile is a new private directory, never a
clone of a runtime home. Only individually reviewed, digest-approved instruction
files may enter it. Secret scanning is heuristic, not DLP: approval must include
content review. Credentials are opaque provider-vault references, not memory.

SQLite serializes workspace-wide names. Ordinary failures roll back metadata and
new files; process/power loss can leave an unreferenced private profile directory
(no claim of distributed/crash atomicity). No existing directory is overwritten.
Use a dedicated SQLite connection and a trusted, private profiles-root parent.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import unicodedata
import uuid

from . import safe_open
from .external_workspace import WorkspaceError, _open_root, _read
from .security import contains_literal_secret


class AgentCreationError(ValueError):
    """Creation rejection, rollback, or explicitly reported post-publication error.

    A published/cleanup-failed outcome is not permission to retry creation.
    """


@dataclass(frozen=True)
class IdentityFile:
    path: str
    approved_sha256: str


@dataclass(frozen=True)
class CreationRequest:
    name: str
    harness: str
    owner_host: str
    remote_workspace_id: str | None = None
    provider_auth_handle: str | None = None
    source_root: Path | None = None
    identity_files: tuple[IdentityFile, ...] = ()


@dataclass(frozen=True)
class CreatedAgent:
    agent_id: str
    name: str
    workspace_id: str
    harness: str
    owner_host: str
    remote_workspace_id: str | None
    session_namespace: str
    memory_namespace: str
    provider_auth_handle: str | None
    kind: str = 'new_agent'
    status: str = 'metadata_only'


@dataclass(frozen=True)
class ExistingAttach:
    host: str
    session_id: str
    kind: str = 'existing_attach'


# Deliberately closed list: no configuration, credentials, history or memory.
_IDENTITY = frozenset({'SOUL.md', 'USER.md', 'AGENTS.md', 'CLAUDE.md',
                       'GEMINI.md', 'CODEX.md', 'INSTRUCTIONS.md'})


def _identifier(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value)


class AgentCreation:
    def __init__(self, db, profiles_root, *, workspace_id, local_host,
                 isolated_harnesses=frozenset()):
        if not _identifier(workspace_id) or not _identifier(local_host):
            raise AgentCreationError('explicit workspace and local host required')
        if db.in_transaction:
            raise AgentCreationError('dedicated idle database connection required')
        self.db = db
        self.profiles_root = Path(profiles_root)
        self.workspace_id = workspace_id
        self.local_host = local_host
        self.isolated_harnesses = frozenset(isolated_harnesses)
        db.execute('''CREATE TABLE IF NOT EXISTS created_agents (
            agent_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL,
            name_key TEXT NOT NULL, record TEXT NOT NULL,
            UNIQUE(workspace_id, name_key))''')
        db.commit()

    def attach(self, *, host, session_id):
        """Describe an existing session; do not fabricate a new agent identity."""
        if not _identifier(host) or not _identifier(session_id):
            raise AgentCreationError('explicit host and session reference required')
        return ExistingAttach(host, session_id)

    def list_agents(self):
        rows = self.db.execute('SELECT record FROM created_agents WHERE workspace_id=? '
                               'ORDER BY name_key', (self.workspace_id,)).fetchall()
        return tuple(CreatedAgent(**json.loads(row[0])) for row in rows)

    def _validate(self, request):
        name = request.name
        if (not isinstance(name, str) or not name.strip() or name != name.strip()
                or len(name) > 128 or any(unicodedata.category(c).startswith('C') for c in name)):
            raise AgentCreationError('nonempty canonical display name required')
        key = unicodedata.normalize('NFKC', name).casefold()
        if not key.strip():
            raise AgentCreationError('empty normalized name')
        if request.harness not in self.isolated_harnesses:
            raise AgentCreationError('clean profile isolation unsupported for harness')
        if not _identifier(request.owner_host):
            raise AgentCreationError('explicit workspace owner host required')
        remote = request.owner_host != self.local_host
        if remote != (request.remote_workspace_id is not None):
            raise AgentCreationError('new remote workspace requires explicit remote ownership')
        if remote and not _identifier(request.remote_workspace_id):
            raise AgentCreationError('invalid remote workspace reference')
        handle = request.provider_auth_handle
        if handle is not None and (not isinstance(handle, str) or not re.fullmatch(
                r'(?:vault|op|bw):[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}', handle)):
            raise AgentCreationError('provider auth must be an opaque reusable vault handle')
        if bool(request.identity_files) != (request.source_root is not None):
            raise AgentCreationError('source and explicitly approved selection required together')
        if len(request.identity_files) > len(_IDENTITY):
            raise AgentCreationError('identity selection exceeds allowlist')
        contents = {}
        for item in request.identity_files:
            if (not isinstance(item, IdentityFile) or item.path not in _IDENTITY
                    or item.path in contents or not isinstance(item.approved_sha256, str)
                    or not re.fullmatch('[a-f0-9]{64}', item.approved_sha256)):
                raise AgentCreationError('only distinct approved identity instruction files allowed')
            data, _, _ = _read(request.source_root, (item.path,), 256 * 1024)
            try:
                text = data.decode('utf-8')
            except UnicodeError as exc:
                raise AgentCreationError('identity must be UTF-8 text') from exc
            if ('\x00' in text or contains_literal_secret(text)
                    or hashlib.sha256(data).hexdigest() != item.approved_sha256):
                raise AgentCreationError('secret, binary or changed identity content rejected')
            contents[item.path] = data
        return key, contents

    def create(self, request):
        """Publish one immutable metadata record and a fresh, clean profile.

        No session or memory is imported; their fresh namespaces are unrelated to
        agent identity. No credentials are resolved, copied, or persisted here.
        """
        if not isinstance(request, CreationRequest):
            raise AgentCreationError('typed creation request required')
        if self.db.in_transaction:
            raise AgentCreationError('dedicated idle database connection required')
        published_agent_id = None
        try:
            key, contents = self._validate(request)
            agent = CreatedAgent(
                agent_id=uuid.uuid4().hex, name=request.name,
                workspace_id=self.workspace_id, harness=request.harness,
                owner_host=request.owner_host, remote_workspace_id=request.remote_workspace_id,
                session_namespace=uuid.uuid4().hex, memory_namespace=uuid.uuid4().hex,
                provider_auth_handle=request.provider_auth_handle)
            with _open_root(self.profiles_root) as root:
                self.db.execute('BEGIN IMMEDIATE')
                made = False
                profile = None
                written = []
                try:
                    if self.db.execute('SELECT 1 FROM created_agents WHERE workspace_id=? '
                                       'AND name_key=?', (self.workspace_id, key)).fetchone():
                        raise AgentCreationError('agent name already exists in workspace')
                    from .public_onboarding_api import assert_request_active
                    assert_request_active()
                    safe_open.mkdir_at(root, agent.agent_id, 0o700)
                    made = True
                    profile = safe_open.open_directory_at(root, agent.agent_id)
                    for name, data in contents.items():
                        fd = safe_open.open_file_at(profile, name, write=True, create=True, exclusive=True, mode=0o600)
                        written.append(name)
                        with os.fdopen(fd, 'wb') as stream:
                            stream.write(data)
                            stream.flush()
                            os.fsync(stream.fileno())
                    safe_open.fsync_directory(profile)
                    safe_open.fsync_directory(root)
                    assert_request_active()
                    self.db.execute('INSERT INTO created_agents VALUES(?,?,?,?)',
                                    (agent.agent_id, self.workspace_id, key,
                                     json.dumps(asdict(agent))))
                    self.db.commit()
                    published_agent_id = agent.agent_id
                except BaseException:
                    self.db.rollback()
                    if profile is not None:
                        for name in written:
                            safe_open.unlink_at(profile, name)
                    if made:
                        safe_open.rmdir_at(root, agent.agent_id)
                    raise
                finally:
                    if profile is not None:
                        os.close(profile)
            return agent
        except (OSError, sqlite3.Error, WorkspaceError) as exc:
            if published_agent_id is not None:
                raise AgentCreationError(
                    f'agent {published_agent_id} published; cleanup failed; do not retry creation') from exc
            raise AgentCreationError('agent creation failed; nothing published') from exc
