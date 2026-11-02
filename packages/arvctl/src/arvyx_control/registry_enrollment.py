"""Explicit human registration of a metadata-profile identity in the owner vault.

A discovered profile is not an identity, and connecting one requires an exact
registered agent whose machine/runtime records agree. Before this module the only
registration path required a running native session, so a fresh installation had
no way to connect any discovered profile. This writes a fresh agent and runtime
record with no scopes: it is not authentication, token issuance, execution, launch
or organizer authority. Existing records are never rewritten.

Publication order is runtime then agent, each O_EXCL and fsynced. A crash between
them can leave an unreferenced runtime record, never an agent without its runtime.
"""
import json
import os
from pathlib import Path
import time
import unicodedata
import uuid

from .auth import AGENT_ID_RE
from .locks import vault_lock
# Harnesses with an implemented local metadata adapter. Registration for any other
# harness would only create an identity nothing can connect.
from .metadata_adapters import METADATA_HARNESSES


def canonical_display_name(name):
    if (not isinstance(name, str) or not name.strip() or name != name.strip()
            or len(name) > 128 or any(unicodedata.category(c).startswith('C') for c in name)):
        raise ValueError('canonical nonempty display name required')
    return name


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _registry_dir(vault, kind):
    path = Path(vault) / 'registry' / kind
    for part in (Path(vault) / 'registry', path):
        if part.is_symlink():
            raise ValueError('registry directory must not be a symlink')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def preflight(vault, machine, display_name, harness):
    """Validate without writing; shared by review snapshot and effect."""
    from .cockpit_primary import read_native_registry
    canonical_display_name(display_name)
    if harness not in METADATA_HARNESSES:
        raise ValueError('no local metadata adapter for harness')
    if not isinstance(machine, str) or not AGENT_ID_RE.fullmatch(machine):
        raise ValueError('exact enrolled machine required')
    record = read_native_registry(vault, 'machines', machine)
    if not isinstance(record, dict) or record.get('id') != machine:
        raise ValueError('existing registered machine required')
    folded = display_name.casefold()
    agents = Path(vault) / 'registry' / 'agents'
    if agents.is_dir():
        for path in sorted(agents.glob('*.json')):
            try:
                existing = json.loads(path.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                raise ValueError('unreadable agent registry record; reconcile before registering') from None
            if isinstance(existing, dict) and str(existing.get('display_name', '')).casefold() == folded:
                raise ValueError('display name already registered')
    return dict(machine=machine, display_name=display_name, harness=harness)


def register_profile_identity(vault, machine, display_name, harness, *, publication_guard=None, plan_recorder=None):
    vault = Path(vault)
    deadline = time.monotonic() + 5
    with vault_lock(vault, deadline=deadline):
        preflight(vault, machine, display_name, harness)
        agent_id, runtime_id = 'local-' + uuid.uuid4().hex, 'local-' + uuid.uuid4().hex
        runtime = dict(id=runtime_id, display_name=display_name + ' runtime', harness=harness)
        agent = dict(id=agent_id, display_name=display_name, machine_id=machine, runtime_id=runtime_id,
                     scopes=[], registration='explicit-local-human-profile')
        if plan_recorder is not None:
            # Name the identifiers durably before the first registry write (REV-0568):
            # an uncertain outcome can then be reconciled against the vault instead of
            # leaving an unnamed identity behind a refused duplicate display name.
            plan_recorder(dict(agent_id=agent_id, runtime_id=runtime_id, display_name=display_name,
                               harness=harness, machine_id=machine))
        if publication_guard is not None:
            publication_guard()
        made = []
        try:
            for kind, record in (('runtimes', runtime), ('agents', agent)):
                directory = _registry_dir(vault, kind)
                path = directory / (record['id'] + '.json')
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                made.append(path)
                with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                    json.dump(record, stream, sort_keys=True)
                    stream.flush()
                    os.fsync(stream.fileno())
                _sync(directory)
        except BaseException:
            for path in reversed(made):
                try:
                    path.unlink()
                    _sync(path.parent)
                except OSError:
                    pass
            raise
    return dict(agent_id=agent_id, display_name=display_name, harness=harness, machine_id=machine,
                scopes=[], registered=True, connected=False, execution=False)
