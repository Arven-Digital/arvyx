"""Append-only work transcript projection over AMC's existing control events.

Raw work records are not promoted memory. Existing control-write identity and
project ownership remain required; no alternate database or bearer is minted.
"""
import hashlib
import json
import os
import re
import uuid

from . import private_paths
from . import safe_open
from . import control
from .filesystem import durable_mkdir


def append_transcript(vault, state, payload, *, actor, replay_only=False):
    expected = {'event_id', 'session', 'run', 'text', 'project', 'task', 'host'}
    organizer = payload.get('kind') == 'organizer'
    if set(payload) != (expected | {'kind', 'agent'} if organizer else expected):
        raise ValueError('exact transcript fields required')
    for key in expected - ({'text', 'project', 'task'} if organizer else {'text'}):
        if not isinstance(payload[key], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', payload[key]):
            raise ValueError('invalid transcript identifier')
    text = payload['text']
    if not isinstance(text, str) or not text or len(text.encode()) > 65536:
        raise ValueError('bounded transcript required')
    control._reject_secret_shaped_text(transcript=text)
    if organizer and (payload['project'] != '' or payload['task'] != '' or payload['agent'] != actor
                      or not re.fullmatch(r'[a-z0-9-]{1,64}', actor)):
        raise ValueError('exact organizer actor context required; no work task is fabricated')
    with control._locked_state(state):
        # Exact historical replay is authorized by the recorded actor and full
        # request digest, not mutable task/project ownership or lifecycle state.
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        previous = control._idempotent_event(state, 'work.transcript', payload['event_id'])
        if previous:
            # Transcript IDs also name a global blob path, so another actor
            # must conflict rather than create a second namespaced record.
            if previous.payload.get('actor') != actor or previous.payload.get('sha256') != digest:
                raise ValueError('transcript event conflict')
            # Repair both authorities before success: private blob then log.
            directory = vault / 'conversations' / 'cockpit-archive'
            blob = directory / (payload['event_id'] + '.json')
            fd = safe_open.open_file(blob)
            try:
                with os.fdopen(fd, 'rb', closefd=False) as stream:
                    if stream.read() != json.dumps(payload, sort_keys=True).encode():
                        raise ValueError('transcript archive unavailable or digest mismatch')
                safe_open.fsync_file(fd)
            finally:
                os.close(fd)
            directory_fd = safe_open.open_directory(directory)
            try:
                safe_open.fsync_directory(directory_fd)
            finally:
                os.close(directory_fd)
            control._acknowledge_replay_unlocked(state, previous)
        else:
            if replay_only:
                raise ValueError('transcript replay requires an existing exact event')
            if organizer:
                if not (vault / 'registry/agents' / (actor + '.json')).is_file():
                    raise ValueError('existing organizer registry identity required')
            else:
                project_path = vault / 'registry/projects' / (payload['project'] + '.json')
                project = json.loads(project_path.read_text())
                if actor != project['owner_agent_id']:
                    raise ValueError('transcript actor must own project')
                tasks = {task.id: task for task in control.list_tasks(state).tasks}
                if payload['task'] not in tasks or tasks[payload['task']].owner != actor:
                    raise ValueError('transcript task ownership mismatch')
            # Raw conversations are NOT placed in the general task/event feed.
            # The existing control authority stores only the private blob receipt.
            directory = vault / 'conversations' / 'cockpit-archive'
            durable_mkdir(directory, mode=0o700)
            if directory.is_symlink() or not private_paths.is_private(directory.stat(), path=directory):
                raise ValueError('private archive directory required')
            blob = directory / (payload['event_id'] + '.json')
            temporary = directory / ('.' + uuid.uuid4().hex)
            raw = json.dumps(payload, sort_keys=True).encode()
            try:
                fd = safe_open.open_file(temporary, write=True, create=True, exclusive=True, mode=0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                safe_open.replace_path(temporary, blob)
                directory_fd = safe_open.open_directory(directory)
                try:
                    safe_open.fsync_directory(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                temporary.unlink(missing_ok=True)
            record = {key: value for key, value in payload.items() if key != 'text'}
            record.update(actor=actor, sha256=digest, idempotency_key=payload['event_id'],
                          text_sha256=hashlib.sha256(text.encode()).hexdigest(), text_bytes=len(text.encode()),
                          storage_ref='conversations/cockpit-archive/' + blob.name)
            event = control._event('work.transcript', 'organizer-' + actor if organizer else payload['task'], control._now(), record)
            control._append_event_unlocked(state, event)
    return {'event_id': payload['event_id'], 'sha256': digest, 'recorded': True, 'curated_memory': False}


def governed_sink(owner):
    """Build the explicit authenticated API adapter, not a network fallback."""
    if owner.team is None:
        raise ValueError('existing AMC team identity unavailable')
    def deliver(row):
        from .cockpit_archive import capture_delivery_payload
        # Persist original metadata before the first network attempt. A retry
        # must not silently rebind its actor/project/task/host to current state.
        payload = capture_delivery_payload(owner, row)
        digest = hashlib.sha256(json.dumps(
            {key: value for key, value in payload.items() if key not in {'actor', 'idempotency_key'}},
            sort_keys=True).encode()).hexdigest()
        response = owner.team._call('POST', '/control/transcripts', payload)
        if response.status not in {200, 201}:
            # A visible receipt on 409 is not a durability acknowledgement.
            raise ValueError('AMC transcript write refused or uncertain; retained locally')
        completed = response.body
        if isinstance(completed, str):
            completed = json.loads(completed)
        if (not isinstance(completed, dict) or completed.get('event_id') != row['event_id']
                or completed.get('sha256') != digest or completed.get('recorded') is not True):
            raise ValueError('AMC transcript durable producer acknowledgment unavailable')
        receipt = owner.team._call('GET', '/control/transcripts/' + row['event_id'])
        if receipt.status != 200:
            raise ValueError('AMC transcript acknowledgment unavailable')
        body = receipt.body
        if isinstance(body, str):
            body = json.loads(body)
        if (not isinstance(body, dict) or body.get('sha256') != digest
                or body.get('event_id') != row['event_id'] or body.get('recorded') is not True):
            raise ValueError('AMC transcript acknowledgment mismatch')
        return body.get('event_id')
    return deliver


def transcript_receipt(vault, state, event_id, *, identity):
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', event_id):
        raise ValueError('invalid transcript event ID')
    event = control._idempotent_event(state, 'work.transcript', event_id)
    if not event:
        raise ValueError('unknown transcript event')
    if identity is None or (identity.binds_actor and identity.agent_id != event.payload['actor']):
        raise ValueError('transcript identity mismatch')
    blob = vault / 'conversations' / 'cockpit-archive' / (event_id + '.json')
    if blob.is_symlink() or hashlib.sha256(blob.read_bytes()).hexdigest() != event.payload['sha256']:
        raise ValueError('transcript archive unavailable or digest mismatch')
    return {'event_id': event_id, 'sha256': event.payload['sha256'], 'recorded': True, 'curated_memory': False}
