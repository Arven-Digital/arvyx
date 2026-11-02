"""Exact current-operator cancellation, never retroactive provenance or success.

No batch selector, agent tool, transport cancellation, or business approval waiver.
The approval reference is audit data: only the caller's existing identity authorizes.
"""
from dataclasses import replace
import hashlib
import json
import os
import re
from pathlib import Path

from .thread_history import (HistoricalAckPolicy, validate_thread_history,
                             validate_idempotency_envelope, IDEMPOTENCY_FIELDS)
from .auth import SCOPE_CONTROL_WRITE
from .control import (_locked_state, read_events, _event, _now, _append_event_unlocked, _acknowledge_replay_unlocked,
                      _project_threads, _project_tasks, _project_handoffs,
                      _thread_event_payload, _reject_secret_shaped_text)

ARCHIVE_TYPES = frozenset({'thread.operator_archived', 'task.operator_archived', 'handoff.operator_archived'})
FIELDS = frozenset({'schema', 'operation', 'record_type', 'record_id', 'expected_event_id',
                    'source_event_id', 'target', 'history_sha256', 'related_revisions',
                    'category', 'reason', 'approval_reference', 'approval_quote',
                    'approval_sha256', 'evidence_references', 'terminal_event_id'})
ID = re.compile(r'(?:session_return|thread|task|handoff|execution|outbox|return)_[a-zA-Z0-9_]+')
# The longer session_return alternative consumes its full identifier before
# return_ can match. Keep legacy substring discovery for other unknown links:
# lexical boundaries could silently discard embedded or Unicode-adjacent IDs.
# Exact documented MCP method/field names, not a general non-hex-ID filter.
# Only narrative fields may classify these as symbols; explicit/unknown fields
# and any identifier with authority history always retain the dependency.
PROSE_FIELDS = frozenset({'body', 'text', 'title', 'message', 'detail', 'reason'})
PROSE_SYMBOLS = frozenset({
    'thread_pending', 'thread_inbox', 'thread_ack', 'thread_post', 'thread_reply',
    'thread_done', 'thread_get', 'task_create', 'handoff_create', 'handoff_complete',
    'handoff_list', 'execution_session_get', 'execution_heartbeat',
    'execution_session_return_request', 'execution_session_return_get', 'decision_request',
    'execution_list', 'execution_count', 'task_id', 'thread_id', 'execution_id',
})
EVENT_ID = re.compile(r'event_[a-f0-9]{24}')
HASH = re.compile(r'[a-f0-9]{64}')
# This release deliberately cannot waive the separately governed publisher gate.
PROTECTED = frozenset({'thread_54db3ef9e6e5_26efde', 'execution_4093064e539572ca2cb4ca83'})


def _kind(identifier):
    return 'outbox' if identifier.startswith('execution_delivery_') else identifier.split('_', 1)[0]


def archived_ids(events):
    return {e.task_id for e in events if e.type in ARCHIVE_TYPES or e.type == 'thread.retired'}


def require_unarchived(state, identifier):
    if identifier in archived_ids(read_events(state)):
        raise ValueError('operator-archived subject is inert')


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate raw JSON key')
        value[key] = item
    return value


def history_digest(state, identifier, *, before_event_id=None):
    """Hash exact JSONL bytes, not a coercing projected/canonical snapshot."""
    digest = hashlib.sha256()
    found = False
    for line in Path(state).read_bytes().splitlines(keepends=True):
        if not line.strip():
            continue
        raw = json.loads(line, object_pairs_hook=_pairs)
        if raw.get('id') == before_event_id:
            break
        if raw.get('task_id') == identifier:
            digest.update(line)
            found = True
    if not found:
        raise ValueError('missing raw record history')
    return digest.hexdigest()


def _references(value, *, known_ids=frozenset(), prose=False):
    if isinstance(value, dict):
        # Archival audit manifests are not newly created business dependencies.
        return set().union(*(_references(v, known_ids=known_ids, prose=k in PROSE_FIELDS)
                             for k, v in value.items()
                             if k not in {'retirement', 'operator_archive', 'operator_archive_json'}), set())
    if isinstance(value, list):
        return set().union(*(_references(v, known_ids=known_ids, prose=prose) for v in value), set())
    if not isinstance(value, str):
        return set()
    refs = set(ID.findall(value))
    return refs - (PROSE_SYMBOLS - known_ids) if prose else refs


def related_records(events, identifier):
    """Conservative undirected transitive closure, including prose references.

    An unresolved reference is retained, so the exact selector rejects rather
    than guessing whether an unknown ID was merely illustrative prose.
    """
    by_event = {e.id: e.task_id for e in events}
    known_ids = frozenset(by_event.values())
    edges = []
    for e in events:
        if e.type in ARCHIVE_TYPES:
            continue
        # A global scan cursor points at the last inspected source, not a
        # business dependency. Its synthetic task_id also matches ID, so the
        # generic source resolver would otherwise join every scanned subject.
        if e.type == 'outbox.materialization.checkpoint' and e.task_id == 'outbox_materialization':
            continue
        refs = _references(e.payload, known_ids=known_ids)
        # A transport/source mismatch cannot hide a reverse dependency.
        def sources(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in {'retirement', 'operator_archive', 'operator_archive_json'}:
                        continue
                    if key in {'source_event_id', 'terminal_event_id'} and item:
                        refs.add(by_event.get(item, item) if isinstance(item, str) else 'unknown-source')
                    elif isinstance(item, (dict, list)):
                        sources(item)
            elif isinstance(value, list):
                for item in value:
                    sources(item)
        # Only source-bearing domain histories, not global checkpoint cursors.
        if ID.fullmatch(e.task_id):
            sources(e.payload)
        edges.append((e.task_id, refs))
    linked = {identifier}
    while True:
        before = set(linked)
        for owner, refs in edges:
            if owner in linked or refs & linked:
                linked.add(owner)
                linked.update(refs)
        if linked == before:
            return linked - {identifier}


def _request(request, identity, record_id, dry_run):
    if (identity is None or identity.kind != 'operator' or identity.agent_id != 'operator'
            or SCOPE_CONTROL_WRITE not in identity.scopes):
        raise ValueError('authenticated operator with control write scope required')
    if type(dry_run) is not bool or type(request) is not dict or set(request) != FIELDS:
        raise ValueError('exact versioned archival request fields required')
    r = json.loads(json.dumps(request))
    for key in FIELDS - {'related_revisions', 'evidence_references'}:
        value = r[key]
        if not isinstance(value, str) or value != value.strip() or (not value and key != 'terminal_event_id'):
            raise ValueError(f'invalid exact {key}')
    if (r['schema'] != 'operator-archive/v1' or r['operation'] != 'archive'
            or r['record_type'] not in {'thread', 'task', 'handoff', 'execution'}
            or r['record_id'] != record_id or not ID.fullmatch(record_id)
            or not record_id.startswith(r['record_type'] + '_')):
        raise ValueError('unsupported archival schema or exact record binding')
    if r['category'] not in {'operator_cancelled_no_longer_needed', 'historical_alert_obsolete'}:
        raise ValueError('unsupported archival category')
    for field in ('expected_event_id', 'source_event_id'):
        if not EVENT_ID.fullmatch(r[field]):
            raise ValueError('invalid event ID')
    if r['terminal_event_id'] and not EVENT_ID.fullmatch(r['terminal_event_id']):
        raise ValueError('invalid terminal event ID')
    for field in ('history_sha256', 'approval_sha256'):
        if not HASH.fullmatch(r[field]):
            raise ValueError('invalid digest')
    if hashlib.sha256(r['approval_quote'].encode()).hexdigest() != r['approval_sha256']:
        raise ValueError('approval quote digest mismatch')
    for key in ('reason', 'approval_reference', 'approval_quote'):
        if len(r[key]) > 1024:
            raise ValueError('archival audit text exceeds bound')
        _reject_secret_shaped_text(**{key: r[key]})
    refs = r['evidence_references']
    if (not isinstance(refs, list) or not 1 <= len(refs) <= 32
            or any(not isinstance(x, str) or not x.strip() or x != x.strip() or len(x) > 1024 for x in refs)
            or len(set(refs)) != len(refs)):
        raise ValueError('bounded unique evidence references required')
    for reference in refs:
        _reject_secret_shaped_text(evidence_reference=reference)
    revisions = r['related_revisions']
    if type(revisions) is not dict or len(revisions) > 2048:
        raise ValueError('bounded exact related revision map required')
    for key, value in revisions.items():
        if (not ID.fullmatch(key) or type(value) is not dict
                or set(value) != {'expected_event_id', 'history_sha256'}
                or not isinstance(value['expected_event_id'], str)
                or not EVENT_ID.fullmatch(value['expected_event_id'])
                or not isinstance(value['history_sha256'], str)
                or not HASH.fullmatch(value['history_sha256'])):
            raise ValueError('malformed related revision fence')
    return r


def _validate_archival_thread_history(events, identifier):
    """Archive-only ACK owner binding; structural acceptance grants no authority."""
    validate_thread_history(
        events, identifier,
        historical_ack_policy=HistoricalAckPolicy.ALLOW_MISSING_IDENTITY,
    )
    for event in events:
        if (event.task_id == identifier and event.type == "thread.acknowledged"
                and event.payload["acked_by"] != event.payload["target"]):
            raise ValueError("historical ACK actor/owner mismatch")


def _simple_history(history, kind):
    required = ({'id', 'title', 'owner', 'status', 'created_at', 'updated_at'} if kind == 'task' else
                {'id', 'title', 'from_agent', 'to_agent', 'status', 'summary', 'created_at', 'updated_at'})
    extras = {'created_by', 'idempotency_key'} if kind == 'task' else {
        'reviewer', 'review_decision', 'review_notes', 'actor_identity_bound', 'accepted_by', 'completed_by'}
    allowed = {'task.created': (None, 'open'), 'task.completed': ({'open'}, 'done'),
               'handoff.created': (None, 'open'), 'handoff.accepted': ({'open'}, 'accepted'),
               'handoff.reviewed': ({'accepted'}, 'reviewed'), 'handoff.completed': ({'accepted', 'reviewed'}, 'completed')}
    previous = None
    for e in history:
        p = e.payload
        validate_idempotency_envelope(p)
        if (e.type not in allowed or not required <= p.keys() or set(p) - required - extras - {'retirement'} - IDEMPOTENCY_FIELDS
                or any(not isinstance(v, str) for k, v in p.items() if k not in {'actor_identity_bound', 'retirement'} | IDEMPOTENCY_FIELDS)
                or ('actor_identity_bound' in p and type(p['actor_identity_bound']) is not bool)
                or p.get('retirement') or p['id'] != e.task_id):
            raise ValueError('malformed or unknown raw ownership history')
        if e.type == 'handoff.accepted' and (not p.get('accepted_by') or p['accepted_by'] != p['to_agent']):
            raise ValueError('historical acceptance actor/owner mismatch')
        before, after = allowed[e.type]
        if p['status'] != after or (previous is None) != (before is None):
            raise ValueError('invalid ownership creation/lifecycle')
        if previous is not None:
            from .thread_history import handoff_completion_supersedes
            supersedes = (kind == 'handoff' and e.type == 'handoff.completed'
                          and handoff_completion_supersedes(previous, p))
            if ((previous['status'] not in before and not supersedes)
                    or any(p[k] != previous[k] for k in required - {'status', 'updated_at'})
                    or (supersedes and any(p.get(k) != previous.get(k) for k in
                                          {'accepted_by', 'reviewer', 'review_decision', 'review_notes'}))):
                raise ValueError('rewritten ownership history')
        previous = p


def _transport_id(p):
    from .outbox import _identity
    payload = p['payload']
    if payload.get('delivery_mode') == 'execution':
        if not payload.get('execution_id') or not payload.get('attempt_id') or payload.get('target') != p['target']:
            raise ValueError('malformed execution wake binding')
        return 'execution_delivery_' + hashlib.sha256(f"{payload['execution_id']}\0{payload['attempt_id']}".encode()).hexdigest()[:24]
    return 'outbox_' + _identity(p.get('subject_id', ''), p.get('target', ''), p['payload_hash'], p.get('epoch', 0))[:24]


def _validate_history(events, identifier):
    from .execution import EXECUTION_STATE_EVENT_TYPES, _project_executions_state, EXECUTION_FIELDS
    from .outbox import OUTBOX_EVENT_TYPES, OutboxItem, _payload_hash, _identity
    history = [e for e in events if e.task_id == identifier]
    if (not history or len({e.id for e in history}) != len(history)
            or any(sum(other.id == e.id for other in events) != 1 for e in history)):
        raise ValueError('missing or duplicate relevant history')
    kind = _kind(identifier)
    archived = [e for e in history if e.type in ARCHIVE_TYPES]
    if archived:
        if len(archived) != 1:
            raise ValueError('duplicate archival event')
        index = history.index(archived[0])
        _validate_history(history[:index], identifier)
        prior = next(e.payload for e in reversed(history[:index]) if 'status' in e.payload)
        p = archived[0].payload
        mutable = {'status', 'latest_at', 'updated_at', 'unread', 'pending', 'retirement'}
        if (p.get('status') != 'retired' or not p.get('retirement')
                or any(p.get(k) != v for k, v in prior.items() if k not in mutable | IDEMPOTENCY_FIELDS | {'actor_identity_bound', 'text', 'posted_by'})
                or any(e.type != 'thread.read' or e.payload.get('status') != 'retired'
                       or e.payload.get('retirement') != p['retirement']
                       or set(e.payload) != set(p)
                       or e.payload.get('unread') is not False
                       or any(e.payload.get(k) != v for k, v in p.items() if k not in {'read_at', 'unread'})
                       for e in history[index + 1:])):
            raise ValueError('archival lifecycle rewritten')
        return
    if kind == 'thread':
        _validate_archival_thread_history(events, identifier)
        return
    if kind in {'task', 'handoff'}:
        _simple_history(history, kind)
        return
    if kind == 'execution':
        projected, malformed = _project_executions_state({}, set(), history)
        if malformed or identifier not in projected:
            raise ValueError('malformed execution history')
        from .execution import _execution_id
        root = history[0].payload
        sources = [e for e in events if e.id == root.get('source_event_id')]
        if (len(sources) != 1 or root.get('subject_type') not in {'thread', 'handoff'}
                or root.get('source_event_type') != sources[0].type
                or sources[0].task_id != root.get('subject_id')
                or sources[0].payload.get('target' if root['subject_type'] == 'thread' else 'to_agent') != root.get('target')
                or identifier != _execution_id(root['subject_type'], root['subject_id'], root['target'])):
            raise ValueError('execution source/owner binding mismatch')
        source = sources[0]
        subject_kind = root['subject_type']
        if source.type != subject_kind + '.created':
            # Historical writers 09cd0d5 / 00f75c5 used this same stable ID,
            # rooted at target ACK/accept (before assignment roots in 9184377).
            # Missing identity is unknown, not authorization to run or complete.
            expected = {'thread': ('thread.acknowledged', 'acked_by', 'target'),
                        'handoff': ('handoff.accepted', 'accepted_by', 'to_agent')}[subject_kind]
            created = [e for e in events if e.task_id == root['subject_id'] and e.type == subject_kind + '.created']
            if (source.type != expected[0] or source.payload.get(expected[1]) != root['target']
                    or ('actor_identity_bound' in source.payload and source.payload['actor_identity_bound'] is not True)
                    or len(created) != 1 or created[0].payload.get(expected[2]) != root['target']
                    or not root['target'] or root['target'] == 'all'
                    or not events.index(created[0]) < events.index(source) < events.index(history[0])
                    or root.get('created_at') != source.timestamp):
                raise ValueError('historical execution ACK/accept source binding mismatch')
        immutable = {'id', 'subject_id', 'subject_type', 'target', 'source_event_id', 'source_event_type', 'created_at'}
        statuses = {'execution.created': {'pending'}, 'execution.attempt.started': {'leased'},
                    'execution.heartbeat': {'leased'}, 'execution.attempt.failed': {'pending', 'dead_lettered'},
                    'execution.dead_lettered': {'dead_lettered'}, 'execution.completed': {'completed'},
                    'execution.replayed': {'pending'}, 'execution.held': {'held'}, 'execution.closed': {'closed'},
                    'execution.cancel_requested': {'paused'}, 'execution.resumed': {'pending', 'paused'}}
        previous = None
        for e in history:
            p = e.payload
            if (e.type not in EXECUTION_STATE_EVENT_TYPES or e.type not in statuses
                    or set(p) - EXECUTION_FIELDS - {'operator_archive'} - {
                        'execution.heartbeat': {'first_heartbeat_seconds', 'runtime_detail', 'heartbeat_by', 'actor_identity_bound'},
                        'execution.resumed': {'resumed_by'},
                        'execution.replayed': {'replayed_by', 'replayed_from_status'},
                    }.get(e.type, set())
                    or p.get('status') not in statuses[e.type]
                    or (previous is None and e.type != 'execution.created')
                    or (previous is not None and e.type == 'execution.created')
                    or (previous is not None and any(p.get(k) != previous.get(k) for k in immutable))
                    or (previous is not None and previous['status'] == 'completed')
                    or (previous is not None and previous['status'] == 'closed' and e.type != 'execution.completed')):
                raise ValueError('unknown or rewritten execution lifecycle')
            if previous is not None:
                before = previous['status']
                permitted = {
                    'execution.attempt.started': {'pending', 'leased'},
                    'execution.heartbeat': {'leased'}, 'execution.attempt.failed': {'leased'},
                    'execution.dead_lettered': {'pending', 'leased'},
                    'execution.completed': {'pending', 'leased', 'held', 'paused', 'dead_lettered', 'closed'},
                    'execution.replayed': {'held', 'dead_lettered'},
                    'execution.held': {'pending', 'leased', 'paused', 'dead_lettered', 'held'},
                    'execution.closed': {'pending', 'held', 'dead_lettered'},
                    'execution.cancel_requested': {'pending', 'leased', 'held', 'dead_lettered'},
                    'execution.resumed': {'paused'},
                }
                if before not in permitted.get(e.type, set()):
                    raise ValueError('illegal raw execution transition')
                if previous.get('operator_archive'):
                    raise ValueError('operator disposition cannot be reconciled to success')
            previous = p
        return
    if kind == 'outbox':
        previous = None
        fields = set(OutboxItem.__dataclass_fields__)
        for e in history:
            p = e.payload
            # Receipt-only events and advanced modes need separate adjudication.
            if (e.type not in OUTBOX_EVENT_TYPES or set(p) - fields
                    or not isinstance(p.get('payload'), dict)
                    or any(not isinstance(v, str) for k, v in p.items() if k not in {'payload', 'retirement', 'attempts', 'failures', 'epoch'})
                    or any(type(p.get(k, 0)) is not int or p.get(k, 0) < 0 for k in ('attempts', 'failures', 'epoch'))
                    or p.get('payload_hash') != _payload_hash(p['payload'])
                    or p.get('id') != identifier
                    or identifier != _transport_id(p)
                    or (previous is None and e.type != 'outbox.enqueued')
                    or (previous is not None and e.type == 'outbox.enqueued')
                    or (previous is not None and any(p.get(k) != previous.get(k) for k in ('subject_id', 'target', 'payload', 'payload_hash', 'epoch', 'created_at')))):
                raise ValueError('unsupported or malformed transport history')
            if p.get('status') not in {'pending', 'leased', 'delivered', 'dead_lettered', 'cancelled', 'ambiguous_delivery'}:
                raise ValueError('unknown transport lifecycle')
            statuses = {
                'outbox.enqueued': {'pending', 'leased'}, 'outbox.attempt.started': {'leased'},
                'outbox.attempt.failed': {'pending', 'dead_lettered', 'ambiguous_delivery'},
                'outbox.delivered': {'delivered'}, 'outbox.deferred': {'pending'},
                'outbox.dead_lettered': {'dead_lettered', 'ambiguous_delivery'},
                'outbox.cancelled': {'cancelled'}, 'outbox.resolved': {'dead_lettered'},
                'outbox.receipt': {'delivered'},
            }
            if p['status'] not in statuses.get(e.type, set()):
                raise ValueError('transport event/status mismatch')
            if previous is not None:
                before = previous['status']
                allowed = {
                    'outbox.attempt.started': {'pending', 'leased'},
                    'outbox.attempt.failed': {'leased'}, 'outbox.delivered': {'leased', 'ambiguous_delivery'},
                    'outbox.deferred': {'pending', 'leased'},
                    'outbox.dead_lettered': {'pending', 'leased', 'ambiguous_delivery'},
                    'outbox.cancelled': {'pending'}, 'outbox.resolved': {'dead_lettered'},
                    'outbox.receipt': {'delivered'},
                }
                if before not in allowed.get(e.type, set()):
                    raise ValueError('illegal transport transition')
                if e.type == 'outbox.receipt' and (p.get('receipt_by') != p['target']
                        or p.get('receipt_status') not in {'seen', 'accepted', 'completed', 'failed'}):
                    raise ValueError('malformed target receipt')
            previous = p
        root = history[0].payload
        payload = root['payload']
        sources = [e for e in events if e.id == payload.get('source_event_id')]
        if (payload.get('schema') != 'v2.agent-delivery/1' or len(sources) != 1
                or payload.get('subject_id') != root['subject_id'] or sources[0].task_id != root['subject_id']):
            raise ValueError('transport source/subject mismatch')
        source = sources[0]
        mode = payload.get('delivery_mode', 'direct')
        if 'execution_managed' in payload or (mode == 'notification' and source.type in {'thread.created', 'handoff.created'}):
            from .execution import execution_assignment_sources
            assignment = execution_assignment_sources(events).get(source.id)
            expected = {'schema': 'v2.agent-delivery/1', 'source_event_id': source.id,
                        'source_event_type': source.type, 'subject_id': source.task_id,
                        'delivery_mode': 'notification', 'execution_managed': True}
            if source.type == 'thread.created':
                artifact = source.payload.get('completion_artifact', '')
                anchor = source.payload.get('completion_anchor', '')
                if artifact and anchor:
                    expected.update(completion_artifact=artifact, completion_anchor=anchor)
            if (payload.get('execution_managed') is not True or assignment is None
                    or root['target'] != assignment[1] or payload != expected):
                raise ValueError('unsupported or misbound execution-managed notification')
            return
        if mode == 'execution':
            execution_history = [e for e in events if e.task_id == payload.get('execution_id')]
            if (not execution_history or payload.get('origin_event_type') != source.type
                    or payload.get('source_event_type') != 'execution.attempt.started'
                    or execution_history[0].payload.get('subject_id') != root['subject_id']
                    or execution_history[0].payload.get('target') != root['target']
                    or not any(e.type == 'execution.attempt.started' and e.payload.get('attempt_id') == payload.get('attempt_id') for e in execution_history)):
                raise ValueError('execution wake relationship mismatch')
        else:
            target_fields = {'thread.created': 'target', 'task.created': 'owner', 'handoff.created': 'to_agent',
                             'thread.done': 'actor', 'handoff.completed': 'from_agent', 'handoff.reviewed': 'from_agent'}
            expected_mode = 'notification' if source.type in {'thread.done', 'handoff.completed', 'handoff.reviewed'} else 'direct'
            if (mode != expected_mode or payload.get('source_event_type') != source.type
                    or source.type not in target_fields or source.payload.get(target_fields[source.type]) != root['target']):
                raise ValueError('unsupported or misbound delivery source/mode')
        return
    raise ValueError('unsupported related record kind')


def generic_archive_enabled():
    """Explicit process configuration; never request-controlled or demo-enabled."""
    return os.environ.get("ARVYX_ENABLE_OPERATOR_ARCHIVE") == "1"


def archive_record(state, *, record_id, request, identity, dry_run=True):
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    if not generic_archive_enabled():
        raise ValueError("generic operator archive disabled")
    r = _request(request, identity, record_id, dry_run)
    with _locked_state(state):
        events = read_events(state)
        history = [e for e in events if e.task_id == record_id]
        if not history:
            raise ValueError('unknown exact record')
        retry = [e for e in history if e.type in ARCHIVE_TYPES or e.payload.get('operator_archive')]
        if retry:
            if len(retry) != 1:
                raise ValueError('ambiguous archival retry')
            action = retry[0]
            metadata = action.payload.get('retirement') or action.payload.get('operator_archive')
            if metadata.get('request') != r or metadata.get('operator') != 'operator':
                raise ValueError('conflicting archival retry')
            _validate_history(events, record_id)
            if history_digest(state, record_id, before_event_id=action.id) != r['history_sha256']:
                raise ValueError('original raw history changed after archival')
            # Exact retries permit only readback, not changed related records.
            for key, fence in r['related_revisions'].items():
                linked = [e for e in events if e.task_id == key]
                if not linked or linked[-1].id != fence['expected_event_id'] or history_digest(state, key) != fence['history_sha256']:
                    raise ValueError('related history changed after archival')
            if related_records(events, record_id) != set(r['related_revisions']):
                raise ValueError('related closure changed after archival')
            if not dry_run:
                _acknowledge_replay_unlocked(state, action)
            return {'record': action.payload, 'event_id': action.id, 'changed': False, 'dry_run': dry_run}
        linked = related_records(events, record_id)
        if linked != set(r['related_revisions']):
            raise ValueError('related revision map is not the complete exact closure')
        identifiers = linked | {record_id}
        if identifiers & PROTECTED:
            raise ValueError('separate publisher/business approval cannot be waived by backlog archival')
        for key in identifiers:
            selected = [e for e in events if e.task_id == key]
            fence = r if key == record_id else r['related_revisions'][key]
            if (not selected or selected[-1].id != fence['expected_event_id']
                    or history_digest(state, key) != fence['history_sha256']):
                raise ValueError('stale exact record or related history fence')
            _validate_history(events, key)
            for e in selected:
                p = e.payload
                if e.type in {'thread.notification_sent', 'thread.notification_failed'}:
                    raise ValueError('legacy notifier history has no settled transport fence; unsupported')
                if (p.get('continuation_thread_id') or p.get('continuation_of')
                        or e.type == 'execution.session_return.requested'
                        or p.get('payload', {}).get('delivery_mode') == 'session_return'):
                    raise ValueError('unsupported continuation/return relationship')
        source = history[0]
        kind = r['record_type']
        if source.id != r['source_event_id'] or source.type != kind + '.created':
            raise ValueError('exact creation source mismatch')
        owner_field = {'thread': 'target', 'task': 'owner', 'handoff': 'to_agent', 'execution': 'target'}[kind]
        if source.payload.get(owner_field) != r['target'] or r['target'] == 'all':
            raise ValueError('exact owner mismatch')
        # Every dependent obligation must be terminal already. No cascading writes.
        # Execution disposition alone may leave its selected subject open.
        subject = source.payload.get('subject_id') if kind == 'execution' else None
        for key in linked:
            selected = [e for e in events if e.task_id == key]
            last = selected[-1].payload
            status = last.get('status')
            allowed = {'thread': {'done', 'retired'}, 'task': {'done', 'retired'},
                       'handoff': {'completed', 'retired'}, 'execution': {'closed', 'completed'},
                       'outbox': {'delivered', 'cancelled', 'dead_lettered'}}.get(_kind(key), set())
            if key == subject or (kind == 'execution' and key.startswith('thread_')
                                  and last.get('target') == 'operator' and last.get('actor') == 'arvyx-watchdog'):
                # Closing an execution neither resolves its subject nor its alert.
                allowed = allowed | {'open', 'acked', 'accepted'}
            if status not in allowed or last.get('lease_owner') or last.get('lease_expires_at'):
                raise ValueError('active or unknown related work must be separately disposed')
            if _kind(key) == 'outbox' and status == 'dead_lettered' and last.get('resolution_category') not in {'obsolete', 'superseded', 'terminal_elsewhere'}:
                raise ValueError('unresolved transport obligation')
        if r['category'] == 'historical_alert_obsolete':
            from .watchdog import _escalation_title
            from .watchdog_alerts import operator_hold_alert_bodies as _operator_hold_alert_bodies
            if kind != 'thread' or r['target'] != 'operator' or source.payload.get('type') != 'blocker' or source.payload.get('actor') != 'arvyx-watchdog' or any(
                    e.type not in {'thread.created', 'thread.read', 'thread.notification_sent', 'thread.notification_failed'} for e in history):
                raise ValueError('not an untouched historical watchdog alert')
            terminals = [e for e in events if e.id == r['terminal_event_id'] and e.task_id in linked and e.type in {'execution.closed', 'execution.completed'}]
            if len(terminals) != 1:
                raise ValueError('exact terminal execution evidence required')
            terminal = terminals[0]
            if next(e.id for e in reversed(events) if e.task_id == terminal.task_id) != terminal.id:
                raise ValueError('terminal evidence is not the latest exact execution revision')
            ep = terminal.payload
            hold = next((e for e in reversed(events[:events.index(source)]) if e.task_id == terminal.task_id and e.type == 'execution.held'), None)
            if (hold is None or source.payload['title'] != _escalation_title(terminal.task_id)
                    or source.payload['body'] not in _operator_hold_alert_bodies(
                        target=ep['target'], subject_type=ep['subject_type'], subject_id=ep['subject_id'],
                        hold_reason=hold.payload.get('hold_reason', ''))
                    or any(e.payload.get('subject_id') == record_id for e in events if e.type.startswith('execution.'))):
                raise ValueError('historical watchdog HOLD/source binding mismatch')
        elif r['terminal_event_id']:
            raise ValueError('cancellation makes no terminal success claim')
        timestamp = _now()
        flag = source.payload.get('actor_identity_bound')
        metadata = {'operator': 'operator', 'operation': 'operator_archive', 'request': r,
                    'request_sha256': hashlib.sha256(json.dumps(r, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                    'source_actor_identity_bound': 'missing' if flag is None else str(flag).lower(),
                    'retired_at': timestamp}
        if kind == 'execution':
            from .execution import project_executions
            record = project_executions(state)[record_id]
            if record.status not in {'pending', 'held', 'dead_lettered'} or record.lease_owner or record.lease_expires_at:
                raise ValueError('execution is not unleased pending/held/dead-lettered')
            updated = replace(record, status='closed', updated_at=timestamp, closed_at=timestamp,
                              closed_by='operator', close_reason=r['reason'], resolution_category='no_longer_actionable',
                              operator_archive_json=json.dumps(metadata, sort_keys=True))
            payload = {**updated.to_dict(), 'operator_archive': metadata}
            event_type = 'execution.closed'
        else:
            project = {'thread': _project_threads, 'task': _project_tasks, 'handoff': _project_handoffs}[kind]
            record = project(state, events)[record_id]
            if record.status not in {'open', 'acked', 'accepted'}:
                raise ValueError('terminal/reviewed record cannot be archived')
            changes = {'status': 'retired', 'retirement_json': json.dumps(metadata, sort_keys=True)}
            changes['latest_at' if kind == 'thread' else 'updated_at'] = timestamp
            if kind == 'thread':
                changes['unread'] = False
            updated = replace(record, **changes)
            # Projected task/handoff dataclasses omit original audit fields.
            # Preserve them so an exact archival retry validates the same history.
            payload = (_thread_event_payload(updated) if kind == 'thread' else
                       {**history[-1].payload, **updated.to_dict()})
            if kind == 'task' and 'created_by' in source.payload:
                payload['created_by'] = source.payload['created_by']
            if kind == 'handoff':
                payload['accepted_by'] = next((e.payload.get('accepted_by', '') for e in reversed(history) if e.type == 'handoff.accepted'), '')
            event_type = kind + '.operator_archived'
        event = _event(event_type, record_id, timestamp, payload)
        _validate_history([*events, event], record_id)
        if dry_run:
            return {'record': payload, 'event_id': None, 'changed': False, 'dry_run': True}
        _append_event_unlocked(state, event)
        return {'record': payload, 'event_id': event.id, 'changed': True, 'dry_run': False}
