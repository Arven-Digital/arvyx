"""Current-operator abandonment of one obsolete watchdog notification only.

This is NOT generic archival and does not establish completed business lineage.
Narrative references are retained as audit, never removed to pass archive_record.
Unknown structured authority, continuation, live runtime and transport fail closed.
"""
from collections import defaultdict
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import re

from .auth import SCOPE_CONTROL_WRITE
from .control import (ControlEvent, _locked_state, _event, _now, _append_event_unlocked, _acknowledge_replay_unlocked,
                      _project_threads, _thread_event_payload)
from .operator_archive import (FIELDS, ID, HASH, PROTECTED, ARCHIVE_TYPES, _pairs,
    _request, _references, _validate_history, _validate_archival_thread_history)
from .watchdog import _escalation_title
from .watchdog_alerts import operator_hold_alert_bodies as _operator_hold_alert_bodies

SCHEMA = 'operator-alert-dismissal/v1'
DISPOSITION = 'notification_only_not_lineage_completion'
EXTRA = frozenset({'authority_sha256', 'execution_id', 'audit_references', 'disposition'})
# Explicit narrative slots only: unknown fields are conservatively structural.
NARRATIVE = frozenset({'title', 'body', 'text', 'message', 'detail', 'reason', 'summary',
    'hold_reason', 'close_reason', 'review_notes', 'last_error', 'runtime_detail', 'receipt_detail'})
AUDIT = frozenset({'retirement', 'operator_archive', 'operator_archive_json'})


def _operator(identity):
    if (identity is None or identity.kind != 'operator' or identity.agent_id != 'operator'
            or SCOPE_CONTROL_WRITE not in identity.scopes):
        raise ValueError('authenticated current operator with control write scope required')


def _raw(state):
    """Read exact authority, rejecting duplicate keys/IDs before projections coerce."""
    data = Path(state).read_bytes()
    if data and not data.endswith(b'\n'):
        raise ValueError('authority must end with a complete JSONL line')
    ids = set()
    events = []
    digests = defaultdict(hashlib.sha256)
    for line in data.splitlines(keepends=True):
        if not line.strip():
            continue
        e = json.loads(line, object_pairs_hook=_pairs)
        if (not isinstance(e, dict) or set(e) != {'id', 'type', 'task_id', 'timestamp', 'payload'}
                or any(not isinstance(e.get(k), str) or not e[k] for k in ('id', 'type', 'task_id', 'timestamp'))
                or e['id'] in ids or not isinstance(e.get('task_id'), str)
                or not isinstance(e.get('payload'), dict)):
            raise ValueError('malformed or duplicate raw authority event')
        ids.add(e['id'])
        digests[e['task_id']].update(line)
        events.append(ControlEvent(**e))
    return data, {key: value.hexdigest() for key, value in digests.items()}, events


def _structural(value, by_event):
    if isinstance(value, dict):
        return set().union(*(_structural(v, by_event) for k, v in value.items()
                            if k not in AUDIT and not (k in NARRATIVE and isinstance(v, str))), set())
    if isinstance(value, list):
        return set().union(*(_structural(v, by_event) for v in value), set())
    if not isinstance(value, str):
        return set()
    refs = set(ID.findall(value))
    refs.update(by_event.get(token, token) for token in re.findall(r'event_[a-zA-Z0-9_]+', value))
    return refs


def _closure(events, seeds):
    """Structural authority only, in both directions, preserving unresolved IDs.

    This intentionally is not related_records() and cannot confer its eligibility.
    Global observation/cursor records do not own domain authority.
    """
    by_event = {e.id: e.task_id for e in events}
    edges = defaultdict(set)
    for e in events:
        if e.type in ARCHIVE_TYPES:
            continue
        if (e.type, e.task_id) in {
                ('outbox.materialization.checkpoint', 'outbox_materialization'),
                ('execution.watchdog.tick', 'watchdog')}:
            continue
        # Unknown owners with structural references are authority ambiguity,
        # not an excuse to drop a reverse dependency.
        for ref in _structural(e.payload, by_event):
            edges[e.task_id].add(ref)
            edges[ref].add(e.task_id)
    linked = set(seeds)
    pending = list(seeds)
    while pending:
        for ref in edges[pending.pop()] - linked:
            linked.add(ref)
            pending.append(ref)
    return linked


def _inspect(events, record_id):
    by = defaultdict(list)
    for e in events:
        by[e.task_id].append(e)
    history = by[record_id]
    if not history:
        raise ValueError('unknown exact watchdog alert')
    source = history[0]
    p = source.payload
    match = re.fullmatch(r'\[watchdog\] execution (execution_[a-f0-9]{24}) held for operator', p.get('title', ''))
    if (source.type != 'thread.created' or p.get('type') != 'blocker'
            or p.get('actor') != 'arvyx-watchdog' or p.get('target') != 'operator'
            or p.get('actor_identity_bound') is True or not match
            or any(e.type not in {'thread.created', 'thread.read'} for e in history)):
        raise ValueError('only untouched operator watchdog notifications may be dismissed')
    _validate_archival_thread_history(history, record_id)
    execution_id = match.group(1)
    execution_history = by[execution_id]
    if not execution_history:
        raise ValueError('unresolved structural originating execution')
    ep = execution_history[0].payload
    subject = ep.get('subject_id')
    if not isinstance(subject, str) or not subject:
        raise ValueError('unresolved structural execution subject')
    holds = [e for e in events[:events.index(source)] if e.task_id == execution_id and e.type == 'execution.held']
    bodies = _operator_hold_alert_bodies(target=ep.get('target'), subject_type=ep.get('subject_type'),
        subject_id=subject, hold_reason=holds[-1].payload.get('hold_reason', '')) if holds else ()
    # The former producer appended one period even without guidance. Enumerate
    # that exact historical spelling; never strip punctuation or accept a prefix.
    if (not holds or p['title'] != _escalation_title(execution_id)
            or p.get('body') not in bodies):
        raise ValueError('exact watchdog creation/HOLD binding mismatch')
    linked = _closure(events, {record_id, execution_id, subject})
    missing = linked - by.keys()
    if missing:
        raise ValueError('unresolved structural authority: ' + ', '.join(sorted(missing)))
    relevant = [e for e in events if e.task_id in linked]
    audit_refs = set().union(*(_references(e.payload) for e in relevant), set()) - linked
    if (linked | audit_refs) & PROTECTED:
        raise ValueError('protected publisher approval cannot be waived by notification dismissal')
    for key in sorted(linked):
        selected = by[key]
        last = selected[-1].payload
        for e in selected:
            payload = e.payload
            if (payload.get('continuation_thread_id') or payload.get('continuation_of')
                    or e.type == 'execution.session_return.requested'
                    or payload.get('payload', {}).get('delivery_mode') == 'session_return'):
                raise ValueError('continuation authority is unsupported: ' + key)
            if e.type in {'thread.notification_sent', 'thread.notification_failed'}:
                raise ValueError('legacy notifier has no settled dispatch fence: ' + key)
        # Business histories are preserved, not authenticated/completed by dismissal.
        # Validate them conservatively rather than interpreting a malformed lineage.
        _validate_history(relevant, key)
        if key.startswith('execution_') and not key.startswith('execution_delivery_'):
            if last.get('subject_id') == record_id:
                raise ValueError('alert owns an execution and is not notification-only')
            if last.get('status') not in {'closed', 'completed'} or last.get('lease_owner') or last.get('lease_expires_at'):
                raise ValueError('live or unresolved execution authority: ' + key)
        elif key.startswith(('outbox_', 'execution_delivery_')):
            if last.get('subject_id') == record_id:
                raise ValueError('alert owns transport; separately adjudicate it')
            if (last.get('status') not in {'delivered', 'cancelled', 'dead_lettered'}
                    or last.get('lease_owner') or last.get('lease_expires_at')
                    or (last.get('status') == 'dead_lettered' and last.get('resolution_category') not in {'obsolete', 'superseded', 'terminal_elsewhere'})):
                raise ValueError('live or ambiguous transport authority: ' + key)
    return source, execution_id, linked, sorted(audit_refs)


def _validate_request(request, identity, record_id, dry_run):
    _operator(identity)
    if type(request) is not dict or set(request) != FIELDS | EXTRA:
        raise ValueError('exact alert dismissal request fields required')
    if (request['schema'] != SCHEMA or request['operation'] != 'dismiss_watchdog_alert'
            or request['disposition'] != DISPOSITION or request['record_type'] != 'thread'
            or request['category'] != 'historical_alert_obsolete' or request['target'] != 'operator'
            or request['terminal_event_id'] != ''
            or not isinstance(request['authority_sha256'], str) or not HASH.fullmatch(request['authority_sha256'])
            or not isinstance(request['execution_id'], str)
            or not re.fullmatch(r'execution_[a-f0-9]{24}', request['execution_id'])
            or not isinstance(request['audit_references'], list)
            or any(not isinstance(x, str) for x in request['audit_references'])
            or request['audit_references'] != sorted(set(request['audit_references']))):
        raise ValueError('invalid notification-only dismissal binding')
    # Share only exact field/type/audit validation, never archive eligibility.
    equivalent = {k: v for k, v in request.items() if k in FIELDS}
    equivalent.update(schema='operator-archive/v1', operation='archive')
    _request(equivalent, identity, record_id, dry_run)
    return json.loads(json.dumps(request))


def prepare_alert_dismissal(state, *, record_id, identity, reason, approval_reference,
                            approval_quote, evidence_references):
    """Authenticated read-only exact preparation; rejects, never prunes, authority."""
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    _operator(identity)
    with _locked_state(state):
        raw, digests, events = _raw(state)
        source, execution_id, linked, audit = _inspect(events, record_id)
        last = {e.task_id: e.id for e in events}
        request = dict(schema=SCHEMA, operation='dismiss_watchdog_alert', disposition=DISPOSITION,
            record_type='thread', record_id=record_id, target='operator', expected_event_id=last[record_id],
            source_event_id=source.id, history_sha256=digests[record_id],
            authority_sha256=hashlib.sha256(raw).hexdigest(), execution_id=execution_id,
            related_revisions={key: dict(expected_event_id=last[key], history_sha256=digests[key]) for key in sorted(linked - {record_id})},
            audit_references=audit, category='historical_alert_obsolete', reason=reason,
            approval_reference=approval_reference, approval_quote=approval_quote,
            approval_sha256=hashlib.sha256(approval_quote.encode()).hexdigest(),
            evidence_references=evidence_references, terminal_event_id='')
        return _validate_request(request, identity, record_id, True)


def _metadata(request, source, timestamp):
    return dict(operator='operator', operation='operator_alert_dismissal', request=request,
        request_sha256=hashlib.sha256(json.dumps(request, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        source_actor_identity_bound=str(source.payload.get('actor_identity_bound', 'missing')).lower(),
        retired_at=timestamp, abandoned='obsolete_watchdog_notification_only',
        lineage_completion_asserted=False, linked_obligations_authorized=False)


def dismiss_alert(state, *, record_id, request, identity, dry_run=True):
    from .replica_authority import assert_state_authority
    assert_state_authority(state)
    r = _validate_request(request, identity, record_id, dry_run)
    with _locked_state(state):
        raw, digests, events = _raw(state)
        history = [e for e in events if e.task_id == record_id]
        retries = [e for e in history if e.type in ARCHIVE_TYPES]
        if retries:
            if len(retries) != 1:
                raise ValueError('ambiguous dismissal retry')
            action = retries[0]
            metadata = action.payload.get('retirement', {})
            if (metadata != _metadata(r, history[0], action.timestamp)
                    or action.payload.get('latest_at') != action.timestamp):
                raise ValueError('conflicting dismissal retry')
            index = events.index(action)
            # Exact whole-authority prefix fencing. Only selected thread reads may
            # follow the append on retry; unrelated concurrent changes fail closed.
            prefix = hashlib.sha256()
            for line in raw.splitlines(keepends=True):
                if line.strip() and json.loads(line, object_pairs_hook=_pairs)['id'] == action.id:
                    break
                prefix.update(line)
            if prefix.hexdigest() != r['authority_sha256']:
                raise ValueError('original authority snapshot changed after dismissal')
            if any(e.task_id != record_id or e.type != 'thread.read' for e in events[index + 1:]):
                raise ValueError('authority changed after dismissal; inspect exact recorded action')
            _validate_history(history, record_id)
            if not dry_run:
                _acknowledge_replay_unlocked(state, action)
            return dict(record=action.payload, event_id=action.id, changed=False, dry_run=dry_run)
        if hashlib.sha256(raw).hexdigest() != r['authority_sha256']:
            raise ValueError('stale exact authority snapshot')
        source, execution_id, linked, audit = _inspect(events, record_id)
        last = {e.task_id: e.id for e in events}
        expected = {key: dict(expected_event_id=last[key], history_sha256=digests[key]) for key in linked - {record_id}}
        if (source.id != r['source_event_id'] or last[record_id] != r['expected_event_id']
                or digests[record_id] != r['history_sha256'] or execution_id != r['execution_id']
                or expected != r['related_revisions'] or audit != r['audit_references']):
            raise ValueError('stale or incomplete exact dismissal fences')
        timestamp = _now()
        metadata = _metadata(r, source, timestamp)
        # Only the selected, validated history is projected for the write.
        # Unrelated business snapshots are neither coerced nor rewritten.
        record = _project_threads(state, history)[record_id]
        updated = replace(record, status='retired', unread=False, latest_at=timestamp,
                          retirement_json=json.dumps(metadata, sort_keys=True))
        payload = _thread_event_payload(updated)
        if dry_run:
            return dict(record=payload, event_id=None, changed=False, dry_run=True)
        event = _event('thread.operator_archived', record_id, timestamp, payload)
        _append_event_unlocked(state, event)
        return dict(record=payload, event_id=event.id, changed=True, dry_run=False)
