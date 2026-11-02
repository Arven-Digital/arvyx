"""Source regressions for canonical history validation; execution not authorized."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from arvyx_control.operator_archive import _validate_archival_thread_history
from arvyx_control.retirement import _validate_thread_history
from arvyx_control.thread_history import HistoricalAckPolicy, validate_thread_history


IDENTIFIER = "thread_history_case"
VALIDATORS = (_validate_thread_history, _validate_archival_thread_history)


def event(kind, payload, index):
    return SimpleNamespace(type=kind, task_id=IDENTIFIER, id=f"event_{index}", payload=payload)


def history():
    root = dict(id=IDENTIFIER, type="ask", actor="operator", target="owner", channel="local",
                severity="info", title="Title", body="Body", created_at="t0", latest_at="t0",
                status="open", unread=True, pending=True)
    ack = dict(root, status="acked", latest_at="t1", acked_at="t1", acked_by="owner",
               actor_identity_bound=True)
    done = dict(ack, status="done", latest_at="t2", done_at="t2", done_by="owner",
                pending=False, evidence_artifact="artifact", evidence_anchor="anchor",
                evidence_method="method")
    return [event("thread.created", root, 0), event("thread.acknowledged", ack, 1),
            event("thread.done", done, 2)]


@pytest.mark.parametrize("validate", VALIDATORS)
def test_valid_completion(validate):
    validate(history(), IDENTIFIER)


def test_missing_ack_identity_is_archive_only():
    events = history()
    del events[1].payload["actor_identity_bound"]
    _validate_archival_thread_history(events, IDENTIFIER)
    with pytest.raises(ValueError, match="identity binding"):
        _validate_thread_history(events, IDENTIFIER)


@pytest.mark.parametrize("validate", VALIDATORS)
@pytest.mark.parametrize("value", [None, 0, "true"])
def test_invalid_ack_identity_is_never_historical(validate, value):
    events = history()
    events[1].payload["actor_identity_bound"] = value
    with pytest.raises(ValueError):
        validate(events, IDENTIFIER)


@pytest.mark.parametrize("validate", VALIDATORS)
def test_missing_done_identity_is_never_historical(validate):
    events = history()
    del events[2].payload["actor_identity_bound"]
    with pytest.raises(ValueError, match="identity binding"):
        validate(events, IDENTIFIER)


def test_archive_retains_distinct_ack_owner_gate():
    events = history()[:2]
    events[1].payload["acked_by"] = "other"
    _validate_thread_history(events, IDENTIFIER)
    with pytest.raises(ValueError, match="actor/owner mismatch"):
        _validate_archival_thread_history(events, IDENTIFIER)


@pytest.mark.parametrize("validate", VALIDATORS)
@pytest.mark.parametrize("mutation", ["immutable", "transition", "messages", "evidence", "duplicate", "unknown"])
def test_common_rejections(validate, mutation):
    events = history()
    if mutation == "immutable":
        events[1].payload["body"] = "rewritten"
    elif mutation == "transition":
        events.append(event("thread.acknowledged", deepcopy(events[1].payload), 3))
    elif mutation == "messages":
        events[1].payload["messages"] = [{"actor": "invented"}]
    elif mutation == "evidence":
        events[0].payload["evidence_artifact"] = "premature"
    elif mutation == "duplicate":
        events[1].id = events[0].id
    else:
        events[1].type = "thread.future"
    with pytest.raises(ValueError):
        validate(events, IDENTIFIER)


@pytest.mark.parametrize("validate", VALIDATORS)
def test_notification_shapes_and_bindings(validate):
    events = history()
    notice = dict(thread_id=IDENTIFIER, kind="notification", title="Title", target="owner",
                  channel="local", severity="info", text="Notice", notified_at="t1")
    events.insert(1, event("thread.notification_sent", notice, 3))
    validate(events, IDENTIFIER)
    notice["target"] = "other"
    with pytest.raises(ValueError, match="notification binding"):
        validate(events, IDENTIFIER)


@pytest.mark.parametrize("validate", VALIDATORS)
def test_retirement_allows_only_read_lifecycle(validate):
    events = history()[:1]
    retired = dict(events[0].payload, status="retired", latest_at="t1", pending=False,
                   unread=False, retirement={"operation": "retire_thread"})
    events.append(event("thread.retired", retired, 1))
    events.append(event("thread.read", dict(retired, read_at="t2"), 2))
    validate(events, IDENTIFIER)
    events.append(event("thread.message.posted", dict(retired, read_at="t2", text="reply",
                                                     posted_by="owner"), 3))
    with pytest.raises(ValueError, match="retired thread lifecycle"):
        validate(events, IDENTIFIER)


def test_unknown_policy_fails_closed():
    with pytest.raises(ValueError, match="unsupported historical ACK policy"):
        validate_thread_history(history(), IDENTIFIER, historical_ack_policy="allow")
    validate_thread_history(history(), IDENTIFIER,
                            historical_ack_policy=HistoricalAckPolicy.REQUIRE_IDENTITY_FIELD)
