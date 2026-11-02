"""Canonical raw thread structure; caller authorization is deliberately separate."""
from enum import Enum
from typing import Mapping, TypedDict, cast


class IdempotencyEnvelope(TypedDict, total=False):
    idempotency_key: str
    idempotency_principal: str | None
    idempotency_request: Mapping[str, object]


IDEMPOTENCY_FIELDS = frozenset(IdempotencyEnvelope.__annotations__)


def validate_idempotency_envelope(payload: Mapping[str, object]) -> IdempotencyEnvelope:
    """Accept canonical envelopes and historical key-only events, never authority.

    Domain validators still reject every unrelated unknown snapshot field.
    An envelope is event-local metadata, not a persistent domain snapshot.
    """
    envelope = {k: payload[k] for k in IDEMPOTENCY_FIELDS if k in payload}
    if not envelope:
        return {}
    key = envelope.get("idempotency_key")
    if not isinstance(key, str) or not 1 <= len(key) <= 128 or key != key.strip():
        raise ValueError("malformed history idempotency key")
    if set(envelope) != {"idempotency_key"}:
        principal = envelope.get("idempotency_principal")
        request = envelope.get("idempotency_request")
        if (set(envelope) != IDEMPOTENCY_FIELDS
                or (principal is not None and not isinstance(principal, str))
                or not isinstance(request, Mapping)
                or any(not isinstance(k, str) for k in request)):
            raise ValueError("malformed history idempotency envelope")
    return cast(IdempotencyEnvelope, envelope)


def completion_supersedes(*, status: str, target: str, actor: str,
                          actor_identity_bound: bool,
                          prior_terminal: Mapping[str, object] | None) -> bool:
    """Only an authenticated target may replace a nonauthoritative completion."""
    return (
        status == "done"
        and actor_identity_bound is True
        and actor.strip().casefold() == target.strip().casefold()
        and prior_terminal is not None
        and not (
            prior_terminal.get("actor_identity_bound") is True
            and isinstance(prior_terminal.get("done_by"), str)
            and cast(str, prior_terminal["done_by"]).strip().casefold() == target.strip().casefold()
        )
    )


def handoff_completion_supersedes(previous: Mapping[str, object],
                                  current: Mapping[str, object]) -> bool:
    """Mirror complete_handoff's target-bound correction, not a terminal retry.

    Structural callers validate field types and immutable ownership separately.
    Missing historical identity is nonauthoritative, as it is in the writer.
    """
    target = previous.get("to_agent")
    actor = current.get("completed_by")
    return (
        previous.get("status") == "completed"
        and current.get("status") == "completed"
        and current.get("actor_identity_bound") is True
        and isinstance(target, str) and isinstance(actor, str)
        and actor.strip().casefold() == target.strip().casefold()
        and not (
            previous.get("actor_identity_bound") is True
            and str(previous.get("completed_by", "")).strip().casefold()
            == target.strip().casefold()
        )
    )


class HistoricalAckPolicy(Enum):
    REQUIRE_IDENTITY_FIELD = "require_identity_field"
    ALLOW_MISSING_IDENTITY = "allow_missing_ack_identity"


def _validated_abandonment(payload):
    metadata = payload.get("retirement", {})
    if metadata.get("operation") != "abandon":
        return False
    fields = {"operation", "category", "operator", "retired_at", "reason",
              "approval_reference", "prior_status"}
    if (set(metadata) != fields
            or any(not isinstance(metadata[k], str) or not metadata[k].strip()
                   or metadata[k] != metadata[k].strip() for k in fields)
            or metadata["category"] != "stale_no_longer_needed"
            or metadata["operator"] != "operator"
            or metadata["prior_status"] not in {"open", "acked"}
            or metadata["retired_at"] != payload["latest_at"]
            or len(metadata["reason"]) > 1024 or len(metadata["approval_reference"]) > 1024):
        raise ValueError("malformed operator abandonment disposition")
    return True


def validate_thread_history(events, identifier, *, historical_ack_policy=HistoricalAckPolicy.REQUIRE_IDENTITY_FIELD):
    """Validate raw append-order snapshots without coercion or identity invention.

    The archival policy permits only an absent ACK identity field, never an
    invalid field or a missing DONE field. Boolean False remains structural
    evidence, not authorization. Callers retain actor/owner and source gates.
    """
    if not isinstance(historical_ack_policy, HistoricalAckPolicy):
        raise ValueError("unsupported historical ACK policy")
    immutable = {"id", "type", "actor", "target", "channel", "severity", "title", "body", "created_at",
                 "completion_artifact", "completion_anchor", "continuation_thread_id"}
    strings = immutable | {"status", "latest_at", "acked_at", "acked_by", "done_at", "done_by", "read_at",
                           "evidence_artifact", "evidence_anchor", "evidence_method"}
    required = {"id", "type", "actor", "target", "channel", "severity", "title", "body", "created_at",
                "status", "latest_at"}
    changes = {
        "thread.read": {"read_at", "unread"},
        "thread.message.posted": {"latest_at", "unread"},
        "thread.acknowledged": {"status", "latest_at", "unread", "acked_at", "acked_by"},
        "thread.done": {"status", "latest_at", "unread", "pending", "done_at", "done_by",
                        "evidence_artifact", "evidence_anchor", "evidence_method"},
        "thread.retired": {"status", "latest_at", "unread", "pending", "retirement"},
    }
    previous = None
    prior_terminal = None
    messages = []
    seen = set()
    notification_claims = {}
    for event in events:
        if event.task_id != identifier:
            continue
        p = event.payload
        if not isinstance(p, dict) or not isinstance(event.id, str) or not event.id or event.id in seen:
            raise ValueError("malformed or duplicate raw thread event")
        seen.add(event.id)
        if event.type in {"thread.notification_sent", "thread.notification_failed"}:
            # Notification bookkeeping is not a lifecycle snapshot.
            fields = ({"thread_id", "kind", "title", "target", "channel", "severity", "text", "notified_at"}
                      if event.type == "thread.notification_sent"
                      else {"thread_id", "kind", "detail", "failed_at"})
            current_failure = event.type == "thread.notification_failed" and "claim_event_id" in p
            if current_failure:
                fields = fields | {"claim_event_id"}
            if (set(p) != fields or previous is None or p.get("thread_id") != identifier
                    or p.get("kind") not in {"notification", "escalation"}
                    or any(not isinstance(v, str) for v in p.values())):
                raise ValueError("malformed thread notification history")
            if event.type == "thread.notification_sent":
                if any(p.get(k) != previous[k] for k in ("title", "target", "channel", "severity")):
                    raise ValueError("thread notification binding mismatch")
                notification_claims[p["kind"]] = event.id
            elif current_failure:
                if not p["claim_event_id"] or notification_claims.get(p["kind"]) != p["claim_event_id"]:
                    raise ValueError("thread notification claim binding mismatch")
                del notification_claims[p["kind"]]
            # Generationless historical failures remain structural evidence;
            # like the canonical projection, they cannot release a live claim.
            continue
        if event.type not in changes and event.type != "thread.created":
            raise ValueError("unknown lineage in selected thread history")
        validate_idempotency_envelope(p)
        extras = {"unread", "pending", "retirement", "messages", "actor_identity_bound", "text", "posted_by",
                  "idempotency_key"}
        if (not required <= p.keys() or set(p) - strings - extras - IDEMPOTENCY_FIELDS
                or any(not isinstance(p.get(k, ""), str) for k in strings | {"text", "posted_by", "idempotency_key"})
                or p.get("id") != identifier or p.get("type") not in {"ask", "handoff", "blocker", "update", "status"}
                or p.get("severity") not in {"info", "notice", "warn", "critical"}
                or any(not p.get(k) for k in ("actor", "target", "created_at", "latest_at"))
                or type(p.get("unread")) is not bool or type(p.get("pending")) is not bool
                # Legacy/non-lifecycle producers serialize unknown provenance as
                # null. It is not False and grants no retirement/ACK/DONE authority.
                or (p.get("actor_identity_bound") is not None and type(p["actor_identity_bound"]) is not bool)
                or not isinstance(p.get("retirement", {}), dict)):
            raise ValueError("malformed raw thread snapshot")
        status = p["status"]
        abandonment = _validated_abandonment(p)
        if (status not in {"open", "acked", "done", "retired"}
                or p["pending"] != (p["type"] in {"ask", "handoff", "blocker"} and status not in {"done", "retired"})
                or bool(p.get("acked_at")) != bool(p.get("acked_by"))
                or bool(p.get("done_at")) != bool(p.get("done_by"))
                or (status == "open" and (p.get("acked_at") or p.get("done_at")))
                or (status == "acked" and (not p.get("acked_at") or p.get("done_at")))
                or (status == "done" and not p.get("done_at"))
                or (status == "retired" and (p.get("done_at") or (p.get("acked_at") and not abandonment)))
                or bool(p.get("retirement")) != (status == "retired")):
            raise ValueError("contradictory raw thread lifecycle")
        snapshot = {k: p.get(k, "") for k in strings}
        snapshot.update(unread=p["unread"], pending=p["pending"], retirement=p.get("retirement", {}))
        if previous is None:
            if event.type != "thread.created" or status != "open":
                raise ValueError("missing original open thread creation")
            creation_identity_bound = p.get("actor_identity_bound")
        else:
            # Non-lifecycle snapshots re-serialize the thread's creation provenance
            # (the projection reads it only from thread.created). ACK/DONE carry the
            # acting actor's own binding instead, so they are checked separately.
            if (event.type not in {"thread.acknowledged", "thread.done"}
                    and p.get("actor_identity_bound") != creation_identity_bound):
                raise ValueError("raw thread creation provenance changed")
            if event.type == "thread.created":
                raise ValueError("duplicate thread creation")
            allowed = changes[event.type]
            if any(snapshot[k] != previous[k] for k in snapshot.keys() - allowed):
                raise ValueError("raw thread immutable binding, continuation, or lifecycle changed")
            before = previous["status"]
            if event.type == "thread.retired" and abandonment:
                if p["retirement"]["prior_status"] != before:
                    raise ValueError("abandonment prior status does not match raw history")
            transition = {"thread.acknowledged": ({"open"}, "acked"),
                          "thread.done": ({"open", "acked"}, "done"),
                          "thread.retired": ({"open", "acked"} if abandonment else {"open"}, "retired")}.get(event.type)
            supersession = event.type == "thread.done" and completion_supersedes(
                status=before, target=p["target"], actor=p.get("done_by", ""),
                actor_identity_bound=p.get("actor_identity_bound") is True, prior_terminal=prior_terminal,
            )
            if transition and ((before not in transition[0] and not supersession) or status != transition[1]):
                raise ValueError("illegal raw thread lifecycle transition")
            if before == "retired" and event.type != "thread.read":
                raise ValueError("retired thread lifecycle changed")
        if event.type == "thread.read" and p["unread"]:
            raise ValueError("read snapshot must clear unread")
        if event.type == "thread.message.posted" and any(
                not isinstance(p.get(k), str) or not p[k].strip() for k in ("text", "posted_by")):
            raise ValueError("malformed raw thread reply")
        if event.type in {"thread.acknowledged", "thread.done"}:
            if (type(p.get("actor_identity_bound")) is not bool
                    and not (historical_ack_policy is HistoricalAckPolicy.ALLOW_MISSING_IDENTITY
                             and event.type == "thread.acknowledged"
                             and "actor_identity_bound" not in p)):
                raise ValueError("unproven lifecycle actor identity binding")
            actor_field = "acked_by" if event.type == "thread.acknowledged" else "done_by"
            if p.get("text") and p.get("posted_by") != p[actor_field]:
                raise ValueError("lifecycle reply actor mismatch")
        if event.type == "thread.message.posted":
            messages.append({"actor": p["posted_by"], "text": p["text"], "created_at": p["latest_at"]})
        if "messages" in p and p["messages"] != messages:
            raise ValueError("malformed or rewritten raw thread messages")
        if status != "done" and any(p.get(k) for k in ("evidence_artifact", "evidence_anchor", "evidence_method")):
            raise ValueError("completion evidence without completion")
        if event.type == "thread.done":
            prior_terminal = {"done_by": p["done_by"], "actor_identity_bound": p["actor_identity_bound"]}
        previous = snapshot
    if previous is None:
        raise ValueError("missing selected thread history")
