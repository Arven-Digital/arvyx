from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import inspect
from io import BytesIO
import json
import threading
from urllib.error import HTTPError, URLError

import pytest

from arvyx_control import notifiers, outbox
from arvyx_control.control import post_thread, project_thread_notifications, read_events
from arvyx_control.replica_authority import authority_context


NOW = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)
FINALIZERS = ("mark_delivered", "record_failure", "defer_lease", "mark_delivery_ambiguous")


@pytest.fixture
def fixture_state(tmp_path):
    state = tmp_path / "events.jsonl"
    vault = tmp_path / "vault"
    vault.mkdir()
    with authority_context(vault, state):
        yield state, vault


def finish(name, state, claim, *, now=NOW, generation=None):
    fn = getattr(outbox, name)
    kwargs = dict(outbox_id=claim.id, worker="shared-worker", now=now)
    # Exercise the old mutation on RED, and the new generation contract on GREEN.
    if "claim_attempts" in inspect.signature(fn).parameters:
        kwargs["claim_attempts"] = claim.attempts if generation is None else generation
    if name == "record_failure":
        kwargs.update(detail="fixture rejection", transient=True, jitter=lambda _: 0)
    if name == "mark_delivery_ambiguous":
        kwargs["detail"] = "fixture unknown acceptance"
    return fn(state, **kwargs)


def claim_one(state, *, now=NOW, mode="direct"):
    outbox.enqueue(state, subject_id="fixture-thread", target="vesper",
                   payload={"delivery_mode": mode}, now=NOW)
    return outbox.claim_due(state, worker="shared-worker", now=now, lease_seconds=10)[0]


@pytest.mark.parametrize("mode", ["direct", "notification"])
@pytest.mark.parametrize("name", FINALIZERS)
def test_stale_claim_cannot_mutate_replacement(fixture_state, mode, name):
    state, _ = fixture_state
    old = claim_one(state, mode=mode)
    later = NOW + timedelta(seconds=11)
    replacement = outbox.claim_due(state, worker="shared-worker", now=later, lease_seconds=10)[0]
    assert replacement.attempts == old.attempts + 1
    before = state.read_bytes()
    with pytest.raises(ValueError):
        finish(name, state, old, now=later)
    assert state.read_bytes() == before
    assert outbox.project_outbox(state)[old.id] == replacement


@pytest.mark.parametrize("name", FINALIZERS)
def test_current_claim_finalizes_normally(fixture_state, name):
    state, _ = fixture_state
    claim = claim_one(state)
    result = finish(name, state, claim)
    assert result.status == {"mark_delivered": "delivered", "record_failure": "pending",
                             "defer_lease": "pending", "mark_delivery_ambiguous": "ambiguous_delivery"}[name]
    assert result.attempts == claim.attempts


@pytest.mark.parametrize("name", FINALIZERS)
@pytest.mark.parametrize("generation", [True, 1.0, "1", 0, -1])
def test_malformed_generation_does_not_alias_attempt_one(fixture_state, name, generation):
    state, _ = fixture_state
    claim = claim_one(state)
    before = state.read_bytes()
    with pytest.raises(ValueError):
        finish(name, state, claim, generation=generation)
    assert state.read_bytes() == before


@pytest.mark.parametrize("name", FINALIZERS)
def test_generation_argument_is_mandatory(fixture_state, name):
    state, _ = fixture_state
    claim = claim_one(state)
    kwargs = dict(outbox_id=claim.id, worker="shared-worker", now=NOW)
    if name == "record_failure":
        kwargs.update(detail="fixture", transient=True)
    elif name == "mark_delivery_ambiguous":
        kwargs["detail"] = "fixture"
    before = state.read_bytes()
    with pytest.raises(TypeError):
        getattr(outbox, name)(state, **kwargs)
    assert state.read_bytes() == before


def test_late_human_receipt_keeps_ambiguity_and_requires_original_generation(fixture_state):
    state, _ = fixture_state
    claim = claim_one(state, mode="decision_card")
    later = NOW + timedelta(seconds=11)
    assert outbox.claim_due(state, worker="shared-worker", now=later) == []
    before = state.read_bytes()
    with pytest.raises(ValueError):
        finish("mark_delivered", state, claim, now=later, generation=claim.attempts + 1)
    assert state.read_bytes() == before
    kwargs = dict(outbox_id=claim.id, worker="shared-worker", provider_receipt="fixture-message", now=later)
    if "claim_attempts" in inspect.signature(outbox.mark_delivered).parameters:
        kwargs["claim_attempts"] = claim.attempts
    late = outbox.mark_delivered(state, **kwargs)
    assert late.status == "ambiguous_delivery"
    assert late.provider_receipt == "fixture-message"
    assert outbox.claim_due(state, worker="shared-worker", now=later) == []


def test_two_senders_barrier_rejects_old_result(fixture_state):
    state, vault = fixture_state
    old = claim_one(state)
    replacement_ready = threading.Event()
    old_finished = threading.Event()
    results = []

    def sender_a():
        with authority_context(vault, state):
            assert replacement_ready.wait(5)
            try:
                finish("mark_delivered", state, old, now=NOW + timedelta(seconds=11))
                results.append("stale accepted")
            except ValueError:
                results.append("stale refused")
            finally:
                old_finished.set()

    thread = threading.Thread(target=sender_a)
    thread.start()
    later = NOW + timedelta(seconds=11)
    replacement = outbox.claim_due(state, worker="shared-worker", now=later)[0]
    replacement_ready.set()
    assert old_finished.wait(5)
    thread.join(5)
    assert not thread.is_alive()
    assert results == ["stale refused"]
    assert finish("mark_delivered", state, replacement, now=later).status == "delivered"


def test_dispatcher_integration_forwards_original_claim_generation(fixture_state):
    """Intentionally fails until dispatcher owner forwards all claim tokens."""
    from arvyx_control.agent_delivery import AgentDeliveryResult, AgentRoute
    from arvyx_control.dispatcher import dispatch_once

    state, vault = fixture_state
    item = outbox.enqueue(state, subject_id="fixture-thread", target="vesper", payload={}, now=NOW)
    sending = threading.Event()
    resume_old = threading.Event()
    replacement_sending = threading.Event()
    resume_new = threading.Event()
    results = {}
    current = [NOW]

    def deliver(claim, route, **kwargs):
        if claim.attempts == 1:
            sending.set()
            assert resume_old.wait(5)
        else:
            replacement_sending.set()
            assert resume_new.wait(5)
        return AgentDeliveryResult(True, "accepted", 200, "fixture accepted")

    def tick(label, tick_now):
        with authority_context(vault, state):
            results[label] = dispatch_once(
                state, routes={"vesper": AgentRoute("vesper", "hermes-webhook", "FIXTURE_URL", "FIXTURE_AUTH", 1)},
                worker="shared-worker", now=tick_now, clock=lambda: current[0],
                deliver_after=(NOW - timedelta(seconds=1)).isoformat(), limit=1, lease_seconds=10,
                environ={"FIXTURE_URL": "https://fixture.invalid/wake", "FIXTURE_AUTH": "fixture"},
                deliverer=deliver,
            )

    a = threading.Thread(target=tick, args=("old", NOW))
    b = threading.Thread(target=tick, args=("new", NOW + timedelta(seconds=11)))
    a.start()
    try:
        assert sending.wait(5)
        current[0] = NOW + timedelta(seconds=11)
        b.start()
        assert replacement_sending.wait(5)
        replacement = outbox.project_outbox(state)[item.id]
        resume_old.set()
        a.join(5)
        assert not a.is_alive()
        assert outbox.project_outbox(state)[item.id] == replacement
    finally:
        resume_old.set()
        resume_new.set()
        a.join(5)
        if b.ident is not None:
            b.join(5)
    assert results["old"].processing_errors == (f"{item.id}: lease lost before finalization",)
    assert results["old"].lost_leases == 1
    assert results["new"].delivered == 1
    assert outbox.project_outbox(state)[item.id].status == "delivered"


@pytest.mark.parametrize("adapter", ["webhook", "telegram"])
@pytest.mark.parametrize("failure", ["after_post", "body_timeout", "oversized", "exit_framing"])
def test_uncertain_post_retains_claim_and_suppresses_next_run(fixture_state, monkeypatch, tmp_path, adapter, failure):
    state, _ = fixture_state
    thread_id = post_thread(state=state, title="Fixture attention", thread_type="ask",
                            target="vesper", actor="fixture").thread.id
    calls = []

    class Response:
        status = 200

        def read(self, size):
            if failure == "body_timeout":
                raise TimeoutError("fixture timeout")
            return b"x" * size if failure == "oversized" else b"{}"

    @contextmanager
    def fake_open(request, timeout):
        calls.append(json.loads(request.data))  # remote consumed the POST
        if failure == "after_post":
            raise URLError("fixture disconnect")
        yield Response()
        if failure == "exit_framing":
            raise ValueError("incomplete HTTP response; nothing retried")

    monkeypatch.setattr(notifiers, "urlopen", fake_open)
    monkeypatch.setenv("FIXTURE_WEBHOOK", "https://fixture.invalid/hook")
    monkeypatch.setenv("FIXTURE_TOKEN", "123:TESTfixture")
    monkeypatch.setenv("FIXTURE_CHAT", "fixture-chat")
    config = tmp_path / "telegram.json"
    config.write_text(json.dumps(dict(adapter="telegram", bot_token_env="FIXTURE_TOKEN", chat_id_env="FIXTURE_CHAT")))
    kwargs = dict(state=state, adapter=adapter, webhook_url_env="FIXTURE_WEBHOOK")
    if adapter == "telegram":
        kwargs.update(config=config, webhook_url_env=None)
    first = notifiers.notify_and_deliver(**kwargs)
    assert [d.status for d in first.deliveries] == ["ambiguous"]
    assert not first.ok
    assert "notification" in project_thread_notifications(state)[thread_id]
    assert not any(e.type == "thread.notification_failed" for e in read_events(state))
    second = notifiers.notify_and_deliver(**kwargs)
    assert second.candidates == []
    assert len(calls) == 1


@pytest.mark.parametrize("status", [400, 429])
def test_http_rejection_releases_claim_for_retry(fixture_state, monkeypatch, status):
    state, _ = fixture_state
    post_thread(state=state, title="Fixture attention", thread_type="ask", target="vesper", actor="fixture")
    calls = []

    def reject(request, timeout):
        calls.append(request)
        raise HTTPError(request.full_url, status, "fixture rejection", {}, BytesIO(b"{}"))

    monkeypatch.setattr(notifiers, "urlopen", reject)
    monkeypatch.setenv("FIXTURE_WEBHOOK", "https://fixture.invalid/hook")
    for _ in range(2):
        result = notifiers.notify_and_deliver(state, adapter="webhook", webhook_url_env="FIXTURE_WEBHOOK")
        assert [d.status for d in result.deliveries] == ["failed"]
    assert len(calls) == 2


@pytest.mark.parametrize("status", [302, 408, 500, 503])
def test_uncertain_http_status_retains_claim(fixture_state, monkeypatch, status):
    state, _ = fixture_state
    thread_id = post_thread(state=state, title="Fixture attention", thread_type="ask",
                            target="vesper", actor="fixture").thread.id
    calls = []
    def reject(request, timeout):
        calls.append(request)
        raise HTTPError(request.full_url, status, "fixture uncertainty", {}, BytesIO(b"{}"))
    monkeypatch.setattr(notifiers, "urlopen", reject)
    monkeypatch.setenv("FIXTURE_WEBHOOK", "https://fixture.invalid/hook")
    first = notifiers.notify_and_deliver(state, adapter="webhook", webhook_url_env="FIXTURE_WEBHOOK")
    assert [d.status for d in first.deliveries] == ["ambiguous"]
    assert not first.ok
    assert "notification" in project_thread_notifications(state)[thread_id]
    assert not any(e.type == "thread.notification_failed" for e in read_events(state))
    assert notifiers.notify_and_deliver(state, adapter="webhook", webhook_url_env="FIXTURE_WEBHOOK").candidates == []
    assert len(calls) == 1


@pytest.mark.parametrize("url,timeout", [("file:///fixture", 10), ("https://fixture.invalid/hook", 0),
                                         ("https://fixture.invalid/hook", float("nan")),
                                         ("https://user:pass@fixture.invalid/hook", 10)])
def test_definite_local_refusal_never_opens_transport(monkeypatch, url, timeout):
    calls = []

    @contextmanager
    def accept(*args, **kwargs):
        calls.append(args)
        class Response:
            status = 200

            def read(self, size):
                return b"{}"
        yield Response()

    monkeypatch.setattr(notifiers, "urlopen", accept)
    delivery = notifiers._WebhookNotifier(url=url, timeout=timeout).deliver({"text": "fixture"}, False)
    assert delivery.status == "failed"
    assert calls == []


def test_successful_post_remains_sent(monkeypatch):
    @contextmanager
    def accept(request, timeout):
        class Response:
            status = 200

            def read(self, size):
                return b"{}"
        yield Response()

    monkeypatch.setattr(notifiers, "urlopen", accept)
    result = notifiers._WebhookNotifier("https://fixture.invalid/hook", 10).deliver({"text": "fixture"}, False)
    assert result.status == "sent"


def test_uncertain_notification_expires_at_configured_dedupe_window(fixture_state, monkeypatch):
    from arvyx_control import health_ops

    state, _ = fixture_state
    thread_id = post_thread(state=state, title="Fixture attention", thread_type="ask",
                            target="vesper", actor="fixture").thread.id
    calls = []

    def uncertain(request, timeout):
        calls.append(request)
        raise URLError("fixture consumed POST then disconnected")

    monkeypatch.setattr(notifiers, "urlopen", uncertain)
    monkeypatch.setenv("FIXTURE_WEBHOOK", "https://fixture.invalid/hook")
    kwargs = dict(adapter="webhook", webhook_url_env="FIXTURE_WEBHOOK", escalate_after_minutes=100000)
    first = notifiers.notify_and_deliver(state, **kwargs)
    assert [d.status for d in first.deliveries] == ["ambiguous"]
    stamp = datetime.fromisoformat(project_thread_notifications(state)[thread_id]["notification"].replace("Z", "+00:00"))
    monkeypatch.setattr(health_ops, "_utcnow", lambda: stamp + timedelta(minutes=239))
    assert notifiers.notify_and_deliver(state, **kwargs).candidates == []
    monkeypatch.setattr(health_ops, "_utcnow", lambda: stamp + timedelta(minutes=240))
    expired = notifiers.notify_and_deliver(state, **kwargs)
    assert [d.status for d in expired.deliveries] == ["ambiguous"]
    assert len(calls) == 2  # existing expiry policy, not indefinite reconciliation
