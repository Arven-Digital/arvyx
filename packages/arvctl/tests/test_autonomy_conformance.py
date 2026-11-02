"""Agent-to-agent autonomy conformance.

Plays two identity-bound agents through the *whole* autonomous chain the way
a real runtime experiences it: every agent call goes through the HTTP ``/mcp``
gateway with the agent's own bearer token, the ``agent`` MCP profile, the
audit/idempotency gate, and the reference safe-mcp-bridge allowlist. Wakes and
session returns travel over a real signed HTTP hop to a fake fleet receiver.

Nothing here reaches into domain functions on the agent's behalf. The
dispatcher, execution worker, and reconciler run exactly as production runs
them. If a seam between the tool taxonomy, the HTTP gate, the bridge
allowlist, the wake prose, and the domain fences drifts, this suite fails
before a production canary does.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
import threading
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from arvyx_control.replica_authority import authority_context
from arvyx_control.agent_delivery import AgentRoute
from arvyx_control.api import handle_api_request
from arvyx_control.auth import issue_token
from arvyx_control.dispatcher import dispatch_once
from arvyx_control.execution import (
    claim_execution,
    deliver_execution_attempt,
    heartbeat_execution,
    materialize_executions,
    project_executions,
    queue_health,
    reconcile_executions,
)
from arvyx_control.outbox import project_outbox
from arvyx_control.vault import init_vault
from arvyx_control.watchdog import run_watchdog

REPO_ROOT = Path(__file__).resolve().parents[3]
REFERENCE_AGENT_POLICY = REPO_ROOT / "examples" / "safe-mcp-bridge" / "agent.json"
AGENT_SCOPES = ["control.read", "control.write", "control.delivery"]
LEASE_SECONDS = 120
# The production worker's default first-heartbeat window (B6).
FIRST_HEARTBEAT_SECONDS = 300

# One hundred whitespace-delimited Turkish words, the same shape the production
# canary demands. Counted by the same rule the server applies: str.split().
STORY = " ".join(
    [
        "Sabah", "erken", "kalkan", "Ada", "pencereden", "gökyüzüne", "baktı", "ve", "bugünün",
        "farklı", "olacağını", "hissetti.", "Bahçedeki", "eski", "ceviz", "ağacının", "altında",
        "küçük", "bir", "kutu", "buldu.", "Kutunun", "içinde", "sararmış", "bir", "harita",
        "vardı.", "Harita", "köyün", "arkasındaki", "tepeye", "işaret", "ediyordu.", "Ada",
        "çantasına", "su", "ve", "ekmek", "koydu,", "sonra", "yola", "çıktı.", "Tepeye",
        "vardığında", "rüzgar", "saçlarını", "dağıttı.", "İşaretli", "yerde", "kazmaya",
        "başladı.", "Toprağın", "altından", "bakır", "bir", "anahtar", "çıktı.", "Anahtarın",
        "üzerinde", "büyükannesinin", "adı", "yazıyordu.", "Ada", "gülümsedi;", "büyükannesi",
        "yıllar", "önce", "ona", "bir", "gün", "bir", "hazine", "bulacağını", "söylemişti.",
        "Evine", "dönerken", "anahtarı", "sıkıca", "tuttu.", "Akşam", "annesine", "her", "şeyi",
        "anlattı.", "Annesi", "eski", "sandığı", "açtı", "ve", "anahtar", "tam", "oturdu.",
        "İçinde", "mektuplar", "vardı.", "Hepsi", "Ada", "içindi,", "sonsuza", "dek.",
    ]
)


def _fresh_key(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


class _FleetReceiver(BaseHTTPRequestHandler):
    """Fake per-agent runtime endpoint plus a deliver-only return receiver.

    ``/wake`` accepts any signed wake and records it. ``/return`` behaves like
    the Hermes deliver-only receiver: it verifies the return credential,
    deduplicates on ``X-Request-ID`` before any provider send, and answers
    with the provider ``message_id``.
    """

    def do_POST(self) -> None:  # noqa: N802
        server: Any = self.server
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        credential = server.return_credential if self.path == "/return" else server.wake_credential
        timestamp = self.headers.get("X-Webhook-Timestamp", "")
        expected = hmac.new(
            credential.encode(), timestamp.encode() + b"." + body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(self.headers.get("X-Webhook-Signature-V2", ""), expected):
            self._reply(401, {"error": "bad signature"})
            return
        payload = json.loads(body)
        request_id = self.headers.get("X-Request-ID", "")
        with server.lock:
            if self.path == "/wake":
                server.wakes.append(payload)
                self._reply(202, {"status": "accepted", "delivery_id": payload["delivery_id"]})
                return
            if self.path != "/return":
                self._reply(404, {"error": "unknown path"})
                return
            if server.return_status:
                # Provider-side timeout: the send outcome is unknowable.
                self._reply(server.return_status, {"error": "provider timeout"})
                return
            receipt = server.receipts.get(request_id)
            if receipt is None:
                server.provider_sends += 1
                receipt = f"tg-message-{server.provider_sends}"
                server.receipts[request_id] = receipt
                server.returns.append(payload)
            self._reply(200, {"status": "sent", "message_id": receipt})

    def _reply(self, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args: Any) -> None:
        return


class _BridgedAgent:
    """A target runtime exactly as the bridge exposes it.

    One bearer token, raw ``/mcp`` JSON-RPC, the ``agent`` profile, and the
    reference allowlist. The idempotency key travels only inside the tool
    arguments, because that is all a stdio bridge client can send.
    """

    def __init__(
        self,
        case: unittest.TestCase,
        *,
        agent_id: str,
        token: str,
        vault: Path,
        state: Path,
        operator_secret: str,
        allowlist: set[str],
    ) -> None:
        self.case = case
        self.agent_id = agent_id
        self.token = token
        self.vault = vault
        self.state = state
        self.operator_secret = operator_secret
        self.allowlist = allowlist
        self.calls: list[str] = []

    def _rpc(self, method: str, params: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        response = handle_api_request(
            method="POST",
            path="/mcp",
            body={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            vault=self.vault,
            state=self.state,
            bearer_secret=self.operator_secret,
            authorization=f"Bearer {self.token}",
            mcp_profile="agent",
        )
        body = json.loads(response.body) if isinstance(response.body, str) else response.body
        return response.status, body

    def call(self, name: str, arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self.case.assertIn(
            name, self.allowlist, f"{name} is not in the reference agent bridge allowlist"
        )
        self.calls.append(name)
        return self._rpc("tools/call", {"name": name, "arguments": arguments})

    def result(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        status, body = self.call(name, arguments)
        self.case.assertEqual(status, 200, f"{self.agent_id} {name}: HTTP {status} {body}")
        self.case.assertNotIn("error", body, f"{self.agent_id} {name}: {body.get('error')}")
        return body["result"]["structuredContent"]

    def error(self, name: str, arguments: dict[str, Any]) -> str:
        status, body = self.call(name, arguments)
        if status != 200:
            return f"HTTP {status}: {body.get('error', body)}"
        self.case.assertIn("error", body, f"{self.agent_id} {name} unexpectedly succeeded: {body}")
        return str(body["error"].get("message", body["error"]))

    def advertised_tools(self) -> set[str]:
        status, body = self._rpc("tools/list", {})
        self.case.assertEqual(status, 200, body)
        return {tool["name"] for tool in body["result"]["tools"]}


class AgentToAgentAutonomyConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.state = root / "events.jsonl"
        self.vault = root / "vault"
        self.enterContext(authority_context(self.vault, self.state))
        init_vault(self.vault)
        self.operator_secret = "operator-shared-secret-for-conformance"
        policy = json.loads(REFERENCE_AGENT_POLICY.read_text(encoding="utf-8"))
        self.allowlist = set(policy["policy"]["allow_tools"])

        self.server: Any = ThreadingHTTPServer(("127.0.0.1", 0), _FleetReceiver)
        self.server.wake_credential = "synthetic-wake-" + uuid.uuid4().hex
        self.server.return_credential = "synthetic-return-" + uuid.uuid4().hex
        self.server.lock = threading.Lock()
        self.server.wakes = []
        self.server.returns = []
        self.server.receipts = {}
        self.server.provider_sends = 0
        self.server.return_status = 0
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: thread.join(timeout=2))
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        base = f"http://127.0.0.1:{self.server.server_address[1]}"

        self.routes = {
            "demobot": AgentRoute(
                "demobot", "hermes-webhook", "ATLAS_WAKE_URL", "ATLAS_WAKE_SECRET",
                return_url_env="ATLAS_RETURN_URL", return_credential_env="ATLAS_RETURN_SECRET",
            ),
            "vesper": AgentRoute("vesper", "hermes-webhook", "VESPER_WAKE_URL", "VESPER_WAKE_SECRET"),
        }
        self.env = {
            "ATLAS_WAKE_URL": f"{base}/wake",
            "ATLAS_WAKE_SECRET": self.server.wake_credential,
            "ATLAS_RETURN_URL": f"{base}/return",
            "ATLAS_RETURN_SECRET": self.server.return_credential,
            "VESPER_WAKE_URL": f"{base}/wake",
            "VESPER_WAKE_SECRET": self.server.wake_credential,
        }
        self.t0 = datetime.now(timezone.utc).replace(microsecond=0)
        self.watermark = (self.t0 - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
        self.demobot = self._agent("demobot")
        self.vesper = self._agent("vesper")

    def _agent(self, agent_id: str) -> _BridgedAgent:
        token = issue_token(self.vault, agent_id, scopes=AGENT_SCOPES, slot="runtime").token
        return _BridgedAgent(
            self,
            agent_id=agent_id,
            token=token,
            vault=self.vault,
            state=self.state,
            operator_secret=self.operator_secret,
            allowlist=self.allowlist,
        )

    def _tick(self, now: datetime):
        return dispatch_once(
            self.state,
            routes=self.routes,
            worker="conformance-dispatcher",
            deliver_after=self.watermark,
            now=now,
            clock=lambda: now,
            environ=self.env,
            limit=5,
            per_target_limit=2,
            lease_seconds=LEASE_SECONDS,
        )

    def _worker_tick(self, now: datetime):
        """One execution-worker tick, exactly as ``arvyx execution worker`` runs it."""
        capable = set(self.routes)
        materialize_executions(self.state, execution_capable_targets=capable, now=now)
        execution = claim_execution(
            self.state, worker="conformance-worker", execution_capable_targets=capable,
            now=now, lease_seconds=LEASE_SECONDS, max_attempts=8,
        )
        if execution is None:
            return None
        delivery = deliver_execution_attempt(
            execution, self.routes[execution.target], now=now, environ=self.env,
            lease_seconds=LEASE_SECONDS, state=self.state,
            first_heartbeat_seconds=FIRST_HEARTBEAT_SECONDS,
        )
        self.assertTrue(delivery.accepted, delivery.detail)
        heartbeat_execution(
            self.state, execution_id=execution.id, attempt_id=execution.attempt_id,
            worker="conformance-worker", now=now, lease_seconds=LEASE_SECONDS,
            detail=json.dumps(delivery.to_dict(), sort_keys=True),
            first_heartbeat_seconds=FIRST_HEARTBEAT_SECONDS,
        )
        return execution

    def _drain_worker(self, now: datetime) -> list[Any]:
        """Run worker ticks at one instant until nothing more is claimable."""
        claimed = []
        while (execution := self._worker_tick(now)) is not None:
            claimed.append(execution)
        return claimed

    def _assert_every_wake_resolves_for_its_owner(self) -> None:
        """Every wake the fleet received names a delivery its target can read
        back, and any execution it names is owned by that same target."""
        agents = {"demobot": self.demobot, "vesper": self.vesper}
        with self.server.lock:
            wakes = list(self.server.wakes)
        self.assertTrue(wakes)
        executions = project_executions(self.state)
        for wake in wakes:
            target = wake["target_agent"]
            mode = wake["payload"].get("delivery_mode", "direct")
            delivery = agents[target].result(
                "control.delivery_get", {"delivery_id": wake["delivery_id"]}
            )["delivery"]
            self.assertEqual(delivery["id"], wake["delivery_id"], mode)
            self.assertEqual(delivery["target"], target, mode)
            self.assertEqual(delivery["payload"], wake["payload"], mode)
            execution_id = wake["payload"].get("execution_id")
            if execution_id:
                self.assertEqual(
                    executions[execution_id].target, target,
                    f"{mode} wake to {target} names an execution owned by another identity",
                )

    def _wakes(self, *, mode: str | None, target: str) -> list[dict[str, Any]]:
        with self.server.lock:
            wakes = list(self.server.wakes)
        return [
            wake for wake in wakes
            if wake["target_agent"] == target and wake["payload"].get("delivery_mode") == mode
        ]

    def _post_thread(self) -> str:
        posted = self.vesper.result(
            "control.thread_post",
            {
                "title": "Elin için yüz kelimelik özgün Türkçe hikaye",
                "body": (
                    "Tam yüz kelimelik özgün bir Türkçe hikaye yaz ve operatörün sabit "
                    "oturum dönüş rotasıyla gönder; sağlayıcı makbuzunu okuyup DONE yaz."
                ),
                "type": "ask",
                "target": "demobot",
                "channel": "squad",
                "idempotency_key": _fresh_key("vesper-post"),
            },
        )
        return posted["thread"]["id"]

    def _run_until_receipt_wake(self) -> tuple[str, str, str, str, dict[str, Any]]:
        """Drive the chain up to the delivered receipt wake; return the ids."""
        thread_id = self._post_thread()

        # The assignment is execution-managed (REV-0493): the dispatcher sends
        # one informational notice, never a direct actionable wake. Only the
        # canonical execution wake below can start work.
        first = self._tick(self.t0)
        self.assertEqual(first.delivered, 1, first)
        self.assertEqual(self._wakes(mode=None, target="demobot"), [], "no direct actionable assignment wake")
        notices = self._wakes(mode="notification", target="demobot")
        self.assertEqual(len(notices), 1)
        wake = notices[0]
        self.assertIs(wake["payload"]["execution_managed"], True)
        self.assertEqual(wake["payload"]["source_event_type"], "thread.created")
        self.assertEqual(wake["payload"]["subject_id"], thread_id)
        self.assertNotIn("execution_id", wake["payload"])
        contract = wake["response_contract"]
        self.assertIn("do not start work, ACK, accept, or DONE", contract)
        for tool in ("control.execution_session_get", "control.delivery_receipt"):
            self.assertIn(tool, contract, f"assignment notice contract does not name {tool}")
        self.assertIn(wake["delivery_id"], contract)

        # Target runtime: only the delivery receipt for the notice; reading the
        # subject is allowed, ACK/DONE are not part of this notice's contract.
        self.demobot.result(
            "control.delivery_receipt",
            {"delivery_id": wake["delivery_id"], "status": "completed", "idempotency_key": _fresh_key("demobot-receipt")},
        )
        fetched = self.demobot.result("control.thread_get", {"thread_id": thread_id})
        self.assertEqual(fetched["thread"]["target"], "demobot")
        self.assertEqual(fetched["thread"]["status"], "open")

        # Execution worker materializes, leases, and wakes the fenced attempt.
        execution = self._worker_tick(self.t0 + timedelta(seconds=5))
        self.assertIsNotNone(execution, "the identity-bound assignment did not yield a live execution")
        self.assertEqual(execution.target, "demobot")
        self.assertEqual(execution.subject_id, thread_id)
        execution_wakes = self._wakes(mode="execution", target="demobot")
        self.assertEqual(len(execution_wakes), 1)
        payload = execution_wakes[0]["payload"]
        self.assertEqual(payload["execution_id"], execution.id)
        self.assertEqual(payload["attempt_id"], execution.attempt_id)
        self.assertEqual(payload["subject_id"], thread_id)
        self.assertEqual(payload["lease_seconds"], LEASE_SECONDS)
        contract = execution_wakes[0]["response_contract"]
        self.assertIn(execution.id, contract)
        self.assertIn(execution.attempt_id, contract)
        self.assertIn("control.execution_heartbeat", contract)
        self.assertIn("control.execution_session_return_request", contract)
        self.assertIn(str(LEASE_SECONDS), contract, "execution contract does not state the lease cadence")
        self.assertEqual(payload["first_heartbeat_seconds"], FIRST_HEARTBEAT_SECONDS)
        self.assertIn(
            f"within {FIRST_HEARTBEAT_SECONDS} seconds", contract,
            "execution contract does not state the first-heartbeat window",
        )

        # Target runtime: rediscover, fetch the fenced session, heartbeat with fresh keys.
        listed = self.demobot.result("control.execution_list", {"target": "demobot"})
        self.assertIn(execution.id, {item["id"] for item in listed["executions"]})
        session = self.demobot.result(
            "control.execution_session_get",
            {"execution_id": execution.id, "attempt_id": execution.attempt_id},
        )
        self.assertEqual(session["subject"]["thread"]["id"], thread_id)
        self.assertEqual(session["execution"]["attempt_id"], execution.attempt_id)
        self.assertEqual(session.get("session_returns"), [], "fresh attempt should expose no prior returns")
        heartbeat_key = _fresh_key("demobot-heartbeat")
        heartbeat_args = {
            "execution_id": execution.id, "attempt_id": execution.attempt_id,
            "lease_seconds": LEASE_SECONDS, "idempotency_key": heartbeat_key,
        }
        self.demobot.result("control.execution_heartbeat", heartbeat_args)
        replay_status, replay_body = self.demobot.call("control.execution_heartbeat", heartbeat_args)
        self.assertEqual(replay_status, 409, "a reused heartbeat key must not be replayed")
        # /mcp answers a completed-operation replay as a JSON-RPC error bound to
        # the current request id, never as a REST body or a second effect.
        self.assertEqual(replay_body["jsonrpc"], "2.0")
        self.assertEqual(replay_body["id"], 1)
        self.assertEqual(replay_body["error"]["message"], "operation_completed_no_replay")
        self.assertTrue(replay_body["error"]["data"]["operation_id"])
        self.demobot.result("control.execution_heartbeat", {**heartbeat_args, "idempotency_key": _fresh_key("demobot-heartbeat")})

        # Target runtime: the work product goes only through the fixed return route.
        requested = self.demobot.result(
            "control.execution_session_return_request",
            {
                "execution_id": execution.id,
                "attempt_id": execution.attempt_id,
                "message": STORY,
                "expected_word_count": 100,
                "idempotency_key": _fresh_key("demobot-return"),
            },
        )["session_return"]
        request_id = requested["request_id"]
        self.assertEqual(requested["word_count"], 100)
        self.assertEqual(requested["message_sha256"], hashlib.sha256(STORY.encode()).hexdigest())

        # Dispatcher: fixed return route, provider receipt, then exactly one continuation wake.
        second = self._tick(self.t0 + timedelta(seconds=10))
        self.assertGreaterEqual(second.delivered, 1, second)
        with self.server.lock:
            self.assertEqual(self.server.provider_sends, 1)
            self.assertEqual(self.server.returns[0]["message"], STORY)
            self.assertEqual(self.server.returns[0]["word_count"], 100)
            self.assertNotIn("target", self.server.returns[0])
        third = self._tick(self.t0 + timedelta(seconds=15))
        self.assertGreaterEqual(third.delivered, 1, third)
        receipt_wakes = self._wakes(mode="session_return_receipt", target="demobot")
        self.assertEqual(len(receipt_wakes), 1)
        receipt_payload = receipt_wakes[0]["payload"]
        self.assertEqual(receipt_payload["session_return_request_id"], request_id)
        self.assertEqual(receipt_payload["execution_id"], execution.id)
        self.assertEqual(receipt_payload["attempt_id"], execution.attempt_id)
        self.assertEqual(
            receipt_payload.get("subject_id"), thread_id,
            "receipt wake must name the thread the target has to complete",
        )
        self.assertEqual(receipt_payload.get("subject_type"), "thread")
        self.assertNotIn("message", receipt_payload)
        self.assertNotIn("provider_receipt", receipt_payload)
        contract = receipt_wakes[0]["response_contract"]
        self.assertIn(request_id, contract)
        self.assertIn(thread_id, contract, "receipt wake contract does not name the thread id")
        self.assertIn("control.execution_session_return_get", contract)
        self.assertIn("control.thread_done", contract)
        self.assertIn("text", contract, "receipt wake contract must say where the receipt citation goes")

        # Re-ticking never duplicates the human-visible send or the continuation.
        self._tick(self.t0 + timedelta(seconds=20))
        with self.server.lock:
            self.assertEqual(self.server.provider_sends, 1)
        self.assertEqual(len(self._wakes(mode="session_return_receipt", target="demobot")), 1)
        return thread_id, execution.id, execution.attempt_id, request_id, receipt_payload

    def test_agent_to_agent_thread_completes_end_to_end_through_the_bridge_surface(self) -> None:
        thread_id, execution_id, attempt_id, request_id, _ = self._run_until_receipt_wake()

        # Target runtime (possibly a fresh session): identity-bound receipt readback needs no key.
        readback = self.demobot.result(
            "control.execution_session_return_get", {"request_id": request_id}
        )["session_return"]
        self.assertEqual(readback["status"], "delivered")
        self.assertEqual(readback["provider_receipt"], "tg-message-1")
        self.assertTrue(readback["delivery_id"])
        self.assertEqual(readback["execution_id"], execution_id)

        # Canonical DONE cites the durable receipt in text; no evidence contract exists on this thread.
        done = self.demobot.result(
            "control.thread_done",
            {
                "thread_id": thread_id,
                "text": (
                    f"Hikaye teslim edildi. session_return={request_id} "
                    f"provider_receipt={readback['provider_receipt']} delivery={readback['delivery_id']} "
                    "readback=control.execution_session_return_get"
                ),
                "idempotency_key": _fresh_key("demobot-done"),
            },
        )
        self.assertEqual(done["thread"]["status"], "done")
        self.assertEqual(done["thread"]["done_by"], "demobot")

        # Worker/reconciler: the target-authored DONE is the only terminal authority.
        reconcile_executions(self.state, now=self.t0 + timedelta(seconds=30))
        execution = project_executions(self.state)[execution_id]
        self.assertEqual(execution.status, "completed")
        self.assertEqual(execution.terminal_event_type, "thread.done")
        health = queue_health(
            self.state, execution_capable_targets=set(self.routes), now=self.t0 + timedelta(seconds=30)
        )
        self.assertEqual(health["live_execution_count"], 0)
        self.assertEqual(health["acked_without_live_execution_count"], 0)
        self.assertEqual(health["dead_lettered_count"], 0)
        self.assertEqual(health["held_count"], 0)

        # The originating agent is woken with a lifecycle notification and closes it.
        fourth = self._tick(self.t0 + timedelta(seconds=35))
        self.assertGreaterEqual(fourth.delivered, 1, fourth)
        notifications = self._wakes(mode="notification", target="vesper")
        self.assertEqual(len(notifications), 1)
        self.assertEqual(notifications[0]["payload"]["source_event_type"], "thread.done")
        self.assertEqual(notifications[0]["payload"]["subject_id"], thread_id)
        seen = self.vesper.result("control.delivery_list", {})["deliveries"]
        self.assertIn(notifications[0]["delivery_id"], {item["id"] for item in seen})
        self.vesper.result(
            "control.delivery_receipt",
            {
                "delivery_id": notifications[0]["delivery_id"],
                "status": "completed",
                "idempotency_key": _fresh_key("vesper-receipt"),
            },
        )

        # Negative controls: the finished attempt is inert and the send count stays one.
        self.assertIn(
            "not live",
            self.demobot.error(
                "control.execution_heartbeat",
                {"execution_id": execution_id, "attempt_id": attempt_id, "idempotency_key": _fresh_key("stale")},
            ),
        )
        self.assertIn(
            "not live",
            self.demobot.error(
                "control.execution_session_return_request",
                {
                    "execution_id": execution_id, "attempt_id": attempt_id,
                    "message": STORY, "expected_word_count": 100,
                    "idempotency_key": _fresh_key("stale-return"),
                },
            ),
        )
        self._tick(self.t0 + timedelta(seconds=40))
        with self.server.lock:
            self.assertEqual(self.server.provider_sends, 1)
        self.assertEqual(sum(1 for item in project_outbox(self.state).values() if item.status == "dead_lettered"), 0)

        # Every wake the chain emitted (assignment notice, execution, receipt
        # continuation, lifecycle notification) names a delivery its own target
        # can resolve. No direct actionable assignment wake exists.
        modes = {
            wake["payload"].get("delivery_mode", "direct") for wake in self.server.wakes
        }
        self.assertEqual(modes, {"execution", "session_return_receipt", "notification"})
        self._assert_every_wake_resolves_for_its_owner()

        # Every tool the chain used is advertised to this token through the agent profile.
        advertised = self.demobot.advertised_tools()
        self.assertEqual(set(self.demobot.calls) - advertised, set())
        self.assertEqual(set(self.vesper.calls) - self.vesper.advertised_tools(), set())

    def test_reclaimed_execution_finalizes_instead_of_sending_a_second_story(self) -> None:
        thread_id, execution_id, attempt_id, request_id, _ = self._run_until_receipt_wake()

        # The target never read back or completed; its lease expires and the worker reclaims.
        later = self.t0 + timedelta(seconds=LEASE_SECONDS + 90)
        reclaimed = self._worker_tick(later)
        self.assertIsNotNone(reclaimed, "expired lease was not reclaimed")
        self.assertEqual(reclaimed.id, execution_id)
        self.assertNotEqual(reclaimed.attempt_id, attempt_id)
        self.assertEqual(reclaimed.attempts, 2)

        # A fresh session on the new attempt sees the delivered return in the fenced session view.
        session = self.demobot.result(
            "control.execution_session_get",
            {"execution_id": execution_id, "attempt_id": reclaimed.attempt_id},
        )
        prior = session.get("session_returns")
        self.assertEqual(
            [(item["request_id"], item["status"], item["provider_receipt"]) for item in prior or []],
            [(request_id, "delivered", "tg-message-1")],
            "new attempt must see the delivered return it has to finalize",
        )
        contract = self._wakes(mode="execution", target="demobot")[-1]["response_contract"]
        self.assertIn("session_returns", contract, "re-wake contract does not tell the target to check prior returns")

        # A second human-visible return on the same execution lineage is refused.
        refusal = self.demobot.error(
            "control.execution_session_return_request",
            {
                "execution_id": execution_id,
                "attempt_id": reclaimed.attempt_id,
                "message": STORY,
                "expected_word_count": 100,
                "idempotency_key": _fresh_key("demobot-second-return"),
            },
        )
        self.assertIn("already", refusal)
        self.assertIn(request_id, refusal)
        self._tick(later + timedelta(seconds=5))
        with self.server.lock:
            self.assertEqual(self.server.provider_sends, 1)

        # The target finalizes through readback plus canonical DONE, closing the lineage.
        readback = self.demobot.result(
            "control.execution_session_return_get", {"request_id": request_id}
        )["session_return"]
        self.assertEqual(readback["provider_receipt"], "tg-message-1")
        self.demobot.result(
            "control.thread_done",
            {
                "thread_id": thread_id,
                "text": f"session_return={request_id} provider_receipt={readback['provider_receipt']}",
                "idempotency_key": _fresh_key("demobot-done"),
            },
        )
        reconcile_executions(self.state, now=later + timedelta(seconds=10))
        self.assertEqual(project_executions(self.state)[execution_id].status, "completed")
        with self.server.lock:
            self.assertEqual(self.server.provider_sends, 1)
        # Both fenced attempts were woken under their own resolvable delivery.
        self.assertEqual(len(self._wakes(mode="execution", target="demobot")), 2)
        self._assert_every_wake_resolves_for_its_owner()

    def test_session_return_problem_handed_to_a_peer_holds_after_bounded_blocked_retries(self) -> None:
        """Regression for thread_7e1f30377bb1_47f5d9 ("Odin AMC session return timeout").

        The owner's session return times out and it hands the execution-scoped
        problem to a peer. The peer is woken only for its *own* execution, can
        never read the owner's fenced execution, return, or delivery, reports
        BLOCKED, gets exactly one bounded re-wake, and is then parked in the
        canonical operator HOLD (escalated once) instead of looping.
        """
        self.server.return_status = 504
        self._post_thread()
        self._tick(self.t0)
        owner_execution = self._worker_tick(self.t0 + timedelta(seconds=5))
        self.assertEqual(owner_execution.target, "demobot")
        request_id = self.demobot.result(
            "control.execution_session_return_request",
            {
                "execution_id": owner_execution.id,
                "attempt_id": owner_execution.attempt_id,
                "message": STORY,
                "expected_word_count": 100,
                "idempotency_key": _fresh_key("demobot-return"),
            },
        )["session_return"]["request_id"]
        returned = self._tick(self.t0 + timedelta(seconds=10))
        self.assertEqual(returned.ambiguous, 1, returned)
        owner_return = self.demobot.result(
            "control.execution_session_return_get", {"request_id": request_id}
        )["session_return"]
        self.assertEqual(owner_return["status"], "ambiguous_delivery")

        # The owner hands its execution-scoped problem to a peer.
        handoff_thread = self.demobot.result(
            "control.thread_post",
            {
                "title": "demobot AMC session return timeout",
                "body": (
                    f"Inspect my fenced execution {owner_execution.id} attempt "
                    f"{owner_execution.attempt_id}; session return {request_id} "
                    f"delivery {owner_return['delivery_id']} timed out."
                ),
                "type": "blocker",
                "target": "vesper",
                "channel": "squad",
                "idempotency_key": _fresh_key("demobot-blocker"),
            },
        )["thread"]
        self._tick(self.t0 + timedelta(seconds=15))

        # The peer is woken for its own execution, never the owner's.
        claimed = self._drain_worker(self.t0 + timedelta(seconds=20))
        self.assertEqual([item.target for item in claimed], ["vesper"])
        peer_execution = claimed[0]
        self.assertEqual(peer_execution.subject_id, handoff_thread["id"])

        # The authority model refuses every foreign read the thread asks for.
        self.assertIn(
            "identity-bound target",
            self.vesper.error(
                "control.execution_session_get",
                {"execution_id": owner_execution.id, "attempt_id": owner_execution.attempt_id},
            ),
        )
        self.assertIn(
            "may only read its own deliveries",
            self.vesper.error("control.delivery_get", {"delivery_id": owner_return["delivery_id"]}),
        )
        self.assertIn(
            "unknown session return",
            self.vesper.error("control.execution_session_return_get", {"request_id": request_id}),
        )

        def report_blocked(text: str) -> None:
            self.vesper.result(
                "control.thread_reply",
                {"thread_id": handoff_thread["id"], "text": text, "idempotency_key": _fresh_key("vesper-blocked")},
            )

        report_blocked(
            f"BLOCKED: execution {owner_execution.id} belongs to demobot; my identity-bound "
            "session cannot inspect or reconcile it."
        )
        # Bounded retry: one re-wake after the attempt expires (plus backoff).
        # The peer never heartbeats, so its attempt lives to the end of the
        # first-heartbeat window opened by its accepted wake at +20 s.
        self.assertEqual(
            self._drain_worker(self.t0 + timedelta(seconds=LEASE_SECONDS + 40)), [],
            "an attempt inside its first-heartbeat window must not be re-woken",
        )
        second = self._drain_worker(self.t0 + timedelta(seconds=20 + FIRST_HEARTBEAT_SECONDS + 20))
        self.assertIn(peer_execution.id, {item.id for item in claimed + second})
        self.assertEqual(
            [item.attempts for item in second if item.id == peer_execution.id], [2],
        )
        # Same blocker, paraphrased by the model; nobody supplied new input.
        report_blocked("Blocked - still cannot access demobot's fenced execution or its session return.")

        # The next reclaim parks it in HOLD instead of waking the peer again.
        later = self.t0 + timedelta(seconds=20 + 2 * FIRST_HEARTBEAT_SECONDS + 80)
        third = self._drain_worker(later)
        self.assertNotIn(peer_execution.id, {item.id for item in third})
        held = project_executions(self.state)[peer_execution.id]
        self.assertEqual(held.status, "held")
        self.assertIn("BLOCKED", held.hold_reason)
        self.assertNotIn(peer_execution.id, {item.id for item in self._drain_worker(later + timedelta(hours=1))})
        self.assertEqual(len(self._wakes(mode="execution", target="vesper")), 2)

        # The HOLD is operator-visible and escalated exactly once.
        first_watch = run_watchdog(
            self.state, routes=self.routes, worker="conformance-watchdog",
            now=later + timedelta(hours=1), environ=self.env,
        )
        self.assertIn(peer_execution.id, first_watch["escalated"])
        self.assertIn("held_executions", first_watch["attention"])
        second_watch = run_watchdog(
            self.state, routes=self.routes, worker="conformance-watchdog",
            now=later + timedelta(hours=1, minutes=1), environ=self.env,
        )
        self.assertNotIn(peer_execution.id, second_watch["escalated"])

        # Session-return traffic only ever targeted the owner, and every wake
        # the peer (or owner) received resolves for its own identity.
        return_items = [
            item for item in project_outbox(self.state).values()
            if str(item.payload.get("delivery_mode", "")).startswith("session_return")
        ]
        self.assertTrue(return_items)
        self.assertEqual({item.target for item in return_items}, {"demobot"})
        self._assert_every_wake_resolves_for_its_owner()


if __name__ == "__main__":
    unittest.main()
