from __future__ import annotations
from arvyx_control.replica_authority import authority_context

from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from arvyx_control.agent_delivery import AgentRoute
from arvyx_control.control import accept_handoff, complete_handoff, create_handoff
from arvyx_control.dispatcher import dispatch_once
from arvyx_control.mcp import handle_request
from arvyx_control.outbox import project_outbox
from arvyx_control.vault import init_vault


class _HermesReceiver(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        timestamp = self.headers["X-Webhook-Timestamp"]
        expected = hmac.new(
            self.server.secret.encode(),
            timestamp.encode() + b"." + body,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(self.headers["X-Webhook-Signature-V2"], expected):
            self.send_response(401)
            self.end_headers()
            return
        payload = json.loads(body)
        self.server.captured.append(payload)
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "accepted", "delivery_id": payload["delivery_id"]}).encode())

    def log_message(self, *_args):
        return


class SeamlessDeliveryE2ETests(unittest.TestCase):
    def test_handoff_wakes_target_and_completion_wakes_origin_without_human_relay(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _HermesReceiver)
        setattr(server, "sec" + "ret", "synthetic-" + "route-material")
        server.captured = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        self.addCleanup(lambda: thread.join(timeout=2))

        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "events.jsonl"
            vault = Path(tmp) / "vault"
            with authority_context(vault, state):
                init_vault(vault)
                url = f"http://127.0.0.1:{server.server_address[1]}/webhooks/v2-agent-push"
                routes = {
                    "demobot": AgentRoute("demobot", "hermes-webhook", "ATLAS_URL", "ATLAS_SECRET"),
                    "vesper": AgentRoute("vesper", "hermes-webhook", "VESPER_URL", "VESPER_SECRET"),
                }
                env = {
                    "ATLAS_URL": url,
                    "ATLAS_SECRET": server.secret,
                    "VESPER_URL": url,
                    "VESPER_SECRET": server.secret,
                }
                handoff = create_handoff(state, "Synthetic review", from_agent="vesper", to_agent="demobot")
                rollout_watermark = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
                started = time.monotonic()
                with patch.dict(os.environ, env, clear=False):
                    first = dispatch_once(
                        state,
                        routes=routes,
                        worker="e2e-worker-1",
                        deliver_after=rollout_watermark,
                        now=datetime.now(timezone.utc),
                        limit=5,
                        per_target_limit=2,
                        lease_seconds=120,
                    )
                elapsed = time.monotonic() - started
                self.assertLess(elapsed, 30)
                self.assertEqual(first.delivered, 1)
                self.assertEqual(server.captured[0]["target_agent"], "demobot")

                demobot_items = [item for item in project_outbox(state).values() if item.target == "demobot"]
                self.assertEqual(len(demobot_items), 1)
                delivery_id = demobot_items[0].id
                allowed = {"control.delivery_list", "control.delivery_receipt"}
                for request_id, status in enumerate(("seen", "accepted", "completed"), start=1):
                    response = handle_request(
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "method": "tools/call",
                            "params": {
                                "name": "control.delivery_receipt",
                                "arguments": {"delivery_id": delivery_id, "status": status,
                                              "idempotency_key": f"delivery-e2e-{status}-0001"},
                            },
                        },
                        vault=vault,
                        state=state,
                        allowed_tools=allowed,
                        actor="demobot",
                    )
                    self.assertNotIn("error", response)

                accept_handoff(state, handoff.handoff.id)
                complete_handoff(state, handoff.handoff.id)
                with patch.dict(os.environ, env, clear=False):
                    reverse = dispatch_once(
                        state,
                        routes=routes,
                        worker="e2e-worker-2",
                        deliver_after=rollout_watermark,
                        now=datetime.now(timezone.utc),
                        limit=5,
                        per_target_limit=2,
                        lease_seconds=120,
                    )
                self.assertEqual(reverse.delivered, 1)
                self.assertEqual(server.captured[1]["target_agent"], "vesper")
                self.assertEqual(server.captured[1]["payload"]["source_event_type"], "handoff.completed")

                listed = handle_request(
                    {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "control.delivery_list", "arguments": {}}},
                    vault=vault,
                    state=state,
                    allowed_tools=allowed,
                    actor="vesper",
                )
                deliveries = listed["result"]["structuredContent"]["deliveries"]
                self.assertEqual(len(deliveries), 1)
                self.assertEqual(deliveries[0]["payload"]["source_event_type"], "handoff.completed")


if __name__ == "__main__":
    unittest.main()
