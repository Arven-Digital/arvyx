"""Proposed standalone mTLS receiver, NOT the external arvyx-secret broker.

Run only after approved enrollment: python -m arvyx_control.secret_delivery_receiver
--config /operator-owned/config.json. No values accepted in argv or environment.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import secrets
import ssl
import threading
import time

from .secret_delivery_protocol import HEX, IDENT, KEY, Principal, Receipts, Rejected, body, peer_pin, private_json, reply
from .secret_delivery_writer import Destination, DeliveryError


class Receiver:
    def __init__(self, target, agent, runtime, client_pins, destination: Destination, receipts: Receipts):
        if not all(isinstance(x, str) and IDENT.fullmatch(x) for x in (target, agent, runtime)) or not client_pins or not all(HEX.fullmatch(x) for x in client_pins):
            raise Rejected()
        self.target, self.agent, self.runtime = target, agent, runtime
        self.client_pins = frozenset(client_pins)
        self.destination = destination
        self.receipts = receipts
        self.preparations = {}
        self.lock = threading.Lock()

    def operate(self, payload):
        action = payload.get("action")
        expected = {"action", "target", "agent", "runtime", "key", "actor"}
        if action == "send":
            expected |= {"value", "delivery_id", "version", "overwrite"}
        elif action != "prepare":
            raise Rejected()
        if set(payload) != expected or (payload["target"], payload["agent"], payload["runtime"]) != (self.target, self.agent, self.runtime):
            raise Rejected()
        key = payload["key"]
        actor = payload['actor']
        Principal(actor, time.time() + 1).check()
        if not isinstance(key, str) or not KEY.fullmatch(key) or key not in self.destination.allowed_keys:
            raise Rejected()
        if action == "prepare":
            prepared = self.destination.prepare(key)
            token = secrets.token_urlsafe(32)
            with self.lock:
                self.preparations = {k: v for k, v in self.preparations.items() if v[1] > time.time()}
                if len(self.preparations) >= 128:
                    raise Rejected()
                self.preparations[token] = (prepared, time.time() + 120, actor)
            return {"exists": prepared.exists, "version": token}
        delivery_id = payload["delivery_id"]
        previous = self.receipts.get(delivery_id, actor)
        if previous:
            if previous["key"] != key or previous["target"] != self.target:
                raise Rejected()
            return {"status": previous["status"]}
        if type(payload["overwrite"]) is not bool or not isinstance(payload["value"], str) or len(payload["value"].encode()) > 65536:
            raise Rejected()
        with self.lock:
            preparation = self.preparations.pop(payload["version"], None)
        if not preparation or preparation[1] <= time.time() or preparation[2] != actor:
            raise Rejected()
        prepared = preparation[0]
        if prepared.key != key or prepared.exists != payload["overwrite"]:
            raise Rejected()
        fresh, receipt = self.receipts.reserve(delivery_id, self.target, key, actor)
        if not fresh:
            return {"status": receipt["status"]}
        status = "ambiguous"
        try:
            self.destination.write(key, payload["value"], overwrite_version=prepared.version)
            status = "saved"
        except DeliveryError as exc:
            code = str(exc)
            if code in ("version-conflict", "overwrite-required"):
                status = code
            elif code in {"invalid-name", "key-not-enrolled", "unsupported-value", "unsupported-file", "duplicate-key", "invalid-destination", "unsafe-destination"}:
                status = "rejected"
            # Unknown codes and any I/O failure remain conservatively ambiguous.
        except Exception:
            pass
        self.receipts.finish(delivery_id, status, actor)
        return {"status": status}

    def handler(self):
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                try:
                    if peer_pin(self) not in receiver.client_pins or self.path != "/v1/deliver":
                        raise Rejected()
                    result = receiver.operate(body(self))
                    reply(self, 200, result)
                except Exception:
                    reply(self, 400, {"error": "secret-delivery-rejected"})

            def do_GET(self):
                reply(self, 405, {"error": "secret-delivery-rejected"})

        return Handler


def tls_context(config, *, require_client=True):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config["certificate"], config["private_key"])
    context.load_verify_locations(config["client_ca"])
    context.verify_mode = ssl.CERT_REQUIRED if require_client else ssl.CERT_OPTIONAL
    return context


def main():
    parser = argparse.ArgumentParser(description="Disabled-until-enrolled Secret Delivery receiver")
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    try:
        config = private_json(args.config)
        if config.get("enabled") is not True:
            raise Rejected()
        destination = Destination(config["directory"], config["filename"], config["owner_uid"], allowed_keys=frozenset(config["allowed_keys"]))
        receiver = Receiver(config["target"], config["agent"], config["runtime"], config["sender_client_sha256"], destination, Receipts(Path(config["receipts"])))
        from .secret_delivery_server import SecretTLSServer
        server = SecretTLSServer((config["bind"], config["port"]), receiver.handler(), tls_context(config))
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    except Exception:
        raise SystemExit("secret-delivery-receiver-unavailable") from None


if __name__ == "__main__":
    main()
