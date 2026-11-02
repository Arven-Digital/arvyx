"""Opt-in operator-only secret ingress; NEVER call the generic API journal."""
from __future__ import annotations

from dataclasses import dataclass, field
from http.cookies import SimpleCookie
import hmac
import json
from pathlib import Path
import secrets
import threading
import time
from urllib.parse import urlsplit

from .secret_delivery_protocol import KEY, Principal, Receipts, Rejected, Target, body, envelope, private_json, reply, validate_response

PREFIX = "/secret-delivery"
ROUTES = ("bootstrap", "prepare", "send", "status")
COOKIE = "__Host-amc-secret-session"


@dataclass(repr=False)
class Session:
    actor: str
    csrf: str = field(repr=False)
    expires: float
    preparations: dict = field(default_factory=dict, repr=False)


class SecretDelivery:
    def __init__(self, origin: str, targets: list[Target], receipts: Receipts, *, vault: Path | None = None):
        parsed = urlsplit(origin)
        if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise Rejected()
        self.vault = None if vault is None else Path(vault).resolve()
        self.origin = origin
        self.targets = {target.id: target for target in targets}
        if len(self.targets) != len(targets):
            raise Rejected()
        self.receipts = receipts
        self.sessions = {}
        self.lock = threading.Lock()

    @classmethod
    def from_manifest(cls, path: Path, vault: Path):
        """Separate operator-owned manifest, not wake routes or agent-supplied data."""
        from .replica_authority import assert_mutation_authority
        assert_mutation_authority(vault)
        config = private_json(path)
        if config.get("enabled") is not True:
            raise Rejected()
        targets = []
        for entry in config["targets"]:
            target = Target(**{**entry, "allowed_keys": tuple(entry["allowed_keys"])})
            registered = json.loads((vault / "registry" / "agents" / (target.agent + ".json")).read_text())
            if registered.get("id") != target.agent or registered.get("runtime_id") != target.runtime:
                raise Rejected()
            runtime = json.loads((vault / "registry" / "runtimes" / (target.runtime + ".json")).read_text())
            if runtime.get("id") != target.runtime:
                raise Rejected()
            targets.append(target)
        if set(config) != {'enabled', 'origin', 'targets', 'receipts'}:
            raise Rejected()
        return cls(config["origin"], targets, Receipts(Path(config["receipts"])), vault=vault)

    def handle(self, handler, principal: Principal):
        """Only the private edge passes an internally verified principal."""
        from .replica_authority import assert_mutation_authority, assert_bound_authority, ReplicaAuthorityUnavailable
        try:
            if self.vault is None:
                assert_bound_authority()
            else:
                assert_mutation_authority(self.vault)
        except ReplicaAuthorityUnavailable:
            reply(handler, 503, {"error": "mutation-authority-unavailable"})
            return
        try:
            if not isinstance(principal, Principal):
                raise Rejected()
            principal.check()
            route = urlsplit(handler.path)
            if handler.command != "POST" or route.query or route.fragment or route.path not in {PREFIX + "/" + name for name in ROUTES}:
                raise Rejected()
            if handler.headers.get_all("Origin") != [self.origin] or handler.headers.get_all("X-Secret-Delivery") != ["1"]:
                raise Rejected()
            if handler.headers.get("Sec-Fetch-Site") not in (None, "same-origin"):
                raise Rejected()
            action = route.path.rsplit("/", 1)[1]
            if action == "bootstrap":
                if body(handler) != {}:
                    raise Rejected()
                with self.lock:
                    self.sessions = {k: v for k, v in self.sessions.items() if v.expires > time.time()}
                    if len(self.sessions) >= 128:
                        raise Rejected()
                    sid = secrets.token_urlsafe(32)
                    principal.check()
                    session = Session(principal.sub, secrets.token_urlsafe(32), min(time.time() + 900, principal.expires))
                    self.sessions[sid] = session
                reply(handler, 200, {"csrf": session.csrf, "targets": [{"id": t.id, "agent": t.agent, "runtime": t.runtime, "allowed_keys": list(t.allowed_keys)} for t in self.targets.values()]}, f"{COOKIE}={sid}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=900")
                return
            cookies = SimpleCookie()
            cookies.load(handler.headers.get("Cookie", ""))
            sid = cookies[COOKIE].value if COOKIE in cookies else ""
            session = self.sessions.get(sid)
            csrf = handler.headers.get_all("X-Secret-CSRF", [])
            if not session or session.expires <= time.time() or session.actor != principal.sub or len(csrf) != 1 or not hmac.compare_digest(session.csrf, csrf[0]):
                raise Rejected()
            payload = body(handler)
            principal.check()
            # Intake can outlive or invalidate the authenticated session. Recheck
            # its identity and binding before target lookup or receipt reservation.
            if (self.sessions.get(sid) is not session or session.expires <= time.time()
                    or session.actor != principal.sub or len(csrf) != 1
                    or not hmac.compare_digest(session.csrf, csrf[0])):
                raise Rejected()
            original_expiry = min(session.expires, principal.expires)
            def publication_guard():
                principal.check()
                if (self.sessions.get(sid) is not session or time.time() >= original_expiry
                        or session.expires <= time.time() or session.actor != principal.sub
                        or not hmac.compare_digest(session.csrf, csrf[0])):
                    raise Rejected()
            result = self.operate(action, payload, session, publication_guard=publication_guard)
            reply(handler, 200, result)
        except Exception:
            # Do not echo payload, URL, exception, transport error or traceback.
            reply(handler, 400, {"error": "secret-delivery-rejected"})

    def operate(self, action, payload, session, *, publication_guard=None):
        original_expiry = session.expires
        def active():
            if time.time() >= original_expiry or session.expires <= time.time():raise Rejected()
            if publication_guard is not None:publication_guard()
        from .replica_authority import assert_mutation_authority, assert_bound_authority
        if self.vault is None:
            assert_bound_authority()
        else:
            assert_mutation_authority(self.vault)
        if action == "status":
            if set(payload) != {"delivery_id"}:
                raise Rejected()
            return {"receipt": self.receipts.get(payload["delivery_id"], session.actor)}
        expected = {"target", "key"} if action == "prepare" else {"target", "key", "value", "delivery_id", "confirmation", "overwrite"}
        if set(payload) != expected:
            raise Rejected()
        target = self.targets.get(payload["target"])
        key = payload["key"]
        if not target or not isinstance(key, str) or not KEY.fullmatch(key) or key not in target.allowed_keys:
            raise Rejected()
        if action == "prepare":
            active()
            response = validate_response('prepare', target.exchange({"action": "prepare", "target": target.id, "agent": target.agent, "runtime": target.runtime, "key": key, "actor": session.actor}))
            # Receiver is trusted to write, not to supply arbitrary dashboard text.
            if type(response.get("exists")) is not bool or not isinstance(response.get("version"), str) or len(response["version"]) > 256:
                raise Rejected()
            confirmation = secrets.token_urlsafe(32)
            with self.lock:
                session.preparations = {k: v for k, v in session.preparations.items() if v[4] > time.time()}
                if len(session.preparations) >= 32:
                    raise Rejected()
                session.preparations[confirmation] = (target.id, key, response["version"], response["exists"], time.time() + 120)
            return {"confirmation": confirmation, "exists": response["exists"], "target": target.id, "key": key}
        delivery_id = payload["delivery_id"]
        previous = self.receipts.get(delivery_id, session.actor)
        if previous:
            if previous["target"] != target.id or previous["key"] != key:
                raise Rejected()
            return {"receipt": previous}
        if not isinstance(payload["value"], str) or len(payload["value"].encode()) > 65536 or type(payload["overwrite"]) is not bool:
            raise Rejected()
        with self.lock:
            prepared = session.preparations.pop(payload["confirmation"], None)
        if not prepared or prepared[:2] != (target.id, key) or prepared[4] <= time.time() or prepared[3] != payload["overwrite"]:
            raise Rejected()
        outbound = {"action": "send", "target": target.id, "agent": target.agent, "runtime": target.runtime, "key": key, "value": payload["value"], "delivery_id": delivery_id, "version": prepared[2], "overwrite": prepared[3], "actor": session.actor}
        envelope(outbound)  # Full envelope, including UTF-8/escaping overhead.
        fresh, receipt = self.receipts.reserve(delivery_id, target.id, key, session.actor)
        if not fresh:
            return {"receipt": receipt}
        try:
            # Reservation can block on SQLite. Its ambiguous record is retained
            # if authentication expires or the exact session is removed/replaced.
            active()
            result = validate_response('send', target.exchange(outbound))
            status = result.get("status")
            if status not in ("saved", "ambiguous", "rejected", "version-conflict", "overwrite-required"):
                status = "ambiguous"
            receipt = self.receipts.finish(delivery_id, status, session.actor)
        except Exception:
            # May already have written. No retry; persisted ambiguous survives crash.
            pass
        return {"receipt": receipt}


def dispatch(handler, service, vault, bearer_secret):
    """Return True for ALL requests in reserved namespace, including disabled."""
    if not urlsplit(handler.path).path.startswith(PREFIX):
        return False
    # Raw V2 never enables secret ingress, even if passed a service accidentally.
    reply(handler, 503, {"error": "secret-delivery-disabled"})
    return True
