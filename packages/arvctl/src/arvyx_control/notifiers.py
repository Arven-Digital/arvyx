from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.client import HTTPException
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any, TextIO
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request
from .http_bounds import BoundedOpener


_OPENER = BoundedOpener()
urlopen = _OPENER.open

from .control import record_thread_notification_failure
from . import health_ops
from .health_ops import NotifyCheckResult
from .security import contains_literal_secret, is_http_url, redact_secrets

NOTIFIER_ADAPTERS = ("stdout", "file", "webhook", "telegram")
# Adapters whose output never leaves this machine; only these may carry a
# loopback dashboard link in human-facing notification text.
LOCAL_ADAPTERS = frozenset({"stdout", "file"})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

DEFAULT_TELEGRAM_API_BASE = "https://api.telegram.org"
# Exfiltration guard: the bot token rides in the request URL, so a config
# pointing api_base_url anywhere else would hand the token to that host.
# Production only ever talks to the real API; a fake-server test base needs
# BOTH this env gate and an unmistakably test-shaped token, so the override
# cannot be combined with real credentials by accident.
TELEGRAM_TEST_API_BASE_ENV = "ARVYX_ALLOW_TELEGRAM_TEST_API_BASE"
_TEST_SHAPED_TOKEN_RE = re.compile(r"\d+:TEST[A-Za-z0-9_-]*\Z")


@dataclass(frozen=True)
class Delivery:
    adapter: str
    kind: str
    thread_id: str
    text: str
    status: str  # printed | recorded | sent | dry-run | failed | ambiguous
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "adapter": self.adapter,
            "kind": self.kind,
            "thread_id": self.thread_id,
            "text": self.text,
            "status": self.status,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class NotifyDeliveryResult:
    adapter: str
    candidates: list[dict[str, str]]
    suppressed: list[str]
    deliveries: list[Delivery]
    dry_run: bool

    @property
    def ok(self) -> bool:
        return all(delivery.status not in {"failed", "ambiguous"} for delivery in self.deliveries)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "candidates": self.candidates,
            "suppressed": self.suppressed,
            "deliveries": [delivery.to_dict() for delivery in self.deliveries],
            "dry_run": self.dry_run,
            "ok": self.ok,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def validate_dashboard_url(url: str, adapter: str) -> str:
    """Validate/sanitize a dashboard link BEFORE any message is constructed.

    Rejects non-http(s) schemes, whitespace/control characters (message and
    header injection), embedded credentials, secret-shaped query strings, and
    loopback links on outbound adapters — a 127.0.0.1 link is only meaningful
    on the machine itself, so it may ride along only on stdout/file output.
    """
    url = url.strip()
    if not url:
        raise ValueError("dashboard url must not be empty")
    if re.search(r"\s", url) or any(ord(char) < 0x20 for char in url):
        raise ValueError("dashboard url must not contain whitespace or control characters")
    if not is_http_url(url):
        raise ValueError("dashboard url must be http(s)")
    parts = urlsplit(url)
    if parts.username or parts.password:
        raise ValueError("dashboard url must not embed credentials")
    if contains_literal_secret(url):
        raise ValueError("dashboard url contains a secret-shaped string")
    host = (parts.hostname or "").lower()
    if host in LOOPBACK_HOSTS and adapter not in LOCAL_ADAPTERS:
        raise ValueError(
            f"loopback dashboard url is not allowed for outbound adapter '{adapter}'; "
            "use the stdout/file adapter or configure a non-loopback base url"
        )
    return url


def notify_check(
    state: Path, dedupe_window_minutes: int = 240,
    escalate_after_minutes: int = 60, dry_run: bool = False,
    dashboard_url: str | None = None,
) -> NotifyCheckResult:
    """Use the shared locked health claim transaction for every caller."""
    return health_ops.notify_check(
        state, dedupe_window_minutes=dedupe_window_minutes,
        escalate_after_minutes=escalate_after_minutes, dry_run=dry_run,
        dashboard_url=dashboard_url,
    )


def notify_and_deliver(
    state: Path,
    adapter: str = "stdout",
    dedupe_window_minutes: int = 240,
    escalate_after_minutes: int = 60,
    dry_run: bool = False,
    dashboard_url: str | None = None,
    deliveries_path: Path | None = None,
    webhook_url_env: str | None = None,
    config: Path | None = None,
    timeout: float = 10.0,
    quiet_stdout: bool = False,
) -> NotifyDeliveryResult:
    """Compute notification candidates, then hand them to one adapter.

    Ordering is deliberate: the dashboard url and the adapter configuration
    are validated BEFORE notify_check runs, so a misconfigured adapter fails
    without claiming candidates in the dedupe log. Delivery happens after the
    state lock is released (no network I/O under the lock). A failed delivery
    appends a failure event that releases the dedupe claim, so a later run may
    retry. An uncertain outbound outcome retains the claim: notification
    retries resume only when the dedupe window expires (escalations stay
    claimed). This is at-least-once, not durable provider reconciliation;
    operators should check provider readback before expiry/resend.
    """
    validated_dashboard = validate_dashboard_url(dashboard_url, adapter) if dashboard_url else None
    notifier = _build_notifier(
        adapter=adapter,
        deliveries_path=deliveries_path,
        webhook_url_env=webhook_url_env,
        config=config,
        timeout=timeout,
        quiet_stdout=quiet_stdout,
    )
    result = notify_check(
        state=state,
        dedupe_window_minutes=dedupe_window_minutes,
        escalate_after_minutes=escalate_after_minutes,
        dry_run=dry_run,
        dashboard_url=validated_dashboard,
    )
    deliveries: list[Delivery] = []
    release_errors: list[Exception] = []
    for candidate in result.candidates:
        try:
            delivery = notifier.deliver(candidate, dry_run=dry_run)
        except Exception as exc:
            # Local sinks are at-least-once and can safely retry a partial write.
            # Unexpected outbound exceptions may follow provider acceptance;
            # retain their claim instead of silently authorizing a resend.
            delivery = _delivery(
                adapter, candidate, redact_secrets(str(candidate.get("text", ""))),
                "failed" if adapter in LOCAL_ADAPTERS else "ambiguous",
                detail=f"adapter raised {type(exc).__name__}",
            )
        deliveries.append(delivery)
        if not dry_run and delivery.status == "failed":
            try:
                record_thread_notification_failure(
                    state,
                    thread_id=str(candidate.get("thread_id", "")),
                    kind=str(candidate.get("kind", "notification")),
                    detail=redact_secrets(delivery.detail),
                    claim_event_id=candidate["claim_event_id"],
                )
            except Exception as exc:
                # A broken receipt store must not prevent release attempts for
                # the rest of the preclaimed batch. Surface it after draining.
                release_errors.append(exc)
    if release_errors:
        raise RuntimeError("notification failure receipts could not all be persisted") from release_errors[0]
    return NotifyDeliveryResult(
        adapter=adapter,
        candidates=result.candidates,
        suppressed=result.suppressed,
        deliveries=deliveries,
        dry_run=dry_run,
    )


def _build_notifier(
    adapter: str,
    deliveries_path: Path | None,
    webhook_url_env: str | None,
    config: Path | None,
    timeout: float,
    quiet_stdout: bool,
):
    if adapter == "stdout":
        return _StdoutNotifier(quiet=quiet_stdout)
    if adapter == "file":
        if deliveries_path is None:
            raise ValueError("file adapter requires --deliveries PATH")
        return _FileNotifier(path=deliveries_path)
    if adapter == "webhook":
        spec = _load_config(config) if config is not None else {}
        if config is not None:
            _require_adapter_field(spec, expected="webhook", config=config)
        env_name = webhook_url_env or str(spec.get("url_env", "")).strip()
        if not env_name:
            raise ValueError("webhook adapter requires --webhook-url-env NAME (or 'url_env' in --config)")
        url = os.environ.get(env_name, "").strip()
        if not url:
            raise ValueError(f"webhook adapter requires the {env_name} environment variable to be set")
        if not is_http_url(url):
            raise ValueError(f"webhook url in {env_name} must be http(s)")
        return _WebhookNotifier(url=url, timeout=float(spec.get("timeout_seconds", timeout)))
    if adapter == "telegram":
        if config is None:
            raise ValueError("telegram adapter requires --config (see examples/notifiers/telegram.example.json)")
        spec = _load_config(config)
        _require_adapter_field(spec, expected="telegram", config=config)
        token_env = str(spec.get("bot_token_env", "")).strip()
        chat_env = str(spec.get("chat_id_env", "")).strip()
        if not token_env or not chat_env:
            raise ValueError("telegram config must declare 'bot_token_env' and 'chat_id_env' (env var names, not values)")
        token = os.environ.get(token_env, "").strip()
        chat_id = os.environ.get(chat_env, "").strip()
        if not token or not chat_id:
            raise ValueError(
                f"telegram adapter refuses to run: set the {token_env} and {chat_env} environment variables"
            )
        api_base = str(spec.get("api_base_url", DEFAULT_TELEGRAM_API_BASE)).strip().rstrip("/")
        if api_base != DEFAULT_TELEGRAM_API_BASE:
            # token exfiltration guard: never send a real token anywhere but
            # the real Telegram API. The test override needs the env gate AND
            # an obviously fake token (numeric id, secret starting with TEST).
            if os.environ.get(TELEGRAM_TEST_API_BASE_ENV, "").strip() != "1":
                raise ValueError(
                    f"telegram api_base_url must be {DEFAULT_TELEGRAM_API_BASE}; overriding it would send the "
                    f"bot token to another host. A local test base additionally requires "
                    f"{TELEGRAM_TEST_API_BASE_ENV}=1 and a test-shaped token"
                )
            if not _TEST_SHAPED_TOKEN_RE.fullmatch(token):
                raise ValueError(
                    f"{TELEGRAM_TEST_API_BASE_ENV}=1 is set but the bot token is not test-shaped "
                    "(expected '<digits>:TEST...'); refusing to send a possibly real token to a "
                    "non-default api_base_url"
                )
            if not is_http_url(api_base):
                raise ValueError("telegram api_base_url must be http(s)")
        return _TelegramNotifier(api_base=api_base, token=token, chat_id=chat_id, timeout=timeout)
    raise ValueError("adapter must be one of: " + ", ".join(NOTIFIER_ADAPTERS))


def build_notifier_from_config(
    config: Path,
    *,
    timeout: float = 10.0,
    stdout_stream: TextIO | None = None,
):
    """Build one out-of-band notifier from a config file that names its adapter.

    Used by the delivery liveness probe and canary, whose alerts must not
    travel through the thread/outbox path they are watching. The config
    declares ``adapter`` (stdout, file, webhook or telegram); secret values
    stay in the environment variables it names, and every existing adapter
    gate (the telegram ``api_base_url`` exfiltration guard included) applies
    unchanged. A ``file`` config names its JSONL ``path``. ``stdout_stream``
    lets a JSON-emitting caller keep alert text off its own stdout.
    """
    spec = _load_config(config)
    adapter = str(spec.get("adapter", "")).strip().lower()
    if adapter not in NOTIFIER_ADAPTERS:
        raise ValueError(
            f"notifier config {config} must declare adapter as one of: " + ", ".join(NOTIFIER_ADAPTERS)
        )
    if adapter == "stdout":
        return _StdoutNotifier(stream=stdout_stream or sys.stdout)
    if adapter == "file":
        raw_path = str(spec.get("path", "")).strip()
        if not raw_path:
            raise ValueError(f"file notifier config {config} requires 'path'")
        return _FileNotifier(path=Path(raw_path))
    return _build_notifier(
        adapter=adapter,
        deliveries_path=None,
        webhook_url_env=None,
        config=config,
        timeout=float(spec.get("timeout_seconds", timeout)),
        quiet_stdout=False,
    )


def _require_adapter_field(spec: dict[str, Any], expected: str, config: Path) -> None:
    """A config written for one adapter must fail clearly on another."""
    declared = str(spec.get("adapter", "")).strip().lower()
    if declared and declared != expected:
        raise ValueError(f"notifier config {config} declares adapter '{declared}'; expected '{expected}'")


def _load_config(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"notifier config not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"notifier config must be a JSON object: {path}")
    return payload


@dataclass(frozen=True)
class _StdoutNotifier:
    quiet: bool = False
    stream: TextIO = field(default_factory=lambda: sys.stdout)

    def deliver(self, candidate: dict[str, str], dry_run: bool) -> Delivery:
        text = redact_secrets(str(candidate.get("text", "")))
        if dry_run:
            return _delivery("stdout", candidate, text, "dry-run")
        if not self.quiet:
            print(text, file=self.stream)
        return _delivery("stdout", candidate, text, "printed")


@dataclass(frozen=True)
class _FileNotifier:
    path: Path

    def deliver(self, candidate: dict[str, str], dry_run: bool) -> Delivery:
        text = redact_secrets(str(candidate.get("text", "")))
        if dry_run:
            return _delivery("file", candidate, text, "dry-run")
        row = {
            "delivered_at": _now(),
            "adapter": "file",
            "kind": str(candidate.get("kind", "")),
            "thread_id": str(candidate.get("thread_id", "")),
            "target": str(candidate.get("target", "")),
            "channel": str(candidate.get("channel", "")),
            "severity": str(candidate.get("severity", "")),
            "title": redact_secrets(str(candidate.get("title", ""))),
            "text": text,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
        return _delivery("file", candidate, text, "recorded", detail=str(self.path))


@dataclass(frozen=True)
class _WebhookNotifier:
    url: str
    timeout: float

    def deliver(self, candidate: dict[str, str], dry_run: bool) -> Delivery:
        text = redact_secrets(str(candidate.get("text", "")))
        if dry_run:
            return _delivery("webhook", candidate, text, "dry-run")
        payload = {
            "delivered_at": _now(),
            "kind": str(candidate.get("kind", "")),
            "thread_id": str(candidate.get("thread_id", "")),
            "target": str(candidate.get("target", "")),
            "channel": str(candidate.get("channel", "")),
            "severity": str(candidate.get("severity", "")),
            "title": redact_secrets(str(candidate.get("title", ""))),
            "text": text,
        }
        outcome = _post_json(self.url, payload, self.timeout)
        return _delivery("webhook", candidate, text, outcome.status, detail=redact_secrets(outcome.detail))


@dataclass(frozen=True)
class _TelegramNotifier:
    api_base: str
    token: str
    chat_id: str
    timeout: float

    def deliver(self, candidate: dict[str, str], dry_run: bool) -> Delivery:
        text = redact_secrets(str(candidate.get("text", "")))
        if dry_run:
            return _delivery("telegram", candidate, text, "dry-run")
        url = f"{self.api_base}/bot{self.token}/sendMessage"
        payload = {"chat_id": self.chat_id, "text": text, "disable_web_page_preview": True}
        outcome = _post_json(url, payload, self.timeout)
        # the bot token rides in the URL; it must never reach a delivery record
        scrubbed = redact_secrets(outcome.detail.replace(self.token, "[REDACTED]"))
        return _delivery("telegram", candidate, text, outcome.status, detail=scrubbed)


@dataclass(frozen=True)
class _PostOutcome:
    status: str  # sent | failed (definite refusal) | ambiguous (acceptance unknown)
    detail: str = ""


def _post_json(url: str, payload: dict[str, Any], timeout: float) -> _PostOutcome:
    """Keep local refusal/provider rejection separate from unknown acceptance.

    BoundedOpener does not expose the point a request reaches the peer. Once
    entered, even an ordinary URLError must conservatively retain the claim.
    Response-body and context-exit framing/deadline failures follow POST too.
    """
    try:
        if not is_http_url(url):
            return _PostOutcome("failed", "refusing non-http(s) url")
        parts = urlsplit(url)
        if not parts.hostname or parts.username or parts.password:
            return _PostOutcome("failed", "HTTP(S) destination without embedded credentials required")
        # Validate the port and the transport's timeout bounds before opening.
        _ = parts.port
        timeout = float(timeout)
        if not math.isfinite(timeout) or not 0 < timeout <= 60:
            return _PostOutcome("failed", "finite bounded transport timeout required")
        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
    except (TypeError, ValueError):
        return _PostOutcome("failed", "invalid notification request")
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - gated above
            status = int(response.status)
            if len(response.read(1024 * 1024 + 1)) > 1024 * 1024:
                raise ValueError("notification response exceeds limit")
    except HTTPError as exc:
        exc.close()
        return _http_status_outcome(exc.code)
    except (URLError, OSError, HTTPException, ValueError) as exc:
        # The shared opener currently wraps HTTPException as URLError; retain
        # the same outcome for alternate/injected transports exposing it raw.
        return _PostOutcome("ambiguous", f"acceptance unknown: {type(exc).__name__}")
    if 200 <= status < 300:
        return _PostOutcome("sent")
    return _http_status_outcome(status)


def _http_status_outcome(status: int) -> _PostOutcome:
    # The endpoint/proxy may fail after committing the visible side effect.
    if 400 <= status < 500 and status != 408:
        return _PostOutcome("failed", f"HTTP {status}")
    return _PostOutcome("ambiguous", f"acceptance unknown: HTTP {status}")


def _delivery(adapter: str, candidate: dict[str, str], text: str, status: str, detail: str = "") -> Delivery:
    return Delivery(
        adapter=adapter,
        kind=str(candidate.get("kind", "")),
        thread_id=str(candidate.get("thread_id", "")),
        text=text,
        status=status,
        detail=detail,
    )


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
