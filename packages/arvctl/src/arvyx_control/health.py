from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, HTTPRedirectHandler, build_opener


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


from .http_bounds import BoundedOpener

urlopen = BoundedOpener().open

from .audit_log import verify_chain
from .control import post_bus_message
from .replica import replica_status
from .security import is_http_url


@dataclass(frozen=True)
class HealthCheck:
    name: str
    ok: bool
    detail: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, **self.detail}


@dataclass(frozen=True)
class HealthResult:
    ok: bool
    checks: list[HealthCheck]

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "checks": [check.to_dict() for check in self.checks]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def run_health(
    url: str | None = None,
    token: str | None = None,
    recall_question: str = "what is the current truth",
    recall_project: str | None = None,
    audit_log: Path | None = None,
    replica_vault: Path | None = None,
    max_replica_age_minutes: int = 60,
    timeout: float = 10.0,
) -> HealthResult:
    """Run host health checks; every requested check must pass."""
    checks: list[HealthCheck] = []
    if url:
        base = url.rstrip("/")
        checks.append(_check_http_health(base, timeout))
        checks.append(_check_recall(base, token, recall_question, recall_project, timeout))
        if token:
            checks.append(_check_summary(base, token, timeout))
    if audit_log is not None:
        result = verify_chain(audit_log)
        checks.append(
            HealthCheck(
                name="audit_chain",
                ok=result.ok,
                detail={"events": result.events, "first_break_line": result.first_break_line},
            )
        )
    if replica_vault is not None:
        status = replica_status(replica_vault)
        max_age = max_replica_age_minutes * 60
        ok = status.is_replica and status.age_seconds is not None and status.age_seconds <= max_age
        checks.append(
            HealthCheck(
                name="replica_freshness",
                ok=ok,
                detail={
                    "is_replica": status.is_replica,
                    "age_seconds": status.age_seconds,
                    "max_age_seconds": max_age,
                    "source": status.source,
                },
            )
        )
    if not checks:
        checks.append(
            HealthCheck(
                name="no_checks_requested",
                ok=False,
                detail={"hint": "pass --url, --audit-log, or --replica-vault"},
            )
        )
    return HealthResult(ok=all(check.ok for check in checks), checks=checks)


def report_failures_to_bus(state: Path, result: HealthResult, host_label: str) -> str | None:
    """Post an alert bus message for failed checks; returns the message id."""
    failed = [check.name for check in result.checks if not check.ok]
    if not failed:
        return None
    posted = post_bus_message(
        state=state,
        message=f"health check failed on {host_label}: {', '.join(failed)}",
        channel="ops",
        actor="health-check",
        severity="alert",
    )
    return posted.message.id


def _check_http_health(base: str, timeout: float) -> HealthCheck:
    try:
        payload = _get_json(f"{base}/health", token=None, timeout=timeout)
    except ValueError as exc:
        return HealthCheck(name="http_health", ok=False, detail={"error": str(exc)})
    body = payload.get("body", payload)
    return HealthCheck(
        name="http_health",
        ok=bool(isinstance(body, dict) and body.get("ok") is True),
        detail={},
    )


def _check_recall(
    base: str,
    token: str | None,
    question: str,
    project: str | None,
    timeout: float,
) -> HealthCheck:
    request_body: dict[str, Any] = {"question": question, "max_tokens": 120}
    if project:
        request_body["project"] = project
    try:
        payload = _post_json(f"{base}/memory/recall", request_body, token=token, timeout=timeout)
    except ValueError as exc:
        return HealthCheck(name="recall_smoke", ok=False, detail={"error": str(exc)})
    body = payload.get("body", payload)
    ok = isinstance(body, dict) and isinstance(body.get("answer"), list) and bool(body.get("answer"))
    return HealthCheck(
        name="recall_smoke",
        ok=ok,
        detail={"confidence": body.get("confidence") if isinstance(body, dict) else None},
    )


def _check_summary(base: str, token: str, timeout: float) -> HealthCheck:
    try:
        payload = _get_json(f"{base}/summary", token=token, timeout=timeout)
    except ValueError as exc:
        return HealthCheck(name="summary_auth", ok=False, detail={"error": str(exc)})
    body = payload.get("body", payload)
    return HealthCheck(
        name="summary_auth",
        ok=bool(isinstance(body, dict) and body.get("ok") is True),
        detail={},
    )


def _get_json(url: str, token: str | None, timeout: float) -> dict[str, Any]:
    return _request_json(Request(url, headers=_headers(token), method="GET"), timeout)


def _post_json(url: str, body: dict[str, Any], token: str | None, timeout: float) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json", **_headers(token)}
    return _request_json(Request(url, data=data, headers=headers, method="POST"), timeout)


def _headers(token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


def _request_json(request: Request, timeout: float) -> dict[str, Any]:
    if not is_http_url(request.full_url):
        raise ValueError(f"refusing non-http(s) host: {request.full_url}")
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-configured host
            raw = response.read(1024*1024+1)
            if len(raw) > 1024*1024:
                raise ValueError('health response byte limit exceeded')
            payload = json.loads(raw.decode("utf-8"))
    except HTTPError as exc:
        exc.close()
        raise ValueError(f"HTTP {exc.code}") from None
    except URLError as exc:
        raise ValueError(f"unreachable: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON response: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("non-object JSON response")
    return payload
