from __future__ import annotations

import argparse
from contextvars import ContextVar
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# One transport policy for doctor and stdio calls, including custom credentials.
from .http_bounds import BoundedOpener

_OPENER = BoundedOpener()

# Fallback when arvyx_control is not importable in the bridge venv; keep
# in sync with arvyx_control.security.SECRET_PATTERNS.
_COMPANY_DOMAIN_RE = re.escape('arven.digital')
_FALLBACK_SECRET_RE = re.compile('((?<![A-Za-z0-9_-])arv_[a-z0-9][a-z0-9_-]{0,63}_[0-9a-f]{40}(?![A-Za-z0-9_-])|sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+|gh[oupsr]_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,}|vcp_[A-Za-z0-9_-]{16,}|sntryu_[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,}|https://hooks\\.slack\\.com/services/[A-Za-z0-9/_-]{20,}|\\b\\d{8,10}:AA[A-Za-z0-9_-]{30,}\\b|sk_(?:live|test)_[A-Za-z0-9]{16,}|\\bAKIA[0-9A-Z]{16}\\b|\\baws_secret_access_key\\s*[:=]\\s*[\'\\"]?[A-Za-z0-9/+=]{35,}|\\bAIza[0-9A-Za-z_-]{35}\\b|\\bpostgres(?:ql)?://[^:\\s]+:[^@\\s]+@[^/\\s]+/[^\\s\'\\"]+|\\b[A-Z0-9._%+-]+@' + _COMPANY_DOMAIN_RE + '\\b|\\beyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\b|Bearer\\s+[A-Za-z0-9._-]{16,}|BEGIN\\s+(RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY|\\b(api[_-]?key|token|password|secret)\\s*[:=]\\s*(?:[\'\\"][^\'\\"\\s]{8,}[\'\\"]|(?![A-Za-z_][A-Za-z0-9_.]*\\()[A-Za-z0-9._/!@#$%^&*+=?-]{8,}))', re.IGNORECASE)


BLOCKED_TOOL_CODE = -32001
BLOCKED_METHOD_CODE = -32002
# JSON-RPC methods a memory client legitimately needs; anything else is
# denied by default instead of being forwarded verbatim upstream.
DEFAULT_ALLOWED_METHODS = (
    "initialize",
    "notifications/initialized",
    "ping",
    "tools/list",
    "tools/call",
)


@dataclass
class _BridgeSession:
    audit_failed: bool = False
    dispatched: bool = False
    response_id: object = None


_SESSION: ContextVar[_BridgeSession | None] = ContextVar('bridge_session', default=None)


class BridgeAuditError(RuntimeError):
    pass


def _checked_audit(config: dict[str, Any], event: dict[str, Any]) -> None:
    try:
        _audit(config, event)
    except Exception:
        session = _SESSION.get()
        if session is not None:
            session.audit_failed = True
        raise BridgeAuditError('bridge audit unavailable') from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="safe-mcp-bridge")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser("doctor", help="Validate bridge config and upstream reachability.")
    doctor_parser.add_argument("config", type=Path)
    doctor_parser.add_argument("--json", action="store_true", dest="json_output")

    lint_parser = subparsers.add_parser("lint", help="Validate bridge config without contacting upstream.")
    lint_parser.add_argument("config", type=Path)
    lint_parser.add_argument("--json", action="store_true", dest="json_output")

    run_parser = subparsers.add_parser("run", help="Run stdio JSON-RPC bridge.")
    run_parser.add_argument("config", type=Path)

    args = parser.parse_args(argv)
    try:
        config = _load_config(args.config)
        if args.command == "doctor":
            result = _doctor(config)
            if args.json_output:
                print(json.dumps(result, sort_keys=True))
            else:
                print(f"ok={str(result['ok']).lower()}")
            return 0 if result["ok"] else 1
        if args.command == "lint":
            result = _lint(config, args.config)
            if args.json_output:
                print(json.dumps(result, sort_keys=True))
            else:
                print(f"ok={str(result['ok']).lower()}")
                for error in result["errors"]:
                    print(f"error={error}", file=sys.stderr)
                for warning in result["warnings"]:
                    print(f"warning={warning}", file=sys.stderr)
            return 0 if result["ok"] else 1
        if args.command == "run":
            return _run(config)
    except BridgeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 1


def _load_config(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BridgeError(f"config not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise BridgeError(f"invalid config JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise BridgeError("config must be a JSON object")
    _target_url(payload)
    _allowed_tools(payload)
    return payload


def _doctor(config: dict[str, Any]) -> dict[str, Any]:
    tools_response = _post_json(config, {"jsonrpc": "2.0", "id": "doctor-tools", "method": "tools/list"})
    _validate_response(tools_response, {"id": "doctor-tools"})
    upstream_tools = _tools_from_response(tools_response)
    allowed = _allowed_tools(config)
    visible_tools = [item for item in upstream_tools if item in allowed]
    unknown_allowed = sorted(set(allowed) - set(upstream_tools))
    return {
        "ok": not unknown_allowed,
        "target": _target_url(config),
        "policy_mode": _policy_mode(config),
        "allowed_tools": allowed,
        "upstream_tools": len(upstream_tools),
        "visible_tools": visible_tools,
        "unknown_allowed_tools": unknown_allowed,
        "redaction_enabled": _redaction_enabled(config),
    }


def _lint(config: dict[str, Any], path: Path) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    allowed = _allowed_tools(config)
    known_tools = _known_tools()
    duplicate_tools = sorted({item for item in allowed if allowed.count(item) > 1})
    unknown_tools = sorted(set(allowed) - known_tools) if known_tools else []
    audit = config.get("audit") if isinstance(config.get("audit"), dict) else {}
    redaction = config.get("redaction") if isinstance(config.get("redaction"), dict) else {}

    if duplicate_tools:
        errors.append(f"duplicate allowlist tools: {', '.join(duplicate_tools)}")
    if unknown_tools:
        errors.append(f"unknown allowlist tools: {', '.join(unknown_tools)}")
    if not _target_url(config).startswith(("http://", "https://")):
        errors.append("target.url must use http or https")
    elif _cleartext_remote(_target_url(config)):
        warnings.append("target.url uses cleartext http to a non-loopback host; the bearer travels unencrypted")
    if not audit.get("path"):
        warnings.append("audit.path is not configured")
    if audit.get("redact") is not True:
        errors.append("audit.redact must be true")
    if redaction.get("fail_on_secret_output") is not True:
        errors.append("redaction.fail_on_secret_output must be true")
    if not _auth_env(config):
        warnings.append("auth.env is not configured")

    return {
        "ok": not errors,
        "config": str(path),
        "target": _target_url(config),
        "policy_mode": _policy_mode(config),
        "allowed_tools": allowed,
        "allowed_tool_count": len(allowed),
        "duplicate_tools": duplicate_tools,
        "unknown_tools": unknown_tools,
        "known_tools_checked": bool(known_tools),
        "auth_env": _auth_env(config),
        "audit_path": audit.get("path"),
        "redaction_enabled": audit.get("redact") is True,
        "fail_on_secret_output": redaction.get("fail_on_secret_output") is True,
        "errors": errors,
        "warnings": warnings,
    }


def _run(config: dict[str, Any]) -> int:
    from .stdio_bounds import bounded_lines
    session = _BridgeSession()
    token = _SESSION.set(session)
    try:
        for line in bounded_lines(sys.stdin):
            session.response_id = None
            session.dispatched = False
            if line is None:
                _emit_response(config, _error(None, -32700, "invalid or oversized UTF-8 request"))
                continue
            if not line.strip():
                continue
            response = _handle_line(config, line)
            if response is not None:  # a JSON-RPC notification has no response
                _emit_response(config, response)
    finally:
        _SESSION.reset(token)
    return 0


def _check_json_depth(value):
    pending = [(value, 0)]
    while pending:
        item, depth = pending.pop()
        if depth > 64:
            raise ValueError('JSON nesting limit exceeded')
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)


def _handle_line(config: dict[str, Any], line: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(line)
        _check_json_depth(payload)
    except (ValueError, RecursionError):
        return _error(None, -32700, "invalid or too deeply nested JSON request")
    if not isinstance(payload, dict):
        return _error(None, -32600, "request must be a JSON object")

    # Standalone installation cannot depend on arvyx_control's validator.
    # Validate before notification classification or forwarding, including IDs.
    import math
    request_id = payload.get("id")
    valid_id = (request_id is None or isinstance(request_id, str)
                or type(request_id) is int
                or (type(request_id) is float and math.isfinite(request_id)))
    if not valid_id:
        return _error(None, -32600, "invalid JSON-RPC id")
    method = payload.get("method")
    if (payload.get("jsonrpc") != "2.0" or not isinstance(method, str)
            or ("params" in payload and not isinstance(payload["params"], dict))):
        return _error(request_id, -32600, "invalid JSON-RPC request envelope")
    is_notification = "id" not in payload
    session = _SESSION.get() or _BridgeSession()
    token = _SESSION.set(session)
    try:
        # Retain only a sanitized client correlation for local failure output;
        # upstream response metadata never supplies failure attribution.
        session.response_id = _redact_secret_shapes(_redact(config, {'id': request_id}))[0]['id']
        if session.audit_failed:
            return None if is_notification else _error(session.response_id, -32004,
                'bridge audit unavailable; dispatch refused; nothing retried')
        return _handle_payload(config, payload, session)
    except BridgeAuditError:
        session.audit_failed = True
        message = ('bridge audit unavailable; outcome uncertain; nothing retried' if session.dispatched
                   else 'bridge audit unavailable before dispatch; nothing dispatched')
        return None if is_notification else _error(session.response_id, -32003, message)
    finally:
        _SESSION.reset(token)


def _handle_payload(config: dict[str, Any], payload: dict[str, Any], session: _BridgeSession) -> dict[str, Any] | None:
    request_id = payload.get('id')
    method = payload['method']
    is_notification = 'id' not in payload
    allowed = set(_allowed_tools(config))

    def reply(response: dict[str, Any]) -> dict[str, Any] | None:
        return None if is_notification else response

    if method not in _allowed_methods(config):
        _checked_audit(config, {"event": "method_blocked", "method": method, "code": BLOCKED_METHOD_CODE})
        return reply(_error(request_id, BLOCKED_METHOD_CODE, f"method blocked by safe-mcp-bridge policy: {method}"))

    if method == "tools/call":
        params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
        tool_name = params.get("name")
        if not isinstance(tool_name, str):
            return reply(_error(request_id, -32602, "tool name must be text"))
        if tool_name not in allowed:
            _checked_audit(config, {"event": "tool_blocked", "tool": tool_name, "code": BLOCKED_TOOL_CODE})
            return reply(_error(request_id, BLOCKED_TOOL_CODE, f"tool blocked by safe-mcp-bridge policy: {tool_name}"))

    # Any upstream failure (HTTP error, timeout, empty/non-JSON body — common
    # for a notification the server answers with 202) must become one JSON-RPC
    # error, not kill the whole long-lived bridge process.
    _checked_audit(config, {"event": "request_admitted", "method": method, "tool": _tool_name(payload)})
    session.dispatched = True
    try:
        upstream = _post_json(config, payload)
        if not is_notification:
            _validate_response(upstream, payload)
            if method == "tools/list" and "result" in upstream:
                _tools_from_response(upstream)
    except BridgeError as exc:
        _checked_audit(config, {"event": "upstream_error", "method": method})
        return reply(_error(request_id, -32000, str(exc)))

    if is_notification:
        _checked_audit(config, {"event": "request_forwarded", "method": method, "tool": _tool_name(payload)})
        return None

    if method == "tools/list":
        result = upstream.get("result")
        if isinstance(result, dict):
            tools = result.get("tools", [])
            tools = tools if isinstance(tools, list) else []
            result["tools"] = [
                item for item in tools
                if isinstance(item, dict) and isinstance(item.get("name"), str)
                and item["name"] in allowed
            ]
            _checked_audit(
                config,
                {
                    "event": "tools_list_filtered",
                    "allowed_tools": sorted(allowed),
                    "upstream_tools": len(tools),
                    "visible_tools": len(result["tools"]),
                },
            )
        # Valid upstream errors remain errors; never synthesize result+error.
        return reply(upstream)

    _checked_audit(config, {"event": "request_forwarded", "method": method, "tool": _tool_name(payload)})
    return reply(upstream)


def _tool_name(payload: dict[str, Any]) -> str:
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    name = params.get("name")
    return str(name) if isinstance(name, str) else ""


def _allowed_methods(config: dict[str, Any]) -> set[str]:
    policy = config.get("policy") if isinstance(config.get("policy"), dict) else {}
    extra = policy.get("allow_methods")
    methods = set(DEFAULT_ALLOWED_METHODS)
    if isinstance(extra, list):
        methods.update(str(item) for item in extra if isinstance(item, str))
    return methods


def _post_json(config: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    url = _target_url(config)
    if urlsplit(url).scheme.lower() not in ("http", "https"):
        raise BridgeError(f"refusing non-http(s) bridge target: {_display_url(url)}")
    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    auth_header = _auth_header(config)
    if auth_header:
        name, value = auth_header
        headers[name] = value
    request = Request(
        url,
        data=data,
        headers=headers,
        method="POST",
    )
    target = config.get("target")
    raw_timeout = target.get("timeout_seconds", 20) if isinstance(target, dict) else 20
    try:
        if isinstance(raw_timeout, bool):
            raise ValueError
        timeout = float(raw_timeout)
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError
    except (TypeError, ValueError, OverflowError):
        raise BridgeError("target timeout_seconds must be a finite positive number; nothing dispatched") from None
    try:
        with _OPENER.open(request, timeout=timeout) as response:  # user-configured bridge target
            raw = response.read(1024*1024+1)
            if len(raw) > 1024*1024:
                raise BridgeError('upstream response byte limit exceeded; nothing retried')
            text = raw.decode("utf-8")
    except HTTPError as exc:
        # the error body is upstream-controlled and surfaces to stderr; redact
        # secret shapes and cap it so a 4xx/5xx body cannot leak a credential
        try:
            raw = exc.read(4096)
        except (OSError, HTTPException):
            raw = b"[error body unavailable]"
        finally:
            exc.close()
        detail = raw.decode("utf-8", errors="replace")
        detail = _redact(config, {"detail": detail})["detail"]
        detail = bounded_secret_subn(detail, _secret_re())[0][:500]
        raise BridgeError(f"upstream HTTP {exc.code}: {detail}") from None
    except URLError:
        raise BridgeError("upstream unreachable; nothing retried") from None
    except (OSError, HTTPException, ValueError):
        raise BridgeError("upstream transport, framing or decoding failure; nothing retried") from None
    try:
        decoded = json.loads(text)
        _check_json_depth(decoded)
    except (ValueError, RecursionError):
        raise BridgeError("upstream returned invalid or too deeply nested JSON") from None
    if not isinstance(decoded, dict):
        raise BridgeError("upstream response must be a JSON object")
    if "id" in payload:
        _validate_response(decoded, payload)
    return decoded


def _emit_response(config: dict[str, Any], response: dict[str, Any]) -> None:
    try:
        response, redacted_spans = _redact_secret_shapes(response)
        if redacted_spans:
            _checked_audit(config, {"event": "secret_shape_redacted", "spans": redacted_spans})
        text = json.dumps(response, sort_keys=True)
        if config.get("redaction", {}).get("fail_on_secret_output", False):
            leaked = [secret for secret in _secret_values(config)
                      if secret and json.dumps(secret)[1:-1] in text]
            if leaked:
                raise BridgeError("refusing to emit response containing configured secret value")
    except BridgeAuditError:
        session = _SESSION.get()
        text = json.dumps(_error(session.response_id if session is not None else None, -32003,
            "bridge audit unavailable; outcome uncertain; nothing retried"), sort_keys=True)
    except Exception:
        # Neither refused bytes, exception text nor the upstream-controlled ID
        # are safe to echo. Do not re-run the redactor/audit that just failed.
        # Upstream effects may have happened; later stdin requests still work.
        text = json.dumps(_error(None, -32003,
            "response withheld; outcome uncertain; nothing retried"), sort_keys=True)
    print(text, flush=True)


def _postgres_spans(text: str, flags: int) -> list[tuple[int, int]]:
    """Index delimiters once, avoiding a suffix scan for every failed URI.

    Four binary searches per prefix bound work to O(n log n), with O(n)
    storage, including repeated prefixes with no @. Character classes match
    the canonical detector (passwords may contain colons and URI prefixes).
    """
    from bisect import bisect_left

    prefixes = list(re.finditer(r"\bpostgres(?:ql)?://", text, flags))
    if not prefixes:
        return []
    boundaries = [
        [match.start() for match in re.finditer(pattern, text)] + [len(text)]
        for pattern in (r"[:\s]", r"[@\s]", r"[/\s]", r"[\s'\"]")
    ]
    spans = []
    for prefix in prefixes:
        start = prefix.end()
        for index, separator in enumerate(":@/"):
            end = boundaries[index][bisect_left(boundaries[index], start)]
            if end == start or end == len(text) or text[end] != separator:
                break
            start = end + 1
        else:
            end = boundaries[3][bisect_left(boundaries[3], start)]
            if end > start:
                spans.append((prefix.start(), end))
    return spans


def _jwt_spans(text: str, flags=re.IGNORECASE):
    """Tokenize once; try the original grammar once per eligible segment.

    Repeated eyJ prefixes in a dotless run cannot trigger repeated suffix
    scans. Successful matches consume disjoint spans; failed triples scan
    at most three runs, preserving Unicode boundaries and IGNORECASE.
    """
    runs = list(re.finditer(r"[A-Za-z0-9_-]+", text, flags))
    prefix = re.compile(r"\beyJ(?=[A-Za-z0-9_-])", flags)
    detector = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", flags)
    consumed = 0
    for first, second, third in zip(runs, runs[1:], runs[2:]):
        if first.start() < consumed:
            continue
        if (text[first.end():second.start()] != '.'
                or text[second.end():third.start()] != '.'):
            continue
        candidate = prefix.search(text, first.start(), first.end())
        if candidate:
            match = detector.match(text, candidate.start())
            if match:
                consumed = match.end()
                yield match.span()


def private_key_block_spans(text):
    """Linear delimiter walk; an unmatched opening suppresses the remainder.

    A nested/mismatched delimiter cannot terminate an active private block.
    No repeated suffix searches or unbounded backtracking are used.
    """
    marker = re.compile(r"(?P<kind>BEGIN|END)\s+(?P<label>(?:(?:RSA|OPENSSH|EC|DSA|ENCRYPTED) )?PRIVATE KEY)(?:-----)?", re.IGNORECASE)
    start = None
    label = None
    for match in marker.finditer(text):
        if start is None and match['kind'].upper() == 'BEGIN':
            start = match.start()
            if text[max(0, start - 5):start] == '-----':
                start -= 5
            label = match['label'].upper()
        elif start is not None and match['kind'].upper() == 'BEGIN':
            # Nested openings are malformed: suppress through EOF.
            label = None
        elif start is not None and match['kind'].upper() == 'END' and match['label'].upper() == label:
            yield start, match.end()
            start = None
    if start is not None:
        yield start, len(text)


def suppress_private_key_blocks(text):
    """Keep line positions stable before source selection and clipping."""
    parts = []
    previous = 0
    for start, end in private_key_block_spans(text):
        parts.extend((text[previous:start], '[REDACTED-SECRET]' + re.sub(r"[^\r\n]", '', text[start:end])))
        previous = end
    parts.append(text[previous:])
    return ''.join(parts)


def bounded_secret_subn(text, detector, replacement="[REDACTED-SECRET]"):
    """Find email runs once; redact the union of all canonical secret spans.

    Overlapping detector spans are conservatively redacted together, never
    exposing a suffix merely because another detector consumed its prefix.
    """
    email = r"\b[A-Z0-9._%+-]+@" + _COMPANY_DOMAIN_RE + r"\b"
    postgres = r"\bpostgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+/[^\s'\"]+"
    jwt = r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
    ordinary = detector.pattern.replace(email, r"(?!)").replace(postgres, r"(?!)").replace(jwt, r"(?!)")
    spans = [match.span() for match in re.finditer(ordinary, text, detector.flags)]
    spans.extend(private_key_block_spans(text))
    if jwt in detector.pattern:
        spans.extend(_jwt_spans(text, detector.flags))
    if postgres in detector.pattern:
        spans.extend(_postgres_spans(text, detector.flags))
    local = re.compile(r"[A-Z0-9._%+-]", re.IGNORECASE)
    word = re.compile(r"\w")
    for suffix in re.finditer(r"@" + _COMPANY_DOMAIN_RE + r"\b", text, re.IGNORECASE):
        start = suffix.start()
        while start and local.fullmatch(text[start - 1]):
            start -= 1
        for pos in range(start, suffix.start()):
            if bool(word.fullmatch(text[pos])) != bool(pos and word.fullmatch(text[pos - 1])):
                spans.append((pos, suffix.end()))
                break
    merged = []
    for start, end in sorted(spans):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    parts = []
    previous = 0
    for start, end in merged:
        parts.extend((text[previous:start], replacement))
        previous = end
    parts.append(text[previous:])
    return ''.join(parts), len(merged)


def _redact_secret_shapes(value: Any) -> tuple[Any, int]:
    # Decode first, then establish PEM context across ordered strings/lists
    # and dictionary keys immediately followed by their values. Collection
    # and scrubbing must use the same traversal; never scan JSON escape syntax.
    strings = []

    def collect(item):
        if isinstance(item, str):
            strings.append(item)
        elif isinstance(item, list):
            for child in item:
                collect(child)
        elif isinstance(item, dict):
            for key, child in item.items():
                collect(key)
                collect(child)

    collect(value)
    spans = list(private_key_block_spans(''.join(strings)))
    position = 0
    index = 0

    def scrub(item):
        nonlocal position, index
        if isinstance(item, str):
            start, end = position, position + len(item)
            position = end
            while index < len(spans) and spans[index][1] <= start:
                index += 1
            parts = []
            previous = 0
            cursor = index
            while cursor < len(spans) and spans[cursor][0] < end:
                left, right = spans[cursor]
                a, b = max(start, left) - start, min(end, right) - start
                parts.extend((item[previous:a], '[REDACTED-SECRET]'))
                previous = b
                cursor += 1
            parts.append(item[previous:])
            return ''.join(parts)
        if isinstance(item, list):
            return [scrub(child) for child in item]
        if isinstance(item, dict):
            payload = {}
            for key, child in item.items():
                key = scrub(key)
                child = scrub(child)
                if key in payload:
                    raise BridgeError('refusing to emit response with redacted dictionary key collision')
                payload[key] = child
            return payload
        return item

    redacted, count = _redact_individual_shapes(scrub(value))
    return redacted, count + len(spans)


def _redact_individual_shapes(value: Any) -> tuple[Any, int]:
    """Redact secret-shaped strings anywhere in the response structure.

    Upstream memory content can contain leaked keys; the bridge is the
    last boundary before the client, so it scrubs string values
    recursively rather than trusting the vault to be clean.
    """
    if isinstance(value, str):
        redacted, count = bounded_secret_subn(value, _secret_re())
        return redacted, count
    if isinstance(value, list):
        total = 0
        items = []
        for item in value:
            item, count = _redact_individual_shapes(item)
            total += count
            items.append(item)
        return items, total
    if isinstance(value, dict):
        total = 0
        payload = {}
        for key, item in value.items():
            # redact keys too: an upstream can return a map keyed by a secret
            if isinstance(key, str):
                key, key_count = bounded_secret_subn(key, _secret_re())
                total += key_count
            item, count = _redact_individual_shapes(item)
            total += count
            if key in payload:
                raise BridgeError('refusing to emit response with redacted dictionary key collision')
            payload[key] = item
        return payload, total
    return value, 0


def _secret_re() -> re.Pattern[str]:
    try:
        from arvyx_control.security import SECRET_RE

        return SECRET_RE
    except ImportError:
        return _FALLBACK_SECRET_RE


def _audit(config: dict[str, Any], event: dict[str, Any]) -> None:
    audit = config.get("audit") if isinstance(config.get("audit"), dict) else {}
    path_value = audit.get("path")
    if not path_value:
        return
    path = Path(str(path_value))
    path.parent.mkdir(parents=True, exist_ok=True)
    safe_event = event
    if audit.get("redact", True):
        safe_event = _redact(config, event)
        # Sanitize decoded metadata before JSON escaping can hide secret shapes.
        safe_event, _ = _redact_secret_shapes(safe_event)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(safe_event, sort_keys=True) + "\n")


def _redact(config: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    secrets = [secret for secret in _secret_values(config) if secret]

    def redact(value: Any) -> Any:
        if isinstance(value, str):
            for secret in secrets:
                value = value.replace(secret, "[redacted]")
            return value
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, dict):
            return {redact(key): redact(item) for key, item in value.items()}
        return value

    # Work on decoded keys and values: JSON escaping must not hide secrets.
    return redact(payload)


def _secret_values(config: dict[str, Any]) -> list[str]:
    auth = config.get("auth") if isinstance(config.get("auth"), dict) else {}
    env_name = auth.get("env")
    return [os.environ.get(str(env_name), "")] if env_name else []


def _auth_env(config: dict[str, Any]) -> str | None:
    auth = config.get("auth") if isinstance(config.get("auth"), dict) else {}
    env_name = auth.get("env")
    return str(env_name) if env_name else None


def _auth_header(config: dict[str, Any]) -> tuple[str, str] | None:
    auth = config.get("auth") if isinstance(config.get("auth"), dict) else {}
    env_name = auth.get("env")
    if not env_name:
        return None
    value_from_env = os.environ.get(str(env_name))
    if not value_from_env:
        raise BridgeError(f"auth env is not set: {env_name}")
    header = str(auth.get("header", "Authorization"))
    prefix = str(auth.get("prefix", "")).strip()
    value = f"{prefix} {value_from_env}" if prefix else value_from_env
    return header, value


def _display_url(url: str) -> str:
    """The target URL without any userinfo, for messages and logs."""
    parts = urlsplit(url)
    if parts.username is None and parts.password is None:
        return url
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def _cleartext_remote(url: str) -> bool:
    """True for http:// targets whose host is not loopback."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    host = (parts.hostname or "").strip("[]").lower()
    return parts.scheme == "http" and not (host in {"localhost", "::1"} or host.startswith("127."))


def _target_url(config: dict[str, Any]) -> str:
    target = config.get("target") if isinstance(config.get("target"), dict) else {}
    url = target.get("url")
    if not isinstance(url, str) or not url:
        raise BridgeError("config target.url is required")
    return url


def _policy_mode(config: dict[str, Any]) -> str:
    policy = config.get("policy") if isinstance(config.get("policy"), dict) else {}
    mode = policy.get("mode", "allowlist")
    if mode != "allowlist":
        raise BridgeError("only allowlist policy mode is supported")
    return str(mode)


def _allowed_tools(config: dict[str, Any]) -> list[str]:
    _policy_mode(config)
    policy = config.get("policy") if isinstance(config.get("policy"), dict) else {}
    tools = policy.get("allow_tools")
    if not isinstance(tools, list) or not all(isinstance(item, str) and item for item in tools):
        raise BridgeError("policy.allow_tools must be a list of tool names")
    return list(tools)


def _validate_response(response: Any, request: dict[str, Any]) -> None:
    """Reject untrusted envelopes without attributing their ID or replaying work."""
    invalid = (not isinstance(response, dict)
               or response.get("jsonrpc") != "2.0"
               or "id" not in response
               or "method" in response
               or ("result" in response) == ("error" in response))
    if not invalid:
        response_id = response["id"]
        request_id = request.get("id")
        # Type equality prevents Python's True == 1 and string/number aliasing.
        invalid = (type(response_id) is not type(request_id)
                   or response_id != request_id
                   or type(response_id) not in (str, int, float, type(None))
                   or (type(response_id) is float and not math.isfinite(response_id)))
    if not invalid and "error" in response:
        error = response["error"]
        invalid = (not isinstance(error, dict)
                   or type(error.get("code")) is not int
                   or not isinstance(error.get("message"), str))
    if invalid:
        raise BridgeError("invalid or uncorrelated upstream JSON-RPC response; outcome uncertain; nothing retried")


def _tools_from_response(response: dict[str, Any]) -> list[str]:
    result = response.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        raise BridgeError("invalid upstream tools/list result; outcome uncertain; nothing retried")
    tools = result["tools"]
    return [item["name"] for item in tools
            if isinstance(item, dict) and isinstance(item.get("name"), str)]


def _redaction_enabled(config: dict[str, Any]) -> bool:
    audit = config.get("audit") if isinstance(config.get("audit"), dict) else {}
    return bool(audit.get("redact", True))


def _known_tools() -> set[str]:
    try:
        from arvyx_control.mcp import TOOL_NAMES
    except ImportError:
        return set()
    return set(TOOL_NAMES)


def _error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class BridgeError(RuntimeError):
    pass


# Console-script compatibility: an earlier packaging revision declared the
# entry point as safe_mcp_bridge.cli:app, and already-installed environments
# keep the generated shim (`from safe_mcp_bridge.cli import app; app()`)
# until they are reinstalled. Keep both names valid so a stale shim works
# without a reinstall; pyproject.toml points new installs at cli:main.
app = main


if __name__ == "__main__":
    raise SystemExit(main())
