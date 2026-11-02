from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "arvctl" / "src"))

from arvyx_control.mcp import MEMORY_TOOL_NAMES, TOOL_NAMES

DEFAULT_FIXTURE = ROOT / "fixtures" / "safe-mcp-bridge" / "read-only-e2e.json"
FORBIDDEN_SUBSTRINGS = (
    "synthetic-dogfood-auth-value",
    "Bearer ",
    "ARVYX_DOGFOOD_AUTH=",
    "/home/",
    "/srv/",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate public-safe safe-mcp-bridge E2E evidence.")
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()

    result = validate_fixture(args.fixture)
    if args.json_output:
        print(json.dumps(result, sort_keys=True))
    elif result["ok"]:
        print(f"ok=true visible_tools={result['visible_tools']} audit_events={result['audit_events']}")
    else:
        for error in result["errors"]:
            print(error, file=sys.stderr)
    return 0 if result["ok"] else 1


def validate_fixture(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    errors: list[str] = []

    visible_tools = _visible_tools(payload)
    audit_events = [item.get("event") for item in payload.get("audit_events", []) if isinstance(item, dict)]
    collected_text = json.dumps(payload, sort_keys=True)

    if visible_tools != list(MEMORY_TOOL_NAMES):
        errors.append(f"expected read-only visible tools {list(MEMORY_TOOL_NAMES)}, got {visible_tools}")
    if set(visible_tools) - set(TOOL_NAMES):
        errors.append("fixture exposes tools not exported by the Arvyx MCP surface")
    if payload.get("recall_call", {}).get("response", {}).get("result") is None:
        errors.append("recall call must contain a successful result")
    if _blocked_error_code(payload) != -32001:
        errors.append("blocked control call must use JSON-RPC error -32001")
    for event in ["tools_list_filtered", "request_forwarded", "tool_blocked"]:
        if event not in audit_events:
            errors.append(f"missing audit event: {event}")
    for item in FORBIDDEN_SUBSTRINGS:
        if item in collected_text:
            errors.append(f"fixture contains forbidden private or credential text: {item}")

    return {
        "ok": not errors,
        "fixture": str(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path),
        "visible_tools": visible_tools,
        "recall_ok": payload.get("recall_call", {}).get("response", {}).get("result") is not None,
        "blocked_control_write": _blocked_error_code(payload) == -32001,
        "audit_events": audit_events,
        "credential_leaked": any(item in collected_text for item in FORBIDDEN_SUBSTRINGS),
        "errors": errors,
    }


def _visible_tools(payload: dict[str, Any]) -> list[str]:
    tools = payload.get("tools_list", {}).get("response", {}).get("result", {}).get("tools", [])
    return [item.get("name") for item in tools if isinstance(item, dict) and isinstance(item.get("name"), str)]


def _blocked_error_code(payload: dict[str, Any]) -> int | None:
    return payload.get("blocked_call", {}).get("response", {}).get("error", {}).get("code")


if __name__ == "__main__":
    raise SystemExit(main())
