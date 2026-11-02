from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "examples" / "mcp-clients" / "streaming-compatibility.json"
DOC = ROOT / "docs" / "mcp-streaming.md"


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate MCP streaming compatibility fixture.")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()

    result = validate()
    if args.json_output:
        print(json.dumps(result, sort_keys=True))
    elif result["ok"]:
        print(f"ok=true transports={result['transports']}")
    else:
        for error in result["errors"]:
            print(error, file=sys.stderr)
    return 0 if result["ok"] else 1


def validate() -> dict[str, Any]:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    doc = DOC.read_text(encoding="utf-8")
    errors: list[str] = []
    transports = payload.get("transports", [])
    by_name = {item.get("name"): item for item in transports if isinstance(item, dict)}

    for required in ["direct-stdio", "http-json-rpc", "safe-mcp-bridge-stdio-to-http", "sse"]:
        if required not in by_name:
            errors.append(f"missing transport fixture: {required}")
    for required in ["Direct stdio", "HTTP JSON-RPC", "safe-mcp-bridge", "SSE"]:
        if required not in doc:
            errors.append(f"docs missing section text: {required}")
    if by_name.get("sse", {}).get("supported") is not False:
        errors.append("sse must remain unsupported until implemented")
    for name in ["direct-stdio", "http-json-rpc", "safe-mcp-bridge-stdio-to-http"]:
        if by_name.get(name, {}).get("supported") is not True:
            errors.append(f"{name} must be marked supported")
        if by_name.get(name, {}).get("streaming") is not False:
            errors.append(f"{name} must be marked request/response, not streaming")
    if payload.get("status") != "alpha-request-response":
        errors.append("unexpected compatibility status")

    return {
        "ok": not errors,
        "fixture": str(FIXTURE.relative_to(ROOT)),
        "doc": str(DOC.relative_to(ROOT)),
        "transports": sorted(by_name),
        "errors": errors,
    }


if __name__ == "__main__":
    raise SystemExit(main())
