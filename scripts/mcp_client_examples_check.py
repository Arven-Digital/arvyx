from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import tomllib
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "mcp-clients"
PRIVATE_MARKERS = ("/home/", "/srv/", "/Users/")
# A drive-letter path (C:\...) or a UNC share (\\host\...). Backslash-anchored
# so it never false-positives on http:// (the `p:/` in an URL); the UNC branch
# requires a share backslash so an escaped-backslash literal in a .py example
# (e.g. a regex "\\d+") is not mistaken for a path.
WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\|\\\\[A-Za-z0-9._$-]+\\")


def _flag_private_paths(name: str, text: str, errors: list[str]) -> None:
    for marker in PRIVATE_MARKERS:
        if marker in text:
            errors.append(f"{name}: private path marker found: {marker}")
    if WINDOWS_PATH_RE.search(text):
        errors.append(f"{name}: Windows local path found; use a /path/to/... placeholder")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate MCP client example fixtures.")
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()

    result = validate_examples()
    if args.json_output:
        print(json.dumps(result, sort_keys=True))
    elif result["ok"]:
        print(f"ok=true examples={result['examples']}")
    else:
        for error in result["errors"]:
            print(error, file=sys.stderr)
    return 0 if result["ok"] else 1


def validate_examples() -> dict[str, Any]:
    errors: list[str] = []
    examples = {
        "claude-desktop": _mcp_servers_json(EXAMPLES / "claude-desktop.json", errors, "claude-desktop.json"),
        "codex": _codex(EXAMPLES / "codex.toml", errors),
        "cursor": _mcp_servers_json(EXAMPLES / "cursor.json", errors, "cursor.json"),
        "openhands": _openhands(EXAMPLES / "openhands.toml", errors),
    }
    for name, server in examples.items():
        if server:
            _validate_server(name, server, errors)

    python_examples = {
        "langgraph": EXAMPLES / "langgraph_client.py",
        "crewai": EXAMPLES / "crewai_client.py",
    }
    for name, path in python_examples.items():
        _validate_python_example(name, path, errors)

    present = [name for name, server in examples.items() if server]
    present += [name for name, path in python_examples.items() if path.is_file()]
    return {
        "ok": not errors,
        "examples": sorted(present),
        "errors": errors,
    }


def _mcp_servers_json(path: Path, errors: list[str], label: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        errors.append(f"{path.relative_to(ROOT)}: {exc}")
        return None
    server = payload.get("mcpServers", {}).get("arvyx-memory")
    if not isinstance(server, dict):
        errors.append(f"{label}: missing mcpServers.arvyx-memory")
        return None
    return server


def _codex(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"{path.relative_to(ROOT)}: {exc}")
        return None
    server = payload.get("mcp_servers", {}).get("arvyx-memory")
    if not isinstance(server, dict):
        errors.append("codex.toml: missing mcp_servers.arvyx-memory")
        return None
    return server


def _openhands(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, tomllib.TOMLDecodeError) as exc:
        errors.append(f"{path.relative_to(ROOT)}: {exc}")
        return None
    servers = payload.get("mcp", {}).get("stdio_servers")
    if not isinstance(servers, list):
        errors.append("openhands.toml: missing mcp.stdio_servers list")
        return None
    server = next((item for item in servers if isinstance(item, dict) and item.get("name") == "arvyx-memory"), None)
    if server is None:
        errors.append("openhands.toml: missing arvyx-memory stdio server")
        return None
    return server


def _validate_python_example(name: str, path: Path, errors: list[str]) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        errors.append(f"{name}: {path.relative_to(ROOT)} not found")
        return
    for token in ("arvyx_control.cli", "mcp", "--profile", "read-only", "--vault", "fixtures/synthetic-vault", "packages/arvctl/src"):
        if token not in text:
            errors.append(f"{name}: example missing {token}")
    _flag_private_paths(name, text, errors)


def _validate_server(name: str, server: dict[str, Any], errors: list[str]) -> None:
    command = server.get("command")
    args = server.get("args")
    env = server.get("env")
    joined = " ".join(str(item) for item in args) if isinstance(args, list) else ""
    text = json.dumps(server, sort_keys=True)

    # Accept any common Python launcher so the same example works on
    # Linux/macOS (python3) and Windows (python / py).
    if command not in {"python3", "python", "py"}:
        errors.append(f"{name}: command must be a python launcher (python3, python, or py)")
    if not isinstance(args, list):
        errors.append(f"{name}: args must be a list")
        return
    for expected in ["-m", "arvyx_control.cli", "mcp", "--vault"]:
        if expected not in args:
            errors.append(f"{name}: args missing {expected}")
    try:
        profile_index = args.index("--profile")
    except ValueError:
        errors.append(f"{name}: args missing explicit --profile read-only")
    else:
        if profile_index + 1 >= len(args) or args[profile_index + 1] != "read-only":
            errors.append(f"{name}: claimed read-only example must pass --profile read-only")
    if "fixtures/synthetic-vault" not in joined:
        errors.append(f"{name}: args must point at fixtures/synthetic-vault placeholder")
    if not isinstance(env, dict) or "PYTHONPATH" not in env:
        errors.append(f"{name}: env.PYTHONPATH is required")
    elif "packages/arvctl/src" not in str(env["PYTHONPATH"]):
        errors.append(f"{name}: env.PYTHONPATH must include packages/arvctl/src")
    _flag_private_paths(name, text, errors)


if __name__ == "__main__":
    raise SystemExit(main())
