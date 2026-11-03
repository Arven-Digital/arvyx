#!/usr/bin/env python3
"""Generate or check executable HTTP, CLI, and MCP contract references."""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "packages" / "arvctl" / "src"
BRIDGE_SRC = ROOT / "packages" / "safe-mcp-bridge" / "src"
DEFAULT_OUTPUT = ROOT / "docs" / "contracts" / "external-contracts.json"

for source in (SRC, BRIDGE_SRC):
    sys.path.insert(0, str(source))


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        if isinstance(node, ast.Name):
            return {"symbol": node.id}
        if isinstance(node, ast.Attribute):
            return {"symbol": ast.unparse(node)}
        return {"expression": ast.unparse(node)}


def _call_name(call: ast.Call) -> str:
    return ast.unparse(call.func)


def _method_from_test(node: ast.AST) -> str | None:
    for part in ast.walk(node):
        if isinstance(part, ast.Compare) and isinstance(part.left, ast.Name) and part.left.id == "method":
            for comparator in part.comparators:
                value = _literal(comparator)
                if isinstance(value, str) and value in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    return value
    return None


def _routes_from_test(node: ast.AST, regexes: dict[str, str]) -> list[str]:
    routes: list[str] = []
    for part in ast.walk(node):
        if isinstance(part, ast.Name) and part.id in regexes:
            routes.append(_regex_to_template(regexes[part.id]))
        if not isinstance(part, ast.Compare) or not isinstance(part.left, ast.Name) or part.left.id != "route":
            continue
        for comparator in part.comparators:
            value = _literal(comparator)
            if isinstance(value, str) and value.startswith("/"):
                routes.append(value)
            elif isinstance(value, (set, tuple, list)):
                routes.extend(item for item in value if isinstance(item, str) and item.startswith("/"))
    return sorted(set(routes))


def _regex_to_template(pattern: str) -> str:
    value = pattern.removeprefix("^").removesuffix("$")
    index = 0
    while "([^/]+)" in value:
        names = ("id", "action_id", "item_id")
        value = value.replace("([^/]+)", "{" + names[min(index, len(names) - 1)] + "}", 1)
        index += 1
    return value.replace("\\/", "/")


def _enclosing_operator_only(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Find authority checks preceding a route in its enclosing body.

    Do not scan sibling branches: their checks do not guard this route.
    The router assigns _operator_only's denial before returning it.
    """
    while node in parents:
        parent = parents[node]
        for _, value in ast.iter_fields(parent):
            if not isinstance(value, list) or node not in value:
                continue
            for statement in value[:value.index(node)]:
                if isinstance(statement, ast.Assign) and any(
                    isinstance(child, ast.Call) and _call_name(child) == "_operator_only"
                    for child in ast.walk(statement.value)
                ):
                    return True
        node = parent
    return False


def _http_contract() -> dict[str, Any]:
    from arvyx_control import api

    path = SRC / "arvyx_control" / "api.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_handle_api_request")
    regexes: dict[str, str] = {}
    for node in ast.walk(function):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, ast.Call) and _call_name(node.value) == "re.fullmatch" and node.value.args:
                pattern = _literal(node.value.args[0])
                if isinstance(pattern, str):
                    regexes[node.targets[0].id] = pattern

    parents = {child: parent for parent in ast.walk(function) for child in ast.iter_child_nodes(parent)}
    operations: dict[tuple[str, str], dict[str, Any]] = {}
    for node in ast.walk(function):
        if not isinstance(node, ast.If):
            continue
        method = _method_from_test(node.test)
        if not method:
            continue
        for route in _routes_from_test(node.test, regexes):
            statuses = sorted({
                value for child in ast.walk(node) if isinstance(child, ast.Call) and _call_name(child) == "ApiResponse"
                and child.args and isinstance((value := _literal(child.args[0])), int)
            })
            representative = re.sub(r"\{[^}]+\}", "synthetic-id", route)
            auth: dict[str, Any] = {"required_scope": api._required_scope(method, representative)}
            # A scope alone does not describe the authority gate: these routes
            # also refuse any identity that is not the operator, so the contract
            # must say so instead of letting a consumer infer write authority.
            if _enclosing_operator_only(node, parents) or any(
                isinstance(child, ast.Call) and _call_name(child) == "_operator_only"
                for child in ast.walk(node)
            ):
                auth["operator_only"] = True
            if method == "POST" and route == "/approvals/{id}/approve":
                auth["operator_only"] = True
                auth["anonymous_demo_exception"] = "explicit allow_unauthenticated_demo only; authenticated non-operators denied"
            operations[(route, method)] = {
                "auth": auth,
                "responses": {str(status): {"shape": "JSON object unless content_type says otherwise"} for status in statuses},
            }
    # Dedicated intake is deliberately outside _handle_api_request and its
    # body-digest journal. Keep its stricter contract explicit and discoverable.
    from arvyx_control.secret_delivery import PREFIX, ROUTES
    for action in ROUTES:
        operations[(PREFIX + "/" + action, "POST")] = {
            "auth": {"operator_only": True, "verified_cloudflare_access_rs256": True,
                     "required_claims": ["iss", "aud", "sub", "exp", "iat", "nbf", "type"],
                     "exact_human_subject_allowlist": True, "actor_scoped_receipts": True,
                     "browser_client_certificate": False, "browser_shared_bearer": False,
                     "exact_origin": "https://control.party", "custom_header": "X-Secret-Delivery: 1",
                     "same_session_csrf": action != "bootstrap", "default_disabled": True},
            "intake": "private existing edge adapter before generic proxy body path; raw V2 always disabled",
            "transport": "new private pinned mTLS receiver; not external broker integration",
            "max_request_body_bytes": 98304,
            "responses": {"200": {"shape": "session/prepare metadata or redacted receipt"},
                          "400": {"shape": "fixed rejection"}, "403": {"shape": "operator denied"},
                          "503": {"shape": "disabled or non-HTTP invocation"}},
        }
    paths: dict[str, Any] = {}
    for (route, method), operation in sorted(operations.items()):
        paths.setdefault(route, {})[method.lower()] = operation
    return {
        "format": "arvyx-openapi-like/v1",
        "source": "packages/arvctl/src/arvyx_control/api.py:_handle_api_request,_required_scope",
        "limits": {"max_request_body_bytes": api.MAX_BODY_BYTES, "max_server_workers": api.MAX_SERVER_WORKERS,
                   "request_body_measurement": "Complete encoded HTTP body in bytes, including JSON envelopes, metadata and escaping; schema maxima do not guarantee their Cartesian product fits. Applies to /memory/suggest-batch and /mcp as well as other generic POST routes; dedicated intake may impose lower limits."},
        "common_errors": {
            "400": {"type": "object", "required": ["ok", "error"], "properties": {"ok": {"const": False}, "error": {"type": "string"}}},
            "401": {"description": "missing or invalid authentication"},
            "403": {"description": "authenticated identity lacks scope or operator authority"},
            "404": {"description": "route not found"},
            "409": {"description": "idempotency conflict or operation already in progress"},
            "413": {"description": "request body exceeds max_request_body_bytes"},
            "500": {"description": "internal failure; secret values are not replayed"},
        },
        "paths": paths,
    }


def _cli_contract(source: Path, program: str, *, include_root: bool = False) -> dict[str, Any]:
    tree = ast.parse(source.read_text(encoding="utf-8"))
    parser_paths: dict[str, list[str]] = {}
    subparser_owner: dict[str, list[str]] = {}
    commands: dict[tuple[str, ...], dict[str, Any]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        target = node.targets[0].id
        if not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if isinstance(call.func, ast.Attribute) and call.func.attr == "add_subparsers" and isinstance(call.func.value, ast.Name):
            owner = call.func.value.id
            subparser_owner[target] = parser_paths.get(owner, [])
        elif isinstance(call.func, ast.Attribute) and call.func.attr == "add_parser" and isinstance(call.func.value, ast.Name) and call.args:
            name = _literal(call.args[0])
            if isinstance(name, str):
                command_path = subparser_owner.get(call.func.value.id, []) + [name]
                parser_paths[target] = command_path
                commands[tuple(command_path)] = {"command": " ".join([program, *command_path]), "help": _literal(next((kw.value for kw in call.keywords if kw.arg == "help"), None)), "arguments": []}
        elif _call_name(call) == "argparse.ArgumentParser":
            parser_paths[target] = []
            # Collect root options even when the root is not a runnable command.
            commands[()] = {"command": program, "help": None, "arguments": []}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
            continue
        call = node.value
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "add_argument" or not isinstance(call.func.value, ast.Name):
            continue
        command_path = parser_paths.get(call.func.value.id)
        if command_path is None or tuple(command_path) not in commands:
            continue
        names = [_literal(arg) for arg in call.args]
        item: dict[str, Any] = {"names": names}
        for keyword in call.keywords:
            if keyword.arg in {"required", "default", "choices", "action", "dest", "help", "type", "nargs"}:
                item[keyword.arg] = _literal(keyword.value)
        commands[tuple(command_path)]["arguments"].append(item)
    result = {"source": source.relative_to(ROOT).as_posix(),
              "commands": [commands[key] for key in sorted(commands) if key or include_root]}
    if not include_root and () in commands and commands[()]["arguments"]:
        result["root_arguments"] = commands[()]["arguments"]
        result["root_argument_placement"] = "Before the first subcommand; inherited by every command path."
    # Preserve the executable cross-argument authority prerequisite as well as
    # argparse's declarations (which alone make --authority-vault optional).
    constraints = sorted({
        message for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _call_name(node) == "parser.error" and node.args
        and isinstance((message := _literal(node.args[0])), str) and "--authority-vault" in message
    })
    if constraints:
        result["invocation_constraints"] = constraints
    return result


def _schema_limits(schema: Any, prefix: str = "") -> dict[str, Any]:
    found: dict[str, Any] = {}
    if isinstance(schema, dict):
        for key, value in schema.items():
            here = f"{prefix}.{key}" if prefix else key
            if key in {"maxItems", "minItems", "maximum", "minimum", "maxLength", "minLength", "pattern"}:
                found[prefix] = {**found.get(prefix, {}), key: value}
            else:
                found.update(_schema_limits(value, here))
    elif isinstance(schema, list):
        for index, value in enumerate(schema):
            found.update(_schema_limits(value, f"{prefix}[{index}]"))
    return found


def _mcp_contract() -> dict[str, Any]:
    from arvyx_control.auth import SCOPE_TOOLS
    from arvyx_control.mcp import IDEMPOTENCY_REQUIRED_TOOL_NAMES, MCP_PROFILES, TOOL_NAMES, _tools

    definitions = {item["name"]: item for item in _tools(allowed_tools=set(TOOL_NAMES))}
    tools = []
    for name in sorted(definitions):
        definition = definitions[name]
        scopes = sorted(scope for scope, names in SCOPE_TOOLS.items() if name in names)
        tools.append({
            "name": name,
            "description": definition.get("description", ""),
            "inputSchema": definition["inputSchema"],
            "auth_scopes": scopes,
            "profiles": sorted(profile for profile, names in MCP_PROFILES.items() if name in names),
            "idempotency_required": name in IDEMPOTENCY_REQUIRED_TOOL_NAMES,
            "limits": _schema_limits(definition["inputSchema"]),
        })
    return {
        "source": "packages/arvctl/src/arvyx_control/mcp.py:_tools,MCP_PROFILES; arvyx_control/auth.py:SCOPE_TOOLS",
        "protocol_version": "2024-11-05",
        "limits_interpretation": "Schema maxItems and maxLength constrain arrays and individual strings, not aggregate encoded bytes. Over HTTP, the complete /mcp JSON-RPC request must also fit http.limits.max_request_body_bytes; stdio is a separate transport. No Cartesian-product admission guarantee.",
        "profiles": {name: sorted(names) for name, names in sorted(MCP_PROFILES.items())},
        "tools": tools,
        "error_shape": {"jsonrpc": "2.0", "id": "request id or null", "error": {"code": "integer", "message": "string"}},
    }


def build_contract() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "generated_from_code": True,
        "notice": "Do not edit this file by hand. Run: python scripts/generate_external_contracts.py",
        "http": _http_contract(),
        "cli": {
            "arvyx": _cli_contract(SRC / "arvyx_control" / "cli.py", "arvyx"),
            "dispatcher": _cli_contract(SRC / "arvyx_control" / "dispatcher.py", "python -m arvyx_control.dispatcher", include_root=True),
            "safe-mcp-bridge": _cli_contract(BRIDGE_SRC / "safe_mcp_bridge" / "cli.py", "safe-mcp-bridge"),
        },
        "mcp": _mcp_contract(),
    }


def render() -> str:
    return json.dumps(build_contract(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if the committed contract differs from code.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    generated = render()
    if args.check:
        try:
            committed = args.output.read_text(encoding="utf-8")
        except FileNotFoundError:
            print(f"missing generated contract: {args.output.relative_to(ROOT)}", file=sys.stderr)
            return 1
        if committed != generated:
            print(f"generated contract drift: run {Path(__file__).relative_to(ROOT)}", file=sys.stderr)
            return 1
        print(json.dumps({"ok": True, "contract": str(args.output.relative_to(ROOT))}, sort_keys=True))
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(generated, encoding="utf-8")
    print(json.dumps({"ok": True, "contract": str(args.output.relative_to(ROOT))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
