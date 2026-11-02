"""The JSON nesting bound is a product contract, identical on every supported Python.

Python 3.11 refused a few hundred nested arrays with RecursionError; 3.12 and later
parse thousands. The intakes must therefore not depend on the interpreter: the
scanner decides, before parsing, and every loopback surface reports the same refusal.
"""
import ast
import json
from pathlib import Path

import pytest

from arvyx_control import security
from arvyx_control.mcp import handle_json_line
from arvyx_control.security import JSONNestingError, MAX_JSON_NESTING, bounded_json_loads, json_nesting_depth


def nested(depth, inner="0"):
    return "[" * depth + inner + "]" * depth


def test_depth_counts_brackets_outside_strings_only():
    assert json_nesting_depth('{"a": [1, {"b": "]}[{\\"}]}') == 3
    assert json_nesting_depth('"[[[[["') == 0
    assert json_nesting_depth('{"escaped\\\\": "[", "q": "\\"[["}') == 1
    assert json_nesting_depth("") == 0
    assert json_nesting_depth("]]]]") == 0  # stray closers never go negative


def test_limit_is_inclusive_and_the_scan_stops_at_the_bound():
    assert json_nesting_depth(nested(MAX_JSON_NESTING)) == MAX_JSON_NESTING
    assert json_nesting_depth(nested(MAX_JSON_NESTING + 1)) == MAX_JSON_NESTING + 1
    # Far deeper input is reported as "over the bound" without walking to its end.
    assert json_nesting_depth(nested(100_000)) == MAX_JSON_NESTING + 1


def test_bounded_loads_accepts_at_the_bound_and_refuses_above_it():
    assert isinstance(bounded_json_loads(nested(MAX_JSON_NESTING)), list)
    with pytest.raises(JSONNestingError):
        bounded_json_loads(nested(MAX_JSON_NESTING + 1))
    with pytest.raises(JSONNestingError):
        bounded_json_loads(nested(5000))
    assert issubclass(JSONNestingError, ValueError)


def test_bounded_loads_takes_bytes_and_keyword_arguments():
    def unique(pairs):
        value = dict(pairs)
        if len(value) != len(pairs):
            raise ValueError("duplicate")
        return value
    assert bounded_json_loads(b'{"a": 1}', object_pairs_hook=unique) == {"a": 1}
    with pytest.raises(ValueError):
        bounded_json_loads(b'{"a": 1, "a": 2}', object_pairs_hook=unique)
    with pytest.raises(UnicodeDecodeError):
        bounded_json_loads(b"\xff\xfe")


def test_mcp_stdio_refuses_over_deep_input_with_a_parse_error(tmp_path):
    response = json.loads(handle_json_line(nested(MAX_JSON_NESTING + 1), tmp_path))
    assert response["error"]["code"] == -32700
    assert "nesting" in response["error"]["message"]
    ok = json.loads(handle_json_line('{"jsonrpc":"2.0","id":7,"method":"ping"}', tmp_path))
    assert ok["id"] == 7


NETWORK_MODULES = (
    "mcp.py", "api.py", "projection_cache.py", "public_onboarding_api.py", "cockpit_web.py",
    "cockpit.py", "external_api.py", "external_presentation.py", "machine_pairing_transport.py",
    "embeddings.py", "remote_effect_fence.py", "secret_delivery_protocol.py",
    "secret_delivery_access.py", "agent_delivery.py", "replica.py", "brokers.py",
)
# Every plain json.loads call still present in those modules, by the source text of
# its first argument. Each parses local operator-owned files, the product's own
# SQLite rows, values the code canonicalised itself, or a response the product
# built. A new json.loads call in one of these modules fails the guard below until
# it is routed through bounded_json_loads or reviewed and listed here.
REVIEWED_LOCAL_PARSES = {
    "api.py": {"value", "response.body", 'path.read_text(encoding="utf-8")'},
    "cockpit.py": {"row['panels']", "project_file.read_text()", "binding[0]", "config.read_text()"},
    "external_api.py": {"row['operations']", "row['resources']"},
    "external_presentation.py": {"p.read_text()"},
    "machine_pairing_transport.py": {"base64.b64decode(row['message'])"},
    "embeddings.py": {'candidate.read_text(encoding="utf-8")'},
    "remote_effect_fence.py": {"_canonical(value)", "_canonical(plan)", "row[0]", "row[1]", "destination[0]", "ticket[0]"},
    "replica.py": {"marker.read_text()", 'status_path.read_text(encoding="utf-8")', 'path.read_text(encoding="utf-8")'},
    "brokers.py": {'candidate.read_text(encoding="utf-8")'},
}


def test_nesting_error_is_a_decode_error():
    # Existing handlers catch either JSONDecodeError or ValueError; both must see it.
    assert issubclass(JSONNestingError, json.JSONDecodeError)
    with pytest.raises(json.JSONDecodeError):
        bounded_json_loads(nested(MAX_JSON_NESTING + 1))


def _plain_json_loads_arguments(text):
    tree = ast.parse(text)
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "loads" or not isinstance(node.func.value, ast.Name) or node.func.value.id != "json":
            continue
        found.add(ast.get_source_segment(text, node.args[0]) if node.args else "<no argument>")
    return found


def test_every_network_intake_uses_the_bound():
    # Syntax-level, not text-level: any json.loads call the modules contain is found
    # whatever its argument is spelled like, and must be in the reviewed set.
    root = Path(security.__file__).resolve().parent
    for module in NETWORK_MODULES:
        text = (root / module).read_text(encoding="utf-8")
        assert "bounded_json_loads" in text or "json_nesting_depth" in text, module
        unexpected = _plain_json_loads_arguments(text) - REVIEWED_LOCAL_PARSES.get(module, set())
        assert not unexpected, f"{module} has an unreviewed plain json.loads: {sorted(unexpected)}"


def test_reviewed_parse_list_has_no_stale_entries():
    root = Path(security.__file__).resolve().parent
    for module, arguments in REVIEWED_LOCAL_PARSES.items():
        present = _plain_json_loads_arguments((root / module).read_text(encoding="utf-8"))
        assert arguments <= present, f"{module}: reviewed entries no longer in the source: {sorted(arguments - present)}"


def test_nesting_error_message_has_no_position_suffix():
    with pytest.raises(JSONNestingError) as info:
        bounded_json_loads(nested(MAX_JSON_NESTING + 1))
    assert str(info.value) == info.value.msg
    assert "line 1 column 1" not in str(info.value)
