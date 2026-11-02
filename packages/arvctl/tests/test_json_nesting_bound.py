"""The JSON nesting bound is a product contract, identical on every supported Python.

Python 3.11 refused a few hundred nested arrays with RecursionError; 3.12 and later
parse thousands. The intakes must therefore not depend on the interpreter: the
scanner decides, before parsing, and every loopback surface reports the same refusal.
"""
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


def test_every_loopback_intake_uses_the_bound():
    root = Path(security.__file__).resolve().parent
    for module in ("mcp.py", "api.py", "projection_cache.py", "public_onboarding_api.py", "cockpit_web.py", "cockpit.py"):
        text = (root / module).read_text(encoding="utf-8")
        assert "bounded_json_loads" in text or "json_nesting_depth" in text, module
