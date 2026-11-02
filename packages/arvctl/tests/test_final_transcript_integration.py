"""Source-contract regressions; not runtime/crash acceptance evidence."""
import ast
from pathlib import Path

import pytest
from arvyx_control.mutation_dispatch import resolve_mutation_key

SOURCE = Path(__file__).parents[1] / 'src/arvyx_control'


def test_transcript_key_matches_original_event_before_claim():
    key = 'transcript-event-0123456789'
    assert resolve_mutation_key({'event_id': key}, route='/control/transcripts', explicit=key) == key
    with pytest.raises(ValueError, match='event ID'):
        resolve_mutation_key({'event_id': 'different'}, route='/control/transcripts', explicit=key)


def test_bound_transcript_recovery_precedes_generic_completed_refusal():
    source = (SOURCE / 'api.py').read_text()
    tree = ast.parse(source)
    handler = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'handle_api_request')
    calls = [n for n in ast.walk(handler) if isinstance(n, ast.Call)]
    repair = next(n for n in calls if isinstance(n.func, ast.Name) and n.func.id == 'append_transcript')
    assert any(k.arg == 'replay_only' and isinstance(k.value, ast.Compare) for k in repair.keywords)
    completion = [n for n in calls if isinstance(n.func, ast.Name) and n.func.id == '_completed_mutation_response']
    assert all(repair.lineno < n.lineno for n in completion)
    assert source.index('if claim.conflict:') < source.index('receipt = append_transcript')
    assert source.index('receipt = append_transcript') < source.index('if claim.state != "completed":')


def test_local_capacity_operations_remain_human_guarded():
    tree = ast.parse((SOURCE / 'cockpit_archive.py').read_text())
    for name in ('raise_capture_capacity', 'export_capture'):
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
        assert any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == '_human' for n in ast.walk(function))
    source = (SOURCE / 'cockpit.py').read_text()
    # The local socket must dispatch both operations to the authenticated local
    # owner (`service`), never to the fleet `dispatcher` that may route remotely.
    handler = next(n for n in ast.parse(source).body
                   if isinstance(n, ast.FunctionDef) and n.name == 'handle_connection')
    routes = [n.value for n in ast.walk(handler) if isinstance(n, ast.Assign)
              and [getattr(t, 'id', None) for t in n.targets] == ['target']]
    assert len(routes) == 1 and isinstance(routes[0], ast.IfExp)
    route = routes[0]
    assert isinstance(route.body, ast.Name) and route.body.id == 'service'
    assert isinstance(route.orelse, ast.Name) and route.orelse.id == 'dispatcher'

    def local_names(test):
        # Names that make the condition true by themselves: an `or` branch or an
        # `operation in {...}` literal set. An `and` would not guarantee routing.
        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
            return set().union(*(local_names(value) for value in test.values))
        if (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == 'operation'
                and len(test.ops) == 1 and isinstance(test.ops[0], ast.In) and isinstance(test.comparators[0], ast.Set)):
            return {e.value for e in test.comparators[0].elts if isinstance(e, ast.Constant)}
        return set()

    assert {'raise_capture_capacity', 'export_capture'} <= local_names(route.test)
    assert source.index('recorder = WorkCapture(self, sid)') < source.index('pid, fd = pty.fork()')
