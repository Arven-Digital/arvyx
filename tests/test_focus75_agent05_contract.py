"""Static regression source only. NOT_EXECUTED in Focus75 agent05.

These source-shape checks preserve existing fences; they are not behavioral
acceptance, independent artifact admission or evidence of a hard service deadline.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'packages/arvctl/src/arvyx_control'


def test_release_boundary_never_advertises_approval():
    tree = ast.parse((ROOT / 'scripts/public_release_boundary.py').read_text())
    approvals = [value for node in ast.walk(tree) if isinstance(node, ast.Dict)
                 for key, value in zip(node.keys, node.values)
                 if isinstance(key, ast.Constant) and key.value == 'release_approved']
    assert approvals
    assert all(isinstance(value, ast.Constant) and value.value is False for value in approvals)


def test_native_policy_keeps_independently_admitted_pin():
    tree = ast.parse((SOURCE / 'native_artifact_policy.py').read_text())
    pins = [node.value.value for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'NATIVE_MOUSE_BINARY_SHA256'
                    for target in node.targets)]
    assert pins == ['c8cd3a11b577a23dc37b34f64814e37242e4d2af27726149e3feed6c21c0fd5a']


def test_endpoint_execute_is_not_inside_sender_authority_lock():
    tree = ast.parse((SOURCE / 'organizer_delegation.py').read_text())
    found = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.With):
            continue
        guarded = any(ast.unparse(item.context_expr) == 'self.authority._lock'
                      for item in node.items)
        if not guarded:
            continue
        found += 1
        # Endpoint I/O must not run under the guard; the SQLite cursor's own
        # self.db.execute is the guarded transaction, not endpoint execution.
        assert not any(isinstance(call, ast.Call)
                       and isinstance(call.func, ast.Attribute)
                       and call.func.attr == 'execute'
                       and ast.unparse(call.func.value) != 'self.db'
                       for call in ast.walk(node))
    assert found
