import time
from unittest.mock import patch
from arvyx_control.audit import _private_context_check
from arvyx_control.security import multiline_constant_shape_spans


def test_nested_dependencies_are_not_traversed_as_source(tmp_path):
    dep=tmp_path/'frontend/node_modules/nested';dep.mkdir(parents=True)
    (dep/'not-source.ts').write_bytes(b'\0binary dependency')
    (tmp_path/'application.ts').write_text('const value = "hello";\n')
    check=_private_context_check(tmp_path)
    assert not any('node_modules' in finding for finding in check.findings)
    (tmp_path/'application.ts').write_bytes(b'\0invalid source')
    assert any('application.ts:decode-error' in f for f in _private_context_check(tmp_path).findings)


def test_large_literal_scanner_is_bounded_and_preserves_secret_detection():
    # Similar to generated .d.ts sources: many short independent string tokens.
    text=''.join(f'type T{i} = "value{i}";\n' for i in range(40000))
    start=time.perf_counter()
    assert not multiline_constant_shape_spans(text)
    elapsed=time.perf_counter()-start
    print(f'40,000 literals: {elapsed:.6f}s')
    assert elapsed < 2.0
    # Construct synthetic detection text without placing a complete shape in source.
    secret='sk-'+'a'*40
    assert multiline_constant_shape_spans('"'+secret[:10]+'" +\n "'+secret[10:]+'"') == {(1,2)}
