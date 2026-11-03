"""Private synthetic security regressions; do not publish."""
import time
import pytest
from arvyx_control.security import (SECRET_RE, SECRET_REDACTION, contains_literal_secret,
    redact_secrets, strip_secret_refs, bounded_secret_subn)

@pytest.mark.parametrize('token', ['ghp_' + 'a' * 24, 'sk-' + 'a' * 24, 'github_pat_' + 'a' * 24])
@pytest.mark.parametrize('location', ['broker', 'path'])
def test_secret_reference_shapes(token, location):
    value = f'secret://{token}/key' if location == 'broker' else f'secret://vault/{token}'
    assert contains_literal_secret(value)
    assert strip_secret_refs(value) == value
    assert token not in redact_secrets(value)

@pytest.mark.parametrize('value', ['secret://vault/service/key', 'secret://broker-name/token'])
def test_safe_references_preserved(value):
    assert not contains_literal_secret(value)
    assert strip_secret_refs(value) == ' '
    assert redact_secrets(value) == value

@pytest.mark.parametrize('value', [
    'postgres://u:p@host/db', 'POSTGRESQL://user:pass@host/db',
    'postgres://u:postgres://u:pass@host/db',
    'postgres://u:p@host/a/b', 'postgres://u:p@h/db"tail',
    'postgres://u:p@h/db postgres://v:q@h/other',
    'postgres://u:p@h/db\npostgres://u:p@h/db',
    'postgres://u:p@host', 'postgres://u:@host/db',
])
def test_postgres_detection_semantics(value):
    assert contains_literal_secret(value) == bool(SECRET_RE.search(value))
    assert bounded_secret_subn(value, SECRET_RE) == SECRET_RE.subn(SECRET_REDACTION, value)

def test_postgres_span_grammar_differential():
    import itertools
    import re
    from arvyx_control.security import _POSTGRES_PATTERN, _postgres_spans
    detector = re.compile(_POSTGRES_PATTERN, re.IGNORECASE)
    pieces = ['u', ':', '@', '/', ' ', '\n', "'", '"', 'postgres://', 'é']
    for parts in itertools.product(pieces, repeat=4):
        value = 'postgres://' + ''.join(parts) + '@host/db'
        assert list(_postgres_spans(value)) == [m.span() for m in detector.finditer(value)]

@pytest.mark.parametrize('suffix', ['', '@host', '@host/', '@host/db'])
@pytest.mark.parametrize('operation', [contains_literal_secret, redact_secrets])
def test_postgres_prefix_scaling(operation, suffix):
    durations = []
    for count in [1000, 4000]:
        text = 'postgres://u:' * count + suffix
        samples = []
        for _ in range(3):
            # perf_counter: process_time has ~16 ms granularity on Windows, which
            # reads a 1000-item run as 0.0 and defeats the ratio.
            start = time.perf_counter()
            operation(text)
            samples.append(time.perf_counter() - start)
        durations.append(min(samples))
    print(operation.__name__, durations)
    assert durations[1] < durations[0] * 7 + 0.01
