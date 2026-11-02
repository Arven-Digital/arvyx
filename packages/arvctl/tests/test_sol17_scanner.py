"""Synthetic regressions for candidate16 Sol findings 3 and 4."""
import pytest
import importlib.util
import time
from pathlib import Path

from arvyx_control import security, audit
from safe_mcp_bridge import cli as bridge

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('sol17_scan', ROOT / 'scripts/private_context_scan.py')
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


@pytest.mark.parametrize('operation', [security.contains_literal_secret, security.redact_secrets,
                                      lambda s: bridge.bounded_secret_subn(s, bridge._FALLBACK_SECRET_RE)])
def test_jwt_nonmatch_cpu(operation):
    durations = []
    for count in (4000, 8000, 16000):
        text = 'eyJ-' * count
        start = time.process_time()
        operation(text)
        durations.append(time.process_time() - start)
    print(operation.__name__, durations)
    assert durations[-1] < 0.5
    assert durations[-1] < durations[0] * 7 + 0.01


def test_jwt_positive_parity():
    import re
    pattern = re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b', re.I)
    for text in ['eyJx.a.b', 'eyJ--eyJx.a.b---', 'éeyJx.a.b', ' eyjx.a.---é', 'eyJx.a.-', 'eyJx.a.b' + 'x' * 100000]:
        expected = bool(pattern.search(text))
        assert security.contains_literal_secret(text) == expected
        assert (security.redact_secrets(text) != text) == expected
        assert (bridge.bounded_secret_subn(text, bridge._FALLBACK_SECRET_RE)[0] != text) == expected


def test_multiline_assignments(tmp_path):
    for name, text in [('a.yaml', 'heading\npassword:\n  abcdefghijk1234\n'),
                       ('a.js', 'heading\nconst token =\n "abcdefghijk1234";\n')]:
        path = tmp_path / name
        path.write_text(text)
        assert security.contains_literal_secret(text)
        hits, _ = scanner.scan(tmp_path)
        assert f'{name}:2' in hits
        result = audit._private_context_check(tmp_path)
        assert not result.ok
        assert f'{name}:2' in result.findings
        path.unlink()


def test_exact_line_exception_does_not_hide_multiline(tmp_path):
    path = tmp_path / 'a.yaml'
    line = 'password: abcdefghijk1234'  # gitleaks:allow -- deliberate synthetic scanner fixture
    path.write_text(line + '\npassword:\n  abcdefghijk1234\n')
    allow = tmp_path / 'fixtures/secret-scan-allowlist.txt'
    allow.parent.mkdir()
    allow.write_text(security.secret_line_fingerprint(Path('a.yaml'), line) + '\n')
    hits, _ = scanner.scan(tmp_path)
    assert 'a.yaml:1' not in hits
    assert 'a.yaml:2' in hits
    assert 'a.yaml:2' in audit._private_context_check(tmp_path).findings


def test_jwt_span_differential():
    import random
    import re
    rng = random.Random(17)
    detector = re.compile(security._JWT_PATTERN, re.I)
    pieces = ['eyJ', 'EYj', '-', '_', 'a', '.', ' ', '\n', 'é', 'İ', 'ſ', 'K']
    for _ in range(10000):
        text = ''.join(rng.choices(pieces, k=20))
        expected = [m.span() for m in detector.finditer(text)]
        assert list(security._jwt_spans(text)) == expected
        assert list(bridge._jwt_spans(text)) == expected


@pytest.mark.parametrize('ending', ['\n', '\r\n', '\r', '\u2028'])
def test_source_line_mapping(ending):
    text = ending.join(['secret://vault/service/key', 'heading', 'password:', ' abcdefghijk1234'])
    assert security.canonical_secret_line_spans(text) == {(3, 4)}
