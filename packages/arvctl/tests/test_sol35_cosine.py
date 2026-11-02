"""Offline candidate-34 finding 3: stable dense cosine and real MCP recall."""
import importlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys

import pytest

recall = importlib.import_module('arvyx_control.recall')
ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize('left,right,expected', [
    ((1e308,), (1e308,), 1.0),
    ((1e-308,), (1e-308,), 1.0),
    ((5e-324,), (5e-324,), 1.0),
    ((1e308, 1e308), (1e-308, 1e-308), 1.0),
    ((1e308, -1e308), (-1e-308, 1e-308), -1.0),
    ((1e308, 0.0), (0.0, 1e-308), 0.0),
    ((3.0, 4.0), (4.0, 3.0), .96),
])
def test_stable_finite_cosine(left, right, expected):
    actual = recall._dense_cosine(left, right)
    assert math.isfinite(actual)
    assert actual == pytest.approx(expected)
    assert -1 <= actual <= 1


@pytest.mark.parametrize('left,right', [
    ((), ()), ((0.0,), (1.0,)), ((1.0,), (0.0,)),
    ((1.0,), (1.0, 2.0)), ((float('nan'),), (1.0,)),
    ((1.0,), (float('inf'),)),
])
def test_unusable_cosine_signals_fallback(left, right):
    assert recall._dense_cosine(left, right) is None


@pytest.mark.parametrize('vector', [[1e308], [1e-308], [5e-324], [0.0]])
@pytest.mark.parametrize('mode', ['hybrid', 'semantic'])
def test_actual_mcp_extreme_provider_keeps_sources(tmp_path, vector, mode):
    project = tmp_path / 'projects' / 'synthetic'
    project.mkdir(parents=True)
    for name in ('one', 'two'):
        (project / (name + '.md')).write_text('Needle memory synthetic offline evidence.\n')
    script = '''
import importlib, io, json, sys
from arvyx_control import embeddings
from arvyx_control.cli import main
recall = importlib.import_module('arvyx_control.recall')
config = embeddings.EmbeddingConfig('http', 'http://synthetic.invalid/embeddings', 'new', None, .5, 64)
recall.load_embedding_config = lambda vault: config
calls = []
vector = json.loads(sys.argv[2])
def transport(request, timeout):
    inputs = json.loads(request.data)['input']
    calls.append(len(inputs))
    return io.BytesIO(json.dumps({'data': [{'index': i, 'embedding': vector} for i in range(len(inputs))]}).encode())
embeddings.urlopen = transport
result = main(['mcp', '--profile', 'read-only', '--vault', sys.argv[1]])
assert calls == [2, 1], calls
raise SystemExit(result)
'''
    requests = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'memory.recall', 'arguments': {'question': 'needle memory', 'retrieval_mode': mode}}},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}},
    ]
    env = {**os.environ, 'PYTHONPATH': str(ROOT / 'packages/arvctl/src')}
    env.pop('ARVYX_EMBEDDINGS', None)
    result = subprocess.run([sys.executable, '-c', script, str(tmp_path), json.dumps(vector)], input=''.join(json.dumps(r) + '\n' for r in requests), capture_output=True, text=True, timeout=15, env=env, cwd=ROOT)
    assert result.returncode == 0, result.stderr
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert [r['id'] for r in replies] == [1, 2]
    assert not replies[0]['result'].get('isError')
    payload = json.loads(replies[0]['result']['content'][0]['text'])
    assert len(payload['sources']) == 2, payload
    assert all(math.isfinite(s['score']) for s in payload['sources'])
