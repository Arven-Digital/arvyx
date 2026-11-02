"""Candidate-26 finding 4: synthetic offline embeddings and real MCP loop."""
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest
from arvyx_control import embeddings

ROOT = Path(__file__).resolve().parents[3]
CONFIG = embeddings.EmbeddingConfig('http', 'http://synthetic.invalid/embeddings', 'synthetic', None, .5, 64)


@pytest.mark.parametrize('depth', [65, 1100])
def test_response_depth_is_bounded(depth):
    body = b'{"data":[{"embedding":[1]}],"extra":' + b'[' * depth + b'0' + b']' * depth + b'}'
    with patch.object(embeddings, 'urlopen', return_value=io.BytesIO(body)):
        with pytest.raises(embeddings.EmbeddingError):
            embeddings.embed_texts(CONFIG, ['needle'])


def test_parser_recursion_is_normalized():
    with patch.object(embeddings, 'urlopen', return_value=io.BytesIO(b'{}')):
        with patch.object(embeddings.json, 'loads', side_effect=RecursionError('synthetic parser recursion')):
            with pytest.raises(embeddings.EmbeddingError):
                embeddings.embed_texts(CONFIG, ['needle'])


def test_shallow_response_with_escaped_delimiters_and_budget():
    body = json.dumps({'data': [{'embedding': [1, 2]}], 'extra': '[{"' * 100}).encode()
    response = io.BytesIO(body)
    with patch.object(embeddings, 'urlopen', return_value=response) as transport:
        assert embeddings.embed_texts(CONFIG, ['needle']) == [[1., 2.]]
    assert response.closed
    assert transport.call_args.kwargs['timeout'] == .5
    with patch.object(embeddings, 'urlopen', return_value=io.BytesIO(b' ' * (1024 * 1024 + 1))):
        with pytest.raises(embeddings.EmbeddingError, match='exceeds limit'):
            embeddings.embed_texts(CONFIG, ['needle'])


@pytest.mark.parametrize('mode', ['hybrid', 'semantic'])
def test_actual_mcp_loop_survives_recursive_response(tmp_path, mode):
    project = tmp_path / 'projects' / 'synthetic'
    project.mkdir(parents=True)
    (project / 'README.md').write_text('Needle memory is synthetic offline evidence.\n')
    # Only the upstream transport and configuration discovery are synthetic.
    # CLI stdio loop, MCP dispatch, recall, index and fallback are real.
    script = '''
import importlib, io, sys
from pathlib import Path
from arvyx_control import embeddings
from arvyx_control.cli import main
recall = importlib.import_module('arvyx_control.recall')
config = embeddings.EmbeddingConfig('http', 'http://synthetic.invalid/embeddings', 'synthetic', None, .5, 64)
recall.load_embedding_config = lambda vault: config
calls = []
def transport(request, timeout):
    calls.append(1)
    print('SYNTHETIC_EMBEDDING_RESPONSE', file=sys.stderr, flush=True)
    return io.BytesIO(b'[' * 1100 + b'0' + b']' * 1100)
embeddings.urlopen = transport
result = main(['mcp', '--profile', 'read-only', '--vault', sys.argv[1]])
assert len(calls) >= 2, 'index and query embedding paths were not both exercised'
raise SystemExit(result)
'''
    requests = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'memory.recall', 'arguments': {'question': 'needle memory', 'retrieval_mode': mode}}},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}},
    ]
    env = {**os.environ, 'PYTHONPATH': str(ROOT / 'packages/arvctl/src')}
    env.pop('ARVYX_EMBEDDINGS', None)
    result = subprocess.run([sys.executable, '-c', script, str(tmp_path)], input=''.join(json.dumps(r) + '\n' for r in requests), capture_output=True, text=True, timeout=15, env=env, cwd=ROOT)
    assert 'SYNTHETIC_EMBEDDING_RESPONSE' in result.stderr
    assert result.returncode == 0, result.stderr
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert [r['id'] for r in responses] == [1, 2]
    assert 'result' in responses[0], responses[0]
    assert not responses[0]['result'].get('isError'), responses[0]
    assert any(t['name'] == 'memory.recall' for t in responses[1]['result']['tools'])
