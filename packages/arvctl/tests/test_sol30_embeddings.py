"""Candidate-29 findings 3/4/5; offline transport, actual retrieval/MCP."""
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest
from arvyx_control import embeddings, index

ROOT = Path(__file__).resolve().parents[3]
CONFIG = embeddings.EmbeddingConfig('http', 'http://synthetic.invalid/embeddings', 'new', None, .5, 64)


def response(items):
    return io.BytesIO(json.dumps({'data': items}).encode())


@pytest.mark.parametrize('indices', [[0, 0], [0, None], [False, 1], [0, True], [-1, 1], [0, 2], ['0', 1], [0.0, 1]])
def test_invalid_index_mapping_is_rejected(indices):
    items = [{'embedding': [i + 1], **({'index': n} if n is not None else {})} for i, n in enumerate(indices)]
    with patch.object(embeddings, 'urlopen', return_value=response(items)):
        with pytest.raises(embeddings.EmbeddingError):
            embeddings.embed_texts(CONFIG, ['first', 'second'])


def test_indexed_reordering_and_explicit_legacy_positional_contract():
    for items in ([{'index': 1, 'embedding': [2]}, {'index': 0, 'embedding': [1]}],
                  [{'embedding': [1]}, {'embedding': [2]}]):
        with patch.object(embeddings, 'urlopen', return_value=response(items)):
            assert embeddings.embed_texts(CONFIG, ['first', 'second']) == [[1.], [2.]]


@pytest.mark.parametrize('mode', ['hybrid', 'semantic'])
def test_failed_migration_successful_query_never_compares_old_vectors(tmp_path, mode):
    project = tmp_path / 'projects' / 'synthetic'
    project.mkdir(parents=True)
    for name in ('one', 'two'):
        (project / (name + '.md')).write_text('Needle memory synthetic ' + name + '\n')
    old = embeddings.EmbeddingConfig('http', CONFIG.url, 'old', None, .5, 64)
    with patch.object(embeddings, 'urlopen', return_value=response([{'index': 0, 'embedding': [1, 0]}, {'index': 1, 'embedding': [0, 1]}])):
        assert all(c.vector is not None for c in index.load_index(tmp_path, old))
    cache_path = tmp_path / '.arvyx' / 'index.json'
    before = cache_path.read_bytes()
    recall = importlib.import_module('arvyx_control.recall')
    calls = []
    def transport(request, timeout):
        inputs = json.loads(request.data)['input']
        calls.append(inputs)
        if len(inputs) == 2:
            raise OSError('synthetic failed document batch')
        return response([{'index': 0, 'embedding': [1, 1]}])
    with patch.object(embeddings, 'urlopen', side_effect=transport), patch.object(recall, 'load_embedding_config', return_value=CONFIG), patch.object(recall, '_dense_cosine', wraps=recall._dense_cosine) as compare:
        recall.recall('needle memory', tmp_path, retrieval_mode=mode)
        assert [len(c) for c in calls] == [2, 1]
        assert compare.call_count == 0
    assert cache_path.read_bytes() == before
    with patch.object(embeddings, 'urlopen', return_value=response([{'index': 1, 'embedding': [2, 2]}, {'index': 0, 'embedding': [1, 1]}])):
        assert all(c.vector is not None for c in index.load_index(tmp_path, CONFIG))
    assert all(f['emb_fingerprint'] == CONFIG.fingerprint() for f in json.loads(cache_path.read_text())['files'].values())


@pytest.mark.parametrize('mode', ['hybrid', 'semantic'])
def test_actual_two_request_mcp_survives_integer_overflow(tmp_path, mode):
    project = tmp_path / 'projects' / 'synthetic'
    project.mkdir(parents=True)
    (project / 'README.md').write_text('Needle memory synthetic offline evidence.\n')
    script = '''
import importlib, io, json, sys
from arvyx_control import embeddings
from arvyx_control.cli import main
recall = importlib.import_module('arvyx_control.recall')
config = embeddings.EmbeddingConfig('http', 'http://synthetic.invalid/embeddings', 'new', None, .5, 64)
recall.load_embedding_config = lambda vault: config
calls = []
def transport(request, timeout):
    calls.append(1)
    print('SYNTHETIC_OVERFLOW_RESPONSE', file=sys.stderr, flush=True)
    return io.BytesIO(json.dumps({'data': [{'index': 0, 'embedding': [10**400]}]}).encode())
embeddings.urlopen = transport
result = main(['mcp', '--profile', 'read-only', '--vault', sys.argv[1]])
assert len(calls) == 2, 'both document and query paths must execute'
raise SystemExit(result)
'''
    requests = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': 'memory.recall', 'arguments': {'question': 'needle memory', 'retrieval_mode': mode}}},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}},
    ]
    env = {**os.environ, 'PYTHONPATH': str(ROOT / 'packages/arvctl/src')}
    env.pop('ARVYX_EMBEDDINGS', None)
    result = subprocess.run([sys.executable, '-c', script, str(tmp_path)], input=''.join(json.dumps(r) + '\n' for r in requests), capture_output=True, text=True, timeout=15, env=env, cwd=ROOT)
    assert 'SYNTHETIC_OVERFLOW_RESPONSE' in result.stderr
    assert result.returncode == 0, result.stderr
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert [r['id'] for r in replies] == [1, 2]
    assert 'result' in replies[0] and not replies[0]['result'].get('isError')
    assert any(t['name'] == 'memory.recall' for t in replies[1]['result']['tools'])
