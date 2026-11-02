"""Offline whole-document output redaction through the real MCP recall path."""
import json
import re
import os
from pathlib import Path
import subprocess
import sys

import pytest
from arvyx_control import index
from arvyx_control.security import redact_secrets

ROOT = Path(__file__).resolve().parents[3]


def material(kind):
    value = 'SYNTHETIC' + '_OUTBOUND_123456789'
    if kind == 'assignment':
        return '# Needle memory\n' + 'token' + '=\n' + value + '\n', value
    if kind == 'heading':
        value = 'sk' + '-' + value
        return '# Needle memory ' + value + '\nPublic evidence.\n', value
    marker = 'PRIVATE' + ' KEY'
    return ('# Needle memory\n-----BEGIN ' + marker + '-----\n# ' + value
            + '\n' + value + '\n-----END ' + marker + '-----\nPublic evidence.\n'), value


@pytest.mark.parametrize('kind', ['assignment', 'heading', 'pem'])
def test_hybrid_mcp_request_bytes_never_contain_document_credentials(tmp_path, kind):
    text, value = material(kind)
    project = tmp_path / 'projects' / 'synthetic'
    project.mkdir(parents=True)
    (project / 'README.md').write_text(text)
    script = '''
import importlib, io, json, sys
from arvyx_control import embeddings
from arvyx_control.cli import main
recall = importlib.import_module('arvyx_control.recall')
recall.load_embedding_config = lambda vault: embeddings.EmbeddingConfig('http', 'http://synthetic.invalid/embeddings', 'synthetic', None, .5, 64)
captured = []
def transport(request, timeout):
    captured.append(request.data.decode())
    inputs = json.loads(request.data)['input']
    return io.BytesIO(json.dumps({'data': [{'index': i, 'embedding': [1, 0]} for i in range(len(inputs))]}).encode())
embeddings.urlopen = transport
result = main(['mcp', '--profile', 'read-only', '--vault', sys.argv[1]])
with open(sys.argv[2], 'w') as handle:
    json.dump(captured, handle)
raise SystemExit(result)
'''
    request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
        'name': 'memory.recall', 'arguments': {'question': 'needle memory', 'retrieval_mode': 'hybrid'}}}
    capture = tmp_path / 'requests.json'
    env = {**os.environ, 'PYTHONPATH': str(ROOT / 'packages/arvctl/src')}
    env.pop('ARVYX_EMBEDDINGS', None)
    result = subprocess.run([sys.executable, '-c', script, str(tmp_path), str(capture)],
                            input=json.dumps(request) + '\n', capture_output=True,
                            text=True, timeout=15, cwd=ROOT, env=env)
    assert result.returncode == 0, result.stderr
    reply = json.loads(result.stdout)
    assert not reply['result'].get('isError')
    assert value not in result.stdout  # Already-safe final output is not sufficient.
    captured = json.loads(capture.read_text())
    assert len(captured) == 2  # Document batch and query, not a lexical fallback.
    assert any('needle memory' == t for t in json.loads(captured[-1])['input'])
    assert value not in ''.join(captured)


@pytest.mark.parametrize('kind', ['assignment', 'heading', 'pem'])
def test_sanitized_document_precedes_heading_selection_and_clipping(tmp_path, kind):
    text, value = material(kind)
    project = tmp_path / 'projects' / 'synthetic'
    project.mkdir(parents=True)
    (project / 'README.md').write_text(text)
    chunks = list(index._index_file(tmp_path, 'projects/synthetic/README.md', 0))
    assert all(value not in c.heading for c in chunks)
    for chunk in chunks:
        output = index._read_chunk_embed_text(tmp_path, chunk.to_dict())
        assert value not in output
        assert len(output) <= index._EMBED_TEXT_CHARS
    # A legacy cached heading must not reintroduce material removed in context.
    raw = chunks[0].to_dict()
    raw['heading'] = value
    assert value not in index._read_chunk_embed_text(tmp_path, raw)
    assert value not in redact_secrets(text)


def test_canonical_detector_configuration_and_preclip_context(tmp_path, monkeypatch):
    from arvyx_control import security
    value = 'CUSTOM' + '_SYNTHETIC_123456789'
    monkeypatch.setattr(security, 'SECRET_RE', re.compile(
        security.SECRET_RE.pattern + '|' + re.escape(value), security.SECRET_RE.flags))
    project = tmp_path / 'projects' / 'synthetic'
    project.mkdir(parents=True)
    text = '# Needle memory\n' + 'x' * 1970 + ' ' + value + '\n'
    (project / 'README.md').write_text(text)
    # Cached chunks must carry the complete persisted contract (terms and
    # counts); only the legacy heading is replaced with the configured value.
    chunks = list(index._index_file(tmp_path, 'projects/synthetic/README.md', 0))
    assert len(chunks) == 1
    raw = chunks[0].to_dict()
    assert (raw['start_line'], raw['end_line']) == (1, 2)
    raw['heading'] = value
    output = index._read_chunk_embed_text(tmp_path, raw)
    assert value not in output
    assert value[:8] not in output  # A post-clip detector would miss the prefix.
    assert len(output) <= index._EMBED_TEXT_CHARS
