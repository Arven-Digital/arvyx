"""Preparation-manifest regressions. NOT_EXECUTED: separate authorization required."""
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from arvyx_control import promotion_transaction as tx
from arvyx_control.vault import init_vault
from arvyx_control.writes import suggest_memory


@pytest.mark.parametrize('boundary', ['partial-write', 'staged', 'renamed'])
def test_interrupted_preparation_allows_fresh_governed_mutation(tmp_path, boundary):
    vault = tmp_path / 'vault'
    init_vault(vault)
    source = vault / 'projects/demo-agent/pending/original.md'
    parent = vault / 'projects/demo-agent/notes/parent.md'
    target = parent.with_name('promoted.md')
    source.parent.mkdir(parents=True, exist_ok=True)
    parent.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(b'Pending original\r\n')
    parent.write_bytes(b'Parent original\r\n')
    originals = {path: (path.read_bytes(), tx.identity(path)) for path in (source, parent)}
    code = r'''import os,sys
from pathlib import Path
from arvyx_control import promotion_transaction as tx
vault=Path(sys.argv[1]);boundary=sys.argv[2]
source=vault/'projects/demo-agent/pending/original.md'
parent=vault/'projects/demo-agent/notes/parent.md'
target=parent.with_name('promoted.md')
real_stage=tx.stage
real_replace=Path.replace
def interrupted_stage(path,data,mode=0o600):
    if path.name in {'manifest.stage','manifest.json'}:
        if boundary=='partial-write':
            with path.open('xb') as stream:
                stream.write(data[:13]);stream.flush();os.fsync(stream.fileno())
                os._exit(71)
        result=real_stage(path,data,mode)
        if boundary=='staged':os._exit(71)
        return result
    return real_stage(path,data,mode)
def interrupted_replace(path,target):
    result=real_replace(path,target)
    if Path(target).name=='manifest.json' and boundary=='renamed':os._exit(71)
    return result
tx.stage=interrupted_stage
Path.replace=interrupted_replace
with tx.memory_mutation(vault):
    tx.publish(vault,source,target,b'Promoted replacement\n',
        {parent:(parent.read_bytes(),b'Parent replacement\n')},source_bytes=source.read_bytes())
'''
    child = subprocess.run([sys.executable, '-c', code, str(vault), boundary], check=False)
    assert child.returncode == 71
    journal, = (vault / '.arvyx/promotions').iterdir()
    if boundary == 'renamed':
        assert json.loads((journal / 'manifest.json').read_text())['schema'] == 1
    else:
        assert not (journal / 'manifest.json').exists()
        assert (journal / 'manifest.stage').exists()
    assert not target.exists()
    for path, (data, identity) in originals.items():
        assert path.read_bytes() == data
        assert tx.identity(path) == identity
    result = suggest_memory(vault, 'demo-agent', 'Fresh mutation', 'New content', 'operator')
    assert (vault / result.path).exists()
    assert not target.exists()
    for path, (data, identity) in originals.items():
        assert path.read_bytes() == data
        assert tx.identity(path) == identity


def test_manifest_rename_is_directory_synced_before_destination_publication(tmp_path):
    vault = tmp_path / 'vault'
    source = vault / 'pending/source.md'
    target = vault / 'notes/target.md'
    source.parent.mkdir(parents=True)
    source.write_bytes(b'original')
    real_sync, real_replace, real_link = tx.sync, Path.replace, os.link
    events = []

    def replacing(path, destination):
        result = real_replace(path, destination)
        if Path(destination).name == 'manifest.json':
            events.append(('manifest', Path(destination).parent))
        return result

    def syncing(path):
        result = real_sync(path)
        events.append(('sync', Path(path)))
        return result

    def linking(path, destination, *args, **kwargs):
        if Path(destination) == target:
            journal = next((vault / '.arvyx/promotions').iterdir())
            assert ('manifest', journal) in events
            rename_index = events.index(('manifest', journal))
            assert ('sync', journal) in events[rename_index + 1:]
            assert not (journal / 'manifest.stage').exists()
            assert json.loads((journal / 'manifest.json').read_text())['schema'] == 1
        return real_link(path, destination, *args, **kwargs)

    with patch.object(tx, 'sync', syncing), patch.object(Path, 'replace', replacing), patch.object(tx.os, 'link', linking):
        tx.publish(vault, source, target, b'replacement', {}, source_bytes=b'original')
    assert target.read_bytes() == b'replacement'
    assert not source.exists()


@pytest.mark.parametrize('contents', ['', '{"schema":'])
def test_malformed_authoritative_manifest_still_blocks_mutation(tmp_path, contents):
    vault = tmp_path / 'vault'
    init_vault(vault)
    journal = vault / '.arvyx/promotions/broken'
    journal.mkdir(parents=True)
    manifest = journal / 'manifest.json'
    manifest.write_text(contents)
    with pytest.raises(json.JSONDecodeError):
        with tx.memory_mutation(vault):
            pytest.fail('malformed authoritative manifest must not yield')
    assert manifest.read_text() == contents
