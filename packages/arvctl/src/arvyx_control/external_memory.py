"""Governed shared-memory selections exported as exact artifact manifests.

No recall query, cache expansion, embeddings, linked resources or squad-wide
reader is exposed to an external principal. The issuer independently reviews
exact content hashes; existing grant/MCP/download checks govern every later read.
"""
import hashlib,re
from pathlib import Path,PurePosixPath
from .external_workspace import snapshot_workspace,_read
from .index import is_forbidden_relative,_frontmatter_status
from .security import contains_literal_secret

def reviewed_memory_snapshot(vault,selection):
    from .replica_authority import assert_mutation_authority
    vault=Path(vault);assert_mutation_authority(vault)
    if type(selection) is not dict or not 1<=len(selection)<=100:raise ValueError('bounded individually reviewed memory selection required')
    for relative,digest in selection.items():
        if not isinstance(relative,str) or not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest):raise ValueError('exact reviewed memory digest required')
        path=PurePosixPath(relative)
        if (path.is_absolute() or len(path.parts)<3 or path.parts[0] not in ('projects','agents') or path.suffix!='.md'
                or is_forbidden_relative(relative) or any(p in ('','.','..') for p in relative.split('/'))):raise ValueError('governed memory path required')
        data,_,_=_read(vault,tuple(path.parts),1024*1024);text=data.decode('utf-8')
        if hashlib.sha256(data).hexdigest()!=digest or contains_literal_secret(text) or _frontmatter_status(text) in ('pending','refining','rejected','archived','superseded') or 'PRIVATE: DO NOT PUBLISH' in text:
            raise ValueError('memory is changed, private or not eligible for export')
    snapshot=snapshot_workspace(vault,list(selection))
    if len(snapshot.files)!=len(selection) or any(selection[f.path]!=f.sha256 for f in snapshot.files):raise ValueError('memory selection changed during publication')
    return snapshot
