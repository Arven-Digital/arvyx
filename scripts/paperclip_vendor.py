"""Copy the exact pinned Paperclip dependency closure into the vendor tree; never alter upstream.

PAPERCLIP_SOURCE must name a checkout of the upstream repository at the pinned commit.
"""
from pathlib import Path
import hashlib, json, os, re, shutil, subprocess, sys
ROOT = Path(__file__).resolve().parents[1]
PIN = 'efce9356b553a08f77a5877bb0ceac68d2cc4ad8'


def main() -> int:
    source_root = os.environ.get('PAPERCLIP_SOURCE')
    if not source_root:
        print('set PAPERCLIP_SOURCE to the upstream checkout at the pinned commit', file=sys.stderr)
        return 2
    SOURCE = Path(source_root)
    assert subprocess.check_output(['git','rev-parse','HEAD'], cwd=SOURCE, text=True).strip() == PIN
    source = SOURCE / 'ui/src'
    target = ROOT / 'frontends/paperclip/vendor'
    queue = ['components/KanbanBoard.tsx', 'lib/issue-filters.ts', 'index.css']
    seen = {}
    while queue:
        rel = queue.pop()
        if rel in seen: continue
        path = source / rel
        data = path.read_bytes()
        seen[rel] = hashlib.sha256(data).hexdigest()
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        for imp in re.findall(r'(?:from\s*|import\s*)[\"\']([^\"\']+)[\"\']', data.decode()):
            if imp == '@/lib/router': continue  # explicitly replaced by inert local detail-link seam
            if not (imp.startswith('.') or imp.startswith('@/')): continue
            base = source / imp[2:] if imp.startswith('@/') else path.parent / imp
            for suffix in ('', '.tsx', '.ts', '/index.tsx', '/index.ts'):
                candidate = Path(str(base) + suffix)
                if candidate.is_file():
                    queue.append(str(candidate.resolve().relative_to(source)))
                    break
    shared_source = SOURCE / 'packages/shared/src'
    for shared_file in shared_source.rglob('*'):
        if shared_file.is_file():
            rel = 'shared/' + str(shared_file.relative_to(shared_source))
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            data = shared_file.read_bytes()
            dest.write_bytes(data)
            seen[rel] = hashlib.sha256(data).hexdigest()
    shutil.copyfile(SOURCE / 'LICENSE', target / 'LICENSE')
    public = ROOT / 'frontends/paperclip/public/fonts'
    public.mkdir(parents=True, exist_ok=True)
    for font in (SOURCE / 'ui/public/fonts').iterdir():
        if font.is_file():
            shutil.copyfile(font, public / font.name)
    (target / 'provenance.json').write_text(json.dumps({'version': 2, 'commit': PIN, 'files': [{'path': path, 'sha256': digest} for path, digest in seen.items()]}, indent=2)+'\n')
    print('Copied', len(seen), 'byte-identical upstream files')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
