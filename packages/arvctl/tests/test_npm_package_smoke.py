"""The npm package smoke's tarball checks refuse incomplete or hooked packages.

The full build/install chain needs Node >=24.11 and runs as `make npm-package-smoke`;
these cases pin the structural refusals with synthetic tarballs only.
"""
import io
import json
from pathlib import Path
import runpy
import tarfile
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[3]
SMOKE = runpy.run_path(str(ROOT / 'scripts/npm_package_smoke.py'))
import tomllib
_PROJECT = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']
# The bundled wheel is named after the distribution in pyproject, whatever it is called.
WHEEL = 'package/payload/{}-{}-py3-none-any.whl'.format(_PROJECT['name'].replace('-', '_'), _PROJECT['version'])
INDEX = ('<link rel="icon" href="/assets/favicon.png">'
         '<script type="module" src="/assets/index-x.js"></script>'
         '<link rel="stylesheet" href="/assets/index-x.css">')


def _wheel(brand=True):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('arvyx_control/__init__.py', '')
        if brand:
            archive.writestr('arvyx_control/static/brand/favicon.png', b'png')
    return stream.getvalue()


def _tarball(path, *, files=None, drop=(), scripts=None):
    members = {
        'package/package.json': json.dumps({'name': 'arvyx-local', 'scripts': scripts or {'test': 'node --test'}}).encode(),
        WHEEL: _wheel(),
        'package/payload/web/index.html': INDEX.encode(),
        'package/payload/web/assets/index-x.js': b'js',
        'package/payload/web/assets/index-x.css': b'css',
    }
    members.update(files or {})
    with tarfile.open(path, 'w:gz') as archive:
        for name, data in members.items():
            if name in drop:
                continue
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def test_complete_synthetic_package_is_accepted(tmp_path):
    result = SMOKE['_verify_tarball'](_tarball(tmp_path / 'ok.tgz'))
    assert result['wheel'] == Path(WHEEL).name
    assert result['web_assets'] == ['assets/favicon.png', 'assets/index-x.css', 'assets/index-x.js']


@pytest.mark.parametrize('case, kwargs, message', [
    ('missing-script-asset', dict(drop={'package/payload/web/assets/index-x.js'}), 'missing assets'),
    ('missing-index', dict(drop={'package/payload/web/index.html'}), 'index.html missing'),
    ('no-wheel', dict(drop={WHEEL}), 'exactly one top-level payload wheel'),
    ('two-wheels', dict(files={'package/payload/other-0-py3-none-any.whl': _wheel()}), 'exactly one top-level payload wheel'),
    ('brand-not-in-wheel', dict(files={WHEEL: _wheel(brand=False)}), 'lacks server-provided brand assets'),
    ('postinstall-hook', dict(scripts={'postinstall': 'node evil.mjs'}), 'lifecycle hooks'),
    ('escaping-member', dict(files={'package/../escape': b'x'}), 'unexpected tarball member'),
    ('outside-package', dict(files={'other/file': b'x'}), 'unexpected tarball member'),
])
def test_incomplete_or_hooked_package_is_refused(tmp_path, case, kwargs, message):
    with pytest.raises(SMOKE['SmokeError'], match=message):
        SMOKE['_verify_tarball'](_tarball(tmp_path / f'{case}.tgz', **kwargs))


def test_script_without_any_bundle_reference_is_refused(tmp_path):
    files = {'package/payload/web/index.html': b'<link rel="icon" href="/assets/favicon.png">'}
    with pytest.raises(SMOKE['SmokeError'], match='references no script bundle'):
        SMOKE['_verify_tarball'](_tarball(tmp_path / 'empty.tgz', files=files))
