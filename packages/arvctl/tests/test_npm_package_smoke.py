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


def test_windows_cmd_shim_uses_command_interpreter():
    from unittest.mock import patch
    namespace = SMOKE['_run'].__globals__
    with patch.dict(namespace, {'_WINDOWS': True}), patch('subprocess.run') as run:
        run.return_value.returncode = 0
        SMOKE['_run'](['C:/Program Files/nodejs/npm.cmd', 'install'], cwd=ROOT)
    assert run.call_args.args[0] == ['C:/Program Files/nodejs/npm.cmd', 'install']
    assert run.call_args.kwargs['shell'] is True


def test_windows_privacy_uses_dacl_and_refuses_wide_access(tmp_path):
    from unittest.mock import Mock, patch
    import sys
    acl = Mock()
    acl.private_path_problem.return_value = None
    namespace = SMOKE['_make_private'].__globals__
    with patch.dict(namespace, {'_WINDOWS': True}), patch.dict(sys.modules, {'arvyx_control.windows_acl': acl}):
        SMOKE['_make_private'](tmp_path)
        acl.make_private.assert_called_once_with(tmp_path)
        SMOKE['_require_private'](tmp_path)
        acl.private_path_problem.return_value = 'wide DACL'
        with pytest.raises(SMOKE['SmokeError'], match='wide DACL'):
            SMOKE['_require_private'](tmp_path)


def test_npm_builder_uses_windows_shim():
    from unittest.mock import patch
    builder = runpy.run_path(str(ROOT / 'scripts/build_arvyx_npm.py'))
    with patch('os.name', 'nt'), patch('shutil.which', return_value='C:/Node/npm.cmd') as which, patch('subprocess.run') as run:
        builder['_npm'](['pack'], cwd=ROOT, check=True)
    which.assert_called_once_with('npm.cmd')
    assert run.call_args.args[0] == ['C:/Node/npm.cmd', 'pack']
    assert run.call_args.kwargs['shell'] is True


def test_history_metadata_is_not_hidden_by_module_platform_skip():
    import ast
    tree = ast.parse((ROOT / 'packages/arvctl/tests/test_wave1_lane4_native_history.py').read_text())
    assert not any(isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'pytestmark' for t in node.targets) for node in tree.body)
    metadata = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name.startswith(('test_native_last5', 'test_native_all_', 'test_existing_owner_trial'))]
    assert len(metadata) == 4
    assert all(not node.decorator_list for node in metadata)


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
