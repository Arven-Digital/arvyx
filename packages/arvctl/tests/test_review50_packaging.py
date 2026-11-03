"""Review50 regression sources. NOT EXECUTED: static-only authorization."""
import os
import pytest
from arvyx_control import native_install


@pytest.mark.skipif(os.name != 'posix', reason='the native runtime (Linux x86_64 artifact) is POSIX-only')
@pytest.mark.parametrize('kind', ['fifo', 'symlink', 'oversized', 'array'])
def test_check_refuses_metadata_before_binary_read(tmp_path, monkeypatch, kind):
    # Isolate leaf admission, not production ancestor policy.
    monkeypatch.setattr(native_install, 'open_native_directory',
                        lambda path: os.open(path, os.O_RDONLY | os.O_DIRECTORY))
    def unexpected(*args, **kwargs):
        raise AssertionError('binary read before metadata admission')
    monkeypatch.setattr(native_install, 'read_native_bytes', unexpected)
    metadata = tmp_path / 'native-install.json'
    if kind == 'fifo':
        os.mkfifo(metadata)
    elif kind == 'symlink':
        metadata.symlink_to(tmp_path / 'missing')
    elif kind == 'oversized':
        metadata.write_bytes(b' ' * (128 * 1024 + 1))
    else:
        metadata.write_text('[]')
    with pytest.raises((ValueError, OSError)):
        native_install.check(tmp_path)
