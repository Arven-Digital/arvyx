"""Exercise native builder provenance without a compiler, install or native start."""
import runpy
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[3]
BUILDER=runpy.run_path(str(ROOT/'scripts/build_arvyx_native.py'))


def test_source_hash_binds_names_modes_and_bytes(tmp_path):
    file=tmp_path/'input.rs';file.write_text('source');file.chmod(0o600)
    digest=BUILDER['source_digest'];before=digest(tmp_path)
    file.write_text('changed');assert digest(tmp_path)!=before
    file.write_text('source');assert digest(tmp_path)==before
    file.chmod(0o700);assert digest(tmp_path)!=before
    file.chmod(0o600);file.rename(tmp_path/'other.rs');assert digest(tmp_path)!=before


def test_source_hash_rejects_external_symlink_input(tmp_path):
    outside=tmp_path/'outside';outside.write_text('unbound mutable compiler input')
    source=tmp_path/'source';source.mkdir();(source/'dependency').symlink_to(outside)
    with pytest.raises(ValueError,match='symlink'):
        BUILDER['source_digest'](source)


def test_closed_build_environment_discards_injection_and_binds_caches(tmp_path):
    build_env=BUILDER.get('build_environment')
    assert build_env is not None,'ambient Cargo/Rust build overrides are still inherited'
    env=build_env(dict(PATH='/usr/bin',LANG='C',RUSTFLAGS='inject',RUSTC_WRAPPER='/untrusted',CARGO_BUILD_RUSTC_WRAPPER='/untrusted',CC='/untrusted',HOME='/untrusted'),{})
    assert env==dict(PATH='/usr/bin',LANG='C',SOURCE_DATE_EPOCH='0',CARGO_NET_OFFLINE='true')
    source=(ROOT/'scripts/build_arvyx_native.py').read_text()
    assert "'client::shell::amc_'" in source
    assert 'registry_source_sha256' in source and 'target_cache_sha256' in source and 'zig_cache_sha256' in source
