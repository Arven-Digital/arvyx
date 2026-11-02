"""Optional native provisioning is explicit; installation never runs a native file."""
import json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]

def test_setup_help_exposes_explicit_native_receipt_pair(tmp_path):
    capture=tmp_path/'capture'
    with capture.open('w') as output:
        p=subprocess.run(['node',str(ROOT/'packaging/npm/bin/arvyx.mjs'),'--help'],stdout=output,stderr=output)
    assert p.returncode==0
    assert '--native-binary' in capture.read_text() and '--native-receipt' in capture.read_text()

def test_incomplete_native_setup_options_fail_before_destination_exists(tmp_path):
    capture=tmp_path/'capture';destination=tmp_path/'prefix'
    with capture.open('w') as output:
        p=subprocess.run(['node',str(ROOT/'packaging/npm/bin/arvyx.mjs'),'setup','--prefix',str(destination),'--native-binary',str(tmp_path/'source')],stdout=output,stderr=output)
    assert p.returncode==2
    assert 'both --native-binary and --native-receipt' in capture.read_text()
    assert not destination.exists()


def test_unapproved_bytes_and_receipt_flags_cannot_grant_installation(tmp_path):
    from arvyx_control.native_install import install
    import hashlib,pytest
    source=tmp_path/'fake';source.write_bytes(b'harmless-unapproved-artifact');source.chmod(0o700)
    receipt=tmp_path/'receipt.json';receipt.write_text(json.dumps(dict(binary_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),release_approved=True)))
    with pytest.raises(ValueError):install(source,receipt,tmp_path/'native')
    assert not (tmp_path/'native').exists()


def test_amc_and_web_refuse_interpreter_only_incomplete_prefix(tmp_path):
    prefix=tmp_path/'prefix';bindir=prefix/('Scripts' if os.name=='nt' else 'bin');bindir.mkdir(parents=True)
    (bindir/('python.exe' if os.name=='nt' else 'python')).write_bytes(b'not-an-installed-environment')
    for command in ('amc','web'):
        result=subprocess.run(['node',str(ROOT/'packaging/npm/bin/arvyx.mjs'),command,'--prefix',str(prefix)],capture_output=True,text=True)
        assert result.returncode==2
        assert 'Setup incomplete' in result.stderr


def test_npm_setup_source_sanitizes_destination_and_checks_before_completion():
    source=(ROOT/'packaging/npm/bin/arvyx.mjs').read_text()
    assert "!/^PIP_|^PYTHON/i.test(key)" in source
    assert 'env.PIP_CONFIG_FILE=devNull' in source
    assert "'--isolated','install','--no-index','--no-deps','--no-user','--prefix',prefix" in source
    assert source.index(' verifyPrefix();',source.index("if(command==='setup')")) < source.index("writeIntent({...intent,state:'complete'},true)")
    assert "wheel_sha256" in source and "requested virtualenv provenance mismatch" in source
