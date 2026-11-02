"""Regression sources only: never execute a native binary or installer."""
import ast

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest

try:
    import fcntl
except ImportError:
    fcntl = None

NATIVE_SUPPORTED = (
    fcntl is not None
    and all(hasattr(fcntl, name) for name in (
        'F_SEAL_WRITE', 'F_SEAL_GROW', 'F_SEAL_SHRINK', 'F_SEAL_SEAL',
        'F_GET_SEALS', 'F_ADD_SEALS'))
    and all(hasattr(os, name) for name in (
        'memfd_create', 'MFD_ALLOW_SEALING', 'MFD_CLOEXEC', 'pread', 'pwrite',
        'O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC', 'getuid'))
    and Path('/proc/self/fd').is_dir()
)
if NATIVE_SUPPORTED:
    from arvyx_control import native_artifact_policy as policy
else:
    policy = None
native_only = pytest.mark.skipif(not NATIVE_SUPPORTED, reason='Linux sealed native descriptors required')

ROOT = Path(__file__).resolve().parents[3]


def approved(monkeypatch, data=b'approved test bytes, not an executable'):
    monkeypatch.setattr(policy, 'NATIVE_MOUSE_BINARY_SHA256', hashlib.sha256(data).hexdigest())
    monkeypatch.setattr(policy, 'read_native_bytes', lambda path: data)
    return data


@native_only
def test_snapshot_is_sealed_and_reused_after_source_replacement(monkeypatch):
    data = approved(monkeypatch)
    with policy.VerifiedNative('/unused') as native:
        fd = native.fd
        calls = []
        def fake(argv, *, pass_fds, **kwargs):
            calls.append(argv)
            assert pass_fds == (fd,)
            assert os.pread(fd, len(data) + 1, 0) == data
        monkeypatch.setattr(policy, 'read_native_bytes', lambda path: b'replacement')
        native.invoke(fake, ['server'])
        with pytest.raises(OSError):
            os.pwrite(fd, b'changed', 0)
        with pytest.raises(OSError):
            os.ftruncate(fd, 0)
        native.invoke(fake, ['api', 'snapshot'])
        assert calls[0][0] == calls[1][0] == native.path
    with pytest.raises(OSError):
        os.fstat(fd)


@native_only
def test_watcher_inherits_same_sealed_object_and_rechecks_binding(monkeypatch):
    approved(monkeypatch)
    with policy.VerifiedNative('/unused') as parent:
        with pytest.raises(ValueError):
            policy.VerifiedNative(binding={'binary_sha256': 'wrong'}, inherited_fd=parent.fd)
        with policy.VerifiedNative(binding={'binary_sha256': parent.digest}, inherited_fd=parent.fd) as watcher:
            assert os.fstat(watcher.fd).st_ino == os.fstat(parent.fd).st_ino
            watcher_fd = watcher.fd
            parent.close()
            assert fcntl.fcntl(watcher.fd, fcntl.F_GET_SEALS) & policy._SEALS == policy._SEALS
        with pytest.raises(OSError):
            os.fstat(watcher_fd)


@native_only
def test_inherited_descriptor_cannot_bypass_seals_or_digest(monkeypatch):
    approved(monkeypatch)
    fd = os.memfd_create('unsealed', os.MFD_ALLOW_SEALING)
    try:
        os.write(fd, b'wrong')
        with pytest.raises(ValueError):
            policy.VerifiedNative(inherited_fd=fd)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, policy._SEALS)
        with pytest.raises(ValueError):
            policy.VerifiedNative(inherited_fd=fd)
    finally:
        os.close(fd)


@native_only
def test_source_final_symlink_and_writable_ancestor_refused(tmp_path):
    # Either an earlier unsafe ancestor or this unsafe directory must reject.
    unsafe = tmp_path / 'unsafe'
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    binary = unsafe / 'native'
    binary.write_bytes(b'not executable')
    binary.chmod(0o700)
    with pytest.raises((ValueError, OSError)):
        policy.read_native_bytes(binary)
    link = tmp_path / 'link'
    link.symlink_to(binary)
    with pytest.raises((ValueError, OSError)):
        policy.read_native_bytes(link)


def test_all_launch_sites_use_snapshot_and_watcher_passes_descriptor():
    source = ROOT / 'packages/arvctl/src/arvyx_control'
    # Guard every assigned native launch site.
    for name in ('cockpit_arvyx.py', 'terminal_sessions.py'):
        tree = ast.parse((source / name).read_text())
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                continue
            if isinstance(call.func.value, ast.Name) and call.func.value.id == 'subprocess':
                if call.func.attr in {'Popen', 'call', 'run', 'check_output'}:
                    # The only direct spawn is the Python watcher, not native.
                    assert call.func.attr == 'Popen'
                    assert any(k.arg == 'pass_fds' for k in call.keywords)
    text = (source / 'cockpit_arvyx.py').read_text()
    assert "'--native-fd', str(native.fd)" in text
    assert 'inherited_fd=native_fd' in text


@pytest.mark.parametrize('failure', ['venv', 'pip', 'native', 'none'])
def test_package_intent_retains_failure_and_python_only_completion(failure):
    """Execute only a mocked JS wrapper: no pip/venv/native execution occurs."""
    repo = ROOT
    script = repo / 'packaging/npm/bin/arvyx.mjs'
    harness = r'''
const fs = require('fs'), vm = require('vm'), path = require('path'), {createHash} = require('crypto'), {devNull} = require('os');
let source=fs.readFileSync(process.argv[1],'utf8').replace(/^#!.*\n/,'').replace(/^import .*;\n/gm,'');
source=source.replace(/const payload=.*;/,'const payload="/payload";');
const failure=process.argv[2], files=new Map(), fds=new Map(); let next=10;
const prefix='/prefix', native=failure!=='none';
files.set('/payload/web/index.html','web'); files.set('/payload/local.whl','mock wheel'); files.set('/binary','bytes');files.set('/receipt','{}');
function invoke(command){
 const messages=[];
 const context={...path, createHash, devNull, existsSync:p=>files.has(p), readdirSync:()=>['local.whl'],
 mkdirSync:p=>{if(files.has(p))throw Error('exists');files.set(p,'DIR')},
 openSync:(p,mode)=>{if(mode==='wx'&&files.has(p))throw Error('exists');if(mode==='wx')files.set(p,'');const fd=next++;fds.set(fd,p);return fd},
 writeFileSync:(fd,data)=>files.set(fds.get(fd),data),fsyncSync:()=>{},closeSync:fd=>fds.delete(fd),
 renameSync:(a,b)=>{files.set(b,files.get(a));files.delete(a)},
 readFileSync:p=>files.get(p),lstatSync:p=>({isFile:()=>files.has(p),isSymbolicLink:()=>false,size:files.get(p)?.length}),
 console:{log:x=>messages.push(x),error:x=>messages.push(x)},
 process:{platform:'linux',env:{PIP_TARGET:'/foreign',PIP_PREFIX:'/foreign',PYTHONPATH:'/hostile'},argv:['node','arvyx',command,'--prefix',prefix,...(command==='setup'&&native?['--native-binary','/binary','--native-receipt','/receipt']:[])],exit:code=>{throw {exit:code}}},
 spawnSync:(program,args,options)=>{
  if(args[0]!=='-I'||options.env.PIP_TARGET||options.env.PIP_PREFIX||options.env.PYTHONPATH||options.env.PIP_CONFIG_FILE!==devNull)throw Error('ambient destination leaked');
  const stage=args.includes('venv')?'venv':args.includes('pip')?'pip':args.includes('arvyx_control.native_install')?'native':'other';
  if(stage===failure)return {status:2};
  if(stage==='venv')files.set('/prefix/bin/python','python');
  if(stage==='native')files.set('/prefix/native','DIR');
  return {status:0};
 }};
 try{vm.runInNewContext(source,context);return {status:0,messages}}catch(e){if(e.exit!==undefined)return {status:e.exit,messages};throw e}
}
const setup=invoke('setup'), record=JSON.parse(files.get('/prefix/setup-intent.json')), doctor=invoke('doctor');
if(failure==='none'){
 if(setup.status!==0||doctor.status!==0||record.state!=='complete'||record.native_requested!==false)throw Error('python-only setup contract');
}else{
 if(setup.status===0||doctor.status===0||record.state!=='incomplete'||record.native_requested!==true)throw Error('partial setup contract');
 if(!doctor.messages.some(x=>x.includes('incomplete')))throw Error('missing diagnostic');
}
console.log('mocked setup intent contract checked');
'''
    result = subprocess.run(['node', '-e', harness, str(script), failure], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
