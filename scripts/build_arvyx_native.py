"""Reproduce a local native artifact from explicit source, patch and offline tools.

Never installs, downloads, starts, attaches to or restarts a native owner. Output
must be new. Historical receipts and tool caches are read-only inputs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_digest(root):
    """Bind relative names, modes and bytes of the copied pre-build source tree."""
    result=hashlib.sha256()
    for path in sorted(root.rglob('*')):
        relative=path.relative_to(root).as_posix().encode()
        info=path.lstat()
        if path.is_symlink():
            target=path.resolve(strict=True)
            if not target.is_relative_to(root.resolve()):
                raise ValueError('external symlink is not a bound source input: '+str(path))
            content=('link:'+os.readlink(path)).encode()
        elif path.is_file():
            content=path.read_bytes()
        elif path.is_dir():
            continue
        else:
            raise ValueError('unsupported source entry: '+str(path))
        for value in (relative,str(info.st_mode).encode(),hashlib.sha256(content).digest()):
            result.update(len(value).to_bytes(8,'big'));result.update(value)
    return result.hexdigest()


def build_environment(ambient, explicit):
    """Discard ambient compiler, linker, Cargo config and profile overrides."""
    env={key:ambient[key] for key in ('PATH','LANG','LC_ALL','SYSTEMROOT') if key in ambient}
    env.update(SOURCE_DATE_EPOCH='0',CARGO_NET_OFFLINE='true')
    env.update(explicit)
    return env


def build_inputs(path) -> dict:
    """Bind explicitly declared compiler, linker, SDK and system-tool roots.

    No discovery through ambient PATH or receipts claiming platform approval.
    The operator supplies a complete inventory for its build host. These hashes
    are provenance; they do not attest to a hermetic kernel or authorize bytes.
    """
    path=Path(path)
    if path.is_symlink() or path.stat().st_size>65536:raise ValueError('bounded explicit build-input inventory required')
    value=json.loads(path.read_text())
    required={'patch','cc','ar','ld','pkg-config','cmake'}
    if set(value)!={'tools','toolchain_roots','sdk_roots'} or set(value['tools'])!=required or not value['toolchain_roots'] or not value['sdk_roots']:
        raise ValueError('complete toolchain/linker/SDK inventory required')
    roots=[Path(p).resolve(strict=True) for p in value['toolchain_roots']+value['sdk_roots']]
    tools={name:Path(p).resolve(strict=True) for name,p in value['tools'].items()}
    if any(not any(p.is_relative_to(root) for root in roots) for p in tools.values()):
        raise ValueError('build tool outside attested roots')
    return dict(tools={name:str(p) for name,p in tools.items()},tool_sha256={name:digest(p) for name,p in tools.items()},
                root_sha256={str(p):source_digest(p) for p in roots},inventory_sha256=digest(path))


NATIVE_TEST_FILTER = 'client::shell::amc_'


def native_test_command(cargo):
    """Include the sessions and sibling/nested RPC tests in one selection."""
    return [str(cargo), 'test', '--offline', '--locked', '--release', '--bin',
            'herdr', NATIVE_TEST_FILTER, '--', '--nocapture']


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','output','cargo','rustc','zig','registry','zig-cache'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--target-cache',type=Path)
    parser.add_argument('--build-inputs',type=Path,required=True,help='Explicit compiler/linker/system-tool/SDK inventory JSON; no ambient tool discovery')
    parser.add_argument('--test',action='store_true')
    args=parser.parse_args()
    # Versions alone do not identify the explicit tool bytes. Capture before
    # building and refuse a changed tool at publication; this is provenance,
    # not execution sealing or a complete system linker/SDK attestation.
    tools={name:getattr(args,name).resolve() for name in ('cargo','rustc','zig')}
    tools['rustdoc']=tools['rustc'].with_name('rustdoc')
    tool_sha256={name:digest(path) for name,path in tools.items()}
    inputs=build_inputs(args.build_inputs)
    if any(not any(path.is_relative_to(Path(root)) for root in inputs['root_sha256']) for path in tools.values()):
        raise ValueError('Rust/Zig tools must belong to attested toolchain roots')
    root=Path(__file__).resolve().parents[1]
    source_input=args.source.resolve(strict=True)
    output=args.output.resolve()
    if output.is_relative_to(source_input):
        raise ValueError('output must not equal or descend from source')
    output.mkdir(parents=True,exist_ok=False)
    source=output/'source'
    shutil.copytree(source_input,source,symlinks=True,ignore=shutil.ignore_patterns('.git','target','.zig-cache','zig-out','__pycache__'))
    input_source_sha256=source_digest(source)
    # Snapshot every overlay before executing any tool. Receipt hashes identify
    # the bytes actually applied, not a potentially changed checkout at the end.
    overlays=output/'overlays';overlays.mkdir()
    overlay_names=['amc-native-mouse.patch','amc_sessions.rs','amc_session_rpc.rs']
    if (root/'frontends/arvyx/amc-native-followup.patch').exists():
        overlay_names.append('amc-native-followup.patch')
    for name in overlay_names:
        shutil.copy2(root/'frontends/arvyx'/name,overlays/name)
    patch=overlays/'amc-native-mouse.patch'
    patch_env=build_environment({},dict(PATH=os.pathsep.join(sorted({str(Path(p).parent) for p in inputs['tools'].values()}))))
    # The source is a fresh copy of the pinned upstream checkout, so the overlay
    # patch must apply forward exactly once; anything else fails closed. A reverse
    # dry run in batch mode is not an "already applied" probe: GNU patch answers its
    # own "unreversed patch" question by applying forward, so a pristine tree looked
    # already patched, the patch was skipped and the overlay never compiled.
    patch_tool=inputs['tools']['patch']
    def apply_patch(path):
        probe=subprocess.run([patch_tool,'--batch','--forward','--dry-run','-p1','-i',str(path)],cwd=source,env=patch_env,capture_output=True,text=True)
        if probe.returncode:
            raise ValueError(f'overlay patch {path.name} does not apply cleanly to the pinned source:\n{probe.stdout}{probe.stderr}')
        subprocess.run([patch_tool,'--batch','--forward','-p1','-i',str(path)],cwd=source,env=patch_env,check=True,stdout=sys.stderr)
    apply_patch(patch)
    followup=overlays/'amc-native-followup.patch'
    if followup.exists():
        apply_patch(followup)
    for name in ('amc_sessions.rs','amc_session_rpc.rs'):
        shutil.copy2(overlays/name, source/'src/client/shell'/name)
    # Positive proof that the overlay is compiled: the module declaration the patch
    # adds must be present, and the RPC module must be reachable from it.
    shell_rs=(source/'src/client/shell.rs').read_text(encoding='utf-8')
    sessions_rs=(source/'src/client/shell/amc_sessions.rs').read_text(encoding='utf-8')
    if 'mod amc_sessions;' not in shell_rs or 'amc_session_rpc.rs' not in sessions_rs:
        raise ValueError('overlay is not wired into the shell module; refusing to build an upstream-only binary')
    prepared_source_sha256=source_digest(source)
    overlay_sha256={name:digest(source/'src/client/shell'/name) for name in ('amc_sessions.rs','amc_session_rpc.rs')}
    cargo_home=output/'cargo-home';(cargo_home/'registry').mkdir(parents=True)
    registry_source_sha256={name:source_digest((args.registry/name).resolve()) for name in ('cache','index','src')}
    for name in ('cache','index','src'):
        (cargo_home/'registry'/name).symlink_to((args.registry/name).resolve(),target_is_directory=True)
    target=output/'target'
    target_cache_sha256=source_digest(args.target_cache.resolve()) if args.target_cache else None
    if args.target_cache:
        shutil.copytree(args.target_cache,target)
    zig_cache=output/'zig-cache';shutil.copytree(args.zig_cache,zig_cache,symlinks=True)
    zig_cache_sha256=source_digest(zig_cache)
    build_home=output/'build-home';build_home.mkdir(mode=0o700)
    env=build_environment(os.environ,dict(HOME=str(build_home),CARGO_HOME=str(cargo_home),CARGO_TARGET_DIR=str(target),
        RUSTC=str(args.rustc.resolve()),RUSTDOC=str(args.rustc.resolve().with_name('rustdoc')),
        ZIG=str(args.zig.resolve()),ZIG_GLOBAL_CACHE_DIR=str(zig_cache),
        CARGO_NET_OFFLINE='true',SOURCE_DATE_EPOCH='0'))
    env.update(PATH=os.pathsep.join(sorted({str(Path(p).parent) for p in [*inputs['tools'].values(),*(str(p) for p in tools.values())]})),
               CC=inputs['tools']['cc'],AR=inputs['tools']['ar'],LD=inputs['tools']['ld'],PKG_CONFIG=inputs['tools']['pkg-config'],CMAKE=inputs['tools']['cmake'])
    command=[str(args.cargo.resolve()),'build','--offline','--locked','--release','--bin','herdr']
    subprocess.run(command,cwd=source,env=env,check=True)
    test_command=native_test_command(args.cargo.resolve()) if args.test else None
    native_test_count=None
    if test_command is not None:
        # The harness output is the evidence: the filter must select at least one
        # overlay test and every selected test must pass. A filter that matches
        # nothing is a build without the overlay, not a passing test step.
        run=subprocess.run(test_command,cwd=source,env=env,capture_output=True,text=True)
        sys.stderr.write(run.stdout);sys.stderr.write(run.stderr)
        if run.returncode:
            raise ValueError('native tests failed')
        native_test_count=sum(int(m) for m in re.findall(r'^running (\d+) tests?$',run.stdout,re.M))
        if native_test_count<1 or not re.search(r'^test result: ok\. \d+ passed; 0 failed',run.stdout,re.M):
            raise ValueError(f'native test filter {NATIVE_TEST_FILTER!r} selected {native_test_count} tests; the overlay tests did not run')
    binary=output/'arvyx';shutil.copy2(target/'release/herdr',binary)
    if any(digest(path)!=tool_sha256[name] for name,path in tools.items()):
        raise ValueError('explicit native build tool changed; artifact is not qualified')
    if any(source_digest((args.registry/name).resolve())!=value for name,value in registry_source_sha256.items()):
        raise ValueError('offline registry input changed; artifact is not qualified')
    if build_inputs(args.build_inputs)!=inputs:
        raise ValueError('toolchain/linker/SDK inventory changed during build')
    manifest=dict(binary=str(binary),binary_sha256=digest(binary),patch_sha256=digest(patch),
        followup_sha256=digest(followup) if followup.exists() else None,
        cargo_lock_sha256=digest(source/'Cargo.lock'),cargo_version=subprocess.check_output([str(args.cargo),'--version'],env=env,text=True).strip(),
        rustc_version=subprocess.check_output([str(args.rustc),'--version'],env=env,text=True).strip(),
        zig_version=subprocess.check_output([str(args.zig),'version'],env=env,text=True).strip(),
        input_source_sha256=input_source_sha256,prepared_source_sha256=prepared_source_sha256,
        source_hash_format='relative-path+mode+content-sha256-length-framed-v1',
        client_overlay_sha256=overlay_sha256,overlay_input_sha256={name:digest(overlays/name) for name in overlay_names},
        explicit_tool_sha256=tool_sha256,
        registry_source_sha256=registry_source_sha256,target_cache_sha256=target_cache_sha256,
        zig_cache_sha256=zig_cache_sha256,build_environment=env,
        native_test_filter=NATIVE_TEST_FILTER if args.test else None,
        native_test_command=test_command,
        native_tests_executed=bool(native_test_count),native_test_count=native_test_count,
        declared_build_inputs=inputs,
        toolchain_scope='explicit Rust/Zig, compiler/linker/system tools and declared toolchain/SDK trees; operator inventory completeness requires independent build-host review',
        requested_capabilities=['onboarding-v1'],runtime_acceptance=False,
        local_only=True,release_approved=False)
    (output/'artifact.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest))

if __name__=='__main__': main()
