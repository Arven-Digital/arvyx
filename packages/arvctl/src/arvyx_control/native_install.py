"""Install verified local bytes without running a binary or granting approval.

Only the existing shared approved digest is accepted. Build receipts bind
provenance, never authorize a new digest. Incomplete destinations are retained
and fail doctor; no existing destination is overwritten or automatically reused.
"""
import argparse,hashlib,json,os,platform,stat,sys
from pathlib import Path
from . import private_paths
from . import safe_open
from .native_artifact_policy import (verify_native_bytes, read_native_bytes, open_native_directory, native_platform_policy,
                                     admitted_capabilities)


def sync(path):
    fd=safe_open.open_directory(path)
    try:safe_open.fsync_directory(fd)
    finally:os.close(fd)


def write(path,data,mode,*,dir_fd=None):
    if dir_fd is not None:
        fd=safe_open.open_file_at(dir_fd,os.fspath(path),write=True,create=True,exclusive=True,mode=mode)
    else:
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|getattr(os,'O_NOFOLLOW',0),mode)
    with os.fdopen(fd,'wb') as stream:
        view=memoryview(data)
        while view:
            count=stream.write(view)
            if not count:raise OSError('short native installation write')
            view=view[count:]
        stream.flush();os.fsync(stream.fileno())


def install(binary,receipt,destination,*,required_capability='mouse-existing'):
    binary=Path(binary);receipt=Path(receipt);destination=Path(destination)
    policy=native_platform_policy()
    if not policy['available']:
        raise ValueError('no approved native artifact for this platform')
    if receipt.is_symlink() or not receipt.is_file() or receipt.stat().st_size>128*1024:raise ValueError('bounded regular provenance receipt required')
    receipt_bytes=receipt.read_bytes();metadata=json.loads(receipt_bytes)
    if type(metadata) is not dict:raise ValueError('provenance object required')
    data=read_native_bytes(binary)
    # Verify and publish the SAME byte snapshot; never verify then reread a path.
    digest=verify_native_bytes(data,dict(binary_sha256=metadata.get('binary_sha256')),required_capability=required_capability)
    parent_fd=open_native_directory(destination.parent)
    try:
        info=os.fstat(parent_fd)
        if not private_paths.owned_by_current_user(info,fd=parent_fd):raise ValueError('owned installation prefix required')
        os.mkdir(destination.name,mode=0o700,dir_fd=parent_fd);os.fsync(parent_fd)
        installed=os.open(destination.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
        try:
            write('arvyx',data,0o700,dir_fd=installed)
            capabilities=admitted_capabilities(digest)
            record=dict(binary_sha256=digest,provenance_sha256=hashlib.sha256(receipt_bytes).hexdigest(),platform=policy['platform'],approved_capabilities=capabilities,onboarding_v1='onboarding-v1' in capabilities,runtime_acceptance=False)
            write('native-install.json',(json.dumps(record,indent=2)+'\n').encode(),0o600,dir_fd=installed);os.fsync(installed)
        finally:os.close(installed)
    finally:os.close(parent_fd)
    return record


def check(destination, *, required_capability='mouse-existing'):
    destination=Path(destination)
    # Admit and pin every ancestor before opening metadata. NONBLOCK prevents
    # FIFO/device opens from hanging; fstat and bounded read apply to the same fd.
    directory=open_native_directory(destination)
    try:
        fd=os.open('native-install.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 128*1024:
                raise ValueError('bounded regular native installation metadata required')
            data=stream.read(128*1024+1)
            if len(data)!=info.st_size:
                raise ValueError('native installation metadata changed while reading')
            metadata=json.loads(data)
            if type(metadata) is not dict:raise ValueError('native installation metadata object required')
    finally:os.close(directory)
    binary=destination/'arvyx'
    if binary.is_symlink():raise ValueError('native executable must not be a symlink')
    digest=verify_native_bytes(read_native_bytes(binary),metadata,required_capability=required_capability)
    return dict(binary_sha256=digest,installed=True,runtime_acceptance=False,
                approved_capabilities=admitted_capabilities(digest),onboarding_v1='onboarding-v1' in admitted_capabilities(digest))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path);parser.add_argument('--receipt',type=Path)
    parser.add_argument('--destination',type=Path);parser.add_argument('--check',type=Path)
    parser.add_argument('--require-capability',default='mouse-existing',choices=['mouse-existing','onboarding-v1'])
    args=parser.parse_args(argv)
    try:
        if args.check:
            if args.binary or args.receipt or args.destination:parser.error('check mode forbids install options')
            result=check(args.check,required_capability=args.require_capability)
        else:
            if not all((args.binary,args.receipt,args.destination)):parser.error('explicit binary, receipt and destination required')
            result=install(args.binary,args.receipt,args.destination,required_capability=args.require_capability)
        print(json.dumps(result));return 0
    except (OSError,ValueError) as exc:
        print('Native provisioning refused: '+str(exc),file=sys.stderr);return 2

if __name__=='__main__':raise SystemExit(main())
