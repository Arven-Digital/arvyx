"""Effective local-shell executor policy; no command strings or privilege escalation.

A sandbox uses an explicitly installed bubblewrap executable. Host/root modes
require the service already have exactly the authorized effective UID. Nothing
here installs a launcher, starts sudo, or probes a provider.
"""
from dataclasses import dataclass
import hashlib,os,stat
from pathlib import Path

@dataclass(frozen=True)
class ExecutionPlan:
    mode: str
    uid: int
    argv: tuple
    environment: dict
    launcher_sha256: str

class ExecutionPolicy:
    def __init__(self,*,host_uid,allow_host=False,allow_root=False,sandbox_launcher=None,sandbox_fd_protocol=None):
        if type(host_uid) is not int or host_uid<0 or type(allow_host) is not bool or type(allow_root) is not bool:
            raise ValueError('explicit executor policy required')
        self.host_uid=host_uid;self.allow_host=allow_host;self.allow_root=allow_root
        if sandbox_fd_protocol not in (None,'arvyx-directory-fd-v1'):raise ValueError('unsupported trusted sandbox directory-fd protocol')
        self.sandbox_fd_protocol=sandbox_fd_protocol
        self.sandbox_launcher=Path(sandbox_launcher) if sandbox_launcher else None
        self.launcher_identity=None
        if self.sandbox_launcher:
            p=self.sandbox_launcher
            if not p.is_absolute() or p.is_symlink():raise ValueError('explicit sandbox executable required')
            s=p.stat()
            if not stat.S_ISREG(s.st_mode) or s.st_mode&0o022 or not s.st_mode&0o111 or s.st_size>32*1024*1024:
                raise ValueError('unsafe sandbox executable')
            self.launcher_identity=(s.st_dev,s.st_ino,hashlib.sha256(p.read_bytes()).hexdigest())

    def plan(self,mode,workspace,*,root_acknowledged=False):
        workspace=Path(workspace)
        if not workspace.is_absolute() or not workspace.is_dir() or workspace.is_symlink():raise ValueError('exact workspace required')
        uid=os.geteuid();argv=('/bin/sh','-i');digest=''
        if mode=='host':
            if not self.allow_host or uid!=self.host_uid or uid==0:raise PermissionError('host executor effective UID mismatch or denied')
        elif mode=='root':
            if not self.allow_root or uid!=0 or root_acknowledged is not True:raise PermissionError('independent root policy, effective root and fresh risk acknowledgement required')
        elif mode=='sandbox':
            if uid==0:raise PermissionError('sandbox service must run under an explicitly unprivileged account')
            if self.sandbox_launcher is None:raise PermissionError('explicit installed sandbox launcher required')
            if self.sandbox_fd_protocol!='arvyx-directory-fd-v1':raise PermissionError('sandbox requires separately provisioned arvyx-directory-fd-v1 launcher; pathname workspace binds refused')
            p=self.sandbox_launcher;s=p.stat();digest=hashlib.sha256(p.read_bytes()).hexdigest()
            if (s.st_dev,s.st_ino,digest)!=self.launcher_identity or s.st_mode&0o022:raise PermissionError('sandbox launcher changed')
            args=[str(p),'--die-with-parent','--new-session','--unshare-all','--cap-drop','ALL','--clearenv']
            for path in ('/usr','/bin','/lib','/lib64'):
                if Path(path).exists():args+=['--ro-bind',path,path]
            # Explicit trusted launcher extension, not an invented bubblewrap
            # capability. It must mount the inherited directory descriptor,
            # never canonicalize it back into a source pathname, and close it
            # before dispatching the sandboxed command. Ordinary bwrap refuses.
            args+=['--proc','/proc','--dev','/dev','--tmpfs','/tmp','--dir','/home','--dir','/home/agent','--bind-fd','@arvyx-workspace-fd@','/workspace','--chdir','/workspace','--setenv','HOME','/home/agent','--setenv','PATH','/usr/bin:/bin','--setenv','TERM','xterm-256color','--',*argv]
            argv=tuple(args)
        else:raise PermissionError('unsupported executor mode')
        env=dict(PATH='/usr/bin:/bin',HOME=str(workspace),TERM='xterm-256color',ENV='/dev/null',PS1='$ ')
        return ExecutionPlan(mode,uid,argv,env,digest)

    def sealed_launcher(self,plan,*,workspace_fd=None):
        """Pin the reviewed launcher bytes across fork/exec; no path re-read race."""
        from contextlib import contextmanager
        @contextmanager
        def pin():
            if plan.mode!='sandbox':
                yield list(plan.argv);return
            if (type(workspace_fd) is not int or not stat.S_ISDIR(os.fstat(workspace_fd).st_mode)
                    or self.sandbox_fd_protocol!='arvyx-directory-fd-v1'):
                raise PermissionError('held workspace descriptor and trusted directory-fd protocol required')
            try:import fcntl
            except ImportError:raise PermissionError('kernel sealing unavailable; sandbox launch refused') from None
            if (any(not hasattr(fcntl,name) for name in ('F_ADD_SEALS','F_SEAL_WRITE','F_SEAL_GROW','F_SEAL_SHRINK','F_SEAL_SEAL'))
                    or any(not hasattr(os,name) for name in ('memfd_create','MFD_CLOEXEC','MFD_ALLOW_SEALING'))):
                raise PermissionError('kernel sealing unavailable; sandbox launch refused')
            data=self.sandbox_launcher.read_bytes()
            if hashlib.sha256(data).hexdigest()!=plan.launcher_sha256:raise PermissionError('sandbox launcher changed before execution')
            fd=os.memfd_create('arvyx-sandbox-launcher',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
            try:
                view=memoryview(data)
                while view:
                    count=os.write(fd,view)
                    if count<=0:raise OSError('short launcher snapshot')
                    view=view[count:]
                os.fchmod(fd,0o500)
                fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
                yield ['/proc/self/fd/'+str(fd),*[str(workspace_fd) if value=='@arvyx-workspace-fd@' else value for value in plan.argv[1:]]]
            finally:os.close(fd)
        return pin()
