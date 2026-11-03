"""One exact profile/session resolver shared by configured and history launch."""
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import time
from . import safe_open
from .locks import try_exclusive_lock
from . import private_paths
from .agent_sessions import RoutingError


@contextmanager
def query_budget(db, owner):
    """Bound the whole read, including schema inspection and cursor iteration."""
    deadline = time.monotonic() + 2
    steps = 0
    def progress():
        nonlocal steps
        steps += 1000
        return int(steps > owner.query_budget_steps or time.monotonic() >= deadline)
    db.set_progress_handler(progress, 1000)
    try:
        yield deadline
        if time.monotonic() >= deadline:
            raise RoutingError('native query work/time budget exceeded')
    except sqlite3.OperationalError as exc:
        if 'interrupted' not in str(exc).lower():
            raise
        raise RoutingError('native query work/time budget exceeded') from None
    finally:
        owner.last_query_steps = steps
        db.set_progress_handler(None, 0)


def inode(path):
    info=path.stat()
    return info.st_dev,info.st_ino


class HermesProfile:
    query_budget_steps = 10_000_000

    def __init__(self,home,store=None):
        original=Path(home)
        if original.is_symlink():raise RoutingError('explicit profile must not be a symlink')
        self.home=original.resolve(strict=True)
        self.store=self.home/'state.db'
        if store is not None and Path(store).absolute()!=self.store:
            raise RoutingError('exact canonical Hermes profile state.db required')
        if self.store.is_symlink():raise RoutingError('Hermes metadata must not be a symlink')
        self.home_identity=inode(self.home)
        self.identity=inode(self.store) if self.store.exists() else None

    def validate(self):
        if (self.home.is_symlink() or self.store.is_symlink() or inode(self.home)!=self.home_identity
                or (inode(self.store) if self.store.exists() else None)!=self.identity):
            raise RoutingError('Hermes profile or metadata database replaced; reconnect explicitly')

    @contextmanager
    def connection(self):
        self.validate()
        if self.identity is None:raise RoutingError('existing exact Hermes metadata required')
        db=sqlite3.connect(self.store.as_uri()+'?mode=ro',uri=True)
        try:
            db.execute('PRAGMA query_only=ON')
            self.validate()
            yield db
            self.validate()
        finally:db.close()

    def resolve(self,session_id,workspace):
        self.validate()
        work=Path(workspace).resolve(strict=True)
        if not work.is_dir():raise RoutingError('existing workspace directory required')
        from .agent_sessions import MAX_METADATA_FIELD_BYTES
        cap = MAX_METADATA_FIELD_BYTES
        if (not isinstance(session_id, str) or not session_id or
                len(session_id) > cap or len(session_id.encode()) > cap):
            raise RoutingError('selection identifier byte/type budget exceeded')
        with self.connection() as db, query_budget(db, self):
            columns={r[1] for r in db.execute('PRAGMA table_info(sessions)')}
            if not {'id','cwd','end_reason'}<=columns:
                raise RoutingError('exact native session/workspace metadata unavailable')
            fields = ('id', 'cwd', 'end_reason')
            checks = ["typeof(id)='text'", "typeof(cwd)='text'"]
            checks += [f"(typeof({f})='null' OR (typeof({f})='text' AND length(CAST({f} AS BLOB))<={cap}))" for f in fields]
            total = '+'.join(f'6*COALESCE(length(CAST({f} AS BLOB)),0)' for f in fields)
            valid = ' AND '.join(checks) + f' AND ({total})<=60000'
            projection = ','.join(f'CASE WHEN {valid} THEN {f} END' for f in fields)
            rows=db.execute(f'SELECT ({valid}),{projection} FROM sessions WHERE id COLLATE BINARY=? LIMIT 2',(session_id,)).fetchall()
        if len(rows)!=1:raise RoutingError('exact existing session unavailable or ambiguous; no fallback')
        if rows[0][0] != 1:
            raise RoutingError('native metadata field/type or aggregate byte budget exceeded')
        row=rows[0][1:]
        if row[2]=='compression':raise RoutingError('compression parent would redirect; select exact continuation ID')
        if not isinstance(row[1],str) or not row[1] or Path(row[1]).resolve()!=work:
            raise RoutingError('exact recorded workspace required for native resume')
        return dict(id=row[0],cwd=row[1],end_reason=row[2])

    def environment(self,base):
        self.validate()
        return dict(base,HOME=str(self.home),HERMES_HOME=str(self.home))

    def assert_idle(self, *, default_home=None, validate_metadata=True):
        """Existing profile-wide idle policy, shared by every Hermes launch route.

        Inaccessible same-UID processes make proof of idleness unavailable. Nothing
        here grants ownership of, or permission to signal, a discovered process.
        """
        if validate_metadata:
            self.validate()
        elif self.home.is_symlink() or inode(self.home) != self.home_identity:
            raise RoutingError('Hermes profile replaced; cleanup unverified')
        default = Path(default_home or Path.home()/'.hermes').resolve()
        proc = Path('/proc')
        if not proc.is_dir():
            raise RoutingError('live-profile startup guard unavailable on this platform')
        marker = os.fsencode(str(self.home))
        for entry in proc.iterdir():
            if not entry.name.isdecimal() or int(entry.name) == os.getpid():
                continue
            try:
                if not private_paths.owned_by_current_user(entry.stat(), path=entry):
                    continue
                values = (entry/'environ').read_bytes().split(b'\0')
                scoped = next((v.split(b'=',1)[1] for v in values if v.startswith(b'HERMES_HOME=')), None)
                if scoped == marker:
                    raise RoutingError('profile already has a live process; use existing attachment instead')
                if self.home == default:
                    command = (entry/'cmdline').read_bytes().lower()
                    if b'hermes' in command and scoped is None:
                        raise RoutingError('default profile has a live or unscoped Hermes process; attach instead')
            except (FileNotFoundError, ProcessLookupError):
                if entry.exists():
                    raise RoutingError('cannot verify profile idle; cold resume refused') from None
                continue
            except OSError:
                raise RoutingError('cannot verify profile idle; cold resume refused') from None

    def reserve(self, conversation, *, default_home=None):
        return ProfileReservation(self, conversation, default_home=default_home)


class ProfileReservation:
    """Cooperative admission, not evidence that an arbitrary PID is ours."""
    def __init__(self, profile, conversation, *, default_home=None):
        import stat
        self.profile = profile
        self.conversation = conversation
        self.fd = None
        profile.validate()
        home_info = profile.home.stat()
        if not private_paths.owned_by_current_user(home_info, path=profile.home) or not private_paths.not_writable_by_others(home_info, path=profile.home):
            raise RoutingError('profile must be owned by current user and not writable by others')
        path = profile.home / '.amc-native-writer.lock'
        fd = safe_open.open_file(path, write=True, create=True, mode=0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not private_paths.owner_private(info, fd=fd) or info.st_nlink != 1:
                raise RoutingError('unsafe native profile reservation')
            if not try_exclusive_lock(fd):
                raise RoutingError('profile already reserved; attach to existing writer instead')
            if inode(path) != (info.st_dev, info.st_ino):
                raise RoutingError('profile reservation replaced')
            profile.assert_idle(default_home=default_home)
            profile.validate()
            self.fd = fd
        except BaseException:
            os.close(fd)
            raise

    def release(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        # Never unlink: waiters must continue to lock the same inode.

