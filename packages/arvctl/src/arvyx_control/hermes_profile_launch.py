"""Blank named identity with native root OAuth fallback, never credential cloning."""
import os
from pathlib import Path
import re
from .agent_sessions import RoutingError
from .hermes_history import HermesHistory


class NewHermesProfile:
    def __init__(self, name, *, root=None, executable=None):
        if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]{0,63}', name) or name == 'default':
            raise RoutingError('explicit non-default profile name required')
        self.root = Path(root or Path.home()/'.hermes').resolve(strict=True)
        self.home = self.root/'profiles'/name
        self.executable = executable

    def prepare(self, workspace, *, confirmed=False):
        if not confirmed:
            raise RoutingError('explicit NEW confirmation required')
        workspace = Path(workspace).resolve(strict=True)
        if not workspace.is_dir():
            raise RoutingError('existing workspace required')
        # Match native AGENTS discovery: cwd only without a Git root.
        chain = [workspace]
        for parent in (workspace, *workspace.parents):
            if (parent/'.git').exists():
                chain = [p for p in (workspace, *workspace.parents) if p == parent or p.is_relative_to(parent)]
                break
        for parent in chain:
            if any((parent/name).exists() for name in ('AGENTS.override.md','AGENTS.md','agents.md','SOUL.md','USER.md','CLAUDE.md','claude.md','.cursorrules','.hermes.md','HERMES.md','.cursor/rules')):
                raise RoutingError('workspace identity detected; use a clean workspace outside existing identity trees')
        profiles = self.root/'profiles'
        if profiles.is_symlink():
            raise RoutingError('profile directory may not be a symlink')
        profiles.mkdir(mode=0o700, exist_ok=True)
        try:
            self.home.mkdir(mode=0o700)
        except FileExistsError:
            raise RoutingError('named profile already exists; never reuse an existing identity') from None
        # Public routing values only. Native Hermes resolves root OAuth in place.
        fd = os.open(self.home/'config.yaml', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', newline="\n") as file:
            file.write('model:\n  provider: openai-codex\n  default: gpt-6.1-sol\n')
        return HermesHistory(self.home, executable=self.executable, default_home=self.root)
