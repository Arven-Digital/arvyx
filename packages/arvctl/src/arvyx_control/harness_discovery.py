"""Opt-in connection suggestions from bounded, metadata-only known paths.

Presence is NOT installation, authentication, liveness, or adapter compatibility.
No PATH search, binary execution, config parsing, workspace inspection, credential
reads, environment expansion, network access, or automatic connection occurs.
Custom state roots and portable/editor extension installations require manual
connection. Profile IDs are directory IDs, not inferred display names.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import errno
from pathlib import Path, PurePosixPath
import re
import stat
import sys


@dataclass(frozen=True)
class Descriptor:
    family: str
    label: str
    kind: str
    evidence: str
    # Paths are home-relative, literal, and never supplied by discovered data.
    markers: tuple[str, ...] = ()
    os_markers: tuple[tuple[str, tuple[str, ...]], ...] = ()
    reason: str = ''


PRODUCT_TARGET_FAMILIES = frozenset({
    'hermes', 'openclaw', 'pi', 'claude', 'codex', 'cursor', 'vscode-copilot',
    'opencode', 'gemini', 'cline', 'aider', 'roo-code', 'continue', 'openhands',
    'swe-agent', 'goose', 'tabby', 'plandex', 'qwen-code', 'amazon-q-developer-cli',
    'zed', 'kilo-code', 'refact', 'amp', 'devin-desktop',
})

# Families whose discovered marker parent can be connected as read-only session
# metadata after human review. Kept equal to the connection adapter registry by
# test. Membership is not runtime-adapter verification (launch, attach, New).
MANUAL_METADATA_FAMILIES = frozenset({'hermes', 'claude', 'codex'})


DESCRIPTORS = (
    Descriptor('hermes', 'Hermes', 'agent', 'https://hermes-agent.nousresearch.com/docs/user-guide/configuration/', ('.hermes/config.yaml',)),
    Descriptor('openclaw', 'OpenClaw', 'agent', 'https://docs.openclaw.ai/concepts/multi-agent', ('.openclaw/openclaw.json',)),
    Descriptor('pi', 'Pi', 'agent', 'https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/docs/configuration.md', ('.pi/agent/settings.json',)),
    Descriptor('claude', 'Claude Code', 'agent', 'https://code.claude.com/docs/en/settings', ('.claude/settings.json',)),
    Descriptor('codex', 'Codex', 'agent', 'https://developers.openai.com/codex/config-basic/', ('.codex/config.toml',)),
    Descriptor('cursor', 'Cursor', 'editor', 'https://cursor.com/docs/context/mcp', ('.cursor/mcp.json',)),
    Descriptor('vscode', 'Visual Studio Code', 'editor', 'https://code.visualstudio.com/docs/configure/profiles', os_markers=(
        ('linux', ('.config/Code/User/settings.json',)),
        ('darwin', ('Library/Application Support/Code/User/settings.json',)),
        ('windows', ('AppData/Roaming/Code/User/settings.json',)))),
    Descriptor('copilot', 'GitHub Copilot CLI', 'agent', 'https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference', ('.copilot/settings.json',)),
    Descriptor('opencode', 'OpenCode', 'agent', 'https://opencode.ai/docs/config/', ('.config/opencode/opencode.json', '.config/opencode/opencode.jsonc')),
    Descriptor('gemini', 'Gemini', 'agent', 'https://geminicli.com/docs/reference/configuration/', ('.gemini/settings.json',)),
    Descriptor('cline', 'Cline', 'agent', 'https://docs.cline.bot/mcp/configuring-mcp-servers', ('.cline/data/settings/cline_mcp_settings.json',)),
    Descriptor('aider', 'Aider', 'agent', 'https://aider.chat/docs/config/aider_conf.html', ('.aider.conf.yml',)),
    Descriptor('goose', 'Goose', 'agent', 'https://block.github.io/goose/', reason='Local path documentation could not be verified; manual connection only.'),
    Descriptor('continue', 'Continue', 'agent', 'https://docs.continue.dev/customize/deep-dives/configuration', ('.continue/config.yaml',)),
    Descriptor('roo-code', 'Roo Code', 'agent', 'https://docs.roocode.com/features/mcp/using-mcp-in-roo', reason='Global configuration is opened through the editor UI; no verified stable global path.'),
    Descriptor('kilo-code', 'Kilo Code', 'agent', 'https://kilo.ai/docs/getting-started/settings', ('.config/kilo/kilo.jsonc',)),
    Descriptor('amp', 'Amp', 'agent', 'https://ampcode.com/manual', reason='No verified bounded local discovery marker in retrieved documentation.'),
    Descriptor('qwen-code', 'Qwen Code', 'agent', 'https://qwenlm.github.io/qwen-code-docs/en/users/configuration/settings/', ('.qwen/settings.json',)),
    Descriptor('crush', 'Crush', 'agent', 'https://github.com/charmbracelet/crush', ('.config/crush/crushrc',)),
    Descriptor('auggie', 'Auggie', 'agent', 'https://docs.augmentcode.com/cli/overview', reason='Configuration reference unavailable; manual connection only.'),
    Descriptor('warp', 'Warp', 'editor', 'https://docs.warp.dev/getting-started/readme', reason='Product documentation does not establish a verified local agent marker.'),
    Descriptor('zed', 'Zed', 'editor', 'https://zed.dev/docs/configuring-zed', reason='Settings schema verified, but no global settings path verified in retrieved reference.'),
    Descriptor('windsurf', 'Windsurf / legacy Cascade', 'editor', 'https://docs.windsurf.com/windsurf/cascade/mcp', reason='Documentation redirects to Devin paths; do not attribute Devin state to a Windsurf installation.'),
    Descriptor('trae', 'TRAE', 'editor', 'https://docs.trae.ai/ide/model-context-protocol', reason='Retrieved client-rendered reference provides no verified global discovery path.'),
    Descriptor('junie', 'Junie', 'agent', 'https://www.jetbrains.com/help/junie/customize-guidelines.html', reason='Reference redirects; workspace guidelines are not a safe global discovery marker.'),
    # Product references are research scope, not newly verified probe paths.
    # Keep existing detected families/IDs instead of relabeling their presence.
    Descriptor('vscode-copilot', 'VSCode-Copilot', 'editor', 'https://code.visualstudio.com/docs/copilot/overview', reason='VS Code settings do not attest Copilot presence; no verified metadata probe or runtime adapter.'),
    Descriptor('openhands', 'OpenHands', 'agent', 'https://github.com/All-Hands-AI/OpenHands', reason='Product research target; no verified metadata probe or runtime adapter.'),
    Descriptor('swe-agent', 'SWE-agent', 'agent', 'https://github.com/SWE-agent/SWE-agent', reason='Product research target; no verified metadata probe or runtime adapter.'),
    Descriptor('tabby', 'Tabby', 'agent', 'https://github.com/TabbyML/tabby', reason='Product research target; no verified metadata probe or runtime adapter.'),
    Descriptor('plandex', 'Plandex', 'agent', 'https://github.com/plandex-ai/plandex', reason='Product research target; no verified metadata probe or runtime adapter.'),
    Descriptor('amazon-q-developer-cli', 'Amazon Q Developer CLI', 'agent', 'https://github.com/aws/amazon-q-developer-cli', reason='Product research target; no verified metadata probe or runtime adapter.'),
    Descriptor('refact', 'Refact', 'agent', 'https://github.com/smallcloudai/refact', reason='Product research target; no verified metadata probe or runtime adapter.'),
    Descriptor('devin-desktop', 'Devin Desktop', 'editor', 'https://devin.ai/desktop', reason='Product research target; no verified metadata probe or runtime adapter.'),
)


def _platform(value: str | None) -> str:
    value = sys.platform if value is None else value
    aliases = {'win32': 'windows', 'windows': 'windows', 'darwin': 'darwin',
               'macos': 'darwin', 'linux': 'linux'}
    if value not in aliases:
        raise ValueError('unsupported platform')
    return aliases[value]


def _markers(descriptor: Descriptor, platform: str) -> tuple[str, ...]:
    return descriptor.markers + dict(descriptor.os_markers).get(platform, ())


def discovery_catalog(platform: str | None = None) -> list[dict]:
    """All product targets plus retained historical metadata-only families."""
    platform = _platform(platform)
    return [dict(family=d.family, label=d.label, kind=d.kind, evidence=d.evidence,
                 product_target=d.family in PRODUCT_TARGET_FAMILIES,
                 # Legacy supported means metadata discovery only, not an adapter.
                 supported=bool(_markers(d, platform)),
                 metadata_discovery_supported=bool(_markers(d, platform)),
                 manual_metadata_connection_supported=d.family in MANUAL_METADATA_FAMILIES,
                 runtime_adapter_verified=False,
                 paths=list(_markers(d, platform)),
                 reason=d.reason or 'Known default markers only; custom roots require manual connection.',
                 requires_explicit_connect=True, auto_import=False)
            for d in DESCRIPTORS]


class _BudgetExhausted(Exception):
    pass


def _unsafe(info: os.stat_result) -> bool:
    # Reject Windows junctions/reparse points as well as POSIX symlinks.
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, 'st_file_attributes', 0) & 0x400)


class _Metadata:
    def __init__(self, home: Path, limit: int):
        self.home, self.limit, self.probes = home, limit, 0
        self.incomplete_reasons = set()

    def _tick(self):
        if self.probes >= self.limit:
            raise _BudgetExhausted
        self.probes += 1

    def _directory(self, relative: str):
        """Open only directories, pinning each ancestor against symlink swaps.

        Windows lacks dir_fd/O_NOFOLLOW: discovery there uses lstat metadata
        only and rejects reparse points. No file payload is ever opened.
        """
        parts = PurePosixPath(relative).parts
        if PurePosixPath(relative).is_absolute() or any(p in {'.', '..'} or '\\' in p or ':' in p for p in parts):
            raise ValueError('non-literal discovery path')
        if os.name == 'posix':
            fd = os.open(self.home.anchor, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for part in (*self.home.parts[1:], *parts):
                    self._tick()
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = child
                return fd
            except BaseException:
                os.close(fd)
                raise
        path = Path(self.home.anchor)
        for part in (*self.home.parts[1:], *parts):
            path /= part
            self._tick()
            info = path.lstat()
            if _unsafe(info) or not stat.S_ISDIR(info.st_mode):
                raise OSError('unsafe directory')
        return path

    def exists(self, relative: str, directory: bool = False) -> bool:
        path = PurePosixPath(relative)
        parent = None
        try:
            parent = self._directory(str(path.parent))
            self._tick()
            info = (os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                    if isinstance(parent, int) else (parent / path.name).lstat())
            return not _unsafe(info) and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                self.incomplete_reasons.add('unreadable_location')
            return False
        finally:
            if isinstance(parent, int):
                os.close(parent)

    def names(self, relative: str, limit: int) -> tuple[list[str], bool]:
        parent = None
        try:
            parent = self._directory(relative)
            names = []
            with os.scandir(parent) as entries:
                # Inspect no more than limit+1 names, never recurse or sort an
                # unbounded directory. Sorting the bounded subset stabilizes UI.
                for entry in entries:
                    self._tick()
                    if len(names) == limit:
                        return sorted(names), True
                    names.append(entry.name)
            return sorted(names), False
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                self.incomplete_reasons.add('unreadable_location')
            return [], False
        finally:
            if isinstance(parent, int):
                os.close(parent)


def discover_harnesses(home: str | Path | None = None, *, platform: str | None = None,
                       max_candidates: int = 100, max_entries: int = 64,
                       max_probes: int = 4096) -> dict:
    """Suggest explicit connections; never import or change any external state.

    Limits cap returned candidates, names per known profile container, and total
    metadata operations (including ancestor checks). A truncated scan must not
    be presented as exhaustive. Missing/unreadable markers are not candidates.
    Default native OS roots only: no custom environment-derived paths are read.
    """
    platform = _platform(platform)
    for value, ceiling in ((max_candidates, 256), (max_entries, 256), (max_probes, 16384)):
        if type(value) is not int or not 1 <= value <= ceiling:
            raise ValueError('discovery limit outside bounded range')
    home = Path.home() if home is None else Path(home)
    if not home.is_absolute() or '..' in home.parts:
        raise ValueError('home must be an absolute non-traversing path')
    metadata = _Metadata(home, max_probes)
    candidates, seen = [], set()
    truncated = False

    def add(descriptor, kind, local_id, relative):
        nonlocal truncated
        key = (descriptor.family, kind, local_id)
        if key in seen:
            return
        if len(candidates) >= max_candidates:
            truncated = True
            raise _BudgetExhausted
        seen.add(key)
        candidates.append(dict(
            id=':'.join(key), family=descriptor.family, label=descriptor.label,
            kind=kind, local_id=local_id, path=str(home / relative),
            location='~/' + relative,
            evidence=descriptor.evidence, status='detected_unverified',
            requires_explicit_connect=True, auto_import=False, connected=False))

    try:
        for descriptor in DESCRIPTORS:
            for relative in _markers(descriptor, platform):
                if metadata.exists(relative):
                    add(descriptor, descriptor.kind, 'default', relative)
        by_family = {d.family: d for d in DESCRIPTORS}
        editor_parent = str(PurePosixPath(_markers(by_family['vscode'], platform)[0]).parent)
        containers = (
            ('hermes', '.hermes/profiles', 'profile', 'config.yaml', False),
            ('openclaw', '.openclaw/agents', 'agent', 'agent', True),
            ('vscode', editor_parent + '/profiles', 'editor_profile', 'settings.json', False),
        )
        for family, parent, kind, leaf, is_dir in containers:
            names, clipped = metadata.names(parent, max_entries)
            truncated |= clipped
            for name in names:
                # IDs are untrusted directory names; never interpret as paths.
                if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', name):
                    continue
                relative = f'{parent}/{name}/{leaf}'
                if metadata.exists(relative, directory=is_dir):
                    add(by_family[family], kind, name, relative)
    except _BudgetExhausted:
        truncated = True
    return dict(candidates=candidates, catalog=discovery_catalog(platform),
                platform=platform, truncated=truncated, probes=metadata.probes,
                incomplete=truncated or bool(metadata.incomplete_reasons),
                incomplete_reasons=sorted(metadata.incomplete_reasons | ({'budget_exhausted'} if truncated else set())),
                requires_explicit_connect=True, auto_import=False)
