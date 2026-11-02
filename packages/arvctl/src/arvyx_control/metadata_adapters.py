"""Local read-only session-metadata adapters keyed by discovery family.

One registry replaces the former Hermes-only branches in review, connection,
discovery and identity registration. An entry here means exactly this: after
human review, the parent directory of a discovered marker can be connected as
exact, read-only session metadata (Last 5, All with search and pagination, and
a reviewed exact inspection). It does not mean a verified runtime adapter:
launch, resume, attach, New, effective environment and recovery stay
unavailable for every family here except the separately reviewed Hermes native
paths. Families without an entry remain "No compatible local connection
adapter is configured"; research targets are not supported harnesses.
"""
from dataclasses import dataclass
import importlib
from pathlib import Path


@dataclass(frozen=True)
class MetadataAdapter:
    family: str
    label: str
    marker: str                 # discovery marker leaf; its parent is the connectable root
    store: str                  # what the adapter reads, stated for the operator
    link_sensitive: tuple       # entries below the root that must not be symlinks at review time
    module: str
    attribute: str

    def open(self, home, *, review_snapshot=None):
        cls = getattr(importlib.import_module(self.module, __package__), self.attribute)
        return cls(home, review_snapshot=review_snapshot)

    def reason(self):
        return (f'Read-only {self.label} metadata adapter. Choose the exact registered agent '
                'identity and review this profile; native reachability is not implied.')

    def refuse_links(self, root):
        root = Path(root)
        if root.is_symlink() or any((root / name).is_symlink() for name in self.link_sensitive):
            raise ValueError('profile and metadata must not be symlinks')

    def describe(self):
        return dict(id=self.family, label=self.label, marker=self.marker, store=self.store,
                    metadata_only=True, runtime_adapter_verified=False)


ADAPTERS = {entry.family: entry for entry in (
    MetadataAdapter('hermes', 'Hermes', 'config.yaml',
                    'state.db sessions table (id, title, timestamps); no transcripts',
                    ('state.db',), '.hermes_history', 'HermesHistory'),
    MetadataAdapter('claude', 'Claude Code', 'settings.json',
                    'projects/<project>/<session>.jsonl file names and stat only; no transcripts',
                    ('projects',), '.claude_code_history', 'ClaudeCodeHistory'),
    MetadataAdapter('codex', 'Codex', 'config.toml',
                    'sessions/YYYY/MM/DD/rollout-*.jsonl[.zst] file names and stat only; no transcripts',
                    ('sessions',), '.codex_history', 'CodexHistory'),
)}

METADATA_HARNESSES = frozenset(ADAPTERS)


def adapter(family):
    try:
        return ADAPTERS[family]
    except (KeyError, TypeError):
        raise ValueError('no local metadata adapter for harness') from None


def open_history(family, home, *, review_snapshot=None):
    return adapter(family).open(home, review_snapshot=review_snapshot)


def candidate_root(candidate):
    """The connectable root of a discovered candidate: its marker's parent directory."""
    if not isinstance(candidate, dict) or candidate.get('family') not in ADAPTERS:
        raise ValueError('compatible discovered profile unavailable')
    path = Path(candidate['path'])
    if path.name != ADAPTERS[candidate['family']].marker:
        raise ValueError('exact supported profile marker required')
    return path.parent


def catalog():
    return [entry.describe() for entry in ADAPTERS.values()]
