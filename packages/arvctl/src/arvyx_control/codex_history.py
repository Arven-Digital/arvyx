"""Read-only Codex session metadata from its default state root.

Layout contract (verified against an installed Codex state root by file name
shape only, 2026-11-01): ``<root>/sessions/YYYY/MM/DD/rollout-<YYYY-MM-DDTHH-MM-SS>-<uuid>.jsonl``,
optionally zstd-compressed as ``.jsonl.zst`` by newer releases. Other entries
under ``sessions/`` are skipped and counted in ``last_scan``. Codex's SQLite
state and ``history.jsonl`` are not read.

Listing never opens a rollout. The exact ID is the literal relative path
``YYYY/MM/DD/<file name>``; the title is the timestamp from the file name; the
activity timestamp is the file's mtime. A reviewed exact inspection of a plain
rollout reads a bounded prefix of its first line (``session_meta`` payload, or
the legacy bare meta object) and returns only ``id`` agreement, ``cwd``,
``cli_version`` and ``timestamp``; ``instructions`` and every later line are
never returned. A compressed rollout yields file-name fields only: this adapter
carries no zstd decoder, so ``cwd`` is reported unavailable rather than
guessed. There is no launch or resume here.
"""
import re

from .agent_sessions import RoutingError
from .session_file_store import FileSessionStore, bounded_text, prefix_records

UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
YEAR = re.compile(r'\d{4}')
MONTH_DAY = re.compile(r'\d{2}')
ROLLOUT = re.compile(rf'rollout-(\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}-\d{{2}}-\d{{2}})-({UUID})\.jsonl(\.zst)?')


class CodexHistory(FileSessionStore):
    harness = 'codex'
    label = 'Codex'
    sessions_relative = 'sessions'

    def _sessions(self, walker, root):
        for year, kind, _m, _s in walker.entries(root):
            if kind != 'dir' or not YEAR.fullmatch(year):
                yield None, year, 0
                continue
            with walker.child_dir(root, year) as year_dir:
                for month, kind, _m, _s in walker.entries(year_dir):
                    if kind != 'dir' or not MONTH_DAY.fullmatch(month):
                        yield None, month, 0
                        continue
                    with walker.child_dir(year_dir, month) as month_dir:
                        for day, kind, _m, _s in walker.entries(month_dir):
                            if kind != 'dir' or not MONTH_DAY.fullmatch(day):
                                yield None, day, 0
                                continue
                            with walker.child_dir(month_dir, day) as day_dir:
                                for name, kind, mtime, _size in walker.entries(day_dir):
                                    match = ROLLOUT.fullmatch(name) if kind == 'file' else None
                                    if match is None:
                                        yield None, name, 0
                                        continue
                                    yield f'{year}/{month}/{day}/{name}', match.group(1), mtime

    def _locate(self, session_id):
        parts = session_id.split('/')
        if (len(parts) != 4 or not YEAR.fullmatch(parts[0])
                or not all(MONTH_DAY.fullmatch(part) for part in parts[1:3])
                or not ROLLOUT.fullmatch(parts[3])):
            raise RoutingError('exact existing session ID unavailable; no fallback')
        return tuple(parts)

    def _routing_fields(self, parts, prefix, complete):
        started, uuid, compressed = ROLLOUT.fullmatch(parts[-1]).groups()
        if compressed:
            return dict(encoding='zstd', cwd=None, cli_version=None, started_at=started,
                        note='compressed rollout; working directory unavailable without a zstd decoder')
        records = prefix_records(prefix, complete, max_lines=1)
        if not records:
            raise RoutingError('session routing metadata unavailable within the bounded prefix')
        first = records[0]
        meta = first.get('payload') if first.get('type') == 'session_meta' else first
        if not isinstance(meta, dict) or meta.get('id') != uuid:
            raise RoutingError('session file identity does not match its name; no fallback')
        return dict(encoding='jsonl', cwd=bounded_text(meta.get('cwd')),
                    cli_version=bounded_text(meta.get('cli_version')),
                    started_at=bounded_text(meta.get('timestamp')) or started)
