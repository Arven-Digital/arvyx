"""Read-only Claude Code session metadata from its default state root.

Layout contract (verified against an installed Claude Code state root by file
name shape only, 2026-11-01): ``<root>/projects/<project>/<session-uuid>.jsonl``,
one file per top-level session, where ``<project>`` is the harness's own encoded
working-directory label. Other entries in a project directory (``memory/``,
``agent-*.jsonl`` subagent files, caches) are not top-level sessions and are
skipped, counted in ``last_scan``.

Listing never opens a session file. The exact ID is ``<project>/<uuid>``; the
title is the project label; the activity timestamp is the file's mtime. A
reviewed exact inspection reads a bounded prefix and returns only ``sessionId``
agreement, ``cwd``, ``version`` and the first timestamp. ``summary`` lines and
``message`` payloads are never returned. There is no launch or resume here.
"""
import re

from .agent_sessions import RoutingError
from .session_file_store import FileSessionStore, bounded_text, prefix_records

UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
# Encoded working-directory labels: "-home-user-work" on POSIX, "C--Users-name-work" on
# Windows. Literal names only; "." and ".." can never be project labels.
PROJECT = re.compile(r'(?!\.\.?$)[A-Za-z0-9_.-]{1,256}')
SESSION = re.compile(rf'({UUID})\.jsonl')
UUID_RE = re.compile(UUID)


class ClaudeCodeHistory(FileSessionStore):
    harness = 'claude'
    label = 'Claude Code'
    sessions_relative = 'projects'

    def _sessions(self, walker, root):
        for project, kind, _mtime, _size in walker.entries(root):
            if kind != 'dir' or not PROJECT.fullmatch(project):
                yield None, project, 0
                continue
            with walker.child_dir(root, project) as directory:
                for name, kind, mtime, _size in walker.entries(directory):
                    match = SESSION.fullmatch(name) if kind == 'file' else None
                    if match is None:
                        yield None, name, 0
                        continue
                    yield project + '/' + match.group(1), project, mtime

    def _locate(self, session_id):
        project, separator, leaf = session_id.partition('/')
        if not separator or not PROJECT.fullmatch(project) or not UUID_RE.fullmatch(leaf):
            raise RoutingError('exact existing session ID unavailable; no fallback')
        return (project, leaf + '.jsonl')

    def _routing_fields(self, parts, prefix, complete):
        uuid = parts[-1][:-len('.jsonl')]
        for record in prefix_records(prefix, complete):
            identity = record.get('sessionId')
            if isinstance(identity, str) and 'cwd' in record:
                if identity != uuid:
                    raise RoutingError('session file identity does not match its name; no fallback')
                return dict(encoding='jsonl', cwd=bounded_text(record.get('cwd')),
                            version=bounded_text(record.get('version')),
                            started_at=bounded_text(record.get('timestamp')))
        raise RoutingError('session routing metadata unavailable within the bounded prefix')
