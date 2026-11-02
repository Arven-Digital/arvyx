"""Read-only tiled stream previews, not a VT emulator.

New Python implementation adapting stable pane/focus separation from Herdr
src/layout.rs at 5bd900d88c80d95f5b145397e45bbeea398b8165 (Apache-2.0).
No Rust or vendored VT code is copied. Native full-screen tools use attach.
"""
from __future__ import annotations
import curses
import re

from .cockpit_client import request

# Strip terminal string commands (including OSC clipboard), CSI and short ESC.
# Unfinished sequences are discarded as well: replay can begin/end mid-sequence.
_ESCAPE = re.compile(r'\x1b(?:\][^\x07\x1b]*(?:\x07|\x1b\\|$)|[P^_X].*?(?:\x1b\\|$)|\[[0-?]*[ -/]*[@-~]|\[[^@-~]*$|[@-_])', re.S)


def preview_lines(output):
    text = _ESCAPE.sub('', output)
    return [''.join(c if c.isprintable() else '?' for c in line)
            for line in text.replace('\r\n', '\n').replace('\r', '\n').split('\n')]


def ordered_sessions(sessions):
    """Attention changes ordering only; no selection write or output heuristic."""
    return sorted(sessions, key=lambda row: row.get('attention') not in {'human', 'review'})


def read_panels(root, model):
    sessions = {row['id']: row for row in model['sessions']}
    result = []
    for sid in model['view'].get('panels', []):
        if sid not in sessions:
            continue
        row = sessions[sid]
        try:
            frame = request(root, 'read', sid=sid, actor='operator', cursor=0)
            lines = preview_lines(frame['output'])
            if frame['truncated']:
                lines.insert(0, '[REPLAY GAP: retained tail only]')
        except (OSError, ValueError) as exc:
            lines = ['[pane unavailable: ' + str(exc) + ']']
        result.append({'id': sid, 'name': row['name'], 'lines': lines,
                       'focused': sid == model['view']['selected']})
    return result


def draw_panels(screen, panes, *, top, left, height, width):
    """Arvyx-style pane chrome with a distinct focus border and inset content.

    Adaptation of ui/panes.rs pane_border_title / pane_inner_rect and one-cell
    gutter behavior at the pinned Apache-2.0 source; no Rust/VT engine copied.
    """
    if not panes or height < 2 or width < 4:
        return
    columns = min(len(panes), max(1, width // 32))
    rows = (len(panes) + columns - 1) // columns
    cell_h, cell_w = height // rows, width // columns
    if cell_h < 2:
        columns, rows = 1, min(len(panes), height // 2)
        cell_h, cell_w = 2, width
        panes = panes[:rows]
    for index, pane in enumerate(panes):
        y, x = top + (index // columns) * cell_h, left + (index % columns) * cell_w
        title = ('● ' if pane['focused'] else '○ ') + pane['name'] + ' · preview'
        attr = curses.A_BOLD if pane['focused'] else curses.A_DIM
        box_w = max(3, cell_w - 1)
        screen.addnstr(y, x, '┌' + '─' * (box_w - 2) + '┐', box_w, attr)
        screen.addnstr(y, x + 2, preview_lines(title)[0], max(1, box_w - 4), attr)
        for offset in range(1, cell_h - 1):
            screen.addnstr(y + offset, x, '│', 1, attr)
            screen.addnstr(y + offset, x + box_w - 1, '│', 1, attr)
        screen.addnstr(y + cell_h - 1, x, '└' + '─' * (box_w - 2) + '┘', box_w, attr)
        visible = pane['lines'][-max(1, cell_h - 2):]
        for offset, line in enumerate(visible[:max(0, cell_h - 2)], 1):
            screen.addnstr(y + offset, x + 1, line, max(1, box_w - 2))
