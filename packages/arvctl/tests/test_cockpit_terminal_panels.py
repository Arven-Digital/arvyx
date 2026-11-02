"""Read-only tiled previews never acquire input authority."""
import unittest
from unittest.mock import patch, MagicMock
import test_cockpit_surface as fixtures
from arvyx_control import cockpit_surface


class PanelTests(unittest.TestCase):
    setUp = fixtures.SurfaceTests.setUp
    session = fixtures.SurfaceTests.session

    def test_pane_chrome_frames_content_and_keeps_focus_distinct(self):
        from arvyx_control.cockpit_terminal_panels import draw_panels
        screen = MagicMock()
        panes = [{'id': 'a', 'name': 'first', 'focused': True, 'lines': ['ONE']},
                 {'id': 'b', 'name': 'second', 'focused': False, 'lines': ['TWO']}]
        draw_panels(screen, panes, top=3, left=30, height=18, width=100)
        calls = screen.addnstr.call_args_list
        text = '\n'.join(str(call.args[2]) for call in calls)
        self.assertIn('┌', text)
        self.assertIn('└', text)
        self.assertIn('first', text)
        self.assertIn('second', text)
        self.assertIn('ONE', text)
        self.assertIn('TWO', text)
        for call in calls:
            y, x, _, size = call.args[:4]
            self.assertGreaterEqual(y, 3)
            self.assertLess(y, 21)
            self.assertGreaterEqual(x, 30)
            self.assertLessEqual(x + size, 130)

    def test_owner_snapshot_uses_bound_identity_and_authority(self):
        first = self.session('first')
        self.service.select(first['id'], revision=0, actor='operator')
        model = self.service.snapshot(actor='operator')
        self.assertEqual(model['host'], 'laptop-a')
        self.assertEqual(model['state'], str(self.root / 'events.jsonl'))
        self.assertEqual(model['tasks'][0]['id'], first['task'])
        self.assertEqual(model['view']['panels'], [first['id']])
        with self.assertRaises(PermissionError):
            self.service.snapshot(actor='agent')

    def test_client_never_assumes_local_authority_path_or_host(self):
        model = {'host': 'remote-fixture', 'tasks': [], 'sessions': [], 'view': {}}
        with patch.object(cockpit_surface, 'request', return_value=model) as rpc:
            self.assertEqual(cockpit_surface.snapshot(self.root), model)
            rpc.assert_called_once_with(self.root, 'snapshot', actor='operator')

    def test_amc_failure_does_not_hide_running_local_sessions(self):
        first = self.session('first')
        with patch('arvyx_control.cockpit.list_tasks', side_effect=OSError('authority unavailable')):
            model = self.service.snapshot(actor='operator')
        self.assertEqual(model['sessions'][0]['id'], first['id'])
        self.assertEqual(model['tasks'], [])
        self.assertFalse(model['availability']['amc_memory'])
        self.assertTrue(model['availability']['machine'])

    def test_previews_are_read_only_and_render_all_shared_panes(self):
        from arvyx_control.cockpit_terminal_panels import read_panels, draw_panels
        first, second = self.session('first'), self.session('second')
        model = self.service.snapshot(actor='operator')
        model['view'] = {'panels': [first['id'], second['id']], 'selected': second['id'], 'revision': 4}
        def rpc(root, operation, **fields):
            self.assertEqual(operation, 'read')
            return {'output': '\x1b]52;c;secret\x07\x1b[31mhello\x1b[0m\r\nworld', 'truncated': True}
        with patch('arvyx_control.cockpit_terminal_panels.request', side_effect=rpc) as calls:
            panes = read_panels(self.root, model)
        self.assertEqual(calls.call_count, 2)
        screen = MagicMock()
        draw_panels(screen, panes, top=4, left=20, height=12, width=60)
        rendered = '\n'.join(str(call.args[2]) for call in screen.addnstr.call_args_list)
        self.assertIn('first', rendered)
        self.assertIn('second', rendered)
        self.assertIn('REPLAY GAP', rendered)
        self.assertIn('hello', rendered)
        self.assertNotIn('secret', rendered)
        self.assertNotIn('\x1b', rendered)

    def test_attention_order_is_stable_and_does_not_change_shared_focus(self):
        from arvyx_control.cockpit_terminal_panels import ordered_sessions
        rows = [{'id': 'a', 'attention': None}, {'id': 'b', 'attention': 'human'},
                {'id': 'c', 'attention': 'review'}, {'id': 'd', 'attention': None}]
        self.assertEqual([s['id'] for s in ordered_sessions(rows)], ['b', 'c', 'a', 'd'])
        self.assertEqual(rows[0]['id'], 'a')

    def test_unreachable_panel_does_not_hide_healthy_panes(self):
        from arvyx_control.cockpit_terminal_panels import read_panels
        model = {'sessions': [{'id': 'a', 'name': 'first'}, {'id': 'b', 'name': 'second'}],
                 'view': {'panels': ['a', 'b'], 'selected': 'a'}}
        with patch('arvyx_control.cockpit_terminal_panels.request', side_effect=[OSError('offline'), {'output': 'alive', 'truncated': False}]):
            panes = read_panels(self.root, model)
        self.assertIn('unavailable', panes[0]['lines'][0])
        self.assertIn('alive', panes[1]['lines'])

    def test_enter_rechecks_revision_even_when_focus_looks_unchanged(self):
        first = dict(self.session('first'), status='running')
        model = {'sessions': [first], 'view': {'panels': [], 'selected': first['id'], 'revision': 0}}
        screen = MagicMock()
        screen.getmaxyx.return_value = (24, 60)
        screen.getch.side_effect = [10, ord('q')]
        with patch.object(cockpit_surface.curses, 'curs_set'), \
             patch.object(cockpit_surface, 'snapshot', return_value=model), \
             patch.object(cockpit_surface, 'export_dashboard'), \
             patch.object(cockpit_surface, 'request', side_effect=ValueError('stale shared view')) as rpc:
            self.assertIsNone(cockpit_surface._navigate(screen, self.root))
        rpc.assert_called_once_with(self.root, 'select', sid=first['id'], revision=0, actor='operator')
