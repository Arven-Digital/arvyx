"""R10-02 regression specifications; no listener or browser required."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from arvyx_control import cockpit_surface, cockpit_web


class DashboardAuthorityTests(unittest.TestCase):
    def model(self, available):
        return {
            'host': 'local', 'tasks': [],
            'sessions': [{'id': 's1', 'name': 'local session', 'project': 'demo',
                          'status': 'running', 'task': '', 'workspace': 'workspace'}],
            'view': {'selected': 's1', 'revision': 1},
            'availability': {'amc_authority': available, 'machine': True,
                             'amc_memory': available, 'private_detail': '/private/secret'},
            'authority_error': '/private/secret/raw-error',
        }

    def response(self, model):
        handler = object.__new__(cockpit_web.DashboardHandler)
        handler.path = '/api/dashboard'
        handler.server = SimpleNamespace(root='unused')
        handler.authorized = Mock(return_value=True)
        handler.reply = Mock()
        with patch.object(cockpit_web, 'snapshot', return_value=model):
            handler.do_GET()
        handler.authorized.assert_called_once_with()
        code, body = handler.reply.call_args.args
        self.assertEqual(code, 200)
        return body

    def test_unavailable_api_and_renderer_preserve_local_sessions_without_private_error(self):
        model = self.model(False)
        body = self.response(model)
        self.assertEqual(body['availability'], {'amc_authority': False,
                         'machine': True, 'amc_memory': False})
        self.assertEqual(body['sessions'], model['sessions'])
        self.assertNotIn('/private/secret', json.dumps(body))
        for page in (body['html'], cockpit_surface.render_dashboard(model)):
            self.assertIn('Task authority unavailable', page)
            self.assertIn('Task ledger unknown', page)
            self.assertIn('Unknown</strong>AMC tasks', page)
            self.assertIn('local session', page)
            self.assertNotIn('No tasks', page)
            self.assertNotIn('/private/secret', page)

    def test_recovery_with_same_empty_ledger_clears_warning(self):
        unavailable = self.response(self.model(False))
        recovered = self.response(self.model(True))
        self.assertEqual(unavailable['tasks'], recovered['tasks'])
        self.assertNotEqual(unavailable['availability'], recovered['availability'])
        self.assertIn('No tasks', recovered['html'])
        self.assertIn('0</strong>AMC tasks', recovered['html'])
        self.assertNotIn('Task authority unavailable', recovered['html'])
        self.assertNotIn('task-authority-warning', recovered['html'])

    def test_browser_projection_tracks_availability_and_keeps_local_actions(self):
        script = cockpit_web.SCRIPT
        projection = next(line for line in script.splitlines() if 'const projection =' in line)
        self.assertIn('model.availability', projection)
        self.assertIn('model.availability.amc_authority === false', script)
        self.assertIn("main.querySelector('.task-authority-warning')", script)
        self.assertIn("api('/api/select'", script)
        self.assertIn("api('/api/end'", script)
        self.assertIn("api('/api/take-control'", script)
