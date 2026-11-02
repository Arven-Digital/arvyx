"""Navigation contracts for the assembled, single-authority UI."""
from html.parser import HTMLParser
import unittest

from arvyx_control.cockpit_web import SHELL
from arvyx_control.cockpit_team import render_team


class Elements(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.tags = []
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class NavigationTests(unittest.TestCase):
    def test_shell_has_persistent_work_and_team_navigation(self):
        tags = Elements(SHELL).tags
        destinations = {attrs['data-route'] for _, attrs in tags if 'data-route' in attrs}
        self.assertEqual(destinations, {'overview', 'sessions', 'tasks', 'projects', 'agents',
                                        'approvals', 'organizer', 'memory', 'history'})
        self.assertIn('aria-label="Main navigation"', SHELL)
        self.assertIn('id="navigation-toggle"', SHELL)
        self.assertIn('aria-controls="sidebar"', SHELL)
        self.assertIn('id="page-title"', SHELL)
        self.assertIn('href="#workspace"', SHELL)

    def test_team_pages_are_distinct_retained_sections_not_an_endless_dashboard(self):
        page = render_team({'availability': {}}, {'sessions': [], 'host': 'fixture'})
        tags = Elements(page).tags
        pages = {attrs['data-page'] for tag, attrs in tags if tag == 'section' and 'data-page' in attrs}
        self.assertEqual(pages, {'tasks', 'projects', 'agents', 'approvals', 'organizer', 'memory', 'history'})
        forms = [attrs['data-team-action'] for tag, attrs in tags if tag == 'form']
        self.assertEqual(set(forms), {'task-create', 'approval-request', 'organizer-post',
                                     'handoff-create', 'memory-recall'})
        self.assertIn('unavailable or unauthorized', page)
        self.assertIn('TEAM', SHELL)

    def test_route_code_never_refreshes_or_submits_team_forms_on_navigation(self):
        from arvyx_control import cockpit_web
        self.assertIn('function showPage(', cockpit_web.SCRIPT)
        route_code = cockpit_web.SCRIPT.split('function showPage(', 1)[1].split('function ', 1)[0]
        self.assertNotIn('refreshTeam()', route_code)
        self.assertNotIn('api(', route_code)
        self.assertNotIn('replaceChildren', route_code)
        self.assertIn('hidden', route_code)
        self.assertIn('aria-current', route_code)

    def test_skip_anchor_does_not_replace_capability_and_unchanged_poll_retains_actions(self):
        from arvyx_control import cockpit_web
        self.assertIn('/^[A-Za-z0-9_-]{32,128}$/.test(fragment)', cockpit_web.SCRIPT)
        self.assertIn('event.preventDefault(); showPage', cockpit_web.SCRIPT)
        self.assertIn('if (projection === renderedProjection) return', cockpit_web.SCRIPT)

    def test_known_absent_delegation_is_not_ambiguous_delivery(self):
        from arvyx_control import cockpit_web
        self.assertIn('if (result === null)', cockpit_web.SCRIPT)
        branch = cockpit_web.SCRIPT.split('if (result === null)', 1)[1].split('} else {', 1)[0]
        self.assertIn('No active operator delegation', branch)
        self.assertIn('take.disabled = false', branch)
        self.assertNotIn('api(', branch)


if __name__ == '__main__':
    unittest.main()
