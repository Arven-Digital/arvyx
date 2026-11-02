from pathlib import Path
import re
import subprocess
import unittest


HTML = (Path(__file__).resolve().parents[1] / "src/arvyx_control/static/index.html").read_text(encoding="utf-8")


class DashboardWorkbenchContractTests(unittest.TestCase):
    def test_refresh_waits_for_selected_timeline_before_enabling_controls(self):
        regression = Path(__file__).with_name("workbench_refresh_behavior.mjs")
        result = subprocess.run(
            ["node", str(regression)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("workbench refresh behavioral regression: PASS", result.stdout)

    def test_workbench_is_hash_opt_in_and_observatory_remains_default(self):
        self.assertIn('id="view-workbench"', HTML)
        self.assertIn('href="#workbench"', HTML)
        self.assertIn('id="observatory-view"', HTML)
        self.assertRegex(HTML, r'location\.hash\s*===\s*"#workbench"')
        self.assertIn('addEventListener("hashchange", applyView)', HTML)

    def test_three_pane_markup_and_accessible_mobile_tabs_exist(self):
        for marker in ('id="workbench-nav"', 'id="workbench-timeline"', 'id="workbench-inspector"'):
            self.assertIn(marker, HTML)
        self.assertIn('role="tablist"', HTML)
        self.assertIn('aria-controls="workbench-timeline"', HTML)
        self.assertIn('aria-live="polite"', HTML)
        for marker in (
            'id="workbench-tab-executions"',
            'aria-labelledby="workbench-tab-executions"',
            'tabindex="0" data-pane="workbench-nav"',
            'tabindex="-1" data-pane="workbench-timeline"',
        ):
            self.assertIn(marker, HTML)
        self.assertIn('["ArrowLeft", "ArrowRight", "Home", "End"]', HTML)
        self.assertNotIn('$(tab.dataset.pane).focus', HTML)

    def test_real_execution_routes_cursor_and_post_mutation_refresh_are_wired(self):
        self.assertIn('api("/executions")', HTML)
        self.assertIn('/events?${params.toString()}', HTML)
        self.assertIn('params.set("after", workbench.nextCursor)', HTML)
        for route in ('cancel: "cancel"', 'resume: "resume"', 'steer: "steer"'):
            self.assertIn(route, HTML)
        self.assertIn('await verifyWorkbenchMutation', HTML)
        self.assertNotIn('mutate("/threads"', HTML)

    def test_event_rendering_uses_production_top_level_safe_fields(self):
        block = HTML[HTML.index("function safeEventSummary"):HTML.index("function renderWorkbenchEvents")]
        self.assertNotIn("event.payload", block)
        for field in ("event.message", "event.reason", "event.status", "event.attempt_id"):
            self.assertIn(field, block)

    def test_selection_generation_fences_stale_timeline_responses(self):
        block = HTML[HTML.index("async function loadWorkbenchEvents"):HTML.index("async function selectExecution")]
        self.assertIn("selectionGeneration", block)
        self.assertIn("requestedExecutionId", block)
        self.assertIn("generation !== workbench.selectionGeneration", block)
        self.assertNotIn("if (!execution || workbench.eventLoading) return", block)

    def test_post_mutation_truth_is_fail_closed_and_requires_both_reads(self):
        block = HTML[HTML.index("async function workbenchMutation"):HTML.index("function applyView")]
        controls = HTML[HTML.index("function renderWorkbenchControls()"):HTML.index("function renderWorkbench()")]
        self.assertIn("await verifyWorkbenchMutation", block)
        self.assertIn("workbench.listError", HTML)
        self.assertIn("workbench.timelineError", HTML)
        self.assertIn("authoritativeUncertainty", controls)
        self.assertIn("authoritativeUncertainty ||", controls)
        self.assertIn("could not be verified", block)
        self.assertNotIn("accepted; refreshing authoritative projection", block)

    def test_steer_verification_binds_the_nested_response_request_id(self):
        block = HTML[HTML.index("function mutationObserved"):HTML.index("async function workbenchMutation")]
        self.assertIn("response?.steer?.request_id", block)
        self.assertIn("item.request_id === expectedRequestId", block)
        self.assertNotIn("!response?.request_id", block)
        self.assertIn("if (kind === \"steer\" && !expectedRequestId) return false", block)

    def test_mutation_verification_pages_past_fifty_with_hard_bounds(self):
        block = HTML[HTML.index("function mutationObserved"):HTML.index("async function workbenchMutation")]
        self.assertIn("WORKBENCH_VERIFY_MAX_PAGES", HTML)
        self.assertIn("WORKBENCH_VERIFY_MAX_EVENTS", HTML)
        self.assertIn('params.set("after", nextCursor)', block)
        self.assertIn("while (hasMore", block)
        self.assertIn("cursor did not advance", block)

    def test_authoritative_errors_clear_only_after_successful_reads(self):
        load = HTML[HTML.index("async function loadWorkbenchEvents"):HTML.index("async function selectExecution")]
        refresh = HTML[HTML.index("async function refreshWorkbench"):HTML.index("function mutationObserved")]
        self.assertNotIn('workbench.timelineError = ""; renderWorkbenchEvents()', load)
        self.assertIn('workbench.timelineError = ""', load)
        self.assertNotIn('workbench.listError = ""; renderWorkbenchNavigator()', refresh)
        self.assertIn('workbench.listError = ""', refresh)

    def test_per_operation_pending_fence_and_stable_idempotency_key(self):
        block = HTML[HTML.index("async function workbenchMutation"):HTML.index("function applyView")]
        self.assertIn("pendingMutations.has(operationKey)", block)
        self.assertIn("logicalMutationKeys", block)
        self.assertIn("idempotencyKey", block)
        self.assertIn("pendingMutations.delete(operationKey)", block)

    def test_controls_are_status_gated_and_steering_is_attempt_bound(self):
        self.assertIn('execution.status === "leased"', HTML)
        self.assertIn('execution.status === "paused"', HTML)
        self.assertIn('body.attempt_id = execution.attempt_id', HTML)
        self.assertIn('workbench-steer', HTML)
        self.assertIn('workbench-cancel', HTML)
        self.assertIn('workbench-resume', HTML)

    def test_controls_fail_closed_during_initial_execution_loading(self):
        controls = HTML[HTML.index("function renderWorkbenchControls()"):HTML.index("function renderWorkbench()")]
        self.assertIn("workbench.loading", controls)
        self.assertIn("authoritativeUncertainty ||", controls)

    def test_controls_fail_closed_during_selected_timeline_loading(self):
        controls = HTML[HTML.index("function renderWorkbenchControls()"):HTML.index("function renderWorkbench()")]
        self.assertIn("workbench.eventLoading", controls)
        self.assertIn("authoritativeUncertainty ||", controls)

    def test_any_pending_mutation_disables_cross_operation_controls_through_verification(self):
        controls = HTML[HTML.index("function renderWorkbenchControls()"):HTML.index("function renderWorkbench()")]
        mutation = HTML[HTML.index("async function workbenchMutation"):HTML.index("function applyView")]
        self.assertIn("pendingMutations.size > 0", controls)
        self.assertNotIn("pendingMutations.has(operationKey", controls)
        self.assertLess(mutation.index("await verifyWorkbenchMutation"), mutation.index("pendingMutations.delete(operationKey)"))

    def test_dynamic_workbench_content_uses_text_content_helpers(self):
        workbench_script = HTML[HTML.index('const workbench ='):]
        self.assertNotIn('.innerHTML', workbench_script)
        self.assertIn('el("strong",', workbench_script)
        self.assertIn('textContent', HTML)

    def test_responsive_overflow_and_reduced_motion_contracts(self):
        self.assertRegex(HTML, r'@media \(max-width:\s*900px\)[\s\S]*\.workbench-grid')
        self.assertIn('overflow-wrap: anywhere', HTML)
        self.assertIn('@media (prefers-reduced-motion: reduce)', HTML)
        self.assertIn('min-width: 0', HTML)
        self.assertRegex(HTML, r'@media \(max-width:\s*900px\)[\s\S]*min-height:\s*44px')
        self.assertIn('.control:disabled', HTML)
        self.assertIn('.control:disabled:hover', HTML)
        self.assertIn('.control.resume-ready', HTML)

    def test_error_is_visible_in_center_first_mobile_timeline(self):
        block = HTML[HTML.index("function renderWorkbenchEvents()"):HTML.index("function appendInspectorSection")]
        self.assertLess(block.index("workbench.timelineError"), block.index("!workbench.selectedId"))
        controls = HTML[HTML.index("function renderWorkbenchControls()"):HTML.index("function renderWorkbench()")]
        self.assertIn('workbench.listError ? `Executions unavailable: ${workbench.listError}`', controls)

    def test_no_dangerous_workbench_controls(self):
        workbench_markup = HTML[HTML.index('id="view-workbench"'):HTML.index('id="backdrop"')]
        for forbidden in ('approval-consume', 'artifact-fetch', 'delete', 'purchase', 'publish', 'Replay execution'):
            self.assertNotIn(forbidden, workbench_markup)


class DashboardDeskAssignmentTests(unittest.TestCase):
    """Presets assign by stable id and registry hint; the operator surface
    restricts presence to the approved four-member fleet."""

    def test_arbitrary_agent_ids_get_desks_and_registry_hints_override(self):
        regression = Path(__file__).with_name("dashboard_desk_behavior.mjs")
        result = subprocess.run(["node", str(regression)], check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("dashboard desk assignment behavioral regression: PASS", result.stdout)

    def test_page_desk_presets_match_the_api_desk_keys(self):
        from arvyx_control.api import DASHBOARD_DESKS

        block = HTML[HTML.index("const DESK_PRESETS = "):HTML.index("function planDesks(")]
        self.assertEqual(tuple(re.findall(r'key: "([a-z]+)"', block)), DASHBOARD_DESKS)

    def test_sprites_are_keyed_by_desk_preset_not_agent_identity(self):
        from arvyx_control.api import DASHBOARD_DESKS

        sprites = set(re.findall(r'<symbol id="sprite-([a-z0-9_-]+)-[12]"', HTML))
        self.assertEqual(sprites, {*DASHBOARD_DESKS, "generic"})
        for retired in ("roleMeta", "excludedAgentIds", "Unconfigured squad desk"):
            self.assertNotIn(retired, HTML)

    def test_registry_dashboard_hints_pass_only_known_desk_and_strict_hidden(self):
        from arvyx_control.api import _dashboard_hints

        self.assertEqual(_dashboard_hints(None), {"desk": None, "hidden": False, "squad": False})
        self.assertEqual(_dashboard_hints({"desk": "research", "hidden": True, "squad": True}),
                         {"desk": "research", "hidden": True, "squad": True})
        self.assertEqual(
            _dashboard_hints({"desk": "<b>research</b>", "hidden": 1, "squad": "true", "tone": "red"}),
            {"desk": None, "hidden": False, "squad": False},
        )
        self.assertEqual(_dashboard_hints(["research"]), {"desk": None, "hidden": False, "squad": False})


if __name__ == "__main__":
    unittest.main()
