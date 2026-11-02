from __future__ import annotations

from pathlib import Path
import unittest

from arvyx_control.vault import run_demo


FIXTURE_VAULT = Path(__file__).resolve().parents[3] / "fixtures" / "synthetic-vault"


class DemoSpineTests(unittest.TestCase):
    def test_demo_proves_thread_health_and_notify_loop(self) -> None:
        result = run_demo(vault=FIXTURE_VAULT)
        self.assertTrue(result.ok)
        checks = {str(check["name"]): check for check in result.checks}

        for name in (
            "recall",
            "context_pack",
            "control_tasks",
            "control_api",
            "thread_war_room_loop",
            "thread_read_all",
            "health_daily_handoff",
            "health_notify_loop",
        ):
            with self.subTest(name=name):
                self.assertIn(name, checks)
                self.assertTrue(checks[name]["ok"])

        self.assertEqual(checks["health_daily_handoff"]["created"], 4)
        self.assertEqual(checks["health_daily_handoff"]["skipped_on_rerun"], 4)
        self.assertEqual(checks["health_notify_loop"]["candidates"], 4)
        self.assertEqual(checks["health_notify_loop"]["deliveries"], 4)
        self.assertEqual(checks["health_notify_loop"]["notification_events"], 4)


if __name__ == "__main__":
    unittest.main()
