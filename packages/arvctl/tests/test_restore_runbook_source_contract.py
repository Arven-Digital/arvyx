"""Read-only source contracts; no application imports or process execution."""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]


class RestoreRunbookSourceContractTests(unittest.TestCase):
    def test_each_maintenance_example_exports_deployment_project(self):
        guide = (ROOT / "docs/vps-deployment.md").read_text()
        blocks = re.findall(r"```bash\n(.*?)```", guide, re.S)
        for operation in ("backup", "restore"):
            command = f'python3 scripts/backup_restore.py --project "$COMPOSE_PROJECT_NAME" {operation}'
            matching = [block for block in blocks if command in block]
            self.assertEqual(len(matching), 1)
            self.assertIn("set -a; . ./.env; set +a", matching[0].split(command)[0])
            self.assertNotIn("--project arvyx", matching[0])
        tree = ast.parse((ROOT / "scripts/backup_restore.py").read_text())
        defaults = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument"
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value == "--project"]
        self.assertEqual(len(defaults), 1)
        default = next(item.value for item in defaults[0].keywords if item.arg == "default")
        self.assertEqual(ast.dump(default), ast.dump(ast.parse('os.environ.get("COMPOSE_PROJECT_NAME", "arvyx")', mode="eval").body))

    def test_recovery_docs_preserve_authority_and_fence(self):
        for path in ("docs/vps-deployment.md", "templates/private-ops-backup-restore.example.md"):
            if not (ROOT / path).is_file():
                self.skipTest(f"{path} is not part of this checkout (public candidate)")
            text = " ".join((ROOT / path).read_text().split())
            for phrase in ("Before pointer commit", "After pointer commit", "network_mode: none",
                           "acknowledged writes", "admission fence", "both volumes",
                           "VolumePointerReconciliationRequired", "cleanup_failures", "restart_failed",
                           "isolate the service immediately"):
                with self.subTest(path=path, phrase=phrase):
                    self.assertIn(phrase, text)
        drill = " ".join((ROOT / "docs/vps-deployment.md").read_text().split("### Restore drill")[1].split("## Upgrade")[0].split())
        self.assertIn("candidate pointer remains authoritative", drill)
        self.assertIn("automatic rollback and candidate deletion are forbidden", drill)
        self.assertIn("Do not repoint `.env` to or restart the previous volume", drill)
        self.assertNotIn("ephemeral loopback port", drill)
        self.assertIn("`docker exec`", drill)

    def test_postcommit_branch_has_no_old_restart_or_deletion(self):
        tree = ast.parse((ROOT / "scripts/backup_restore.py").read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_restore_private")
        branch = next(node for node in ast.walk(function) if isinstance(node, ast.If)
                      and ast.dump(node.test) == ast.dump(ast.parse("pointer_committed or admission_started", mode="eval").body))
        constants = [node.value for statement in branch.body for node in ast.walk(statement)
                     if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        self.assertIn("stop", constants)
        self.assertIn("post-commit admission fence", constants)
        self.assertNotIn("up", constants)
        self.assertNotIn("rm", constants)
        self.assertNotIn("down", constants)
        calls = [node for statement in branch.body for node in ast.walk(statement) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(call.func, ast.Name) and call.func.id in
                             {"_atomic_update_active_volume", "_rollback_active_volume_pointer"} for call in calls))
        self.assertTrue(any(isinstance(statement, ast.Raise) for statement in branch.body))


if __name__ == "__main__":
    unittest.main()
