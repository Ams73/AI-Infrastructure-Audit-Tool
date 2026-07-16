import subprocess
import sys
import unittest
from pathlib import Path


class CliFlowTests(unittest.TestCase):
    def test_cli_runs_with_default_settings(self):
        repo_root = Path(__file__).resolve().parents[1]
        completed = subprocess.run(
            [sys.executable, "run_audit.py", "--host", "demo", "--platform", "linux"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0)
        self.assertIn("Audit results", completed.stdout)


if __name__ == "__main__":
    unittest.main()
