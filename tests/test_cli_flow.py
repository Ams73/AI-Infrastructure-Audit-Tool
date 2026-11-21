import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from audit_tool import cli
from audit_tool.checks.linux import LINUX_CHECKS
from audit_tool.executors import ExecutionError
from tests.fakes import FIXTURE_DATE, FakeExecutor, clean_linux_responses

REPO_ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTED_LINUX = sum(1 for check in LINUX_CHECKS if check.implemented)


def linux_executor(disk_fixture="df_healthy.txt", **kwargs):
    return FakeExecutor(platform="linux", responses=clean_linux_responses(disk_fixture), **kwargs)


class CliTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch("audit_tool.checks.linux._today", return_value=FIXTURE_DATE)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, argv, executor=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            if executor is None:
                code = cli.main(argv)
            else:
                with mock.patch("audit_tool.cli.build_executor", return_value=executor) as build:
                    code = cli.main(argv)
                    self.build_kwargs = build.call_args.kwargs
        return code, stdout.getvalue(), stderr.getvalue()

    def test_clean_host_exits_zero(self):
        code, out, _ = self.run_cli(["--host", "web01", "--platform", "linux"], linux_executor())
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("Audit results for web01 (linux)", out)
        self.assertIn("[PASS   ] [high  ] LNX-OS-001", out)
        self.assertIn("[SKIPPED] [medium] LNX-CRON-001", out)

    def test_failed_check_exits_one_and_respects_fail_on(self):
        argv = ["--host", "web01", "--platform", "linux"]
        code, _, _ = self.run_cli(argv, linux_executor("df_pressure.txt"))
        self.assertEqual(code, cli.EXIT_FINDINGS)
        # The disk check is medium severity, so --fail-on high ignores it.
        code, _, _ = self.run_cli(argv + ["--fail-on", "high"], linux_executor("df_pressure.txt"))
        self.assertEqual(code, cli.EXIT_OK)

    def test_unreachable_host_exits_incomplete(self):
        executor = linux_executor(connect_error=ExecutionError("Connection refused"))
        code, out, _ = self.run_cli(["--host", "web01", "--platform", "linux", "--format", "json"], executor)
        self.assertEqual(code, cli.EXIT_INCOMPLETE)
        payload = json.loads(out)
        self.assertEqual(payload["summary"]["by_status"]["error"], IMPLEMENTED_LINUX)
        self.assertEqual(payload["summary"]["by_status"]["pass"], 0)

    def test_password_comes_from_environment(self):
        with mock.patch.dict(os.environ, {"AUDIT_PASSWORD": "s3cret"}):
            self.run_cli(["--host", "web01", "--platform", "linux"], linux_executor())
        self.assertEqual(self.build_kwargs["password"], "s3cret")

    def test_config_overrides_and_timeout(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "c.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"command_timeout": 15, "checks": {"LNX-DISK-001": {"enabled": False}}}, handle)
            code, out, _ = self.run_cli(
                ["--host", "web01", "--platform", "linux", "--config", path, "--format", "json"],
                linux_executor("df_pressure.txt"),
            )
        self.assertEqual(code, cli.EXIT_OK)
        self.assertNotIn("LNX-DISK-001", out)
        self.assertEqual(self.build_kwargs["command_timeout"], 15)

    def test_output_file_is_written(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.md")
            code, out, err = self.run_cli(
                ["--host", "web01", "--platform", "linux", "--format", "markdown", "--output", path],
                linux_executor(),
            )
            self.assertEqual(code, cli.EXIT_OK)
            self.assertEqual(out, "")
            self.assertIn("Report written", err)
            with open(path, encoding="utf-8") as handle:
                self.assertIn("# Audit Report", handle.read())

    def test_usage_errors_exit_two(self):
        code, _, err = self.run_cli(["--host", "web01"])  # remote host, no platform
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("--platform is required", err)
        code, _, err = self.run_cli(["--config", "does-not-exist.json"])
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("not found", err)

    def test_list_checks(self):
        code, out, _ = self.run_cli(["--list-checks"])
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("LNX-SSH-001", out)
        self.assertIn("[implemented]", out)
        self.assertIn("[planned]", out)

    def test_ai_dry_run_prints_payload_and_sends_nothing(self):
        with mock.patch("audit_tool.ai_summary.summarize") as summarize:
            code, out, err = self.run_cli(
                ["--host", "web01", "--platform", "linux", "--ai-dry-run"], linux_executor("df_pressure.txt")
            )
        summarize.assert_not_called()
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertIn("nothing was sent", err)
        payload = json.loads(err.split("(nothing was sent):", 1)[1])
        self.assertEqual([f["check_id"] for f in payload["findings"]], ["LNX-DISK-001"])
        self.assertNotIn("web01", err.split("(nothing was sent):", 1)[1])
        self.assertNotIn("AI summary", out)

    def test_ai_failure_warns_and_keeps_exit_code(self):
        from audit_tool.ai_summary import AISummaryError

        with mock.patch("audit_tool.ai_summary.summarize", side_effect=AISummaryError("authentication failed")):
            code, out, err = self.run_cli(
                ["--host", "web01", "--platform", "linux", "--ai-summary"], linux_executor("df_pressure.txt")
            )
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertIn("warning: AI summary skipped: authentication failed", err)
        self.assertIn("LNX-DISK-001", out)

    def test_unexpected_ai_error_never_loses_the_report(self):
        with mock.patch("audit_tool.ai_summary.summarize", side_effect=RuntimeError("bug")):
            code, out, err = self.run_cli(
                ["--host", "web01", "--platform", "linux", "--ai-summary"], linux_executor()
            )
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("unexpected error", err)
        self.assertIn("LNX-SSH-001", out)

    def test_ai_summary_options_are_passed_through(self):
        from audit_tool.ai_summary import AISummary

        summary = AISummary("All good.", "low", [], [], model="claude-opus-5-5")
        with mock.patch("audit_tool.ai_summary.summarize", return_value=summary) as summarize:
            code, out, _ = self.run_cli(
                [
                    "--host", "web01", "--platform", "linux", "--ai-summary", "--ai-effort", "high",
                    "--ai-evidence", "none", "--ai-redact", "Acme", "--ai-model", "claude-sonnet-5-5",
                ],
                linux_executor(),
            )
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("AI summary by claude-opus-5-5", out)
        kwargs = summarize.call_args.kwargs
        self.assertEqual(
            (kwargs["model"], kwargs["effort"], kwargs["include_evidence"], kwargs["redact_terms"]),
            ("claude-sonnet-5-5", "high", False, ["Acme"]),
        )
        self.assertIn("web01", kwargs["hosts"])

    def test_entry_point_script_runs(self):
        completed = subprocess.run(
            [sys.executable, "run_audit.py", "--list-checks"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("WIN-FW-001", completed.stdout)


if __name__ == "__main__":
    unittest.main()
