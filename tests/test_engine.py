import unittest

from audit_tool.checks.base import Check, worst_status
from audit_tool.engine import AuditEngine
from audit_tool.executors import ExecutionError
from audit_tool.models import CommandResult, Evaluation, Status
from tests.fakes import FakeExecutor, ok


def _pass(result, params):
    return Evaluation(Status.PASS, result.stdout)


def _boom(result, params):
    raise RuntimeError("parser bug")


def make_check(check_id, platform="linux", command="cmd", evaluate=_pass, **kwargs):
    return Check(
        id=check_id,
        name=check_id,
        platform=platform,
        severity="medium",
        description="d",
        command=command,
        evaluate=evaluate if command else None,
        **kwargs,
    )


class CheckRunTests(unittest.TestCase):
    def test_unimplemented_check_is_skipped(self):
        finding = make_check("X", command=None).run(FakeExecutor(), "h")
        self.assertEqual(finding.status, Status.SKIPPED)

    def test_execution_error_becomes_error_status(self):
        executor = FakeExecutor(responses={"cmd": ExecutionError("timed out after 60s")})
        finding = make_check("X").run(executor, "h")
        self.assertEqual(finding.status, Status.ERROR)
        self.assertIn("timed out", finding.evidence)

    def test_unexpected_executor_exception_becomes_error(self):
        executor = FakeExecutor(responses={"cmd": KeyError("oops")})
        self.assertEqual(make_check("X").run(executor, "h").status, Status.ERROR)

    def test_evaluator_crash_becomes_error(self):
        executor = FakeExecutor(responses={"cmd": CommandResult(0, "out", "warning text")})
        finding = make_check("X", evaluate=_boom).run(executor, "h")
        self.assertEqual(finding.status, Status.ERROR)
        self.assertIn("parser bug", finding.evidence)
        self.assertIn("warning text", finding.evidence)

    def test_finding_has_full_data_model(self):
        finding = make_check("X", recommendation="fix it").run(FakeExecutor(responses={"cmd": ok("e")}), "h")
        self.assertEqual(finding.evidence, "e")
        self.assertEqual(finding.recommendation, "fix it")
        self.assertTrue(finding.timestamp.endswith("+00:00"))

    def test_long_evidence_is_truncated(self):
        executor = FakeExecutor(responses={"cmd": ok("x" * 5000)})
        self.assertIn("(truncated)", make_check("X").run(executor, "h").evidence)

    def test_invalid_definitions_are_rejected(self):
        with self.assertRaises(ValueError):
            make_check("X", platform="bsd")
        with self.assertRaises(ValueError):
            Check(id="X", name="X", platform="linux", severity="medium", description="d", command="cmd")

    def test_overrides_merge_params(self):
        check = make_check("X", params={"a": 1, "b": 2}).with_overrides(severity="high", params={"b": 3})
        self.assertEqual(dict(check.params), {"a": 1, "b": 3})
        self.assertEqual(check.severity, "high")

    def test_worst_status(self):
        self.assertEqual(worst_status([]), Status.PASS)
        self.assertEqual(worst_status([Status.PASS, Status.WARN]), Status.WARN)
        self.assertEqual(worst_status([Status.FAIL, Status.WARN]), Status.FAIL)


class AuditEngineTests(unittest.TestCase):
    def test_runs_only_enabled_checks_for_executor_platform(self):
        checks = [
            make_check("L1"),
            make_check("W1", platform="windows"),
            make_check("L2", enabled=False),
        ]
        executor = FakeExecutor(responses={"cmd": ok("fine")})
        findings = AuditEngine(checks).run(executor, "web01")
        self.assertEqual([f.check_id for f in findings], ["L1"])
        self.assertEqual(findings[0].host, "web01")

    def test_connection_failure_marks_checks_error_without_running_commands(self):
        checks = [make_check("L1"), make_check("L2"), make_check("L3", command=None)]
        executor = FakeExecutor(connect_error=ExecutionError("Connection refused"))
        findings = AuditEngine(checks).run(executor, "web01")
        self.assertEqual([f.status for f in findings], [Status.ERROR, Status.ERROR, Status.SKIPPED])
        self.assertIn("Connection refused", findings[0].evidence)
        self.assertEqual(executor.commands, [])
        self.assertEqual(executor.connect_calls, 1)

    def test_no_connection_needed_when_nothing_is_implemented(self):
        executor = FakeExecutor(connect_error=ExecutionError("unreachable"))
        findings = AuditEngine([make_check("L1", command=None)]).run(executor, "h")
        self.assertEqual(findings[0].status, Status.SKIPPED)
        self.assertEqual(executor.connect_calls, 0)


if __name__ == "__main__":
    unittest.main()
