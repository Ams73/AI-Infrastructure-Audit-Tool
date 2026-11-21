import unittest

from audit_tool.checks.windows import (
    DEFENDER_COMMAND,
    FIREWALL_COMMAND,
    WINDOWS_CHECKS,
    evaluate_defender,
    evaluate_firewall,
)
from audit_tool.models import CommandResult, Status
from tests.fakes import FakeExecutor, fixture, ok

FIREWALL_CHECK = next(c for c in WINDOWS_CHECKS if c.id == "WIN-FW-001")
DEFENDER_CHECK = next(c for c in WINDOWS_CHECKS if c.id == "WIN-DEF-001")


class FirewallTests(unittest.TestCase):
    def test_all_profiles_enabled_passes(self):
        evaluation = evaluate_firewall(ok(fixture("win_firewall_enabled.json")), {})
        self.assertEqual(evaluation.status, Status.PASS)
        self.assertEqual(len(evaluation.evidence.splitlines()), 3)

    def test_disabled_profile_fails(self):
        evaluation = evaluate_firewall(ok(fixture("win_firewall_public_disabled.json")), {})
        self.assertEqual(evaluation.status, Status.FAIL)
        self.assertIn("Public: enabled=False", evaluation.evidence)
        self.assertIn("Private: enabled=True, default inbound=Allow -> inbound traffic allowed", evaluation.evidence)

    def test_single_profile_object_is_accepted(self):
        output = ok('{"Name":"Public","Enabled":"True","DefaultInboundAction":"Block"}')
        self.assertEqual(evaluate_firewall(output, {}).status, Status.PASS)

    def test_cmdlet_failure_is_error(self):
        executor = FakeExecutor(
            platform="windows",
            responses={FIREWALL_COMMAND: CommandResult(1, "", "Get-NetFirewallProfile : Access is denied.")},
        )
        finding = FIREWALL_CHECK.run(executor, "win01")
        self.assertEqual(finding.status, Status.ERROR)
        self.assertIn("Access is denied", finding.evidence)


class DefenderTests(unittest.TestCase):
    def test_healthy_defender_passes(self):
        evaluation = evaluate_defender(ok(fixture("win_defender_healthy.json")), DEFENDER_CHECK.params)
        self.assertEqual(evaluation.status, Status.PASS)

    def test_realtime_protection_off_fails(self):
        evaluation = evaluate_defender(ok(fixture("win_defender_degraded.json")), DEFENDER_CHECK.params)
        self.assertEqual(evaluation.status, Status.FAIL)
        self.assertIn("RealTimeProtectionEnabled = False  <-- FAIL", evaluation.evidence)
        self.assertIn("12 days (max 3)  <-- WARN", evaluation.evidence)

    def test_stale_signatures_warn(self):
        output = ok(
            '{"AMServiceEnabled":true,"AntivirusEnabled":true,'
            '"RealTimeProtectionEnabled":true,"AntivirusSignatureAge":5}'
        )
        self.assertEqual(evaluate_defender(output, {"max_signature_age_days": 3}).status, Status.WARN)
        self.assertEqual(evaluate_defender(output, {"max_signature_age_days": 7}).status, Status.PASS)

    def test_invalid_json_is_error(self):
        executor = FakeExecutor(platform="windows", responses={DEFENDER_COMMAND: ok("not json")})
        self.assertEqual(DEFENDER_CHECK.run(executor, "win01").status, Status.ERROR)


if __name__ == "__main__":
    unittest.main()
