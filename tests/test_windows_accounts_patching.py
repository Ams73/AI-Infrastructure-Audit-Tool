"""Tests for WIN-ADM-001, WIN-UPD-001 and WIN-BL-001.

The PowerShell commands were run on a real Windows 11 host to confirm the
output shape; fixtures are synthetic so they contain no real account data.
"""
import unittest

from audit_tool.checks.windows import (
    BITLOCKER_COMMAND,
    UPDATES_COMMAND,
    WINDOWS_CHECKS,
    evaluate_admins,
    evaluate_bitlocker,
    evaluate_updates,
)
from audit_tool.models import CommandResult, Status
from tests.fakes import FakeExecutor, fixture, ok

CHECKS = {check.id: check for check in WINDOWS_CHECKS}


class AdministratorsTests(unittest.TestCase):
    PARAMS = CHECKS["WIN-ADM-001"].params

    def test_clean_configuration_passes(self):
        evaluation = evaluate_admins(ok(fixture("win_admins_clean.json")), self.PARAMS)
        self.assertEqual(evaluation.status, Status.PASS)
        self.assertIn("Administrators group (2 members)", evaluation.evidence)

    def test_risky_configuration(self):
        evaluation = evaluate_admins(ok(fixture("win_admins_risky.json")), self.PARAMS)
        self.assertEqual(evaluation.status, Status.FAIL)
        evidence = evaluation.evidence
        self.assertIn("WARN: 4 members exceeds max_members (3)", evidence)
        self.assertIn("WARN: built-in Administrator account 'Administrator' is enabled", evidence)
        self.assertIn("FAIL: enabled administrator account 'helpdesk' does not require a password", evidence)
        self.assertIn("WARN: enabled account 'kiosk' does not require a password", evidence)
        self.assertTrue({"helpdesk", "kiosk", "svc_backup", "Domain Admins"} <= set(evaluation.accounts))
        self.assertNotIn("Guest", evidence.split("members):", 1)[1].split("WARN", 1)[0])  # disabled: ignored

    def test_allowed_members_list(self):
        allowed = ["WIN01\\Administrator", "contoso\\domain admins"]  # case-insensitive
        evaluation = evaluate_admins(ok(fixture("win_admins_risky.json")), {"allowed_members": allowed, "max_members": 3})
        self.assertIn("FAIL: members not in allowed_members: WIN01\\helpdesk, CONTOSO\\svc_backup", evaluation.evidence)
        self.assertNotIn("max_members", evaluation.evidence)

    def test_single_member_object_is_accepted(self):
        output = ok('{"members":{"Name":"WIN01\\\\localadmin","SID":"S-1-5-21-1-2-3-1001"},"users":[]}')
        self.assertEqual(evaluate_admins(output, self.PARAMS).status, Status.PASS)


class PatchCurrencyTests(unittest.TestCase):
    PARAMS = CHECKS["WIN-UPD-001"].params

    def test_recent_updates_pass(self):
        evaluation = evaluate_updates(ok(fixture("win_updates_current.json")), self.PARAMS)
        self.assertEqual(evaluation.status, Status.PASS)
        self.assertIn("KB5132061 installed 2026-11-14 (8 days ago)", evaluation.evidence)

    def test_stale_updates_and_pending_reboot(self):
        evaluation = evaluate_updates(ok(fixture("win_updates_stale.json")), self.PARAMS)
        self.assertEqual(evaluation.status, Status.FAIL)
        self.assertIn("more than 60 days", evaluation.evidence)
        self.assertIn("reboot is pending", evaluation.evidence)

    def test_thresholds_from_params(self):
        output = ok(fixture("win_updates_current.json"))
        self.assertEqual(evaluate_updates(output, {"warn_days": 5, "fail_days": 30}).status, Status.WARN)

    def test_no_dated_updates_is_error(self):
        executor = FakeExecutor(
            platform="windows", responses={UPDATES_COMMAND: ok('{"hotfixes":[],"reboot_pending":false}')}
        )
        self.assertEqual(CHECKS["WIN-UPD-001"].run(executor, "h").status, Status.ERROR)


class BitLockerTests(unittest.TestCase):
    PARAMS = CHECKS["WIN-BL-001"].params

    def test_protected_volumes_pass(self):
        evaluation = evaluate_bitlocker(ok(fixture("win_bitlocker_protected.json")), self.PARAMS)
        self.assertEqual(evaluation.status, Status.PASS)

    def test_unprotected_os_volume_fails_and_data_volume_warns(self):
        evaluation = evaluate_bitlocker(ok(fixture("win_bitlocker_os_off.json")), self.PARAMS)
        self.assertEqual(evaluation.status, Status.FAIL)
        self.assertIn("C: (OperatingSystem): protection Off, FullyDecrypted, 0% encrypted  <-- FAIL", evaluation.evidence)
        self.assertIn("D: (Data): protection Off, FullyDecrypted, 0% encrypted  <-- WARN", evaluation.evidence)

    def test_data_volumes_can_be_required(self):
        output = ok(
            '[{"MountPoint":"C:","VolumeType":"OperatingSystem","ProtectionStatus":"On"},'
            '{"MountPoint":"D:","VolumeType":"Data","ProtectionStatus":"Off"}]'
        )
        self.assertEqual(evaluate_bitlocker(output, {"require_data_volumes": False}).status, Status.WARN)
        self.assertEqual(evaluate_bitlocker(output, {"require_data_volumes": True}).status, Status.FAIL)

    def test_access_denied_is_error_with_admin_hint(self):
        # Recorded shape of the real failure from a non-elevated shell.
        stderr = "Get-CimInstance : Access denied \nAt C:\\WINDOWS\\system32\\...\\BitLocker.psm1:144 char:13"
        executor = FakeExecutor(platform="windows", responses={BITLOCKER_COMMAND: CommandResult(1, "", stderr)})
        finding = CHECKS["WIN-BL-001"].run(executor, "h")
        self.assertEqual(finding.status, Status.ERROR)
        self.assertIn("Hint: this check needs administrator", finding.evidence)
        self.assertEqual(finding.evidence.count("Access denied"), 1)


if __name__ == "__main__":
    unittest.main()
