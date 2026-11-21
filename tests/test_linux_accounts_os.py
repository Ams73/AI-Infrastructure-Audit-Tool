"""Tests for LNX-OS-001, LNX-ACCT-001 and LNX-SUDO-001.

Fixtures named *_ubuntu* / *_clean / *_default were recorded from real Ubuntu
systems; *_risky fixtures are synthetic and model common misconfigurations.
"""
import unittest
from datetime import date
from unittest import mock

from audit_tool.checks.linux import (
    ACCOUNTS_COMMAND,
    LINUX_CHECKS,
    SUDOERS_COMMAND,
    evaluate_accounts,
    evaluate_disk,
    evaluate_os_release,
    evaluate_sudoers,
)
from audit_tool.models import Status
from tests.fakes import FakeExecutor, fixture, ok

CHECKS = {check.id: check for check in LINUX_CHECKS}
OS_PARAMS = CHECKS["LNX-OS-001"].params
TODAY = date(2026, 11, 22)


def os_release(**fields):
    return ok("\n".join(f'{key}="{value}"' for key, value in fields.items()) + "\nKERNEL=6.1.0\n")


@mock.patch("audit_tool.checks.linux._today", return_value=TODAY)
class OsSupportTests(unittest.TestCase):
    def test_supported_release_passes(self, _):
        evaluation = evaluate_os_release(ok(fixture("os_release_ubuntu2204.txt")), OS_PARAMS)
        self.assertEqual(evaluation.status, Status.PASS)
        self.assertIn("Ubuntu 22.04", evaluation.evidence)
        self.assertIn("Supported until 2027-06-30", evaluation.evidence)

    def test_end_of_life_release_fails(self, _):
        evaluation = evaluate_os_release(ok(fixture("os_release_ubuntu2004.txt")), OS_PARAMS)
        self.assertEqual(evaluation.status, Status.FAIL)
        self.assertIn("support ended on 2025-05-31", evaluation.evidence)

    def test_release_near_end_of_life_warns(self, _):
        params = {"warn_days_before_eol": 365, "extra_eol_dates": {}}
        evaluation = evaluate_os_release(ok(fixture("os_release_ubuntu2204.txt")), params)
        self.assertEqual(evaluation.status, Status.WARN)

    def test_rhel_family_uses_major_version(self, _):
        evaluation = evaluate_os_release(os_release(ID="rocky", VERSION_ID="8.10"), OS_PARAMS)
        self.assertEqual(evaluation.status, Status.PASS)
        self.assertIn("2029-05-31", evaluation.evidence)
        evaluation = evaluate_os_release(os_release(ID="centos", VERSION_ID="7"), OS_PARAMS)
        self.assertEqual(evaluation.status, Status.FAIL)

    def test_unknown_release_warns_and_can_be_added_via_params(self, _):
        output = os_release(ID="ubuntu", VERSION_ID="26.10", PRETTY_NAME="Ubuntu 26.10")
        self.assertEqual(evaluate_os_release(output, OS_PARAMS).status, Status.WARN)
        params = {"warn_days_before_eol": 180, "extra_eol_dates": {"ubuntu:26.10": "2027-07-31"}}
        self.assertEqual(evaluate_os_release(output, params).status, Status.PASS)

    def test_rolling_release_without_version_warns(self, _):
        self.assertEqual(evaluate_os_release(os_release(ID="arch"), OS_PARAMS).status, Status.WARN)

    def test_missing_os_release_is_error(self, _):
        executor = FakeExecutor(responses={CHECKS["LNX-OS-001"].command: ok("KERNEL=6.1.0\n")})
        self.assertEqual(CHECKS["LNX-OS-001"].run(executor, "h").status, Status.ERROR)


class AccountTests(unittest.TestCase):
    def test_clean_system_passes(self):
        self.assertEqual(evaluate_accounts(ok(fixture("accounts_clean.txt")), {}).status, Status.PASS)

    def test_extra_uid0_and_empty_password_fail(self):
        evaluation = evaluate_accounts(ok("uid0:root\nuid0:toor\nemptypw:guest\nshadow:ok\n"), {})
        self.assertEqual(evaluation.status, Status.FAIL)
        self.assertIn("other than root have UID 0: toor", evaluation.evidence)
        self.assertIn("empty password: guest", evaluation.evidence)
        self.assertEqual(set(evaluation.accounts), {"root", "toor", "guest"})

    def test_unreadable_shadow_warns(self):
        evaluation = evaluate_accounts(ok("uid0:root\nshadow:unreadable\n"), {})
        self.assertEqual(evaluation.status, Status.WARN)
        self.assertIn("run as root", evaluation.evidence)

    def test_missing_passwd_output_is_error(self):
        executor = FakeExecutor(responses={ACCOUNTS_COMMAND: ok("")})
        self.assertEqual(CHECKS["LNX-ACCT-001"].run(executor, "h").status, Status.ERROR)


class SudoersTests(unittest.TestCase):
    PARAMS = CHECKS["LNX-SUDO-001"].params

    def test_stock_ubuntu_sudoers_passes(self):
        evaluation = evaluate_sudoers(ok(fixture("sudoers_ubuntu_default.txt")), self.PARAMS)
        self.assertEqual(evaluation.status, Status.PASS)
        self.assertIn("/etc/sudoers", evaluation.evidence)

    def test_risky_rules_are_classified(self):
        evidence = evaluate_sudoers(ok(fixture("sudoers_risky.txt")), self.PARAMS).evidence
        fails = [line for line in evidence.splitlines() if line.startswith("FAIL")]
        warns = [line for line in evidence.splitlines() if line.startswith("WARN")]

        self.assertTrue(any("authentication disabled" in line and "backup" in line for line in fails))
        self.assertTrue(any("ubuntu ALL=(ALL) NOPASSWD:ALL" in line for line in fails))
        self.assertTrue(any("%ops" in line for line in fails))  # SETENV: tag doesn't hide ALL
        self.assertTrue(any("ansible" in line for line in fails))
        # Continuation lines are joined; specific commands are a warning, not a failure.
        self.assertTrue(any("deploy" in line and "systemctl status app" in line for line in warns))
        # ALL after a PASSWD: tag still needs a password.
        self.assertTrue(any("jenkins" in line for line in warns))
        self.assertTrue(any("/etc/sudoers.d/legacy" in line for line in warns))
        self.assertNotIn("commented out", evidence)
        self.assertEqual(len(fails), 4)

    def test_principals_are_reported_for_redaction(self):
        evaluation = evaluate_sudoers(ok(fixture("sudoers_risky.txt")), self.PARAMS)
        self.assertEqual(
            set(evaluation.accounts), {"backup", "ubuntu", "deploy", "jenkins", "%ops", "ansible"}
        )

    def test_allowed_principals_are_accepted(self):
        params = {"allowed_nopasswd": ["ansible", "ubuntu", "%ops"]}
        evidence = evaluate_sudoers(ok(fixture("sudoers_risky.txt")), params).evidence
        self.assertIn("allowed: /etc/sudoers.d/deploy: ansible", evidence)
        fails = [line for line in evidence.splitlines() if line.startswith("FAIL")]
        self.assertEqual(len(fails), 1)  # only Defaults:backup !authenticate remains

    def test_unreadable_main_file_is_error_with_root_hint(self):
        executor = FakeExecutor(responses={SUDOERS_COMMAND: ok("# unreadable: /etc/sudoers\n")})
        finding = CHECKS["LNX-SUDO-001"].run(executor, "h")
        self.assertEqual(finding.status, Status.ERROR)
        self.assertIn("Hint: this check needs administrator", finding.evidence)


class DiskReadOnlyTests(unittest.TestCase):
    def test_read_only_mounts_are_ignored(self):
        # Recorded on WSL Ubuntu: a read-only kernel-headers image is 100% full.
        evaluation = evaluate_disk(ok(fixture("df_wsl_readonly_mounts.txt")), CHECKS["LNX-DISK-001"].params)
        self.assertEqual(evaluation.status, Status.PASS)
        self.assertIn("Ignored read-only mounts:", evaluation.evidence)
        self.assertNotIn("100% used", evaluation.evidence)

    def test_octal_escaped_mount_points_are_decoded(self):
        output = ok(
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/sr0 1000 1000 0 100% /media/install disk\n"
            "/dev/sda1 1000 100 900 10% /\n"
            "__INODES__\n__READONLY__\n/media/install\\040disk\n"
        )
        self.assertEqual(evaluate_disk(output, CHECKS["LNX-DISK-001"].params).status, Status.PASS)


if __name__ == "__main__":
    unittest.main()
