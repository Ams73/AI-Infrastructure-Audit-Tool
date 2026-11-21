import unittest

from audit_tool.checks.linux import (
    DISK_COMMAND,
    LINUX_CHECKS,
    SSHD_COMMAND,
    evaluate_disk,
    evaluate_sshd,
    parse_sshd_config,
)
from audit_tool.models import CommandResult, Status
from tests.fakes import FakeExecutor, fixture, ok

SSH_CHECK = next(c for c in LINUX_CHECKS if c.id == "LNX-SSH-001")
DISK_CHECK = next(c for c in LINUX_CHECKS if c.id == "LNX-DISK-001")


class SshHardeningTests(unittest.TestCase):
    def test_hardened_effective_config_passes(self):
        evaluation = evaluate_sshd(ok(fixture("sshd_T_hardened.txt")), SSH_CHECK.params)
        self.assertEqual(evaluation.status, Status.PASS)
        self.assertIn("Source: sshd -T", evaluation.evidence)
        self.assertIn("permitrootlogin = no", evaluation.evidence)

    def test_weak_config_fails_with_reasons(self):
        evaluation = evaluate_sshd(ok(fixture("sshd_config_weak.txt")), SSH_CHECK.params)
        self.assertEqual(evaluation.status, Status.FAIL)
        self.assertIn("PermitRootLogin allows root", evaluation.evidence)
        # PasswordAuthentication is commented out, so the OpenSSH default (yes) applies.
        self.assertIn("passwordauthentication = yes (default)", evaluation.evidence)
        self.assertIn("Include directives", evaluation.evidence)

    def test_first_value_wins_and_match_blocks_are_ignored(self):
        _, settings, has_include = parse_sshd_config(fixture("sshd_config_weak.txt"))
        self.assertEqual(settings["permitrootlogin"], "yes")
        self.assertTrue(has_include)

    def test_key_equals_value_syntax(self):
        _, settings, _ = parse_sshd_config("# source: x\nPermitRootLogin=no\nPasswordAuthentication = no\n")
        self.assertEqual(settings["permitrootlogin"], "no")
        self.assertEqual(settings["passwordauthentication"], "no")

    def test_root_key_login_warns_unless_allowed(self):
        output = ok("# source: sshd -T\npermitrootlogin prohibit-password\npasswordauthentication no\n")
        self.assertEqual(evaluate_sshd(output, {"allow_root_key_login": False}).status, Status.WARN)
        self.assertEqual(evaluate_sshd(output, {"allow_root_key_login": True}).status, Status.PASS)

    def test_no_ssh_server_is_skipped(self):
        self.assertEqual(evaluate_sshd(ok("# source: none\n"), SSH_CHECK.params).status, Status.SKIPPED)

    def test_check_runs_through_executor(self):
        executor = FakeExecutor(responses={SSHD_COMMAND: ok(fixture("sshd_T_hardened.txt"))})
        finding = SSH_CHECK.run(executor, "web01")
        self.assertEqual(finding.status, Status.PASS)
        self.assertEqual(finding.check_id, "LNX-SSH-001")
        self.assertEqual(executor.commands, [SSHD_COMMAND])

    def test_garbage_output_is_error_not_pass(self):
        executor = FakeExecutor(responses={SSHD_COMMAND: ok("bash: syntax error")})
        self.assertEqual(SSH_CHECK.run(executor, "web01").status, Status.ERROR)


class DiskUsageTests(unittest.TestCase):
    def test_healthy_disks_pass_and_pseudo_filesystems_are_ignored(self):
        evaluation = evaluate_disk(ok(fixture("df_healthy.txt")), DISK_CHECK.params)
        self.assertEqual(evaluation.status, Status.PASS)
        self.assertIn("/srv/data files space: 53% used", evaluation.evidence)
        self.assertNotIn("/snap", evaluation.evidence)
        self.assertNotIn("/dev/shm", evaluation.evidence)

    def test_space_and_inode_pressure_fail(self):
        evaluation = evaluate_disk(ok(fixture("df_pressure.txt")), DISK_CHECK.params)
        self.assertEqual(evaluation.status, Status.FAIL)
        self.assertIn("/ space: 95% used  <-- FAIL", evaluation.evidence)
        self.assertIn("/var space: 84% used  <-- WARN", evaluation.evidence)
        self.assertIn("/var inodes: 95% used  <-- FAIL", evaluation.evidence)

    def test_thresholds_come_from_params(self):
        evaluation = evaluate_disk(ok(fixture("df_healthy.txt")), {"warn_percent": 40, "fail_percent": 99})
        self.assertEqual(evaluation.status, Status.WARN)

    def test_empty_output_is_error(self):
        executor = FakeExecutor(responses={DISK_COMMAND: CommandResult(127, "", "df: not found")})
        finding = DISK_CHECK.run(executor, "web01")
        self.assertEqual(finding.status, Status.ERROR)
        self.assertIn("df: not found", finding.evidence)


if __name__ == "__main__":
    unittest.main()
