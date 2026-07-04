import unittest

from audit_tool.engine import AuditEngine, build_default_checks


class AuditEngineTests(unittest.TestCase):
    def test_default_checks_include_linux_and_windows_checks(self):
        checks = build_default_checks()

        self.assertGreaterEqual(len(checks), 3)
        platforms = {check.platform for check in checks}
        self.assertIn("linux", platforms)
        self.assertIn("windows", platforms)

    def test_engine_runs_checks_and_returns_findings(self):
        engine = AuditEngine(build_default_checks())
        findings = engine.run(hostname="demo-host", platform="linux")

        self.assertTrue(findings)
        self.assertEqual(findings[0].host, "demo-host")
        self.assertEqual(findings[0].platform, "linux")


if __name__ == "__main__":
    unittest.main()
