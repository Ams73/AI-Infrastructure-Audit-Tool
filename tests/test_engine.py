import json
import os
import tempfile
import unittest

from audit_tool.engine import AuditEngine, build_default_checks, build_checks_from_config


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

    def test_build_checks_from_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = os.path.join(tmpdir, "config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "checks": [
                            {"name": "Custom Linux Check", "platform": "linux", "description": "Example", "severity": "high"}
                        ]
                    },
                    handle,
                )

            checks = build_checks_from_config(config_path)
            self.assertEqual(len(checks), 1)
            self.assertEqual(checks[0].name, "Custom Linux Check")


if __name__ == "__main__":
    unittest.main()
