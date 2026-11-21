import json
import os
import tempfile
import unittest

from audit_tool.checks import BUILTIN_CHECKS
from audit_tool.config import ConfigError, apply_config, load_config

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def write(self, payload):
        path = os.path.join(self.tmpdir.name, "config.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(payload if isinstance(payload, str) else json.dumps(payload))
        return path

    def apply(self, payload):
        return {c.id: c for c in apply_config(BUILTIN_CHECKS, load_config(self.write(payload)))}

    def test_sample_config_is_valid(self):
        config = load_config(os.path.join(REPO_ROOT, "sample_config.json"))
        apply_config(BUILTIN_CHECKS, config)

    def test_overrides_are_applied(self):
        checks = self.apply(
            {
                "checks": {
                    "LNX-DISK-001": {"params": {"warn_percent": 70}},
                    "WIN-DEF-001": {"severity": "high"},
                    "LNX-CRON-001": {"enabled": False},
                }
            }
        )
        self.assertEqual(dict(checks["LNX-DISK-001"].params), {"warn_percent": 70, "fail_percent": 90})
        self.assertEqual(checks["WIN-DEF-001"].severity, "high")
        self.assertFalse(checks["LNX-CRON-001"].enabled)
        self.assertTrue(checks["LNX-SSH-001"].enabled)

    def test_missing_file_is_an_error(self):
        with self.assertRaises(ConfigError):
            load_config(os.path.join(self.tmpdir.name, "missing.json"))

    def test_invalid_inputs_are_rejected(self):
        bad_configs = [
            "{not json",
            {"checks": [{"name": "legacy list format"}]},
            {"unknown": 1},
            {"command_timeout": 0},
            {"checks": {"LNX-NOPE-001": {}}},
            {"checks": {"LNX-SSH-001": {"enabeld": False}}},
            {"checks": {"LNX-SSH-001": {"severity": "critical"}}},
            {"checks": {"LNX-SSH-001": {"enabled": "no"}}},
            {"checks": {"LNX-DISK-001": {"params": {"warn_pct": 70}}}},
        ]
        for payload in bad_configs:
            with self.subTest(payload=payload), self.assertRaises(ConfigError):
                self.apply(payload)


if __name__ == "__main__":
    unittest.main()
