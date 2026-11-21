import unittest

from audit_tool.checks import BUILTIN_CHECKS
from audit_tool.registry import CheckRegistry, build_registry


class RegistryTests(unittest.TestCase):
    def test_builtin_registry_has_both_platforms(self):
        registry = build_registry()
        self.assertGreaterEqual(len(registry.get_by_platform("linux")), 5)
        self.assertGreaterEqual(len(registry.get_by_platform("windows")), 5)

    def test_duplicate_ids_are_rejected(self):
        registry = CheckRegistry([BUILTIN_CHECKS[0]])
        with self.assertRaises(ValueError):
            registry.register(BUILTIN_CHECKS[0])

    def test_ids_follow_convention_and_match_platform(self):
        for check in BUILTIN_CHECKS:
            self.assertRegex(check.id, r"^(LNX|WIN)-[A-Z]+-\d{3}$")
            self.assertEqual(check.id.startswith("LNX"), check.platform == "linux", check.id)

    def test_implemented_checks_have_recommendations(self):
        for check in BUILTIN_CHECKS:
            if check.implemented:
                self.assertTrue(check.recommendation, check.id)

    def test_get_by_id(self):
        registry = build_registry()
        self.assertEqual(registry.get("LNX-SSH-001").name, "SSH hardening review")
        self.assertIsNone(registry.get("NOPE"))


if __name__ == "__main__":
    unittest.main()
