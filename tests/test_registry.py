import unittest

from audit_tool.registry import CheckRegistry, build_registry


class RegistryTests(unittest.TestCase):
    def test_registry_registers_and_filters_checks(self):
        registry = CheckRegistry()
        registry.register(
            type("CheckStub", (), {"name": "demo", "platform": "linux", "description": "x", "severity": "high"})()
        )
        self.assertEqual(len(registry.get_all()), 1)
        self.assertEqual(len(registry.get_by_platform("linux")), 1)

    def test_build_registry_contains_linux_and_windows_checks(self):
        registry = build_registry()
        platforms = {check.platform for check in registry.get_all()}
        self.assertIn("linux", platforms)
        self.assertIn("windows", platforms)
        self.assertGreaterEqual(len(registry.get_by_platform("linux")), 5)
        self.assertGreaterEqual(len(registry.get_by_platform("windows")), 5)


if __name__ == "__main__":
    unittest.main()
