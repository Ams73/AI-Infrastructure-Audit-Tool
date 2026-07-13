from __future__ import annotations

from typing import Dict, List

from audit_tool.engine import Check


class CheckRegistry:
    def __init__(self) -> None:
        self._checks: Dict[str, Check] = {}

    def register(self, check: Check) -> None:
        self._checks[check.name] = check

    def get_all(self) -> List[Check]:
        return list(self._checks.values())

    def get_by_platform(self, platform: str) -> List[Check]:
        return [check for check in self._checks.values() if check.platform == platform]


def build_registry() -> CheckRegistry:
    registry = CheckRegistry()

    linux_checks = [
        ("OS version and distribution verification", "Verify the operating system version and distribution.", "high"),
        ("SSH hardening review", "Validate SSH configuration hardening settings.", "high"),
        ("Sudoers misconfiguration review", "Check for unsafe sudoers rules and NOPASSWD usage.", "high"),
        ("World-writable files review", "Identify world-writable files and directories that may be risky.", "medium"),
        ("Disk space and inode usage review", "Check for low disk space and inode exhaustion risk.", "medium"),
        ("Service status review", "Review critical services for unexpected disabled or failed states.", "medium"),
        ("Cron job integrity review", "Inspect cron jobs for unusual or risky scheduled tasks.", "medium"),
    ]

    windows_checks = [
        ("Pending security updates review", "Review pending security updates on the host.", "high"),
        ("Firewall profile status review", "Verify firewall profiles and enabled protections.", "medium"),
        ("Local administrator account review", "Review local administrator accounts and privilege exposure.", "high"),
        ("BitLocker protection review", "Verify BitLocker protection is enabled for relevant drives.", "medium"),
        ("Windows Defender status review", "Confirm Windows Defender is enabled and healthy.", "medium"),
        ("Enabled services review", "Inspect enabled services for unexpected or risky startup state.", "medium"),
        ("Scheduled tasks review", "Look for suspicious or unnecessary scheduled tasks.", "medium"),
    ]

    for name, description, severity in linux_checks:
        registry.register(Check(name=name, platform="linux", description=description, severity=severity))

    for name, description, severity in windows_checks:
        registry.register(Check(name=name, platform="windows", description=description, severity=severity))

    return registry
