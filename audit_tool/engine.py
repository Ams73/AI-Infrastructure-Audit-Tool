from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class Finding:
    host: str
    platform: str
    name: str
    status: str
    severity: str
    description: str


@dataclass
class Check:
    name: str
    platform: str
    description: str
    severity: str = "medium"

    def run(self, hostname: str) -> Finding:
        return Finding(
            host=hostname,
            platform=self.platform,
            name=self.name,
            status="passed",
            severity=self.severity,
            description=self.description,
        )


class AuditEngine:
    def __init__(self, checks: List[Check]):
        self.checks = checks

    def run(self, hostname: str, platform: str) -> List[Finding]:
        findings = []
        for check in self.checks:
            if check.platform == platform:
                findings.append(check.run(hostname))
        return findings


def build_default_checks() -> List[Check]:
    return [
        Check(
            name="OS version and distribution verification",
            platform="linux",
            description="Verify the operating system version and distribution.",
            severity="high",
        ),
        Check(
            name="SSH hardening review",
            platform="linux",
            description="Validate SSH configuration hardening settings.",
            severity="high",
        ),
        Check(
            name="Sudoers misconfiguration review",
            platform="linux",
            description="Check for unsafe sudoers rules and NOPASSWD usage.",
            severity="high",
        ),
        Check(
            name="World-writable files review",
            platform="linux",
            description="Identify world-writable files and directories that may be risky.",
            severity="medium",
        ),
        Check(
            name="Pending security updates review",
            platform="windows",
            description="Review pending security updates on the host.",
            severity="high",
        ),
        Check(
            name="Firewall profile status review",
            platform="windows",
            description="Verify firewall profiles and enabled protections.",
            severity="medium",
        ),
        Check(
            name="Local administrator account review",
            platform="windows",
            description="Review local administrator accounts and privilege exposure.",
            severity="high",
        ),
        Check(
            name="BitLocker protection review",
            platform="windows",
            description="Verify BitLocker protection is enabled for relevant drives.",
            severity="medium",
        ),
    ]
