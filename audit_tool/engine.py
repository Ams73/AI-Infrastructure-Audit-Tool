from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


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
    def __init__(self, checks: List[Check], remote_executor: Optional[object] = None):
        self.checks = checks
        self.remote_executor = remote_executor

    def run(self, hostname: str, platform: str) -> List[Finding]:
        findings = []
        for check in self.checks:
            if check.platform == platform:
                finding = check.run(hostname)
                if self.remote_executor is not None:
                    finding.description = f"{finding.description} | remote output: {self.remote_executor.run_command('echo connected')}"
                findings.append(finding)
        return findings


def build_default_checks() -> List[Check]:
    from audit_tool.registry import build_registry

    return build_registry().get_all()


def build_checks_from_config(config_path: str | None = None) -> List[Check]:
    if not config_path:
        return build_default_checks()

    path = Path(config_path)
    if not path.exists():
        return build_default_checks()

    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    checks = payload.get("checks", [])
    return [
        Check(
            name=item.get("name", "Unnamed check"),
            platform=item.get("platform", "linux"),
            description=item.get("description", ""),
            severity=item.get("severity", "medium"),
        )
        for item in checks
    ]
