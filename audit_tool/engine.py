from __future__ import annotations

import logging
from typing import Iterable, List

from audit_tool.checks import Check
from audit_tool.executors import Executor
from audit_tool.models import Finding, Status

log = logging.getLogger(__name__)


class AuditEngine:
    """Runs the enabled checks for the executor's platform against one host."""

    def __init__(self, checks: Iterable[Check], command_timeout: int = 60) -> None:
        self.checks = list(checks)
        self.command_timeout = command_timeout

    def applicable_checks(self, platform: str) -> List[Check]:
        return [check for check in self.checks if check.platform == platform and check.enabled]

    def run(self, executor: Executor, hostname: str) -> List[Finding]:
        checks = self.applicable_checks(executor.platform)
        implemented = [check for check in checks if check.implemented]

        if implemented:
            try:
                executor.connect()
            except Exception as exc:
                # Connect once up front: if the host is unreachable, report every
                # check as ERROR instead of retrying the connection per check.
                log.error("Could not connect to %s: %s", hostname, exc)
                return [
                    check.make_finding(hostname, Status.ERROR, f"Could not connect to host: {exc}")
                    if check.implemented
                    else check.run(executor, hostname)
                    for check in checks
                ]

        findings = []
        for check in checks:
            log.info("Running %s (%s)", check.id, check.name)
            findings.append(check.run(executor, hostname, timeout=self.command_timeout))
        return findings
