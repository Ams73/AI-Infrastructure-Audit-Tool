"""The Check type and helpers for writing evaluators."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, Iterable, Mapping, Optional

from audit_tool.executors import ExecutionError, Executor
from audit_tool.models import PLATFORMS, CommandResult, Evaluation, Finding, Severity, Status, utc_now_iso

Evaluator = Callable[[CommandResult, Mapping[str, Any]], Evaluation]

_EVIDENCE_LIMIT = 2000
_PERMISSION_ERROR = re.compile(r"access (is )?denied|permission denied|must run as root|requires? root", re.I)


class CheckError(Exception):
    """Raised by an evaluator when output cannot be interpreted. Becomes ERROR."""


@dataclass(frozen=True)
class Check:
    """One audit check.

    A check runs `command` on the target and passes the result plus its
    `params` (tunable thresholds, overridable from config) to `evaluate`.
    A check with no command is a placeholder and reports SKIPPED.
    """

    id: str
    name: str
    platform: str
    severity: str
    description: str
    recommendation: str = ""
    command: Optional[str] = None
    evaluate: Optional[Evaluator] = None
    params: Mapping[str, Any] = field(default_factory=dict)
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.platform not in PLATFORMS:
            raise ValueError(f"{self.id}: invalid platform {self.platform!r}")
        if self.severity not in Severity.ALL:
            raise ValueError(f"{self.id}: invalid severity {self.severity!r}")
        if (self.command is None) != (self.evaluate is None):
            raise ValueError(f"{self.id}: command and evaluate must be set together")

    @property
    def implemented(self) -> bool:
        return self.command is not None

    def with_overrides(
        self,
        severity: Optional[str] = None,
        params: Optional[Mapping[str, Any]] = None,
        enabled: Optional[bool] = None,
    ) -> "Check":
        merged: Dict[str, Any] = dict(self.params)
        merged.update(params or {})
        return replace(
            self,
            severity=severity if severity is not None else self.severity,
            params=merged,
            enabled=enabled if enabled is not None else self.enabled,
        )

    def make_finding(self, host: str, status: str, evidence: str, accounts: Iterable[str] = ()) -> Finding:
        if len(evidence) > _EVIDENCE_LIMIT:
            evidence = evidence[:_EVIDENCE_LIMIT] + "\n... (truncated)"
        return Finding(
            check_id=self.id,
            name=self.name,
            host=host,
            platform=self.platform,
            severity=self.severity,
            status=status,
            description=self.description,
            evidence=evidence,
            recommendation=self.recommendation,
            timestamp=utc_now_iso(),
            accounts=sorted(set(accounts)),
        )

    def run(self, executor: Executor, host: str, timeout: int = 60) -> Finding:
        if not self.implemented:
            return self.make_finding(host, Status.SKIPPED, "Check not yet implemented.")
        try:
            result = executor.run(self.command, timeout=timeout)
        except ExecutionError as exc:
            return self.make_finding(host, Status.ERROR, f"Command execution failed: {exc}")
        except Exception as exc:  # one broken check must not abort the audit
            return self.make_finding(host, Status.ERROR, f"Unexpected executor error: {exc!r}")
        try:
            evaluation = self.evaluate(result, self.params)
        except Exception as exc:
            detail = f"Could not evaluate command output: {exc}"
            stderr = result.stderr.strip()
            if stderr and stderr[:200] not in detail:
                detail += f"\nstderr: {stderr}"
            if _PERMISSION_ERROR.search(result.stderr + result.stdout + str(exc)):
                detail += "\nHint: this check needs administrator (Windows) or root (Linux) rights."
            return self.make_finding(host, Status.ERROR, detail)
        return self.make_finding(host, evaluation.status, evaluation.evidence, evaluation.accounts)


# --- helpers for evaluators -------------------------------------------------

_STATUS_ORDER = {Status.PASS: 0, Status.SKIPPED: 0, Status.WARN: 1, Status.FAIL: 2}


def worst_status(statuses: Iterable[str]) -> str:
    """Most severe of PASS/WARN/FAIL. An empty input is a PASS."""
    worst = Status.PASS
    for status in statuses:
        if _STATUS_ORDER[status] > _STATUS_ORDER[worst]:
            worst = status
    return worst


def require_success(result: CommandResult) -> None:
    if not result.ok:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        raise CheckError(f"command exited with code {result.exit_code}: {detail[:500]}")


def parse_json_output(result: CommandResult) -> Any:
    """Parse JSON printed by a PowerShell ConvertTo-Json command."""
    require_success(result)
    text = result.stdout.strip()
    if not text:
        raise CheckError("command produced no output")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise CheckError(f"output is not valid JSON: {exc}") from exc
