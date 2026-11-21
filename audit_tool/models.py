"""Core data types shared by checks, executors, the engine and reports."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict

PLATFORMS = ("linux", "windows")


class Status:
    """Outcome of a single check.

    ERROR means the check could not determine an answer (connection failure,
    command failure, unparseable output). It must never be treated as a pass.
    """

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"

    ALL = (PASS, WARN, FAIL, ERROR, SKIPPED)


class Severity:
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    ALL = (HIGH, MEDIUM, LOW)
    RANK = {LOW: 1, MEDIUM: 2, HIGH: 3}


@dataclass(frozen=True)
class CommandResult:
    """Raw result of running one command on a target."""

    exit_code: int
    stdout: str
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@dataclass(frozen=True)
class Evaluation:
    """What a check's evaluator concluded from a CommandResult."""

    status: str
    evidence: str

    def __post_init__(self) -> None:
        if self.status not in Status.ALL:
            raise ValueError(f"Invalid status {self.status!r}")


@dataclass
class Finding:
    """One check's result for one host. Matches the data model in PLAN.md."""

    check_id: str
    name: str
    host: str
    platform: str
    severity: str
    status: str
    description: str
    evidence: str
    recommendation: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
