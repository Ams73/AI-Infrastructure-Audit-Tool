"""Test doubles: an executor that replays recorded command output."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Union

from audit_tool.executors import ExecutionError, Executor
from audit_tool.models import CommandResult

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def ok(stdout: str) -> CommandResult:
    return CommandResult(exit_code=0, stdout=stdout, stderr="")


Response = Union[CommandResult, Exception]


class FakeExecutor(Executor):
    """Returns canned responses keyed by exact command text.

    Unknown commands raise ExecutionError so a test can't pass by accident.
    """

    def __init__(
        self,
        platform: str = "linux",
        responses: Optional[Dict[str, Response]] = None,
        connect_error: Optional[Exception] = None,
        host: str = "fake-host",
    ) -> None:
        self.host = host
        self.platform = platform
        self.responses = dict(responses or {})
        self.connect_error = connect_error
        self.commands: List[str] = []
        self.connect_calls = 0
        self.closed = False

    def connect(self) -> None:
        self.connect_calls += 1
        if self.connect_error is not None:
            raise self.connect_error

    def run(self, command: str, timeout: int = 60) -> CommandResult:
        self.commands.append(command)
        if command not in self.responses:
            raise ExecutionError(f"no recorded response for command: {command[:60]}")
        response = self.responses[command]
        if isinstance(response, Exception):
            raise response
        return response

    def close(self) -> None:
        self.closed = True
