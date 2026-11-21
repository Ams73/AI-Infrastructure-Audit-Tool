from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from audit_tool.checks import BUILTIN_CHECKS, Check


class CheckRegistry:
    """Checks indexed by their stable ID."""

    def __init__(self, checks: Iterable[Check] = ()) -> None:
        self._checks: Dict[str, Check] = {}
        for check in checks:
            self.register(check)

    def register(self, check: Check) -> None:
        if check.id in self._checks:
            raise ValueError(f"Duplicate check ID {check.id!r}")
        self._checks[check.id] = check

    def get(self, check_id: str) -> Optional[Check]:
        return self._checks.get(check_id)

    def get_all(self) -> List[Check]:
        return list(self._checks.values())

    def get_by_platform(self, platform: str) -> List[Check]:
        return [check for check in self._checks.values() if check.platform == platform]


def build_registry() -> CheckRegistry:
    return CheckRegistry(BUILTIN_CHECKS)
