"""Built-in audit checks."""
from audit_tool.checks.base import Check, CheckError
from audit_tool.checks.linux import LINUX_CHECKS
from audit_tool.checks.windows import WINDOWS_CHECKS

BUILTIN_CHECKS = [*LINUX_CHECKS, *WINDOWS_CHECKS]

__all__ = ["BUILTIN_CHECKS", "Check", "CheckError"]
