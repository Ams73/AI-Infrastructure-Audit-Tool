"""Linux audit checks."""
from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Tuple

from audit_tool.checks.base import Check, CheckError, worst_status
from audit_tool.models import CommandResult, Evaluation, Severity, Status

# --- SSH hardening ------------------------------------------------------------

# Prefer `sshd -T` (the effective config, needs root); otherwise read the file.
# The "# source:" marker tells the evaluator which one it got.
SSHD_COMMAND = (
    'if out=$( { /usr/sbin/sshd -T || sshd -T; } 2>/dev/null ) && [ -n "$out" ]; then '
    'echo "# source: sshd -T"; printf "%s\\n" "$out"; '
    "elif [ -r /etc/ssh/sshd_config ]; then "
    'echo "# source: /etc/ssh/sshd_config"; cat /etc/ssh/sshd_config; '
    'else echo "# source: none"; fi'
)

# OpenSSH defaults (7.0+) used when a key is absent from sshd_config.
_SSHD_DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "permitemptypasswords": "no",
}

_SSHD_LINE = re.compile(r"(\w+)\s*[=\s]\s*(.*)")


def parse_sshd_config(text: str) -> Tuple[str, Dict[str, str], bool]:
    """Return (source, settings, has_include). First occurrence of a key wins,
    matching sshd semantics; parsing stops at the first Match block."""
    source = "unknown"
    settings: Dict[str, str] = {}
    has_include = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("# source:"):
            source = line.split(":", 1)[1].strip()
            continue
        if not line or line.startswith("#"):
            continue
        match = _SSHD_LINE.match(line)
        if not match:
            continue
        key, value = match.group(1).lower(), match.group(2).strip().lower()
        if key == "match":
            break
        if key == "include":
            has_include = True
        settings.setdefault(key, value)
    return source, settings, has_include


def evaluate_sshd(result: CommandResult, params: Mapping[str, Any]) -> Evaluation:
    source, settings, has_include = parse_sshd_config(result.stdout)
    if source == "none":
        return Evaluation(Status.SKIPPED, "No sshd configuration found; the SSH server appears not to be installed.")
    if source == "unknown":
        raise CheckError("unexpected output (missing source marker)")

    effective = {key: settings.get(key, default) for key, default in _SSHD_DEFAULTS.items()}
    issues: List[Tuple[str, str]] = []

    root = effective["permitrootlogin"]
    if root == "yes":
        issues.append((Status.FAIL, "PermitRootLogin allows root to log in with a password."))
    elif root != "no" and not params.get("allow_root_key_login", False):
        issues.append((Status.WARN, f"PermitRootLogin is '{root}'; root can still log in with a key."))

    if effective["passwordauthentication"] == "yes":
        issues.append((Status.FAIL, "PasswordAuthentication is enabled."))
    if effective["permitemptypasswords"] == "yes":
        issues.append((Status.FAIL, "PermitEmptyPasswords is enabled."))

    if source != "sshd -T" and has_include:
        issues.append(
            (
                Status.WARN,
                "sshd_config uses Include directives that were not resolved; the effective "
                "configuration may differ. Run the audit as root so 'sshd -T' can be used.",
            )
        )

    lines = [f"Source: {source}"]
    lines += [f"{key} = {value}" + ("" if key in settings else " (default)") for key, value in effective.items()]
    lines += [f"{status.upper()}: {message}" for status, message in issues]
    return Evaluation(worst_status(status for status, _ in issues), "\n".join(lines))


# --- Disk and inode usage -------------------------------------------------------

DISK_COMMAND = "df -P; echo __INODES__; df -P -i 2>/dev/null || true"

_IGNORED_FILESYSTEMS = {"tmpfs", "devtmpfs", "overlay", "squashfs", "udev", "none", "shm", "efivarfs"}
_IGNORED_MOUNT_ROOTS = ("/proc", "/sys", "/dev", "/run", "/snap")


def _ignored_mount(filesystem: str, mount: str) -> bool:
    if filesystem in _IGNORED_FILESYSTEMS:
        return True
    return any(mount == root or mount.startswith(root + "/") for root in _IGNORED_MOUNT_ROOTS)


def parse_df(text: str) -> List[Tuple[str, int]]:
    """Parse POSIX `df -P` output into (mount point, percent used)."""
    usage = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("Filesystem"):
            continue
        parts = line.split(None, 5)
        if len(parts) < 6 or not parts[4].endswith("%"):
            continue  # e.g. "-" for filesystems without inode accounting
        filesystem, mount = parts[0], parts[5]
        if _ignored_mount(filesystem, mount):
            continue
        usage.append((mount, int(parts[4][:-1])))
    return usage


def evaluate_disk(result: CommandResult, params: Mapping[str, Any]) -> Evaluation:
    warn_at = int(params["warn_percent"])
    fail_at = int(params["fail_percent"])
    if warn_at > fail_at:
        raise CheckError(f"warn_percent ({warn_at}) must not exceed fail_percent ({fail_at})")

    blocks_text, _, inodes_text = result.stdout.partition("__INODES__")
    blocks = parse_df(blocks_text)
    if not blocks:
        raise CheckError("no filesystems found in df output")
    inodes = parse_df(inodes_text)

    statuses = []
    lines = [f"Thresholds: warn at {warn_at}%, fail at {fail_at}%"]
    for label, entries in (("space", blocks), ("inodes", inodes)):
        for mount, percent in entries:
            status = Status.FAIL if percent >= fail_at else Status.WARN if percent >= warn_at else Status.PASS
            statuses.append(status)
            marker = "" if status == Status.PASS else f"  <-- {status.upper()}"
            lines.append(f"{mount} {label}: {percent}% used{marker}")
    return Evaluation(worst_status(statuses), "\n".join(lines))


# --- Registry -------------------------------------------------------------------

LINUX_CHECKS = [
    Check(
        id="LNX-OS-001",
        name="OS version and distribution verification",
        platform="linux",
        severity=Severity.HIGH,
        description="Verify the operating system version and distribution.",
    ),
    Check(
        id="LNX-SSH-001",
        name="SSH hardening review",
        platform="linux",
        severity=Severity.HIGH,
        description="Validate SSH daemon settings for root login, password and empty-password authentication.",
        recommendation=(
            "In /etc/ssh/sshd_config set 'PermitRootLogin no', 'PasswordAuthentication no' and "
            "'PermitEmptyPasswords no', make sure key-based access works, then reload sshd."
        ),
        command=SSHD_COMMAND,
        evaluate=evaluate_sshd,
        params={"allow_root_key_login": False},
    ),
    Check(
        id="LNX-SUDO-001",
        name="Sudoers misconfiguration review",
        platform="linux",
        severity=Severity.HIGH,
        description="Check for unsafe sudoers rules and NOPASSWD usage.",
    ),
    Check(
        id="LNX-FS-001",
        name="World-writable files review",
        platform="linux",
        severity=Severity.MEDIUM,
        description="Identify world-writable files and directories that may be risky.",
    ),
    Check(
        id="LNX-DISK-001",
        name="Disk space and inode usage review",
        platform="linux",
        severity=Severity.MEDIUM,
        description="Check persistent filesystems for low free space and inode exhaustion.",
        recommendation=(
            "Free space or extend the flagged filesystems, review log rotation, and set up "
            "monitoring alerts below the failure threshold."
        ),
        command=DISK_COMMAND,
        evaluate=evaluate_disk,
        params={"warn_percent": 80, "fail_percent": 90},
    ),
    Check(
        id="LNX-SVC-001",
        name="Service status review",
        platform="linux",
        severity=Severity.MEDIUM,
        description="Review critical services for unexpected disabled or failed states.",
    ),
    Check(
        id="LNX-CRON-001",
        name="Cron job integrity review",
        platform="linux",
        severity=Severity.MEDIUM,
        description="Inspect cron jobs for unusual or risky scheduled tasks.",
    ),
]
