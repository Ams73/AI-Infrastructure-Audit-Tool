"""Linux audit checks."""
from __future__ import annotations

import re
from datetime import date
from typing import Any, Dict, List, Mapping, Optional, Tuple

from audit_tool.checks.base import Check, CheckError, worst_status
from audit_tool.models import CommandResult, Evaluation, Severity, Status


def _today() -> date:
    """Indirection so tests can pin the date."""
    return date.today()


# --- OS version and support status ----------------------------------------------

OS_RELEASE_COMMAND = 'cat /etc/os-release; echo "KERNEL=$(uname -r)"'

# End of vendor security support, keyed by (os-release ID, version key). The
# version key is VERSION_ID for Ubuntu and the major version elsewhere.
# Dates come from vendor lifecycle pages. Extend or correct them per site with
# the "extra_eol_dates" param, e.g. {"ubuntu:26.10": "2027-07-31"}.
_RHEL_FAMILY_EOL = {"7": "2024-06-30", "8": "2029-05-31", "9": "2032-05-31", "10": "2035-05-31"}
EOL_DATES: Dict[Tuple[str, str], str] = {
    ("ubuntu", "16.04"): "2021-04-30",
    ("ubuntu", "18.04"): "2023-05-31",
    ("ubuntu", "20.04"): "2025-05-31",
    ("ubuntu", "22.04"): "2027-06-30",
    ("ubuntu", "24.04"): "2029-05-31",
    ("ubuntu", "26.04"): "2031-05-31",
    ("debian", "9"): "2022-06-30",
    ("debian", "10"): "2024-06-30",
    ("debian", "11"): "2026-08-31",
    ("debian", "12"): "2028-06-30",
    ("debian", "13"): "2030-06-30",
    ("centos", "7"): "2024-06-30",
    ("centos", "8"): "2024-05-31",
    ("centos", "9"): "2027-05-31",
    ("amzn", "2"): "2026-06-30",
    ("amzn", "2023"): "2029-06-30",
}
for _distro in ("rhel", "rocky", "almalinux", "ol"):
    EOL_DATES.update({(_distro, major): eol for major, eol in _RHEL_FAMILY_EOL.items()})


def parse_os_release(text: str) -> Dict[str, str]:
    values = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip():
            values[key.strip()] = value.strip().strip("\"'")
    return values


def _eol_for(distro: str, version_id: str, extra: Mapping[str, str]) -> Optional[Tuple[str, date]]:
    version_key = version_id if distro == "ubuntu" else version_id.split(".")[0]
    raw = extra.get(f"{distro}:{version_key}") or EOL_DATES.get((distro, version_key))
    if raw is None:
        return None
    try:
        return version_key, date.fromisoformat(raw)
    except ValueError as exc:
        raise CheckError(f"invalid EOL date {raw!r} for {distro}:{version_key}") from exc


def evaluate_os_release(result: CommandResult, params: Mapping[str, Any]) -> Evaluation:
    info = parse_os_release(result.stdout)
    distro = info.get("ID", "").lower()
    if not distro:
        raise CheckError("/etc/os-release could not be read")
    version_id = info.get("VERSION_ID", "")
    lines = [
        f"OS: {info.get('PRETTY_NAME', distro)}",
        f"ID={distro} VERSION_ID={version_id or '(none)'}",
        f"Kernel: {info.get('KERNEL', 'unknown')}",
    ]

    eol = _eol_for(distro, version_id, params.get("extra_eol_dates") or {}) if version_id else None
    if eol is None:
        lines.append(
            "WARN: release not in the lifecycle table; support status unknown "
            "(add it with the extra_eol_dates param)."
        )
        return Evaluation(Status.WARN, "\n".join(lines))

    _, eol_date = eol
    days_left = (eol_date - _today()).days
    if days_left < 0:
        lines.append(f"FAIL: vendor security support ended on {eol_date} ({-days_left} days ago).")
        return Evaluation(Status.FAIL, "\n".join(lines))
    if days_left <= int(params["warn_days_before_eol"]):
        lines.append(f"WARN: vendor security support ends on {eol_date} ({days_left} days left).")
        return Evaluation(Status.WARN, "\n".join(lines))
    lines.append(f"Supported until {eol_date} ({days_left} days left).")
    return Evaluation(Status.PASS, "\n".join(lines))


# --- Privileged and passwordless accounts --------------------------------------------

ACCOUNTS_COMMAND = (
    "awk -F: '$3 == 0 { print \"uid0:\" $1 }' /etc/passwd; "
    "if [ -r /etc/shadow ]; then "
    "awk -F: '$2 == \"\" { print \"emptypw:\" $1 }' /etc/shadow; echo shadow:ok; "
    "else echo shadow:unreadable; fi"
)


def evaluate_accounts(result: CommandResult, params: Mapping[str, Any]) -> Evaluation:
    uid0, empty, shadow = [], [], None
    for line in result.stdout.splitlines():
        kind, _, value = line.strip().partition(":")
        if kind == "uid0":
            uid0.append(value)
        elif kind == "emptypw":
            empty.append(value)
        elif kind == "shadow":
            shadow = value
    if shadow is None or not uid0:
        raise CheckError("could not read /etc/passwd")

    statuses, lines = [], [f"UID 0 accounts: {', '.join(uid0)}"]
    extra_root = [name for name in uid0 if name != "root"]
    if extra_root:
        statuses.append(Status.FAIL)
        lines.append(f"FAIL: accounts other than root have UID 0: {', '.join(extra_root)}")
    if shadow == "unreadable":
        statuses.append(Status.WARN)
        lines.append("WARN: /etc/shadow is not readable; empty passwords were not checked (run as root).")
    elif empty:
        statuses.append(Status.FAIL)
        lines.append(f"FAIL: accounts with an empty password: {', '.join(empty)}")
    else:
        lines.append("No accounts with an empty password.")
    return Evaluation(worst_status(statuses), "\n".join(lines), accounts=tuple(uid0 + empty))


# --- Sudoers --------------------------------------------------------------------------

SUDOERS_COMMAND = (
    "for f in /etc/sudoers /etc/sudoers.d/*; do "
    '[ -f "$f" ] || continue; '
    'if [ -r "$f" ]; then echo "# file: $f"; cat "$f"; echo; '
    'else echo "# unreadable: $f"; fi; '
    "done"
)

_SUDO_TAG = re.compile(r"\b[A-Z_]+:")
_SUDO_PASSWD_TAG = re.compile(r"\bPASSWD:")  # \b keeps it from matching inside NOPASSWD:
_SUDO_ALL = re.compile(r"(?:^|,)\s*ALL\s*(?:,|$)")


def _logical_lines(text: str) -> List[str]:
    """Join backslash continuations; keep marker lines; drop comments/blanks."""
    lines, buffer = [], ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("# file:") or line.startswith("# unreadable:"):
            lines.append(line)
            continue
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        line = (buffer + line).strip()
        buffer = ""
        if line and not line.startswith("#") and not line.startswith("@include"):
            lines.append(line)
    return lines


def evaluate_sudoers(result: CommandResult, params: Mapping[str, Any]) -> Evaluation:
    allowed = {name.lower() for name in params.get("allowed_nopasswd") or []}
    files, unreadable = [], []
    statuses, findings = [], []
    principals: List[str] = []
    current = "?"

    for line in _logical_lines(result.stdout):
        if line.startswith("# file:"):
            current = line.split(":", 1)[1].strip()
            files.append(current)
            continue
        if line.startswith("# unreadable:"):
            unreadable.append(line.split(":", 1)[1].strip())
            continue
        if line.startswith("Defaults") and "!authenticate" in line:
            scoped = re.match(r"Defaults[:>@!](\S+)", line)
            if scoped:
                principals.append(scoped.group(1))
            statuses.append(Status.FAIL)
            findings.append(f"FAIL: {current}: authentication disabled: {line}")
            continue
        if "NOPASSWD:" not in line or "=" not in line:
            continue
        principal = line.split()[0]
        principals.append(principal)
        if principal.lower() in allowed:
            findings.append(f"allowed: {current}: {line}")
            continue
        # Commands after NOPASSWD: up to a later PASSWD: tag; other tags (SETENV:,
        # NOEXEC:...) don't change whether a password is needed.
        commands = _SUDO_PASSWD_TAG.split(line.split("NOPASSWD:", 1)[1])[0]
        if _SUDO_ALL.search(_SUDO_TAG.sub("", commands)):
            statuses.append(Status.FAIL)
            findings.append(f"FAIL: {current}: passwordless sudo for ALL commands: {line}")
        else:
            statuses.append(Status.WARN)
            findings.append(f"WARN: {current}: passwordless sudo for specific commands: {line}")

    if "/etc/sudoers" in unreadable or not (files or unreadable):
        raise CheckError("/etc/sudoers is not readable; this check must run as root")
    if unreadable:
        statuses.append(Status.WARN)
        findings.append(f"WARN: could not read: {', '.join(unreadable)} (run as root)")

    lines = [f"Files reviewed: {', '.join(files)}"] + (findings or ["No NOPASSWD or !authenticate rules found."])
    return Evaluation(worst_status(statuses), "\n".join(lines), accounts=tuple(principals))


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
                "configuration may differ. 'sshd -T' was unavailable (it needs root and the "
                "server's host keys).",
            )
        )

    lines = [f"Source: {source}"]
    lines += [f"{key} = {value}" + ("" if key in settings else " (default)") for key, value in effective.items()]
    lines += [f"{status.upper()}: {message}" for status, message in issues]
    return Evaluation(worst_status(status for status, _ in issues), "\n".join(lines))


# --- Disk and inode usage -------------------------------------------------------

# Read-only mounts (images, ISOs, erofs) are full by design, so they are listed
# from /proc/mounts and excluded.
DISK_COMMAND = (
    "df -P; echo __INODES__; df -P -i 2>/dev/null || true; "
    "echo __READONLY__; awk '$4 ~ /(^|,)ro(,|$)/ { print $2 }' /proc/mounts 2>/dev/null || true"
)

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

    blocks_text, _, rest = result.stdout.partition("__INODES__")
    inodes_text, _, readonly_text = rest.partition("__READONLY__")
    # /proc/mounts escapes spaces and other characters as octal (e.g.  ).
    readonly = {
        re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), line.strip())
        for line in readonly_text.splitlines()
        if line.strip()
    }
    blocks = [entry for entry in parse_df(blocks_text) if entry[0] not in readonly]
    if not blocks:
        raise CheckError("no writable filesystems found in df output")
    inodes = [entry for entry in parse_df(inodes_text) if entry[0] not in readonly]

    statuses = []
    lines = [f"Thresholds: warn at {warn_at}%, fail at {fail_at}%"]
    if readonly:
        lines.append(f"Ignored read-only mounts: {', '.join(sorted(readonly))}")
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
        description="Identify the distribution and release and verify it still receives vendor security updates.",
        recommendation=(
            "Upgrade to a supported release of the distribution, or buy extended support "
            "(e.g. Ubuntu Pro, Debian ELTS, RHEL ELS) until the upgrade is done."
        ),
        command=OS_RELEASE_COMMAND,
        evaluate=evaluate_os_release,
        params={"warn_days_before_eol": 180, "extra_eol_dates": {}},
    ),
    Check(
        id="LNX-ACCT-001",
        name="Privileged and passwordless account review",
        platform="linux",
        severity=Severity.HIGH,
        description="Find accounts other than root with UID 0 and accounts with an empty password.",
        recommendation=(
            "Remove or renumber extra UID 0 accounts and use sudo for privilege instead. "
            "Lock accounts with empty passwords (passwd -l <user>) or set a password."
        ),
        command=ACCOUNTS_COMMAND,
        evaluate=evaluate_accounts,
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
        description="Check sudoers for passwordless (NOPASSWD) rules and disabled authentication.",
        recommendation=(
            "Remove NOPASSWD from rules granting ALL commands and remove '!authenticate' defaults. "
            "Limit passwordless rules to specific commands for automation accounts and list those "
            "accounts in the allowed_nopasswd param. Edit with visudo."
        ),
        command=SUDOERS_COMMAND,
        evaluate=evaluate_sudoers,
        params={"allowed_nopasswd": []},
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
