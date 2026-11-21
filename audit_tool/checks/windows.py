"""Windows audit checks (PowerShell)."""
from __future__ import annotations

from typing import Any, List, Mapping

from audit_tool.checks.base import Check, CheckError, parse_json_output, worst_status
from audit_tool.models import CommandResult, Evaluation, Severity, Status


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


# --- Local administrators and passwordless accounts --------------------------------

# Groups are looked up by well-known SID so the check works on localized Windows.
ADMINS_COMMAND = (
    "$members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { "
    "[pscustomobject]@{ Name = $_.Name; ObjectClass = [string]$_.ObjectClass; "
    "Source = [string]$_.PrincipalSource; SID = [string]$_.SID } }); "
    "$users = @(Get-LocalUser -ErrorAction Stop | ForEach-Object { "
    "[pscustomobject]@{ Name = $_.Name; SID = [string]$_.SID; Enabled = [bool]$_.Enabled; "
    "PasswordRequired = [bool]$_.PasswordRequired } }); "
    "ConvertTo-Json -Compress -Depth 4 -InputObject @{ members = $members; users = $users }"
)


def evaluate_admins(result: CommandResult, params: Mapping[str, Any]) -> Evaluation:
    data = parse_json_output(result)
    if not isinstance(data, dict) or "members" not in data:
        raise CheckError("unexpected output")
    members = _as_list(data.get("members"))
    users = _as_list(data.get("users"))
    allowed = {name.lower() for name in params.get("allowed_members") or []}
    max_members = int(params["max_members"])

    statuses: List[str] = []
    lines = [f"Administrators group ({len(members)} members):"]
    lines += [f"  {m.get('Name')} [{m.get('ObjectClass')}, {m.get('Source')}]" for m in members]

    if allowed:
        unexpected = [m.get("Name", "?") for m in members if str(m.get("Name", "")).lower() not in allowed]
        if unexpected:
            statuses.append(Status.FAIL)
            lines.append(f"FAIL: members not in allowed_members: {', '.join(unexpected)}")
    elif len(members) > max_members:
        statuses.append(Status.WARN)
        lines.append(f"WARN: {len(members)} members exceeds max_members ({max_members}); review each one.")

    admin_sids = {m.get("SID") for m in members}
    for user in users:
        name, sid = user.get("Name", "?"), str(user.get("SID", ""))
        if not user.get("Enabled"):
            continue
        if sid.endswith("-500"):
            statuses.append(Status.WARN)
            lines.append(f"WARN: built-in Administrator account '{name}' is enabled.")
        if user.get("PasswordRequired") is False:
            is_admin = sid in admin_sids
            statuses.append(Status.FAIL if is_admin else Status.WARN)
            label = "FAIL" if is_admin else "WARN"
            role = "administrator account" if is_admin else "account"
            lines.append(f"{label}: enabled {role} '{name}' does not require a password (it may be empty).")
    return Evaluation(worst_status(statuses), "\n".join(lines))


# --- Patch currency -------------------------------------------------------------------

UPDATES_COMMAND = (
    "$hf = @(Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | "
    "Sort-Object InstalledOn -Descending | Select-Object -First 5 | ForEach-Object { "
    "[pscustomobject]@{ HotFixID = $_.HotFixID; Description = $_.Description; "
    "InstalledOn = $_.InstalledOn.ToString('yyyy-MM-dd'); "
    "DaysAgo = [int][math]::Floor(((Get-Date) - $_.InstalledOn).TotalDays) } }); "
    r"$reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') "
    r"-or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'); "
    "ConvertTo-Json -Compress -Depth 3 -InputObject @{ hotfixes = $hf; reboot_pending = $reboot }"
)


def evaluate_updates(result: CommandResult, params: Mapping[str, Any]) -> Evaluation:
    data = parse_json_output(result)
    if not isinstance(data, dict):
        raise CheckError("unexpected output")
    hotfixes = _as_list(data.get("hotfixes"))
    if not hotfixes:
        raise CheckError("no installed updates with an install date were found")
    warn_days, fail_days = int(params["warn_days"]), int(params["fail_days"])

    latest = hotfixes[0]
    days = int(latest.get("DaysAgo", 0))
    statuses: List[str] = []
    lines = [f"Most recent update: {latest.get('HotFixID')} installed {latest.get('InstalledOn')} ({days} days ago)"]
    if days > fail_days:
        statuses.append(Status.FAIL)
        lines.append(f"FAIL: no update installed in more than {fail_days} days.")
    elif days > warn_days:
        statuses.append(Status.WARN)
        lines.append(f"WARN: no update installed in more than {warn_days} days.")
    if data.get("reboot_pending"):
        statuses.append(Status.WARN)
        lines.append("WARN: a reboot is pending; installed updates are not active yet.")
    lines.append("Recent updates:")
    lines += [f"  {h.get('InstalledOn')} {h.get('HotFixID')} {h.get('Description')}" for h in hotfixes]
    return Evaluation(worst_status(statuses), "\n".join(lines))


# --- BitLocker --------------------------------------------------------------------------

BITLOCKER_COMMAND = (
    "ConvertTo-Json -Compress -InputObject @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object { "
    "[pscustomobject]@{ MountPoint = $_.MountPoint; VolumeType = [string]$_.VolumeType; "
    "ProtectionStatus = [string]$_.ProtectionStatus; VolumeStatus = [string]$_.VolumeStatus; "
    "EncryptionPercentage = $_.EncryptionPercentage } })"
)


def evaluate_bitlocker(result: CommandResult, params: Mapping[str, Any]) -> Evaluation:
    volumes = _as_list(parse_json_output(result))
    if not any(v.get("VolumeType") == "OperatingSystem" for v in volumes):
        raise CheckError("no operating system volume reported")
    data_status = Status.FAIL if params.get("require_data_volumes") else Status.WARN

    statuses: List[str] = []
    lines = []
    for volume in volumes:
        protected = volume.get("ProtectionStatus") == "On"
        is_os = volume.get("VolumeType") == "OperatingSystem"
        status = Status.PASS if protected else (Status.FAIL if is_os else data_status)
        statuses.append(status)
        marker = "" if protected else f"  <-- {status.upper()}"
        lines.append(
            f"{volume.get('MountPoint')} ({volume.get('VolumeType')}): protection {volume.get('ProtectionStatus')}, "
            f"{volume.get('VolumeStatus')}, {volume.get('EncryptionPercentage')}% encrypted{marker}"
        )
    return Evaluation(worst_status(statuses), "\n".join(lines))


# --- Firewall profiles -----------------------------------------------------------

# ActiveStore gives the effective settings including Group Policy. Enums are cast
# to strings so the JSON is readable; @() guarantees a JSON array.
FIREWALL_COMMAND = (
    "ConvertTo-Json -Compress -InputObject @(Get-NetFirewallProfile -PolicyStore ActiveStore "
    "-ErrorAction Stop | Select-Object Name, "
    "@{n='Enabled';e={[string]$_.Enabled}}, "
    "@{n='DefaultInboundAction';e={[string]$_.DefaultInboundAction}})"
)


def evaluate_firewall(result: CommandResult, params: Mapping[str, Any]) -> Evaluation:
    data = parse_json_output(result)
    profiles = data if isinstance(data, list) else [data]
    if not profiles:
        raise CheckError("no firewall profiles returned")

    statuses: List[str] = []
    lines = []
    for profile in profiles:
        name = profile.get("Name", "?")
        enabled = str(profile.get("Enabled", "")).lower() == "true"
        inbound = str(profile.get("DefaultInboundAction", "NotConfigured"))
        if not enabled:
            status, note = Status.FAIL, "firewall disabled"
        elif inbound.lower() == "allow":
            status, note = Status.WARN, "inbound traffic allowed by default"
        else:
            status, note = Status.PASS, "ok"
        statuses.append(status)
        lines.append(f"{name}: enabled={enabled}, default inbound={inbound} -> {note}")
    return Evaluation(worst_status(statuses), "\n".join(lines))


# --- Microsoft Defender -------------------------------------------------------------

DEFENDER_COMMAND = (
    "Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled, AntivirusEnabled, "
    "RealTimeProtectionEnabled, AntivirusSignatureAge | ConvertTo-Json -Compress"
)


def evaluate_defender(result: CommandResult, params: Mapping[str, Any]) -> Evaluation:
    data = parse_json_output(result)
    if not isinstance(data, dict):
        raise CheckError("unexpected Get-MpComputerStatus output")
    max_age = int(params["max_signature_age_days"])

    statuses: List[str] = []
    lines = []
    for key in ("AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled"):
        value = data.get(key)
        ok = value is True
        statuses.append(Status.PASS if ok else Status.FAIL)
        lines.append(f"{key} = {value}" + ("" if ok else "  <-- FAIL"))

    age = data.get("AntivirusSignatureAge")
    if not isinstance(age, int):
        statuses.append(Status.WARN)
        lines.append(f"AntivirusSignatureAge = {age} (unknown)  <-- WARN")
    elif age > max_age:
        statuses.append(Status.WARN)
        lines.append(f"AntivirusSignatureAge = {age} days (max {max_age})  <-- WARN")
    else:
        lines.append(f"AntivirusSignatureAge = {age} days (max {max_age})")
    return Evaluation(worst_status(statuses), "\n".join(lines))


# --- Registry ------------------------------------------------------------------------

WINDOWS_CHECKS = [
    Check(
        id="WIN-UPD-001",
        name="Patch currency review",
        platform="windows",
        severity=Severity.HIGH,
        description=(
            "Check how recently updates were installed (Get-HotFix) and whether a reboot is pending. "
            "This is a proxy for missing security updates; it does not query Windows Update."
        ),
        recommendation=(
            "Install the latest cumulative update through Windows Update, WSUS or your patch tool, "
            "reboot to complete installation, and confirm monthly patching is scheduled."
        ),
        command=UPDATES_COMMAND,
        evaluate=evaluate_updates,
        params={"warn_days": 35, "fail_days": 60},
    ),
    Check(
        id="WIN-FW-001",
        name="Firewall profile status review",
        platform="windows",
        severity=Severity.HIGH,
        description="Verify all firewall profiles are enabled and block inbound traffic by default.",
        recommendation=(
            "Enable Windows Defender Firewall for the Domain, Private and Public profiles "
            "(Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block), "
            "preferably through Group Policy."
        ),
        command=FIREWALL_COMMAND,
        evaluate=evaluate_firewall,
    ),
    Check(
        id="WIN-ADM-001",
        name="Local administrator account review",
        platform="windows",
        severity=Severity.HIGH,
        description=(
            "Review Administrators group membership, the built-in Administrator account, and enabled "
            "local accounts that do not require a password."
        ),
        recommendation=(
            "Remove unneeded members from the local Administrators group (manage it through Group Policy "
            "or LAPS), disable the built-in Administrator account, and require passwords on all local "
            "accounts (net user <name> /passwordreq:yes)."
        ),
        command=ADMINS_COMMAND,
        evaluate=evaluate_admins,
        params={"allowed_members": [], "max_members": 3},
    ),
    Check(
        id="WIN-BL-001",
        name="BitLocker protection review",
        platform="windows",
        severity=Severity.MEDIUM,
        description="Verify BitLocker protection is on for the operating system volume and data volumes.",
        recommendation=(
            "Enable BitLocker on the OS volume with a TPM protector and escrow the recovery key to AD or "
            "Entra ID (Enable-BitLocker -MountPoint C: -TpmProtector), then encrypt fixed data volumes."
        ),
        command=BITLOCKER_COMMAND,
        evaluate=evaluate_bitlocker,
        params={"require_data_volumes": False},
    ),
    Check(
        id="WIN-DEF-001",
        name="Windows Defender status review",
        platform="windows",
        severity=Severity.MEDIUM,
        description="Confirm Microsoft Defender antivirus and real-time protection are on and signatures are current.",
        recommendation=(
            "Enable Defender real-time protection and ensure signature updates succeed "
            "(Update-MpSignature). If a third-party antivirus is the standard, disable this "
            "check in the config and audit that product instead."
        ),
        command=DEFENDER_COMMAND,
        evaluate=evaluate_defender,
        params={"max_signature_age_days": 3},
    ),
    Check(
        id="WIN-SVC-001",
        name="Enabled services review",
        platform="windows",
        severity=Severity.MEDIUM,
        description="Inspect enabled services for unexpected or risky startup state.",
    ),
    Check(
        id="WIN-TASK-001",
        name="Scheduled tasks review",
        platform="windows",
        severity=Severity.MEDIUM,
        description="Look for suspicious or unnecessary scheduled tasks.",
    ),
]
