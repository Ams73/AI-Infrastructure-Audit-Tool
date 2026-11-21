"""Windows audit checks (PowerShell)."""
from __future__ import annotations

from typing import Any, List, Mapping

from audit_tool.checks.base import Check, CheckError, parse_json_output, worst_status
from audit_tool.models import CommandResult, Evaluation, Severity, Status

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
        name="Pending security updates review",
        platform="windows",
        severity=Severity.HIGH,
        description="Review pending security updates on the host.",
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
        description="Review local administrator accounts and privilege exposure.",
    ),
    Check(
        id="WIN-BL-001",
        name="BitLocker protection review",
        platform="windows",
        severity=Severity.MEDIUM,
        description="Verify BitLocker protection is enabled for relevant drives.",
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
