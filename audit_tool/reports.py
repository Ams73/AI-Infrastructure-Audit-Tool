from __future__ import annotations

import json
from pathlib import Path
import textwrap
from typing import TYPE_CHECKING, Iterable, List, Optional

from audit_tool.models import Finding, Severity, Status, utc_now_iso
from audit_tool.scoring import ResultScorer

if TYPE_CHECKING:
    from audit_tool.ai_summary import AISummary

AI_DISCLAIMER = "AI-generated from the findings below; verify before acting."

FORMATS = ("text", "json", "markdown")

_STATUS_ORDER = {Status.FAIL: 0, Status.ERROR: 1, Status.WARN: 2, Status.PASS: 3, Status.SKIPPED: 4}
_ATTENTION = (Status.FAIL, Status.ERROR, Status.WARN)
# Recommendations describe how to fix a finding; for ERROR the problem is the run itself.
_ACTIONABLE = (Status.FAIL, Status.WARN)


def sort_findings(findings: Iterable[Finding]) -> List[Finding]:
    """Most actionable first: by status, then severity (high first), then ID."""
    return sorted(
        findings,
        key=lambda f: (_STATUS_ORDER.get(f.status, 9), -Severity.RANK.get(f.severity, 0), f.check_id),
    )


def _targets(findings: List[Finding]) -> str:
    targets = sorted({f"{f.host} ({f.platform})" for f in findings})
    return ", ".join(targets) or "n/a"


def _render_json(findings: List[Finding], summary: dict, generated_at: str, ai: "Optional[AISummary]") -> str:
    payload = {
        "generated_at": generated_at,
        "summary": summary,
        "findings": [finding.to_dict() for finding in findings],
    }
    if ai is not None:
        payload["ai_summary"] = {"disclaimer": AI_DISCLAIMER, **ai.to_dict()}
    return json.dumps(payload, indent=2)


def _wrap(text: str, indent: str) -> str:
    return textwrap.fill(text, width=100, initial_indent=indent, subsequent_indent=" " * len(indent))


def _ai_text_lines(ai: "AISummary") -> List[str]:
    wrap = _wrap
    lines = [f"AI summary by {ai.model} ({AI_DISCLAIMER})", f"Overall risk: {ai.overall_risk}"]
    lines.append(wrap(ai.executive_summary, "  "))
    for rank, priority in enumerate(ai.priorities, 1):
        ids = ", ".join(priority.get("check_ids", [])) or "general"
        lines.append(f"  {rank}. {priority['title']} [{ids}] (effort: {priority['effort']})")
        lines.append(wrap(priority["rationale"], "       "))
        lines.extend(wrap(action, "       - ") for action in priority["actions"])
    if ai.coverage_gaps:
        lines.append("  Coverage gaps:")
        lines.extend(wrap(gap, "    - ") for gap in ai.coverage_gaps)
    lines.extend(f"  Note: {note}" for note in ai.notes)
    return lines + [""]


def _render_text(findings: List[Finding], summary: dict, generated_at: str, ai: "Optional[AISummary]") -> str:
    counts = summary["by_status"]
    lines = [
        f"Audit results for {_targets(findings)} at {generated_at}",
        f"Checks: {summary['total']}  "
        + "  ".join(f"{status}: {counts[status]}" for status in Status.ALL)
        + f"  risk score: {summary['risk_score']}",
        "",
    ]
    if ai is not None:
        lines += _ai_text_lines(ai)
    for finding in findings:
        lines.append(f"[{finding.status.upper():7}] [{finding.severity:6}] {finding.check_id} {finding.name}")
        if finding.status in _ATTENTION:
            lines.extend(f"      {line}" for line in finding.evidence.splitlines())
            if finding.recommendation and finding.status in _ACTIONABLE:
                lines.append(f"      Fix: {finding.recommendation}")
    return "\n".join(lines)


def _md_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _fence(text: str) -> str:
    fence = "```"
    while fence in text:
        fence += "`"
    return f"{fence}\n{text}\n{fence}"


def _ai_markdown_lines(ai: "AISummary") -> List[str]:
    lines = [
        "## AI summary",
        "",
        f"> {AI_DISCLAIMER} Written by `{ai.model}` at {ai.generated_at}.",
        "",
        f"**Overall risk: {ai.overall_risk}**",
        "",
        ai.executive_summary,
        "",
    ]
    if ai.priorities:
        lines += ["### Remediation priorities", ""]
        for rank, priority in enumerate(ai.priorities, 1):
            ids = ", ".join(f"`{cid}`" for cid in priority.get("check_ids", [])) or "general"
            lines += [
                f"{rank}. **{priority['title']}** ({ids}; effort: {priority['effort']})",
                f"   {priority['rationale']}",
            ]
            lines += [f"   - {action}" for action in priority["actions"]]
        lines.append("")
    if ai.coverage_gaps:
        lines += ["### Coverage gaps", ""] + [f"- {gap}" for gap in ai.coverage_gaps] + [""]
    if ai.notes:
        lines += [f"_Note: {note}_" for note in ai.notes] + [""]
    return lines


def _render_markdown(findings: List[Finding], summary: dict, generated_at: str, ai: "Optional[AISummary]") -> str:
    counts = summary["by_status"]
    failed = summary["failed_by_severity"]
    lines = [
        "# Audit Report",
        "",
        f"- Target: {_targets(findings)}",
        f"- Generated: {generated_at}",
        f"- Risk score: {summary['risk_score']} (sum of severity weights of failed checks)",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "| --- | --- |",
    ]
    lines += [f"| {status} | {counts[status]} |" for status in Status.ALL]
    lines += ["", "Failed by severity: " + ", ".join(f"{sev} {failed[sev]}" for sev in Severity.ALL), ""]
    if ai is not None:
        lines += _ai_markdown_lines(ai)

    attention = [f for f in findings if f.status in _ATTENTION]
    lines += ["## Findings requiring attention", ""]
    if not attention:
        lines += ["None.", ""]
    for finding in attention:
        lines += [
            f"### [{finding.status.upper()}] {finding.check_id}: {finding.name}",
            "",
            f"- Host: {finding.host} ({finding.platform})",
            f"- Severity: {finding.severity}",
            f"- Checked: {finding.timestamp}",
            f"- Description: {finding.description}",
        ]
        if finding.recommendation and finding.status in _ACTIONABLE:
            lines.append(f"- Recommendation: {finding.recommendation}")
        lines += ["", "Evidence:", "", _fence(finding.evidence), ""]

    rest = [f for f in findings if f.status not in _ATTENTION]
    if rest:
        lines += ["## Other checks", "", "| Status | ID | Check | Severity |", "| --- | --- | --- | --- |"]
        lines += [
            f"| {f.status} | {f.check_id} | {_md_cell(f.name)} | {f.severity} |" for f in rest
        ]
    return "\n".join(lines).rstrip() + "\n"


_RENDERERS = {"json": _render_json, "text": _render_text, "markdown": _render_markdown}


def export_findings(
    findings: Iterable[Finding],
    output_format: str = "json",
    output_file: Optional[str] = None,
    ai_summary: "Optional[AISummary]" = None,
) -> str:
    if output_format not in _RENDERERS:
        raise ValueError(f"Unknown format {output_format!r}; choose from {', '.join(FORMATS)}")
    ordered = sort_findings(findings)
    summary = ResultScorer().summarize(ordered)
    rendered = _RENDERERS[output_format](ordered, summary, utc_now_iso(), ai_summary)
    if output_file:
        Path(output_file).write_text(rendered, encoding="utf-8")
    return rendered
