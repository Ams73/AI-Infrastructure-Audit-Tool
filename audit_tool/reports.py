from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from audit_tool.engine import Finding
from audit_tool.scoring import ResultScorer


def export_findings(findings: Iterable[Finding], output_format: str = "json", output_file: str | None = None) -> str:
    findings_list = list(findings)
    scorer = ResultScorer()
    summary = scorer.summarize(findings_list)

    if output_format == "json":
        payload = {
            "summary": summary,
            "findings": [finding.__dict__ for finding in findings_list],
        }
        rendered = json.dumps(payload, indent=2)
    elif output_format == "markdown":
        lines = ["# Audit Report", "", "## Summary", ""]
        lines.append(f"- Total checks: {summary['total']}")
        lines.append(f"- High severity: {summary['high']}")
        lines.append(f"- Medium severity: {summary['medium']}")
        lines.append(f"- Low severity: {summary['low']}")
        lines.append(f"- Risk score: {summary['score']}")
        lines.append("")
        lines.append("## Findings")
        lines.append("")
        for finding in findings_list:
            lines.append(f"### {finding.name}")
            lines.append(f"- Host: {finding.host}")
            lines.append(f"- Platform: {finding.platform}")
            lines.append(f"- Status: {finding.status}")
            lines.append(f"- Severity: {finding.severity}")
            lines.append(f"- Description: {finding.description}")
            lines.append("")
        rendered = "\n".join(lines).strip() + "\n"
    else:
        rendered = "\n".join(
            f"[{finding.severity}] {finding.name} ({finding.platform}) - {finding.status}: {finding.description}"
            for finding in findings_list
        )

    if output_file:
        Path(output_file).write_text(rendered, encoding="utf-8")

    return rendered
