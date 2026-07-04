from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from audit_tool.engine import Finding


def export_findings(findings: Iterable[Finding], output_format: str = "json", output_file: str | None = None) -> str:
    if output_format == "json":
        rendered = json.dumps([finding.__dict__ for finding in findings], indent=2)
    elif output_format == "markdown":
        lines = ["# Audit Report", ""]
        for finding in findings:
            lines.append(f"## {finding.name}")
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
            for finding in findings
        )

    if output_file:
        Path(output_file).write_text(rendered, encoding="utf-8")

    return rendered
