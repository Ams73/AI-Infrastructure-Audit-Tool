from __future__ import annotations

from typing import List

from audit_tool.engine import Finding


class ResultScorer:
    def __init__(self) -> None:
        self.weights = {"high": 3, "medium": 2, "low": 1}

    def score_findings(self, findings: List[Finding]) -> int:
        return sum(self.weights.get(finding.severity, 1) for finding in findings)

    def summarize(self, findings: List[Finding]) -> dict:
        return {
            "total": len(findings),
            "high": sum(1 for finding in findings if finding.severity == "high"),
            "medium": sum(1 for finding in findings if finding.severity == "medium"),
            "low": sum(1 for finding in findings if finding.severity == "low"),
            "score": self.score_findings(findings),
        }
