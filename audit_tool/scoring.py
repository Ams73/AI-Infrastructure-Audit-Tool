from __future__ import annotations

from typing import Dict, List

from audit_tool.models import Finding, Severity, Status


class ResultScorer:
    """Summarizes findings.

    The risk score is the sum of severity weights (high=3, medium=2, low=1) of
    FAILED checks only, so a fully hardened host scores 0. Warnings and errors
    are counted separately but do not add to the score.
    """

    def __init__(self) -> None:
        self.weights = dict(Severity.RANK)

    def score_findings(self, findings: List[Finding]) -> int:
        return sum(self.weights.get(f.severity, 1) for f in findings if f.status == Status.FAIL)

    def summarize(self, findings: List[Finding]) -> Dict[str, object]:
        return {
            "total": len(findings),
            "by_status": {status: sum(1 for f in findings if f.status == status) for status in Status.ALL},
            "failed_by_severity": {
                severity: sum(1 for f in findings if f.status == Status.FAIL and f.severity == severity)
                for severity in Severity.ALL
            },
            "risk_score": self.score_findings(findings),
        }
