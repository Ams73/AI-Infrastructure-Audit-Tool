import unittest

from audit_tool.models import Finding
from audit_tool.scoring import ResultScorer


def finding(status, severity):
    return Finding("ID", "n", "h", "linux", severity, status, "d", "e", "r", "t")


class ScoringTests(unittest.TestCase):
    def test_only_failures_contribute_to_risk_score(self):
        findings = [
            finding("fail", "high"),
            finding("fail", "low"),
            finding("pass", "high"),
            finding("warn", "high"),
            finding("error", "medium"),
        ]
        summary = ResultScorer().summarize(findings)
        self.assertEqual(summary["risk_score"], 4)
        self.assertEqual(summary["total"], 5)
        self.assertEqual(summary["by_status"]["fail"], 2)
        self.assertEqual(summary["by_status"]["error"], 1)
        self.assertEqual(summary["failed_by_severity"], {"high": 1, "medium": 0, "low": 1})

    def test_clean_host_scores_zero(self):
        summary = ResultScorer().summarize([finding("pass", "high"), finding("skipped", "high")])
        self.assertEqual(summary["risk_score"], 0)


if __name__ == "__main__":
    unittest.main()
