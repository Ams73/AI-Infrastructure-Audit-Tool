import unittest

from audit_tool.engine import Finding
from audit_tool.scoring import ResultScorer


class ScoringTests(unittest.TestCase):
    def test_scorer_counts_findings_and_severity(self):
        scorer = ResultScorer()
        findings = [
            Finding(host="a", platform="linux", name="one", status="passed", severity="high", description="x"),
            Finding(host="a", platform="linux", name="two", status="passed", severity="medium", description="x"),
        ]
        summary = scorer.summarize(findings)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["high"], 1)
        self.assertEqual(summary["score"], 5)


if __name__ == "__main__":
    unittest.main()
