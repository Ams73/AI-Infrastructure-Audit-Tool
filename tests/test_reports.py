import json
import os
import tempfile
import unittest

from audit_tool.models import Finding
from audit_tool.reports import export_findings, sort_findings


def finding(check_id, status, severity="high", evidence="evidence", recommendation="do x"):
    return Finding(
        check_id, f"name {check_id}", "web01", "linux", severity, status, "desc", evidence,
        recommendation, "2026-11-22T00:00:00+00:00",
    )


FINDINGS = [finding("A", "pass"), finding("B", "fail", "low"), finding("C", "fail"), finding("D", "error")]


class ReportTests(unittest.TestCase):
    def test_sorting_puts_actionable_first(self):
        self.assertEqual([f.check_id for f in sort_findings(FINDINGS)], ["C", "B", "D", "A"])

    def test_json_contains_full_data_model(self):
        payload = json.loads(export_findings(FINDINGS, "json"))
        self.assertEqual(payload["summary"]["risk_score"], 4)
        first = payload["findings"][0]
        for key in ("check_id", "host", "platform", "name", "severity", "status", "description",
                    "evidence", "recommendation", "timestamp"):
            self.assertIn(key, first)

    def test_markdown_shows_evidence_and_recommendation_for_failures(self):
        rendered = export_findings(FINDINGS, "markdown")
        self.assertIn("# Audit Report", rendered)
        self.assertIn("### [FAIL] C: name C", rendered)
        self.assertIn("- Recommendation: do x", rendered)
        self.assertIn("| pass | A | name A | high |", rendered)

    def test_errors_do_not_show_hardening_recommendation(self):
        for fmt in ("markdown", "text"):
            rendered = export_findings([finding("D", "error", recommendation="harden it")], fmt)
            self.assertNotIn("harden it", rendered, fmt)

    def test_markdown_fence_survives_backticks_in_evidence(self):
        rendered = export_findings([finding("A", "fail", evidence="```\ninjected")], "markdown")
        self.assertIn("````\n```\ninjected\n````", rendered)

    def test_text_report_writes_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "report.txt")
            rendered = export_findings(FINDINGS, "text", output_file=path)
            with open(path, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), rendered)
        self.assertIn("[FAIL   ] [high  ] C name C", rendered)

    def test_unknown_format_rejected(self):
        with self.assertRaises(ValueError):
            export_findings(FINDINGS, "html")


if __name__ == "__main__":
    unittest.main()
