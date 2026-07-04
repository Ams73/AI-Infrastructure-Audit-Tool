import json
import os
import tempfile
import unittest

from audit_tool.engine import Finding
from audit_tool.reports import export_findings


class ReportTests(unittest.TestCase):
    def test_json_export_contains_findings(self):
        findings = [Finding(host="a", platform="linux", name="SSH", status="passed", severity="high", description="ok")]
        rendered = export_findings(findings, output_format="json")
        payload = json.loads(rendered)
        self.assertEqual(payload[0]["name"], "SSH")

    def test_markdown_export_writes_file(self):
        findings = [Finding(host="a", platform="windows", name="Updates", status="warning", severity="high", description="pending")]
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "report.md")
            export_findings(findings, output_format="markdown", output_file=output_path)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, "r", encoding="utf-8") as handle:
                content = handle.read()
            self.assertIn("# Audit Report", content)


if __name__ == "__main__":
    unittest.main()
