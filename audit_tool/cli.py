from __future__ import annotations

import argparse

from audit_tool.engine import AuditEngine, build_default_checks
from audit_tool.reports import export_findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Run infrastructure audit checks")
    parser.add_argument("--host", default="localhost", help="Target hostname or IP")
    parser.add_argument("--platform", choices=["linux", "windows"], default="linux")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    parser.add_argument("--output", help="Optional path to write the report")
    args = parser.parse_args()

    engine = AuditEngine(build_default_checks())
    findings = engine.run(hostname=args.host, platform=args.platform)

    if args.format == "text":
        print(f"Audit results for {args.host} ({args.platform})")
        for finding in findings:
            print(f"- [{finding.severity}] {finding.name}: {finding.status}")
    else:
        rendered = export_findings(findings, output_format=args.format, output_file=args.output)
        print(rendered)


if __name__ == "__main__":
    main()
