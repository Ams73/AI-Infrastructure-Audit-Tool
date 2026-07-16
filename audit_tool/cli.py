from __future__ import annotations

import argparse

from audit_tool.engine import AuditEngine, build_checks_from_config
from audit_tool.reports import export_findings
from audit_tool.remote import RemoteConnection, RemoteExecutor


def main() -> None:
    parser = argparse.ArgumentParser(description="Run infrastructure audit checks")
    parser.add_argument("--host", default="localhost", help="Target hostname or IP (default: localhost)")
    parser.add_argument("--platform", choices=["linux", "windows"], default="linux", help="Target platform")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="text", help="Output format")
    parser.add_argument("--output", help="Optional path to write the report")
    parser.add_argument("--config", help="Optional path to a JSON configuration file")
    parser.add_argument("--username", help="Optional remote username")
    parser.add_argument("--port", type=int, default=22, help="Remote SSH port (default: 22)")
    args = parser.parse_args()

    checks = build_checks_from_config(args.config)
    remote_executor = None
    if args.username or args.host:
        remote_executor = RemoteExecutor(
            RemoteConnection(host=args.host, username=args.username, port=args.port, platform=args.platform)
        )
    engine = AuditEngine(checks, remote_executor=remote_executor)
    findings = engine.run(hostname=args.host, platform=args.platform)

    if args.format == "text":
        print(f"Audit results for {args.host} ({args.platform})")
        print(f"Checks executed: {len(findings)}")
        for finding in findings:
            print(f"- [{finding.severity}] {finding.name}: {finding.status}")
    else:
        rendered = export_findings(findings, output_format=args.format, output_file=args.output)
        print(rendered)


if __name__ == "__main__":
    main()
