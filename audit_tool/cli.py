from __future__ import annotations

import argparse
import logging
import json
import os
import socket
import sys
from typing import Iterable, List, Optional

from audit_tool import ai_summary as ai
from audit_tool.config import ConfigError, apply_config, load_config
from audit_tool.engine import AuditEngine
from audit_tool.executors import PLATFORMS, TRANSPORTS, WINRM_TRANSPORTS, build_executor
from audit_tool.models import Finding, Severity, Status
from audit_tool.registry import build_registry
from audit_tool.reports import FORMATS, export_findings

# Exit codes, so the tool can gate CI/CD pipelines.
EXIT_OK = 0  # no failed checks at or above --fail-on
EXIT_FINDINGS = 1  # at least one failed check at or above --fail-on
EXIT_USAGE = 2  # bad arguments or config (also argparse's own code)
EXIT_INCOMPLETE = 3  # no qualifying failures, but some checks errored

PASSWORD_ENV = "AUDIT_PASSWORD"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run infrastructure audit checks",
        epilog=(
            f"Passwords are read from the {PASSWORD_ENV} environment variable, never from arguments. "
            "Exit codes: 0 clean, 1 failed checks, 2 usage/config error, 3 incomplete (checks errored)."
        ),
    )
    target = parser.add_argument_group("target")
    target.add_argument("--host", default="localhost", help="Target hostname or IP (default: localhost)")
    target.add_argument(
        "--platform",
        choices=PLATFORMS,
        help="Target platform. Detected automatically for localhost; required for remote hosts with --transport auto",
    )
    target.add_argument(
        "--transport",
        choices=TRANSPORTS,
        default="auto",
        help="auto: local for localhost, ssh for linux, winrm for windows (default: auto)",
    )
    target.add_argument("--username", help="Remote username")
    target.add_argument("--port", type=int, help="Remote port (default: 22 for SSH, 5985/5986 for WinRM)")
    target.add_argument("--key-file", help="SSH private key file (SSH agent and default keys are also tried)")
    target.add_argument(
        "--accept-unknown-host-keys",
        action="store_true",
        help="INSECURE: accept SSH host keys not in known_hosts",
    )
    target.add_argument("--winrm-transport", choices=WINRM_TRANSPORTS, default="ntlm", help="WinRM auth (default: ntlm)")
    target.add_argument("--winrm-https", action="store_true", help="Use WinRM over HTTPS (port 5986)")

    run = parser.add_argument_group("run")
    run.add_argument("--config", help="JSON config with per-check overrides (see sample_config.json)")
    run.add_argument("--timeout", type=int, help="Per-command timeout in seconds (default: 60, or from config)")
    run.add_argument(
        "--fail-on",
        choices=Severity.ALL,
        default=Severity.LOW,
        help="Lowest severity of failed check that causes exit code 1 (default: low)",
    )
    run.add_argument("--list-checks", action="store_true", help="List available checks and exit")
    run.add_argument("-v", "--verbose", action="store_true", help="Log progress to stderr")

    summary = parser.add_argument_group(
        "AI summary (optional; needs the [ai] extra and Anthropic API credentials)"
    )
    summary.add_argument(
        "--ai-summary",
        action="store_true",
        help="Add an executive summary and remediation plan written by Claude. Findings are "
        "redacted before they are sent; see --ai-dry-run",
    )
    summary.add_argument("--ai-model", default=ai.DEFAULT_MODEL, help=f"Claude model (default: {ai.DEFAULT_MODEL})")
    summary.add_argument(
        "--ai-effort", choices=ai.EFFORT_LEVELS, default=ai.DEFAULT_EFFORT,
        help=f"Reasoning effort (default: {ai.DEFAULT_EFFORT})",
    )
    summary.add_argument(
        "--ai-evidence", choices=ai.EVIDENCE_MODES, default="redacted",
        help="Send redacted evidence (default) or none: only check IDs, statuses and descriptions",
    )
    summary.add_argument(
        "--ai-redact", action="append", default=[], metavar="TERM",
        help="Extra value to replace with a placeholder, e.g. an account or company name (repeatable)",
    )
    summary.add_argument(
        "--ai-dry-run", action="store_true",
        help="Print the exact redacted data that would be sent to stderr, and send nothing",
    )

    output = parser.add_argument_group("output")
    output.add_argument("--format", choices=FORMATS, default="text", help="Report format (default: text)")
    output.add_argument("--output", help="Write the report to this file instead of stdout")
    return parser


def exit_code_for(findings: Iterable[Finding], fail_on: str) -> int:
    findings = list(findings)
    threshold = Severity.RANK[fail_on]
    if any(f.status == Status.FAIL and Severity.RANK[f.severity] >= threshold for f in findings):
        return EXIT_FINDINGS
    if any(f.status == Status.ERROR for f in findings):
        return EXIT_INCOMPLETE
    return EXIT_OK


def _list_checks(checks) -> None:
    for check in checks:
        state = "implemented" if check.implemented else "planned"
        if not check.enabled:
            state += ", disabled"
        print(f"{check.id:14} {check.platform:8} {check.severity:7} {check.name} [{state}]")


def _ai_summary(args: argparse.Namespace, findings: List[Finding]) -> "Optional[ai.AISummary]":
    """Run the optional AI step. Failures are reported but never fail the audit."""
    if not (args.ai_summary or args.ai_dry_run):
        return None
    hosts = [args.host, socket.gethostname()]
    include_evidence = args.ai_evidence == "redacted"
    if args.ai_dry_run:
        redactor = ai.payload_redactor(findings, hosts, args.ai_redact)
        payload = ai.build_payload(findings, redactor, include_evidence)
        print("AI dry run: this is the data --ai-summary would send (nothing was sent):", file=sys.stderr)
        print(json.dumps(payload, indent=2, sort_keys=True), file=sys.stderr)
        return None
    try:
        return ai.summarize(
            findings,
            model=args.ai_model,
            effort=args.ai_effort,
            include_evidence=include_evidence,
            hosts=hosts,
            redact_terms=args.ai_redact,
        )
    except ai.AISummaryError as exc:
        print(f"warning: AI summary skipped: {exc}", file=sys.stderr)
        return None
    except Exception as exc:  # the summary is optional: never lose the audit report over it
        logging.getLogger(__name__).debug("AI summary failed", exc_info=True)
        print(f"warning: AI summary skipped after an unexpected error: {exc!r}", file=sys.stderr)
        return None


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    checks = build_registry().get_all()
    timeout = 60
    if args.config:
        try:
            config = load_config(args.config)
            checks = apply_config(checks, config)
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_USAGE
        timeout = config.get("command_timeout", timeout)
    if args.timeout is not None:
        if args.timeout <= 0:
            print("error: --timeout must be positive", file=sys.stderr)
            return EXIT_USAGE
        timeout = args.timeout

    if args.list_checks:
        _list_checks(checks)
        return EXIT_OK

    try:
        executor = build_executor(
            host=args.host,
            platform=args.platform,
            transport=args.transport,
            username=args.username,
            password=os.environ.get(PASSWORD_ENV),
            port=args.port,
            key_file=args.key_file,
            accept_unknown_host_keys=args.accept_unknown_host_keys,
            winrm_transport=args.winrm_transport,
            winrm_https=args.winrm_https,
            command_timeout=timeout,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    with executor:
        findings = AuditEngine(checks, command_timeout=timeout).run(executor, hostname=args.host)

    summary = _ai_summary(args, findings)
    rendered = export_findings(
        findings, output_format=args.format, output_file=args.output, ai_summary=summary
    )
    if args.output:
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(rendered)
    return exit_code_for(findings, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
