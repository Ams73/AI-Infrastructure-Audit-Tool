# AI Infrastructure Audit Tool

Audits Linux and Windows servers for security and operational problems and produces reports
for administrators and compliance teams. Deterministic checks decide what passes and fails; an
optional AI summary (Claude) turns the findings into an executive summary and a prioritized
remediation plan.

The tool provides:
- a check framework where each check runs a command and evaluates its output into
  `pass` / `warn` / `fail` / `error` / `skipped`, with evidence and a recommendation
- local execution, SSH (Linux) and WinRM/PowerShell (Windows), one session per host
- per-check configuration (enable/disable, severity, thresholds) via JSON
- reports in text, JSON and Markdown, with a risk score based on failed checks
- exit codes suitable for CI/CD gating
- an optional AI summary that redacts host names, addresses and account names before sending
- a browser UI with login and a fixed list of audit targets

**Status:** 10 of the 60 planned checks are implemented, 5 per platform:

| Linux | Windows |
| --- | --- |
| `LNX-OS-001` OS release and vendor support (EOL) | `WIN-UPD-001` Patch currency and pending reboot |
| `LNX-ACCT-001` Extra UID 0 and empty-password accounts | `WIN-ADM-001` Administrators group and passwordless accounts |
| `LNX-SSH-001` SSH daemon hardening | `WIN-FW-001` Firewall profiles |
| `LNX-SUDO-001` NOPASSWD and `!authenticate` sudo rules | `WIN-DEF-001` Microsoft Defender status |
| `LNX-DISK-001` Disk space and inode usage | `WIN-BL-001` BitLocker protection |

The remaining checks are listed and report `skipped` until implemented. Run
`python run_audit.py --list-checks`. Run audits as root / Administrator: `LNX-SUDO-001`,
`WIN-BL-001` and parts of other checks cannot see everything otherwise and will say so.
See [sample_report.md](sample_report.md) for an example report.

For a complete install and run walkthrough, see [INSTALL_AND_RUN.md](INSTALL_AND_RUN.md).

## Install

Requires Python 3.9 or newer, in a virtual environment:

```bash
python -m pip install --upgrade pip      # editable installs need pip 21.3 or newer
python -m pip install -e ".[web,ai]"     # drop web/ai if you don't need the web UI or AI summary
```

## Run the CLI

```bash
# Audit this machine (platform detected automatically)
python run_audit.py

# Audit a Linux host over SSH (uses your SSH agent/keys and known_hosts)
python run_audit.py --host web01 --platform linux --username auditor --format markdown --output report.md

# Audit a Windows host over WinRM (password from the environment, never the command line)
export AUDIT_PASSWORD='...'
python run_audit.py --host win01 --platform windows --username 'CORP\auditor' --winrm-https
```

Exit codes: `0` no failed checks, `1` failed checks at or above `--fail-on` (default `low`),
`2` usage or config error, `3` no failures but some checks could not run (`error`).

Many checks need elevated rights (for example `sshd -T` needs root); otherwise they fall back
to less precise data or report `error`.

## AI summary (optional)

```bash
export ANTHROPIC_API_KEY='...'
python run_audit.py --ai-dry-run                       # show exactly what would be sent; sends nothing
python run_audit.py --ai-summary --format markdown --output report.md
```

`--ai-summary` sends the findings that need attention to Claude (`claude-opus-5-5` by default)
and adds an executive summary, overall risk and remediation priorities to the report, marked as
AI-generated. Before sending, host names, IP and MAC addresses, e-mail addresses, domain SIDs,
account names reported by the checks, the current user name and secrets are replaced with
placeholders such as `[HOST-1]`. The placeholders are mapped back in your local report. Use
`--ai-redact TERM` to hide more values, or `--ai-evidence none` to send no evidence at all.
If the summary fails, the audit report and exit code are unaffected. Details in
[INSTALL_AND_RUN.md](INSTALL_AND_RUN.md#7-ai-summary).

## Configuration

`--config` takes a JSON file of per-check overrides. Unknown check IDs, keys or parameters
are rejected so typos can't silently weaken an audit. See [sample_config.json](sample_config.json).

## Adding a check

Add a `Check` to `audit_tool/checks/linux.py` or `audit_tool/checks/windows.py` with a stable ID, a `command`,
an `evaluate(result, params)` function returning an `Evaluation`, and a `recommendation`.
If the evidence names accounts, return them in `Evaluation.accounts` so the AI summary can
redact them. Test the evaluator with recorded command output in `tests/fixtures/` and the
`FakeExecutor` in `tests/fakes.py`.

## Run the tests

```bash
python -m pip install -e ".[web,ai,dev]"
python -m unittest discover
```

CI runs the suite on Python 3.9, 3.12 and 3.13 on Linux and 3.12 on Windows.

## Run the web UI

The web UI requires a login and can only audit hosts from a configured list:

```bash
export AUDIT_WEB_USERNAME=auditor
export AUDIT_WEB_PASSWORD='at-least-12-characters'
export AUDIT_WEB_TARGETS='localhost, web01:linux:svc_audit, win01:windows:CORP\svc_audit'
python -m uvicorn web.app:app
```

Then open http://127.0.0.1:8000/. Until the username and password are set, the UI stays locked.
Logins use HTTP Basic, so serve it over HTTPS (`--ssl-certfile`/`--ssl-keyfile`) if it is reachable
from anywhere other than localhost. See [INSTALL_AND_RUN.md](INSTALL_AND_RUN.md#6-run-the-web-ui).

## Build and install a release artifact

```bash
python -m pip install build
python -m build
python -m pip install "dist/ai_infrastructure_audit_tool-<version>-py3-none-any.whl[web,ai]"
```

The release process is in [RELEASE.md](RELEASE.md) and the version history in
[CHANGELOG.md](CHANGELOG.md). Note: the `v0.1.0` release predates real checks (every check
reported `passed`); use a later version.
