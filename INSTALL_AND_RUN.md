# Install and Run Guide

This document provides step-by-step instructions to install and run the AI Infrastructure Audit Tool.

## 1. Prerequisites

- Python 3.9 or newer installed on your system (3.11 or newer recommended; 3.9 is past end of life).
- Git if you want to clone the repository.
- Internet access to install Python dependencies.

## 2. Clone the repository

```bash
git clone <repository-url>
cd AI-Infrastructure-Audit-Tool
```

## 3. Install on Windows

### 3.1 Create and activate a virtual environment

PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Command Prompt:

```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### 3.2 Install the package and its dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[web,ai]"
```

Upgrading pip first matters: editable installs from `pyproject.toml` need pip 21.3 or newer.
The `[web]` extra adds the web UI and `[ai]` the optional AI summary; leave out what you don't
need. The editable install (`-e`) makes the package available as `audit_tool` while still
allowing local changes. (`requirements*.txt` list the same dependencies for tools that need them.)

## 4. Install on Linux

### 4.1 Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### 4.2 Install the package and its dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[web,ai]"
```

## 5. Run the CLI

The command syntax is the same on Windows and Linux. The installed package also provides the
same CLI as the `infra-audit` command, so `infra-audit --list-checks` is equivalent to
`python run_audit.py --list-checks` (useful when installed from a wheel, without the repository).

### Audit the local machine

```bash
python run_audit.py
```

The platform is detected automatically for `localhost`.

### Audit a remote host

```bash
python run_audit.py --host web01 --platform linux --username auditor --format markdown --output report.md
python run_audit.py --host win01 --platform windows --username auditor --winrm-https
```

- Linux hosts are reached over SSH. Host keys must already be in `known_hosts`
  (connect once with `ssh`, or use `ssh-keyscan`); unknown hosts are rejected.
- Windows hosts are reached over WinRM and run PowerShell. Use `--winrm-https` where possible.
- Passwords are read from the `AUDIT_PASSWORD` environment variable, never from arguments
  (PowerShell: `$env:AUDIT_PASSWORD = "..."`; Linux: `export AUDIT_PASSWORD='...'`).
- Run the audit as root (Linux) or from an elevated shell / Administrator account (Windows).
  Some checks report `error` or `warn` otherwise, and say which rights they need.

### Common CLI options

- `--host`: Target hostname or IP (default: `localhost`)
- `--platform`: `linux` or `windows` (required for remote hosts)
- `--transport`: `auto` (default), `local`, `ssh`, or `winrm`
- `--username`, `--port`, `--key-file`: Remote connection settings
- `--accept-unknown-host-keys`: Accept SSH hosts missing from `known_hosts` (insecure; avoid)
- `--winrm-transport`: `ntlm` (default), `kerberos`, `credssp`, or `basic` (HTTPS only)
- `--winrm-https`: Use WinRM over HTTPS (port 5986)
- `--config`: JSON file with per-check overrides (see `sample_config.json`)
- `--timeout`: Per-command timeout in seconds (default: 60)
- `--fail-on`: Lowest severity of failed check that makes the exit code `1` (default: `low`)
- `--format`: `text`, `json`, or `markdown`
- `--output`: Write the report to a file instead of stdout
- `--list-checks`: Show all checks and whether they are implemented
- `-v`: Log progress to stderr
- `--ai-summary`, `--ai-dry-run` and the other `--ai-*` options: see section 7

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No failed checks at or above `--fail-on` |
| 1 | At least one failed check at or above `--fail-on` |
| 2 | Invalid arguments or configuration, or the report file could not be written (the report is then printed to stdout) |
| 3 | No qualifying failures, but some checks could not run (`error`) |
| 130 | Interrupted with Ctrl+C |

## 6. Run the web UI

### 6.1 Configure it

The web UI reads its settings from environment variables. It stays locked (HTTP 503) until a
username and a password of at least 12 characters are set.

| Variable | Purpose |
| --- | --- |
| `AUDIT_WEB_USERNAME` | Login name for the web UI |
| `AUDIT_WEB_PASSWORD` | Login password (12+ characters) |
| `AUDIT_WEB_TARGETS` | Hosts the UI may audit: comma-separated `host:platform[:username]` |
| `AUDIT_PASSWORD` | Password the server uses to connect to targets (optional with SSH keys) |

Example `AUDIT_WEB_TARGETS`: `localhost, web01:linux:svc_audit, win01:windows:CORP\svc_audit`.
`localhost` may omit the platform. Use host names, not IPv6 addresses.

PowerShell:

```powershell
$env:AUDIT_WEB_USERNAME = "auditor"
$env:AUDIT_WEB_PASSWORD = "at-least-12-characters"
$env:AUDIT_WEB_TARGETS = "localhost, web01:linux:svc_audit"
```

Linux:

```bash
export AUDIT_WEB_USERNAME=auditor
export AUDIT_WEB_PASSWORD='at-least-12-characters'
export AUDIT_WEB_TARGETS='localhost, web01:linux:svc_audit'
```

### 6.2 Start it

```bash
python -m uvicorn audit_tool.web:app
```

(The older `python -m uvicorn web.app:app` still works from a source checkout.)

Then open `http://127.0.0.1:8000/`, sign in, pick a target and run the audit.

### 6.3 Security notes

- Users can only pick from `AUDIT_WEB_TARGETS`. They cannot enter a host name, so the UI cannot
  be used to send the server's SSH keys or `AUDIT_PASSWORD` to a host of their choosing.
- The audit form carries an anti-CSRF token, and responses send headers that block framing,
  caching and content sniffing.
- Only one audit runs at a time; further requests get HTTP 429 until it finishes.
- Logins use HTTP Basic, which sends the password with every request. If the UI is reachable
  from anything other than localhost, serve it over HTTPS:
  `python -m uvicorn audit_tool.web:app --host 0.0.0.0 --ssl-certfile cert.pem --ssl-keyfile key.pem`.
- Failed logins are logged with the attempted username. There is no lockout yet, so keep the UI
  on a trusted network.

## 7. AI summary

The optional AI summary asks Claude to write an executive summary, an overall risk rating and
a prioritized remediation plan from the audit findings. The checks still decide what passed and
failed; the summary only explains and prioritizes, and is marked as AI-generated in every report.

### 7.1 Set it up

Install the `[ai]` extra (section 3 or 4) and provide Anthropic API credentials, either an API
key or a login with the `ant` CLI:

```bash
export ANTHROPIC_API_KEY='...'          # PowerShell: $env:ANTHROPIC_API_KEY = "..."
```

### 7.2 Review what is sent, then run it

```bash
python run_audit.py --ai-dry-run          # prints the redacted data to stderr; sends nothing
python run_audit.py --ai-summary --format markdown --output report.md
```

| Option | Purpose |
| --- | --- |
| `--ai-summary` | Add the AI summary to the report |
| `--ai-dry-run` | Print exactly what would be sent, and send nothing |
| `--ai-model` | Claude model (default `claude-opus-5-5`) |
| `--ai-effort` | `low`, `medium` (default), `high`, `xhigh` or `max`: more effort is slower and costs more |
| `--ai-evidence` | `redacted` (default) or `none` to send only check IDs, statuses and descriptions |
| `--ai-redact TERM` | Another value to hide, such as a company or project name (repeatable) |

### 7.3 What is sent and what is redacted

- Only findings that need attention (`fail`, `warn`, `error`) are sent in full. Passed and
  skipped checks are sent by ID only. If nothing needs attention, no request is made.
- Replaced with placeholders such as `[HOST-1]` or `[USER-2]`: the target and local host names,
  IP and MAC addresses, e-mail addresses, Windows domain SIDs and `DOMAIN\` prefixes, account
  names reported by the checks, the user running the tool, user names in home-directory paths,
  private keys and values of password/secret/token/key settings.
- Kept readable because the analysis needs them: well-known accounts such as `root`,
  `Administrator` and `Guest`, file paths, versions and setting names.
- Placeholders in the answer are mapped back to the real values in your local report.
- Redaction is pattern-based. Review the `--ai-dry-run` output before using the summary with
  sensitive systems, and add `--ai-redact` terms or use `--ai-evidence none` where needed.

### 7.4 If it fails

Missing credentials, network errors, rate limits or a declined request print a warning, and the
report is written without the AI section. The exit code always reflects the audit, never the AI
summary. For models that support it, a request the model declines is automatically retried on a
fallback model, and the report notes which model wrote the summary.

## 8. Run the demo script (Windows)

The repository includes a Windows demo batch script:

```cmd
scripts\run_demo.bat
```

This audits the local machine and writes `demo_report.md`.

## 9. Build release artifacts

To create distributable packages:

```bash
python -m pip install build
python -m build
```

Artifacts will be generated in the `dist/` folder. The release process is in `RELEASE.md`.

## 10. Notes

- If a host cannot be reached, its checks are reported as `error`, never as `pass`.
- Use `sample_config.json` as a starting point for custom check configuration.
- Secrets in `AUDIT_PASSWORD` and `AUDIT_WEB_PASSWORD` are not passed on to the commands the tool runs locally.
