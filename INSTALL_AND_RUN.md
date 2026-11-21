# Install and Run Guide

This document provides step-by-step instructions to install and run the AI Infrastructure Audit Tool.

## 1. Prerequisites

- Python 3.9 or newer installed on your system.
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

### 3.2 Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements_web.txt
```

### 3.3 Install the package in editable mode

```bash
python -m pip install -e .
```

This makes the package available as `audit_tool` while still allowing local changes.

## 4. Install on Linux

### 4.1 Create and activate a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate
```

### 4.2 Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements_web.txt
```

### 4.3 Install the package in editable mode

```bash
python -m pip install -e .
```

## 5. Run the CLI

The command syntax is the same on Windows and Linux.

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
- Passwords are read from the `AUDIT_PASSWORD` environment variable, never from arguments.

### Common CLI options

- `--host`: Target hostname or IP (default: `localhost`)
- `--platform`: `linux` or `windows` (required for remote hosts)
- `--transport`: `auto` (default), `local`, `ssh`, or `winrm`
- `--username`, `--port`, `--key-file`: Remote connection settings
- `--winrm-transport`: `ntlm` (default), `kerberos`, `credssp`, or `basic` (HTTPS only)
- `--config`: JSON file with per-check overrides (see `sample_config.json`)
- `--timeout`: Per-command timeout in seconds (default: 60)
- `--fail-on`: Lowest severity of failed check that makes the exit code `1` (default: `low`)
- `--format`: `text`, `json`, or `markdown`
- `--output`: Write the report to a file instead of stdout
- `--list-checks`: Show all checks and whether they are implemented
- `-v`: Log progress to stderr

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No failed checks at or above `--fail-on` |
| 1 | At least one failed check at or above `--fail-on` |
| 2 | Invalid arguments or configuration |
| 3 | No qualifying failures, but some checks could not run (`error`) |

## 6. Run the web UI

The web UI launch command is the same on Windows and Linux.

```bash
python -m uvicorn web.app:app --reload
```

Then open the browser at:

```
http://127.0.0.1:8000/
```

Use the web form to start an audit and view results in the browser.

## 7. Run the demo script (Windows)

The repository includes a Windows demo batch script:

```cmd
scripts\run_demo.bat
```

This audits the local machine and writes `demo_report.md`.

## 8. Build release artifacts

To create distributable packages:

```bash
python -m pip install build
python -m build
```

Artifacts will be generated in the `dist/` folder.

## 9. Notes

- If a host cannot be reached, its checks are reported as `error`, never as `pass`.
- Use `sample_config.json` as a starting point for custom check configuration.
- The web UI has no authentication yet; keep it bound to localhost.
