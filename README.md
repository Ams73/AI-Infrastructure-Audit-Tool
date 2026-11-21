# AI Infrastructure Audit Tool

This project is a prototype AI-assisted infrastructure audit tool for Linux and Windows servers. It runs a broad set of security and operational checks, identifies risks, and produces clear reports for administrators and compliance teams.

The tool currently provides:
- a check framework where each check runs a command and evaluates its output into
  `pass` / `warn` / `fail` / `error` / `skipped`, with evidence and a recommendation
- local execution, SSH (Linux) and WinRM/PowerShell (Windows), one session per host
- per-check configuration (enable/disable, severity, thresholds) via JSON
- report export in text, JSON, and Markdown with a risk score based on failed checks
- exit codes suitable for CI/CD gating
- a lightweight browser UI for running audits

**Status:** the framework is in place; 4 of the 60 planned checks are implemented
(`LNX-SSH-001`, `LNX-DISK-001`, `WIN-FW-001`, `WIN-DEF-001`). The remaining checks are
listed and report `skipped` until implemented. Run `python run_audit.py --list-checks`.

For a complete install and run walkthrough, see [INSTALL_AND_RUN.md](INSTALL_AND_RUN.md).

## Install

```bash
python -m pip install -r requirements.txt
python -m pip install -r requirements_web.txt
python -m pip install -e .
```

## Run the CLI

```bash
# Audit this machine (platform detected automatically)
python run_audit.py

# Audit a Linux host over SSH (uses your SSH agent/keys and known_hosts)
python run_audit.py --host web01 --platform linux --username auditor --format markdown --output report.md

# Audit a Windows host over WinRM (password from the environment, never the command line)
export AUDIT_PASSWORD='...'
python run_audit.py --host win01 --platform windows --username 'CORPuditor' --winrm-https
```

Exit codes: `0` no failed checks, `1` failed checks at or above `--fail-on` (default `low`),
`2` usage or config error, `3` no failures but some checks could not run (`error`).

Many checks need elevated rights (for example `sshd -T` needs root); otherwise they fall back
to less precise data or report `error`.

## Configuration

`--config` takes a JSON file of per-check overrides. Unknown check IDs, keys or parameters
are rejected so typos can't silently weaken an audit. See [sample_config.json](sample_config.json).

## Adding a check

Add a `Check` to `audit_tool/checks/linux.py` or `windows.py` with a stable ID, a `command`,
an `evaluate(result, params)` function returning an `Evaluation`, and a `recommendation`.
Test the evaluator with recorded command output in `tests/fixtures/` and the `FakeExecutor`
in `tests/fakes.py`.

## Run the tests

```bash
python -m unittest discover
```

## Run the web UI

```bash
python -m uvicorn web.app:app --reload
```

Then open http://127.0.0.1:8000/ in your browser. The web UI has no authentication yet and
can connect to hosts with the server's credentials, so keep it bound to localhost.

## Build a release artifact

```bash
python -m pip install build
python -m build
```

Built artifacts will be written to the dist/ directory.

## Install from the built wheel

```bash
python -m pip install dist/ai_infrastructure_audit_tool-0.1.0-py3-none-any.whl
```
