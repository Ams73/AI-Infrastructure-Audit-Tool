# AI Infrastructure Audit Tool

This project is a prototype AI-assisted infrastructure audit tool for Linux and Windows servers. It runs a broad set of security and operational checks, identifies risks, and produces clear reports for administrators and compliance teams.

The tool currently provides:
- a Python-based audit engine
- configurable checks via JSON
- report export in text, JSON, and Markdown formats with summary scoring
- a lightweight browser UI for running audits
- a modular check registry and remote execution foundation with SSH/WinRM support

For a complete install and run walkthrough, see [INSTALL_AND_RUN.md](INSTALL_AND_RUN.md).

## Install

```bash
python -m pip install -r requirements.txt
python -m pip install -r requirements_web.txt
python -m pip install -e .
```

## Run the CLI

```bash
python run_audit.py --host demo-host --platform linux --format markdown --output report.md
```

## Run the web UI

```bash
python -m uvicorn web.app:app --reload
```

Then open http://127.0.0.1:8000/ in your browser.

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
