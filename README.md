# AI Infrastructure Audit Tool

This project is building an AI-assisted infrastructure audit tool for Linux and Windows servers. The goal is to run a broad set of security and operational checks, identify risks, and produce clear reports for administrators and compliance teams.

The tool currently provides:
- a Python-based audit engine
- configurable checks via JSON
- report export in text, JSON, and Markdown formats with summary scoring
- a lightweight browser UI for running audits
- a modular check registry and remote execution foundation

## Run the CLI

```bash
python run_audit.py --host demo-host --platform linux --format markdown --output report.md
```

## Run the web UI

```bash
python -m uvicorn web.app:app --reload
```

Then open http://127.0.0.1:8000/ in your browser.
