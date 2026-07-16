# GitHub Release Draft - v0.1.0

## AI Infrastructure Audit Tool 0.1.0

This first release delivers a working infrastructure audit prototype for Linux and Windows environments.

### Highlights

- **Audit engine + CLI**: Run infrastructure checks from the command line with `run_audit.py`.
- **Report export**: Output audit results in text, JSON, or Markdown formats.
- **Browser UI**: Launch a lightweight FastAPI web interface for ad hoc audits.
- **Remote execution**: Support real SSH-based Linux execution via Paramiko and Windows WinRM via pywinrm.
- **Package build**: Wheel and source distribution are included in `dist/`.
- **CI automation**: GitHub Actions workflow runs tests and builds package artifacts on push.

### Included artifacts

- `dist/ai_infrastructure_audit_tool-0.1.0-py3-none-any.whl`
- `dist/ai_infrastructure_audit_tool-0.1.0.tar.gz`

### Install

```bash
python -m pip install -r requirements.txt
python -m pip install -r requirements_web.txt
python -m pip install -e .
```

### Run

```bash
python run_audit.py --host demo-host --platform linux --format markdown --output report.md
```

### Web UI

```bash
python -m uvicorn web.app:app --reload
```

Then open `http://127.0.0.1:8000/`.

### Notes

- This release is focused on providing a reusable audit foundation and first-run experience.
- The package is ready for distribution and CI-driven build validation.
