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

## 3. Create a Python virtual environment

```bash
python -m venv .venv
```

## 4. Activate the virtual environment

### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
```

### Windows Command Prompt

```cmd
.venv\Scripts\activate.bat
```

## 5. Install dependencies

The project has two dependency files:

- `requirements.txt` for core dependencies
- `requirements_web.txt` for the web UI dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r requirements_web.txt
```

## 6. Install the package in editable mode

```bash
python -m pip install -e .
```

This makes the package available as `audit_tool` while still allowing local code changes.

## 7. Run the CLI

### Default audit run

```bash
python run_audit.py --host demo-host --platform linux --format markdown --output report.md
```

### Common CLI options

- `--host`: Target hostname or IP (default: `localhost`)
- `--platform`: `linux` or `windows`
- `--format`: `text`, `json`, or `markdown`
- `--output`: Path to save the report
- `--config`: Optional JSON configuration file path
- `--username`: Optional remote username
- `--port`: SSH port (default: 22)

### Example with a local host

```bash
python run_audit.py --host localhost --platform linux --format text
```

## 8. Run the web UI

```bash
python -m uvicorn web.app:app --reload
```

Then open the browser at:

```
http://127.0.0.1:8000/
```

Use the web form to start an audit and view results in the browser.

## 9. Run the demo script (Windows)

The repository includes a demo batch script:

```cmd
scripts\run_demo.bat
```

This runs a sample audit and writes `demo_report.md`.

## 10. Build release artifacts

To create distributable packages:

```bash
python -m pip install build
python -m build
```

Artifacts will be generated in the `dist/` folder.

## 11. Notes

- The tool supports live SSH execution for Linux and WinRM for Windows when credentials are provided.
- If `ssh` or WinRM connectivity is not available, the tool falls back to placeholder output.
- Use `sample_config.json` as a starting point for custom check configuration.
