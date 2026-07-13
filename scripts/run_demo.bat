@echo off
setlocal
python run_audit.py --host demo-host --platform linux --format markdown --output demo_report.md
echo Demo report written to demo_report.md
