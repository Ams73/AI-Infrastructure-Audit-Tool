"""Compatibility shim for `uvicorn web.app:app` from a source checkout.

The web UI now lives in the package as audit_tool.web, which is what gets
installed. Use:  python -m uvicorn audit_tool.web:app
"""
from audit_tool.web import app  # noqa: F401
