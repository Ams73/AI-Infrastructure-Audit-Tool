"""Minimal browser UI. Uses the same execution path as the CLI.

Security note: this UI has no authentication. Anyone who can reach it can make
the server connect to hosts using its SSH agent/keys and AUDIT_PASSWORD. Only
bind it to localhost (the uvicorn default) until authentication is added.
"""
import html
import os

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse

from audit_tool.engine import AuditEngine
from audit_tool.executors import PLATFORMS, build_executor
from audit_tool.registry import build_registry
from audit_tool.reports import export_findings

app = FastAPI(title="AI Infrastructure Audit Tool")

_STYLE = """
      body { font-family: Arial, sans-serif; margin: 2rem; }
      form { max-width: 480px; display: grid; gap: 0.75rem; }
      input, select, button { padding: 0.6rem; font-size: 1rem; }
      pre { background: #f5f5f5; padding: 1rem; border-radius: 6px; white-space: pre-wrap; }
"""

HTML_PAGE = f"""
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>AI Infrastructure Audit Tool</title>
    <style>{_STYLE}</style>
  </head>
  <body>
    <h1>AI Infrastructure Audit Tool</h1>
    <p>Run an audit from the browser. Use <code>localhost</code> to audit this machine.</p>
    <form method="post" action="/run">
      <input name="host" placeholder="Hostname or IP" required />
      <select name="platform">
        <option value="linux">Linux</option>
        <option value="windows">Windows</option>
      </select>
      <input name="username" placeholder="Username (optional)" />
      <button type="submit">Run Audit</button>
    </form>
  </body>
</html>
"""


def _page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    content = (
        f'<!DOCTYPE html><html><head><meta charset="utf-8" /><title>{html.escape(title)}</title>'
        f"<style>{_STYLE}</style></head><body><h1>{html.escape(title)}</h1>{body}"
        '<p><a href="/">Run another audit</a></p></body></html>'
    )
    return HTMLResponse(content, status_code=status_code)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return HTML_PAGE


@app.post("/run", response_class=HTMLResponse)
def run_audit(host: str = Form(...), platform: str = Form(...), username: str = Form("")) -> HTMLResponse:
    if platform not in PLATFORMS:
        return _page("Invalid request", f"<p>Unknown platform: {html.escape(platform)}</p>", 400)
    try:
        executor = build_executor(
            host=host.strip(),
            platform=platform,
            username=username.strip() or None,
            password=os.environ.get("AUDIT_PASSWORD"),
        )
    except ValueError as exc:
        return _page("Invalid request", f"<p>{html.escape(str(exc))}</p>", 400)

    with executor:
        findings = AuditEngine(build_registry().get_all()).run(executor, hostname=host.strip())
    report = export_findings(findings, output_format="markdown")
    return _page("Audit Results", f"<pre>{html.escape(report)}</pre>")
