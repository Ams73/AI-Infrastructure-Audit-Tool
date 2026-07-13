from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
from audit_tool.engine import AuditEngine, build_checks_from_config
from audit_tool.reports import export_findings

app = FastAPI(title="AI Infrastructure Audit Tool")

HTML_PAGE = """
<!DOCTYPE html>
<html>
  <head>
    <meta charset=\"utf-8\" />
    <title>AI Infrastructure Audit Tool</title>
    <style>
      body { font-family: Arial, sans-serif; margin: 2rem; }
      form { max-width: 480px; display: grid; gap: 0.75rem; }
      input, select, button { padding: 0.6rem; font-size: 1rem; }
      pre { background: #f5f5f5; padding: 1rem; border-radius: 6px; }
    </style>
  </head>
  <body>
    <h1>AI Infrastructure Audit Tool</h1>
    <p>Run a lightweight audit from the browser.</p>
    <form method=\"post\" action=\"/run\">
      <input name=\"host\" placeholder=\"Hostname or IP\" required />
      <select name=\"platform\">
        <option value=\"linux\">Linux</option>
        <option value=\"windows\">Windows</option>
      </select>
      <button type=\"submit\">Run Audit</button>
    </form>
  </body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return HTML_PAGE


@app.post("/run", response_class=HTMLResponse)
def run_audit(host: str = Form(...), platform: str = Form(...)) -> str:
    checks = build_checks_from_config()
    engine = AuditEngine(checks)
    findings = engine.run(hostname=host, platform=platform)
    report = export_findings(findings, output_format="markdown")
    return f"<html><body><h1>Audit Results</h1><pre>{report}</pre></body></html>"
