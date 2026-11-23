"""Minimal browser UI. Uses the same execution path as the CLI.

Run it with:  python -m uvicorn audit_tool.web:app

Security model:
- HTTP Basic authentication is required. The UI is locked until
  AUDIT_WEB_USERNAME and AUDIT_WEB_PASSWORD (12+ characters) are set.
- Only targets listed in AUDIT_WEB_TARGETS can be audited. Users pick from a
  list and cannot type a hostname, so the UI can't be used to send the
  server's credentials (SSH keys, AUDIT_PASSWORD) to an arbitrary host.
- The audit form carries a CSRF token, so other web pages can't trigger audits
  through a logged-in browser.
- One audit runs at a time.
- Basic auth sends the password with every request: serve over HTTPS
  (uvicorn --ssl-certfile/--ssl-keyfile) whenever it is not bound to localhost.

AUDIT_WEB_TARGETS is a comma-separated list of host:platform[:username], e.g.
    localhost, web01:linux:auditor, win01:windows:CORP\\auditor
"localhost" may omit the platform. IPv6 literals are not supported; use a name.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import logging
import os
import secrets
import threading
from dataclasses import dataclass, field
from typing import List, Mapping, Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from audit_tool.engine import AuditEngine
from audit_tool.executors import LOCAL_HOSTNAMES, PLATFORMS, build_executor
from audit_tool.registry import build_registry
from audit_tool.reports import export_findings

log = logging.getLogger(__name__)

MIN_PASSWORD_LENGTH = 12

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",  # reports describe weaknesses; don't cache them
}

_STYLE = """
      body { font-family: Arial, sans-serif; margin: 2rem; }
      form { max-width: 480px; display: grid; gap: 0.75rem; }
      select, button { padding: 0.6rem; font-size: 1rem; }
      pre { background: #f5f5f5; padding: 1rem; border-radius: 6px; white-space: pre-wrap; }
"""


@dataclass(frozen=True)
class Target:
    host: str
    platform: Optional[str] = None
    username: Optional[str] = None

    @property
    def label(self) -> str:
        label = f"{self.host} ({self.platform or 'this machine'})"
        return f"{label} as {self.username}" if self.username else label


def parse_targets(spec: str) -> List[Target]:
    targets = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        host, _, rest = item.partition(":")
        platform, _, username = rest.partition(":")
        host, platform, username = host.strip(), platform.strip() or None, username.strip() or None
        if not host:
            raise ValueError(f"AUDIT_WEB_TARGETS entry {item!r} has no host")
        if platform is not None and platform not in PLATFORMS:
            raise ValueError(f"AUDIT_WEB_TARGETS entry {item!r}: platform must be one of {', '.join(PLATFORMS)}")
        if platform is None and host not in LOCAL_HOSTNAMES:
            raise ValueError(f"AUDIT_WEB_TARGETS entry {item!r} needs a platform, e.g. {host}:linux")
        targets.append(Target(host, platform, username))
    return targets


@dataclass
class WebSettings:
    username: str = ""
    password: str = ""
    targets: List[Target] = field(default_factory=list)
    secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))

    @property
    def auth_problem(self) -> Optional[str]:
        if not (self.username and self.password):
            return "Web UI is locked: set AUDIT_WEB_USERNAME and AUDIT_WEB_PASSWORD on the server."
        if len(self.password) < MIN_PASSWORD_LENGTH:
            return f"Web UI is locked: AUDIT_WEB_PASSWORD must be at least {MIN_PASSWORD_LENGTH} characters."
        return None

    @property
    def csrf_token(self) -> str:
        return hmac.new(self.secret, b"run-audit", hashlib.sha256).hexdigest()

    @classmethod
    def from_env(cls, environ: Mapping[str, str] = os.environ) -> "WebSettings":
        return cls(
            username=environ.get("AUDIT_WEB_USERNAME", ""),
            password=environ.get("AUDIT_WEB_PASSWORD", ""),
            targets=parse_targets(environ.get("AUDIT_WEB_TARGETS", "")),
        )


def _equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    content = (
        f'<!DOCTYPE html><html><head><meta charset="utf-8" /><title>{html.escape(title)}</title>'
        f"<style>{_STYLE}</style></head><body><h1>{html.escape(title)}</h1>{body}</body></html>"
    )
    return HTMLResponse(content, status_code=status_code)


def create_app(settings: WebSettings) -> FastAPI:
    app = FastAPI(title="AI Infrastructure Audit Tool", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.audit_lock = threading.Lock()
    basic = HTTPBasic(auto_error=False)

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        return response

    def require_user(credentials: Optional[HTTPBasicCredentials] = Depends(basic)) -> str:
        problem = settings.auth_problem
        if problem:
            raise HTTPException(status_code=503, detail=problem)
        # Evaluate both comparisons so timing doesn't reveal which one failed.
        valid = credentials is not None
        user_ok = _equal(credentials.username if valid else "", settings.username)
        password_ok = _equal(credentials.password if valid else "", settings.password)
        if not (valid and user_ok and password_ok):
            if valid:
                log.warning("Failed web UI login for user %r", credentials.username)
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"WWW-Authenticate": 'Basic realm="audit", charset="UTF-8"'},
            )
        return credentials.username

    @app.get("/", response_class=HTMLResponse)
    def index(user: str = Depends(require_user)) -> HTMLResponse:
        if not settings.targets:
            return _page(
                "AI Infrastructure Audit Tool",
                "<p>No audit targets are configured. Set AUDIT_WEB_TARGETS on the server.</p>",
            )
        options = "".join(
            f'<option value="{index}">{html.escape(target.label)}</option>'
            for index, target in enumerate(settings.targets)
        )
        body = (
            f"<p>Signed in as {html.escape(user)}.</p>"
            '<form method="post" action="/run">'
            f'<select name="target">{options}</select>'
            f'<input type="hidden" name="csrf_token" value="{settings.csrf_token}" />'
            '<button type="submit">Run Audit</button></form>'
        )
        return _page("AI Infrastructure Audit Tool", body)

    @app.post("/run", response_class=HTMLResponse)
    def run_audit(
        target: str = Form(""),
        csrf_token: str = Form(""),
        user: str = Depends(require_user),
    ) -> HTMLResponse:
        back = '<p><a href="/">Back</a></p>'
        if not _equal(csrf_token, settings.csrf_token):
            return _page("Request rejected", "<p>Invalid or missing form token. Reload the page.</p>" + back, 403)
        if not (target.isascii() and target.isdigit()) or int(target) >= len(settings.targets):
            return _page("Invalid request", "<p>Unknown target.</p>" + back, 400)
        chosen = settings.targets[int(target)]

        if not app.state.audit_lock.acquire(blocking=False):
            return _page("Busy", "<p>Another audit is running. Try again shortly.</p>" + back, 429)
        try:
            log.info("User %r started an audit of %s", user, chosen.label)
            try:
                executor = build_executor(
                    host=chosen.host,
                    platform=chosen.platform,
                    username=chosen.username,
                    password=os.environ.get("AUDIT_PASSWORD"),
                )
            except ValueError as exc:
                return _page("Invalid target", f"<p>{html.escape(str(exc))}</p>" + back, 400)
            with executor:
                findings = AuditEngine(build_registry().get_all()).run(executor, hostname=chosen.host)
        finally:
            app.state.audit_lock.release()

        report = export_findings(findings, output_format="markdown")
        return _page("Audit Results", f"<pre>{html.escape(report)}</pre>" + back)

    return app


app = create_app(WebSettings.from_env())
