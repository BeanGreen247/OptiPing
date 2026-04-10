# Copyright (c) 2026 Tomáš Moždřeň (BeanGreen247)
# https://github.com/BeanGreen247/OptiPing
# MIT License

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import pyotp
import time
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware

from core import Database, MonitorScheduler

log = logging.getLogger("optiping.server")


def create_app(
    db: Database,
    scheduler: MonitorScheduler,
    config: dict,
) -> FastAPI:
    app = FastAPI(title="OptiPing", docs_url=None, redoc_url=None)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    app.state.db = db
    app.state.scheduler = scheduler
    app.state.config = config

    auth_cfg = config.get("auth", {})
    _auth_enabled = auth_cfg.get("enabled", False)
    _auth_user = auth_cfg.get("username", "admin")
    _auth_pass = auth_cfg.get("password", "changeme")

    def _check_auth(request: Request):
        if not _auth_enabled:
            return
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Basic "):
            raise HTTPException(
                status_code=401,
                detail="Unauthorized",
                headers={"WWW-Authenticate": "Basic realm=\"OptiPing\""},
            )
        try:
            decoded = base64.b64decode(auth_header[6:]).decode()
            user, _, pw = decoded.partition(":")
        except Exception:
            raise HTTPException(status_code=401, detail="Bad credentials")
        if user != _auth_user or pw != _auth_pass:
            raise HTTPException(status_code=401, detail="Bad credentials")

    AuthDep = Depends(_check_auth)

    auth_cfg = config.get("auth", {})
    _admin_pw = auth_cfg.get("admin_password", "changeme")
    _totp_secret = auth_cfg.get("totp_secret", "").strip()
    _ADMIN_COOKIE = "optiping_admin"

    def _admin_token() -> str:
        return hmac.new(
            _admin_pw.encode(),
            b"optiping-admin-v1",
            hashlib.sha256,
        ).hexdigest()

    def _require_admin(request: Request):
        cookie = request.cookies.get(_ADMIN_COOKIE, "")
        if not hmac.compare_digest(cookie, _admin_token()):
            raise HTTPException(status_code=403, detail="Admin authentication required")

    AdminDep = Depends(_require_admin)

    @app.get("/health")
    async def health():
        return {"status": "ok", "ts": time.time()}

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        import os
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.jpg")
        if os.path.exists(path):
            return FileResponse(path, media_type="image/jpeg")
        return Response(status_code=204)

    @app.get("/logo", include_in_schema=False)
    async def logo():
        import os
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.jpg")
        if os.path.exists(path):
            return FileResponse(path, media_type="image/jpeg")
        return Response(status_code=204)

    @app.get("/admin", response_class=HTMLResponse)
    async def admin_page(request: Request):
        cookie = request.cookies.get(_ADMIN_COOKIE, "")
        authed = hmac.compare_digest(cookie, _admin_token())
        if not authed:
            return HTMLResponse(_render_admin_login(show_totp=bool(_totp_secret)))
        incidents = app.state.db.get_incidents(include_resolved=True, limit=50)
        return HTMLResponse(_render_admin_dashboard(incidents))

    @app.post("/admin/login")
    async def admin_login(request: Request):
        form = await request.form()
        pw = str(form.get("password", ""))
        if not hmac.compare_digest(pw, _admin_pw):
            return HTMLResponse(_render_admin_login(wrong=True, show_totp=bool(_totp_secret)), status_code=401)
        if _totp_secret:
            code = str(form.get("totp", "")).strip().replace(" ", "")
            if not pyotp.TOTP(_totp_secret).verify(code):
                return HTMLResponse(_render_admin_login(wrong_totp=True, show_totp=True), status_code=401)
        from fastapi.responses import RedirectResponse
        resp = RedirectResponse("/admin", status_code=303)
        resp.set_cookie(
            _ADMIN_COOKIE,
            _admin_token(),
            httponly=True,
            samesite="strict",
            max_age=86400,
        )
        return resp

    @app.post("/admin/logout")
    async def admin_logout():
        from fastapi.responses import RedirectResponse
        resp = RedirectResponse("/admin", status_code=303)
        resp.delete_cookie(_ADMIN_COOKIE)
        return resp

    @app.get("/admin/2fa-setup", response_class=HTMLResponse)
    async def admin_2fa_setup(request: Request):
        cookie = request.cookies.get(_ADMIN_COOKIE, "")
        if not hmac.compare_digest(cookie, _admin_token()):
            from fastapi.responses import RedirectResponse
            return RedirectResponse("/admin", status_code=303)
        title = config.get("server", {}).get("title", "OptiPing")
        return HTMLResponse(_render_2fa_setup(_totp_secret, title))

    @app.get("/api/monitors", dependencies=[AuthDep])
    async def api_monitors():
        states = app.state.scheduler.get_states()
        result = []
        for name, st in states.items():
            result.append({
                **st,
                "uptime_24h": app.state.db.get_uptime_pct(name, 24),
                "uptime_7d":  app.state.db.get_uptime_pct(name, 168),
                "uptime_30d": app.state.db.get_uptime_pct(name, 720),
                "avg_ms_24h": app.state.db.get_avg_latency(name, 24),
            })
        return JSONResponse(result)

    @app.get("/api/monitors/{name}", dependencies=[AuthDep])
    async def api_monitor_detail(name: str):
        states = app.state.scheduler.get_states()
        if name not in states:
            raise HTTPException(404, f"monitor not found: {name!r}")
        st = states[name]
        checks = app.state.db.get_recent_checks(name, limit=200)
        return JSONResponse({
            **st,
            "uptime_24h":   app.state.db.get_uptime_pct(name, 24),
            "uptime_7d":    app.state.db.get_uptime_pct(name, 168),
            "uptime_30d":   app.state.db.get_uptime_pct(name, 720),
            "avg_ms_24h":   app.state.db.get_avg_latency(name, 24),
            "recent_checks": checks[:50],
            "timeline_24h": app.state.db.get_timeline(name, hours=24,  buckets=48),
            "timeline_7d":  app.state.db.get_timeline(name, hours=168, buckets=84),
            "timeline_30d": app.state.db.get_timeline(name, hours=720, buckets=90),
        })

    @app.get("/api/summary", dependencies=[AuthDep])
    async def api_summary():
        states = app.state.scheduler.get_states()
        total = len(states)
        up = sum(1 for s in states.values() if s["status"] == "up")
        down = sum(1 for s in states.values() if s["status"] == "down")
        return JSONResponse({
            "total": total,
            "up": up,
            "down": down,
            "degraded": total - up - down,
            "ts": time.time(),
        })

    @app.get("/api/incidents")
    async def api_incidents(resolved: bool = False):
        return JSONResponse(app.state.db.get_incidents(include_resolved=resolved))

    @app.post("/api/incidents", dependencies=[AdminDep])
    async def api_create_incident(request: Request):
        data = await request.json()
        title = str(data.get("title", "")).strip()
        if not title:
            raise HTTPException(400, "title is required")
        body = str(data.get("body", "")).strip()
        severity = str(data.get("severity", "investigating")).strip()
        valid = {"investigating", "identified", "monitoring", "resolved"}
        if severity not in valid:
            severity = "investigating"
        incident_id = await app.state.db.create_incident(title, body, severity)
        return JSONResponse({"id": incident_id}, status_code=201)

    @app.patch("/api/incidents/{incident_id}", dependencies=[AdminDep])
    async def api_update_incident(incident_id: int, request: Request):
        data = await request.json()
        body = str(data.get("body", "")).strip()
        severity = str(data.get("severity", "investigating")).strip()
        valid = {"investigating", "identified", "monitoring", "resolved"}
        if severity not in valid:
            severity = "investigating"
        if severity == "resolved":
            await app.state.db.resolve_incident(incident_id)
        else:
            await app.state.db.update_incident(incident_id, body, severity)
        return JSONResponse({"ok": True})

    @app.post("/api/incidents/{incident_id}/resolve", dependencies=[AdminDep])
    async def api_resolve_incident(incident_id: int):
        await app.state.db.resolve_incident(incident_id)
        return JSONResponse({"ok": True})

    @app.delete("/api/incidents/{incident_id}", dependencies=[AdminDep])
    async def api_delete_incident(incident_id: int):
        await app.state.db.delete_incident(incident_id)
        return JSONResponse({"ok": True})

    @app.get("/api/stream", dependencies=[AuthDep])
    async def sse_stream(request: Request):
        queue = app.state.scheduler.subscribe()

        async def event_generator():
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        payload = await asyncio.wait_for(queue.get(), timeout=15)
                        data = json.dumps(payload)
                        yield f"data: {data}\n\n"
                    except asyncio.TimeoutError:
                        yield ": heartbeat\n\n"
            finally:
                app.state.scheduler.unsubscribe(queue)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/", response_class=HTMLResponse, dependencies=[AuthDep])
    async def status_page():
        cfg = app.state.config
        title = cfg.get("server", {}).get("title", "OptiPing Status")
        description = cfg.get("server", {}).get("description", "")
        return HTMLResponse(_render_page(title, description))

    return app



def _render_page(title: str, description: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>{title}</title>
  <link rel="icon" href="/favicon.ico" type="image/jpeg"/>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
  <style>
    /* ---- color variables matching beangreen247.xyz ---- */
    :root {{
      --bg:          #ffffff;
      --text:        #1a1a1a;
      --muted:       #555555;
      --accent:      #0066cc;
      --accent-h:    #004499;
      --nav-active:  #101f97;
      --border:      #dddddd;
      --section-bg:  #f8f8f8;
      --tag-bg:      #e8f0fe;
      --up:          #2e7d32;
      --down:        #c62828;
      --degraded:    #e65100;
      --unknown:     #888888;
      --bar-nodata:  #e0e0e0;
      --max-w:       860px;
    }}
    [data-theme="dark"] {{
      --bg:          #111111;
      --text:        #e0e0e0;
      --muted:       #999999;
      --accent:      #4d9fff;
      --accent-h:    #80bcff;
      --nav-active:  #101f97;
      --border:      #2a2a2a;
      --section-bg:  #1a1a1a;
      --tag-bg:      #152030;
      --up:          #43a047;
      --down:        #ef5350;
      --degraded:    #fb8c00;
      --unknown:     #666666;
      --bar-nodata:  #2a2a2a;
    }}

    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    html {{ font-size: 16px; scroll-behavior: smooth; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
    }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ color: var(--accent-h); text-decoration: underline; }}

    /* layout */
    .container {{ max-width: var(--max-w); margin: 0 auto; padding: 0 1.25rem; }}

    /* header */
    header {{
      border-bottom: 1px solid var(--border);
      padding: 1rem 0;
      margin-bottom: 2rem;
      position: sticky; top: 0;
      background: var(--bg);
      z-index: 10;
    }}
    header .inner {{ display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }}
    header h1 {{ font-size: 1.4rem; font-weight: 700; }}
    header p {{ font-size: 0.9rem; color: var(--muted); margin-top: 0.1rem; }}
    .header-right {{ display: flex; align-items: center; gap: 0.75rem; }}

    /* overall badge */
    .badge {{
      font-size: 0.8rem; font-weight: 600;
      padding: 0.2rem 0.7rem;
      border-radius: 4px;
      border: 1px solid var(--border);
      background: var(--section-bg);
      color: var(--muted);
    }}
    .badge.ok   {{ border-color: var(--up);   color: var(--up);   background: transparent; }}
    .badge.down {{ border-color: var(--down); color: var(--down); background: transparent; }}

    /* theme toggle */
    .theme-btn {{
      background: var(--section-bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 0.25rem 0.5rem;
      cursor: pointer;
      color: var(--muted);
      font-size: 0.85rem;
      line-height: 1.4;
    }}
    .theme-btn:hover {{ color: var(--text); border-color: var(--accent); }}

    /* summary row */
    .summary {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 0.75rem;
      margin-bottom: 2rem;
    }}
    .stat-box {{
      background: var(--section-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.9rem 1rem;
      text-align: center;
    }}
    .stat-box .num {{ font-size: 2rem; font-weight: 700; line-height: 1; }}
    .stat-box .lbl {{ font-size: 0.75rem; color: var(--muted); margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.04em; }}
    .stat-box.up-box   .num {{ color: var(--up); }}
    .stat-box.down-box .num {{ color: var(--down); }}

    /* section heading */
    h2 {{
      font-size: 1.1rem; font-weight: 600;
      padding-bottom: 0.4rem;
      border-bottom: 2px solid var(--accent);
      margin-bottom: 1rem;
      color: var(--text);
    }}

    /* monitor list */
    #monitor-list {{ list-style: none; }}
    .monitor-row {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      padding: 0.75rem 0;
      border-bottom: 1px solid var(--border);
      cursor: pointer;
      flex-wrap: wrap;
    }}
    .monitor-row:last-child {{ border-bottom: none; }}
    .monitor-row:hover .mname {{ color: var(--accent); }}
    .monitor-left {{ display: flex; align-items: center; gap: 0.6rem; min-width: 0; }}
    .monitor-right {{ display: flex; align-items: center; gap: 1.5rem; flex-shrink: 0; }}
    .mname {{ font-weight: 600; font-size: 0.95rem; }}
    .mtarget {{ font-size: 0.8rem; color: var(--muted); }}
    .meta-col {{ text-align: right; }}
    .meta-col .meta-lbl {{ font-size: 0.72rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.03em; }}
    .meta-col .meta-val {{ font-size: 0.9rem; font-weight: 600; font-variant-numeric: tabular-nums; }}
    .meta-col .meta-val.mono {{ font-family: "JetBrains Mono", "Fira Code", Consolas, monospace; font-weight: 400; }}
    .status-label {{ font-size: 0.82rem; font-weight: 600; min-width: 72px; text-align: right; }}

    /* status dots */
    .dot {{
      width: 9px; height: 9px; border-radius: 50%; display: inline-block; flex-shrink: 0;
    }}
    .dot-up      {{ background: var(--up); }}
    .dot-down    {{ background: var(--down); }}
    .dot-degraded{{ background: var(--degraded); }}
    .dot-unknown {{ background: var(--unknown); }}

    /* status text colors */
    .c-up      {{ color: var(--up); }}
    .c-down    {{ color: var(--down); }}
    .c-degraded{{ color: var(--degraded); }}
    .c-unknown {{ color: var(--unknown); }}

    /* timeline bars */
    .tl-wrap {{ display: flex; gap: 2px; height: 32px; margin: 0.5rem 0 0.25rem; }}
    .tl-bar  {{
      flex: 1; min-width: 2px; border-radius: 2px; cursor: default;
      transition: opacity 0.12s;
    }}
    .tl-bar:hover {{ opacity: 0.65; }}
    .tl-up       {{ background: var(--up); }}
    .tl-down     {{ background: var(--down); }}
    .tl-degraded {{ background: var(--degraded); }}
    .tl-no_data  {{ background: var(--bar-nodata); }}

    /* detail panel (dialog) */
    dialog {{
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--bg);
      color: var(--text);
      padding: 0;
      max-width: 720px;
      width: calc(100% - 2rem);
      max-height: 90vh;
      overflow-y: auto;
      /* center in viewport */
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      margin: 0;
    }}
    dialog::backdrop {{ background: rgba(0,0,0,0.5); }}
    .dialog-header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 1rem 1.25rem 0.75rem;
      border-bottom: 1px solid var(--border);
    }}
    .dialog-header h3 {{ font-size: 1.1rem; font-weight: 700; }}
    .dialog-close {{
      background: none; border: none; cursor: pointer;
      font-size: 1.1rem; color: var(--muted); line-height: 1;
    }}
    .dialog-close:hover {{ color: var(--text); }}
    .dialog-body {{ padding: 1.25rem; }}

    /* stats grid inside dialog */
    .stat-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
      gap: 0.5rem;
      margin-bottom: 1.25rem;
    }}
    .stat-cell {{
      background: var(--section-bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 0.6rem 0.75rem;
      text-align: center;
    }}
    .stat-cell .sc-lbl {{ font-size: 0.72rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.03em; margin-bottom: 0.25rem; }}
    .stat-cell .sc-val {{ font-size: 1.1rem; font-weight: 700; }}
    .sc-mono {{ font-family: "JetBrains Mono", "Fira Code", Consolas, monospace; font-weight: 400; font-size: 1rem !important; }}

    /* tabs */
    .tabs {{ margin-bottom: 0.5rem; }}
    .tab-btns {{
      display: flex;
      gap: 0;
      background: var(--section-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 3px;
      width: fit-content;
    }}
    .tab-btn {{
      background: transparent;
      border: none;
      padding: 0.35rem 1rem;
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 500;
      color: var(--muted);
      border-radius: 4px;
      transition: all 0.15s;
    }}
    .tab-btn:hover {{ color: var(--text); }}
    .tab-btn.active {{
      color: #fff;
      background: var(--nav-active);
    }}
    .tab-content {{ display: none; }}
    .tab-content.active {{ display: block; animation: fadeIn 0.2s ease; }}

    /* recent checks */
    .checks-list {{ max-height: 200px; overflow-y: auto; margin-top: 0.25rem; }}
    .check-row {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.3rem 0;
      border-bottom: 1px solid var(--border);
      font-size: 0.82rem;
    }}
    .check-row:last-child {{ border-bottom: none; }}
    .check-left {{ display: flex; align-items: center; gap: 0.4rem; }}
    .check-right {{ display: flex; gap: 1rem; color: var(--muted); font-variant-numeric: tabular-nums; }}
    .check-right .ms {{ font-family: "JetBrains Mono", "Fira Code", Consolas, monospace; font-size: 0.8rem; }}
    .check-err {{ color: var(--muted); font-size: 0.78rem; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

    .incident-item {{
      background: var(--section-bg);
      border: 1px solid var(--border);
      border-left: 4px solid var(--degraded);
      border-radius: 6px;
      padding: 0.9rem 1rem;
      margin-bottom: 0.6rem;
    }}
    .incident-item.investigating {{ border-left-color: var(--down); }}
    .incident-item.identified    {{ border-left-color: var(--degraded); }}
    .incident-item.monitoring    {{ border-left-color: #1976d2; }}
    .incident-header {{ display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 0.25rem; }}
    .incident-title {{ font-weight: 700; font-size: 0.95rem; }}
    .incident-badge {{
      font-size: 0.75rem; font-weight: 600;
      padding: 0.15rem 0.55rem; border-radius: 3px;
      background: var(--tag-bg); color: var(--accent);
      text-transform: capitalize;
    }}
    .incident-badge.investigating {{ background: #fde8e8; color: var(--down); }}
    .incident-badge.identified    {{ background: #fff3e0; color: var(--degraded); }}
    .incident-badge.monitoring    {{ background: #e3f2fd; color: #1976d2; }}
    [data-theme="dark"] .incident-badge.investigating {{ background: #3b1a1a; }}
    [data-theme="dark"] .incident-badge.identified    {{ background: #2d1e0a; }}
    [data-theme="dark"] .incident-badge.monitoring    {{ background: #0d1e30; }}
    .incident-body {{ font-size: 0.88rem; color: var(--muted); margin-bottom: 0.3rem; white-space: pre-wrap; }}
    .incident-meta {{ font-size: 0.78rem; color: var(--muted); }}

    footer {{
      border-top: 1px solid var(--border);
      padding: 1.25rem 0;
      margin-top: 3rem;
      text-align: center;
      font-size: 0.85rem;
      color: var(--muted);
    }}

    @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(4px); }} to {{ opacity: 1; transform: none; }} }}

    @media (max-width: 600px) {{
      .monitor-right {{ gap: 0.75rem; }}
      .meta-col:not(:last-child) {{ display: none; }}
      .summary {{ grid-template-columns: repeat(3, 1fr); }}
    }}
  </style>
</head>
<body>

<header>
  <div class="container">
    <div class="inner">
      <div>
        <h1>{title}</h1>
        {f'<p>{description}</p>' if description else ''}
      </div>
      <div class="header-right">
        <span id="overall-badge" class="badge">Loading&hellip;</span>
        <button class="theme-btn" onclick="toggleTheme()" title="Toggle dark/light mode">&#9728; / &#9790;</button>
      </div>
    </div>
  </div>
</header>

<main class="container">

  <div class="summary">
    <div class="stat-box up-box">
      <div class="num" id="sum-up">—</div>
      <div class="lbl">Operational</div>
    </div>
    <div class="stat-box down-box">
      <div class="num" id="sum-down">—</div>
      <div class="lbl">Down</div>
    </div>
    <div class="stat-box">
      <div class="num" id="sum-total">—</div>
      <div class="lbl">Total</div>
    </div>
  </div>

  <!-- Active incidents -->
  <div id="incident-section" style="display:none">
    <h2>Active Incidents</h2>
    <div id="incident-list"></div>
  </div>

  <h2>Monitors</h2>
  <ul id="monitor-list">
    <li style="padding:1rem 0; color:var(--muted); font-size:0.9rem;">Loading&hellip;</li>
  </ul>

</main>

<footer>
  <div class="container">
    OptiPing &mdash; uptime monitor &middot; <span id="footer-ts"></span>
    &middot; <span id="footer-render"></span>
    &middot; <a href="https://github.com/BeanGreen247/OptiPing" target="_blank" rel="noopener">GitHub</a>
  </div>
</footer>

<!-- Detail dialog -->
<dialog id="detail-dialog">
  <div class="dialog-header">
    <h3 id="dlg-title"></h3>
    <button class="dialog-close" onclick="closeDetail()">&#x2715;</button>
  </div>
  <div class="dialog-body" id="dlg-body">
    <p style="color:var(--muted);text-align:center;padding:2rem 0;">Loading&hellip;</p>
  </div>
</dialog>

<script>
// Theme
(function() {{
  const saved = localStorage.getItem('optiping-theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  if (saved === 'dark' || (!saved && prefersDark)) {{
    document.documentElement.setAttribute('data-theme', 'dark');
  }}
}})();

function toggleTheme() {{
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  document.documentElement.setAttribute('data-theme', isDark ? 'light' : 'dark');
  localStorage.setItem('optiping-theme', isDark ? 'light' : 'dark');
  if (activeChart) redrawChart(activeChartData);
}}

// State
let monitors = {{}};
let activeChart = null;
let activeChartData = null;

// Helpers
function esc(s) {{
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

function ago(ts) {{
  const d = Math.floor(Date.now()/1000 - ts);
  if (d < 5)    return 'just now';
  if (d < 60)   return d + 's ago';
  if (d < 3600) return Math.floor(d/60) + 'm ago';
  if (d < 86400)return Math.floor(d/3600) + 'h ago';
  return Math.floor(d/86400) + 'd ago';
}}

function pctColor(p) {{
  if (p >= 99) return 'c-up';
  if (p >= 95) return 'c-degraded';
  return 'c-down';
}}

function dotCls(s)   {{ return 'dot dot-' + (s || 'unknown'); }}
function textCls(s)  {{ return 'c-' + (s || 'unknown'); }}
function statusStr(s){{ return {{up:'Operational', down:'Down', degraded:'Degraded', unknown:'Pending'}}[s] || s; }}

function cssVar(name) {{
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}}

// Monitors list
async function fetchMonitors() {{
  const _t0 = performance.now();
  try {{
    const data = await fetch('/api/monitors').then(r => r.json());
    data.forEach(m => monitors[m.name] = m);
    renderList();
    const _elapsed = (performance.now() - _t0).toFixed(0);
    const _rEl = document.getElementById('footer-render');
    if (_rEl) _rEl.textContent = 'rendered in ' + _elapsed + 'ms';
  }} catch(e) {{
    document.getElementById('monitor-list').innerHTML =
      '<li style="color:var(--down);padding:1rem 0">Failed to load monitors.</li>';
  }}
  fetchSummary();
}}

async function fetchSummary() {{
  try {{
    const d = await fetch('/api/summary').then(r => r.json());
    document.getElementById('sum-up').textContent    = d.up;
    document.getElementById('sum-down').textContent  = d.down;
    document.getElementById('sum-total').textContent = d.total;

    const badge = document.getElementById('overall-badge');
    if (d.total === 0) {{
      badge.className = 'badge'; badge.textContent = 'No monitors';
    }} else if (d.down === 0) {{
      badge.className = 'badge ok'; badge.textContent = 'All Systems Operational';
    }} else {{
      badge.className = 'badge down';
      badge.textContent = d.down + ' Service' + (d.down > 1 ? 's' : '') + ' Down';
    }}

    document.getElementById('footer-ts').textContent =
      'Last updated ' + new Date().toLocaleTimeString();
  }} catch(e) {{}}
}}

function renderList() {{
  const ul = document.getElementById('monitor-list');
  const items = Object.values(monitors);
  if (!items.length) {{
    ul.innerHTML = '<li style="padding:1rem 0;color:var(--muted)">No monitors configured.</li>';
    return;
  }}
  ul.innerHTML = items.map(m => {{
    const u24  = m.uptime_24h  != null ? m.uptime_24h.toFixed(2)  + '%' : '—';
    const u30  = m.uptime_30d  != null ? m.uptime_30d.toFixed(2)  + '%' : '—';
    const lat  = m.avg_ms_24h  != null ? m.avg_ms_24h.toFixed(1)  + ' ms' : '—';
    const last = m.last_check  ? ago(m.last_check) : 'never';
    return `<li class="monitor-row" onclick="openDetail('${{esc(m.name)}}')">
      <div class="monitor-left">
        <span class="${{dotCls(m.status)}}"></span>
        <div>
          <div class="mname">${{esc(m.name)}}</div>
          <div class="mtarget">${{esc(m.target)}} &middot; ${{m.kind}}</div>
        </div>
      </div>
      <div class="monitor-right">
        <div class="meta-col">
          <div class="meta-lbl">24h</div>
          <div class="meta-val ${{pctColor(m.uptime_24h||0)}}">${{u24}}</div>
        </div>
        <div class="meta-col">
          <div class="meta-lbl">30d</div>
          <div class="meta-val ${{pctColor(m.uptime_30d||0)}}">${{u30}}</div>
        </div>
        <div class="meta-col">
          <div class="meta-lbl">Latency</div>
          <div class="meta-val mono">${{lat}}</div>
        </div>
        <div class="meta-col">
          <div class="meta-lbl">Checked</div>
          <div class="meta-val" style="font-weight:400;color:var(--muted)">${{last}}</div>
        </div>
        <div class="status-label ${{textCls(m.status)}}">${{statusStr(m.status)}}</div>
      </div>
    </li>`;
  }}).join('');
}}

// Detail dialog
async function openDetail(name) {{
  const dlg = document.getElementById('detail-dialog');
  document.getElementById('dlg-title').textContent = name;
  document.getElementById('dlg-body').innerHTML =
    '<p style="color:var(--muted);text-align:center;padding:2rem 0;">Loading&hellip;</p>';
  dlg.showModal();

  if (activeChart) {{ activeChart.destroy(); activeChart = null; activeChartData = null; }}

  try {{
    const d = await fetch('/api/monitors/' + encodeURIComponent(name)).then(r => r.json());
    renderDetail(d);
  }} catch(e) {{
    document.getElementById('dlg-body').innerHTML =
      '<p style="color:var(--down);text-align:center;padding:2rem 0;">Failed to load data.</p>';
  }}
}}

function closeDetail() {{
  document.getElementById('detail-dialog').close();
  if (activeChart) {{ activeChart.destroy(); activeChart = null; activeChartData = null; }}
}}

document.getElementById('detail-dialog')
  .addEventListener('click', e => {{ if (e.target.id === 'detail-dialog') closeDetail(); }});
document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closeDetail(); }});

function renderDetail(d) {{
  const u24  = d.uptime_24h  != null ? d.uptime_24h.toFixed(2)  + '%' : '—';
  const u7   = d.uptime_7d   != null ? d.uptime_7d.toFixed(2)   + '%' : '—';
  const u30  = d.uptime_30d  != null ? d.uptime_30d.toFixed(2)  + '%' : '—';
  const lat  = d.avg_ms_24h  != null ? d.avg_ms_24h.toFixed(1)  + ' ms' : '—';
  const last = d.last_check  ? new Date(d.last_check * 1000).toLocaleString() : 'Never';

  document.getElementById('dlg-body').innerHTML = `
    <div class="stat-grid">
      <div class="stat-cell">
        <div class="sc-lbl">Status</div>
        <div class="sc-val ${{textCls(d.status)}}" style="display:flex;align-items:center;justify-content:center;gap:0.4rem">
          <span class="${{dotCls(d.status)}}"></span> ${{statusStr(d.status)}}
        </div>
      </div>
      <div class="stat-cell">
        <div class="sc-lbl">24h uptime</div>
        <div class="sc-val ${{pctColor(d.uptime_24h||0)}}">${{u24}}</div>
      </div>
      <div class="stat-cell">
        <div class="sc-lbl">7d uptime</div>
        <div class="sc-val ${{pctColor(d.uptime_7d||0)}}">${{u7}}</div>
      </div>
      <div class="stat-cell">
        <div class="sc-lbl">30d uptime</div>
        <div class="sc-val ${{pctColor(d.uptime_30d||0)}}">${{u30}}</div>
      </div>
      <div class="stat-cell">
        <div class="sc-lbl">Avg latency</div>
        <div class="sc-val sc-mono">${{lat}}</div>
      </div>
    </div>

    <div class="tabs">
      <div class="tab-btns">
        <button class="tab-btn active" onclick="switchTab(this,'tl-24h',d)">24h</button>
        <button class="tab-btn"        onclick="switchTab(this,'tl-7d', d)">7d</button>
        <button class="tab-btn"        onclick="switchTab(this,'tl-30d',d)">30d</button>
      </div>
    </div>

    <div id="tl-24h" class="tab-content active">
      <div class="tl-wrap" id="bars-24h"></div>
      <canvas id="chart-24h" height="70" style="margin-top:0.5rem"></canvas>
    </div>
    <div id="tl-7d" class="tab-content">
      <div class="tl-wrap" id="bars-7d"></div>
      <canvas id="chart-7d" height="70" style="margin-top:0.5rem"></canvas>
    </div>
    <div id="tl-30d" class="tab-content">
      <div class="tl-wrap" id="bars-30d"></div>
      <canvas id="chart-30d" height="70" style="margin-top:0.5rem"></canvas>
    </div>

    <p style="font-size:0.78rem;color:var(--muted);margin:0.75rem 0 1.25rem">Last checked: ${{last}}</p>

    <h2 style="font-size:0.9rem;border-bottom-width:1px">Recent checks</h2>
    <div class="checks-list">
      ${{(d.recent_checks||[]).map(c => `
        <div class="check-row">
          <div class="check-left">
            <span class="${{dotCls(c.status)}}"></span>
            <span class="${{textCls(c.status)}}" style="font-weight:600;font-size:0.82rem">${{c.status}}</span>
            ${{c.error ? `<span class="check-err" title="${{esc(c.error)}}">${{esc(c.error.slice(0,60))}}</span>` : ''}}
          </div>
          <div class="check-right">
            <span class="ms">${{c.response_ms != null ? c.response_ms.toFixed(1)+'ms' : '—'}}</span>
            <span>${{ago(c.checked_at)}}</span>
          </div>
        </div>`).join('')}}
    </div>
  `;

  renderBars(d.timeline_24h, 'bars-24h');
  renderBars(d.timeline_7d,  'bars-7d');
  renderBars(d.timeline_30d, 'bars-30d');
  drawChart('chart-24h', d.timeline_24h);
  activeChartData = d.timeline_24h;
}}

function renderBars(data, id) {{
  const el = document.getElementById(id);
  if (!el || !data) return;
  el.innerHTML = data.map(b => {{
    const tip = b.avg_ms ? b.avg_ms.toFixed(1)+'ms' : (b.status || 'no data');
    return `<div class="tl-bar tl-${{b.status||'no_data'}}" title="${{tip}}"></div>`;
  }}).join('');
}}

function switchTab(btn, tabId, d) {{
  btn.closest('.tabs').querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.getElementById(tabId).classList.add('active');

  if (activeChart) {{ activeChart.destroy(); activeChart = null; }}
  const tlMap = {{ 'tl-24h': d.timeline_24h, 'tl-7d': d.timeline_7d, 'tl-30d': d.timeline_30d }};
  const tl = tlMap[tabId];
  const chartId = tabId.replace('tl-', 'chart-');
  activeChartData = tl;
  drawChart(chartId, tl);
}}

function drawChart(canvasId, timeline) {{
  const ctx = document.getElementById(canvasId);
  if (!ctx || !timeline) return;

  const labels = timeline.map(b =>
    new Date(b.t * 1000).toLocaleString([], {{month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'}})
  );
  const data = timeline.map(b => b.avg_ms);

  const accent  = cssVar('--accent');
  const gridClr = cssVar('--border');
  const txtClr  = cssVar('--muted');

  activeChart = new Chart(ctx, {{
    type: 'line',
    data: {{
      labels,
      datasets: [{{
        label: 'Latency (ms)',
        data,
        borderColor: accent,
        backgroundColor: accent + '22',
        fill: true,
        tension: 0.35,
        pointRadius: 0,
        borderWidth: 1.5,
        spanGaps: true,
      }}]
    }},
    options: {{
      responsive: true,
      animation: false,
      interaction: {{
        mode: 'index',
        intersect: false,
      }},
      plugins: {{
        legend: {{ display: false }},
        tooltip: {{
          callbacks: {{
            label: ctx => ctx.raw != null ? ctx.raw.toFixed(1) + ' ms' : 'no data',
            title: items => items[0].label,
          }}
        }}
      }},
      scales: {{
        x: {{ display: false }},
        y: {{
          min: 0,
          ticks: {{ color: txtClr, callback: v => v + 'ms', maxTicksLimit: 4 }},
          grid: {{ color: gridClr }},
          border: {{ display: false }},
        }}
      }}
    }}
  }});
}}

function redrawChart(data) {{
  if (!activeChart || !data) return;
  const canvas = activeChart.canvas;
  activeChart.destroy();
  activeChart = null;
  drawChart(canvas.id, data);
}}

// Incidents (read-only display)
const SEVERITY_LABEL = {{
  investigating: 'Investigating',
  identified:    'Identified',
  monitoring:    'Monitoring',
  resolved:      'Resolved',
}};

async function fetchIncidents() {{
  try {{
    const data = await fetch('/api/incidents').then(r => r.json());
    renderIncidents(data);
  }} catch(_) {{}}
}}

function renderIncidents(list) {{
  const section = document.getElementById('incident-section');
  const container = document.getElementById('incident-list');
  if (!list || !list.length) {{
    section.style.display = 'none';
    return;
  }}
  section.style.display = 'block';
  container.innerHTML = list.map(inc => {{
    const created = new Date(inc.created_at * 1000).toLocaleString();
    const updated = inc.updated_at !== inc.created_at
      ? ' &middot; updated ' + ago(inc.updated_at) : '';
    const bodyHtml = inc.body
      ? `<div class="incident-body">${{esc(inc.body)}}</div>` : '';
    return `<div class="incident-item ${{inc.severity}}" id="inc-${{inc.id}}">
      <div class="incident-header">
        <span class="incident-title">${{esc(inc.title)}}</span>
        <span class="incident-badge ${{inc.severity}}">${{SEVERITY_LABEL[inc.severity] || inc.severity}}</span>
      </div>
      ${{bodyHtml}}
      <div class="incident-meta">Posted ${{created}}${{updated}}</div>
    </div>`;
  }}).join('');
}}

// SSE — real-time updates
function startSSE() {{
  const es = new EventSource('/api/stream');
  es.onmessage = e => {{
    try {{
      const d = JSON.parse(e.data);
      if (monitors[d.monitor_name]) {{
        monitors[d.monitor_name].status         = d.status;
        monitors[d.monitor_name].last_check     = d.checked_at;
        monitors[d.monitor_name].last_response_ms = d.response_ms;
        renderList();
        fetchSummary();
      }}
    }} catch(_) {{}}
  }};
  es.onerror = () => {{ es.close(); setTimeout(startSSE, 5000); }};
}}

// Boot
let _monitorTimer = null;
let _incidentTimer = null;

function startPolling() {{
  if (_monitorTimer) clearInterval(_monitorTimer);
  if (_incidentTimer) clearInterval(_incidentTimer);
  _monitorTimer  = setInterval(fetchMonitors,  60000);
  _incidentTimer = setInterval(fetchIncidents, 60000);
}}

function stopPolling() {{
  clearInterval(_monitorTimer);
  clearInterval(_incidentTimer);
  _monitorTimer = _incidentTimer = null;
}}

document.addEventListener('visibilitychange', () => {{
  if (document.hidden) {{
    stopPolling();
  }} else {{
    fetchMonitors();
    fetchIncidents();
    startPolling();
  }}
}});

fetchMonitors();
fetchIncidents();
startSSE();
startPolling();
</script>
</body>
</html>"""


_ADMIN_CSS = """
  :root {
    --bg: #ffffff; --text: #1a1a1a; --muted: #555555;
    --accent: #0066cc; --accent-h: #004499;
    --border: #dddddd; --section-bg: #f8f8f8;
    --down: #c62828; --up: #2e7d32;
  }
  [data-theme="dark"] {
    --bg: #111111; --text: #e0e0e0; --muted: #999999;
    --accent: #4d9fff; --accent-h: #80bcff;
    --border: #2a2a2a; --section-bg: #1a1a1a;
    --down: #ef5350; --up: #43a047;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
  }
  a { color: var(--accent); text-decoration: none; }
  a:hover { color: var(--accent-h); text-decoration: underline; }
  .container { max-width: 860px; margin: 0 auto; padding: 2rem 1.25rem; }
  h1 { font-size: 1.4rem; font-weight: 700; margin-bottom: 0.25rem; }
  h2 { font-size: 1.1rem; font-weight: 600; padding-bottom: 0.4rem;
       border-bottom: 2px solid var(--accent); margin: 1.5rem 0 1rem; }
  .card {
    background: var(--section-bg); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.5rem; max-width: 360px; margin: 3rem auto;
  }
  .card h2 { margin-top: 0; }
  label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.4rem; }
  input[type=password], .totp-inp {
    width: 100%; padding: 0.45rem 0.7rem; font-size: 0.9rem;
    border: 1px solid var(--border); border-radius: 4px;
    background: var(--bg); color: var(--text); margin-bottom: 1rem;
  }
  input[type=password]:focus, .totp-inp:focus { outline: none; border-color: var(--accent); }
  .totp-inp { letter-spacing: 0.25em; text-align: center; font-size: 1.1rem; }
  .btn {
    display: inline-block; padding: 0.45rem 1.2rem; font-size: 0.9rem;
    background: var(--accent); color: #fff; border: none; border-radius: 4px;
    cursor: pointer; font-family: inherit;
  }
  .btn:hover { background: var(--accent-h); }
  .btn-sm {
    font-size: 0.8rem; padding: 0.25rem 0.7rem; border: 1px solid var(--border);
    background: var(--section-bg); color: var(--muted); border-radius: 4px;
    cursor: pointer; font-family: inherit;
  }
  .btn-sm:hover { border-color: var(--accent); color: var(--text); }
  .btn-danger { border-color: var(--down); color: var(--down); }
  .btn-danger:hover { background: var(--down); color: #fff; }
  .err { color: var(--down); font-size: 0.85rem; margin-bottom: 0.75rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  th { text-align: left; font-size: 0.75rem; text-transform: uppercase;
       letter-spacing: 0.04em; color: var(--muted); padding: 0.4rem 0.6rem;
       border-bottom: 2px solid var(--border); }
  td { padding: 0.6rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  .sev { font-size: 0.75rem; font-weight: 600; padding: 0.15rem 0.5rem;
         border-radius: 3px; text-transform: capitalize; }
  .sev-investigating { background: #fde8e8; color: var(--down); }
  .sev-identified    { background: #fff3e0; color: #e65100; }
  .sev-monitoring    { background: #e3f2fd; color: #1976d2; }
  .sev-resolved      { background: #e8f5e9; color: var(--up); }
  .form-row { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
  .form-row input, .form-row select, .form-row textarea {
    font-size: 0.85rem; padding: 0.35rem 0.6rem;
    border: 1px solid var(--border); border-radius: 4px;
    background: var(--bg); color: var(--text); font-family: inherit;
  }
  .form-row input:focus, .form-row select:focus, .form-row textarea:focus {
    outline: none; border-color: var(--accent);
  }
  .inp-title { flex: 1; min-width: 180px; }
  .inp-body  { flex: 1; min-width: 180px; }
  .nav { display: flex; align-items: center; justify-content: space-between;
         padding: 0.75rem 0; margin-bottom: 1.5rem;
         border-bottom: 1px solid var(--border); }
  .nav-title { font-weight: 700; font-size: 1.1rem; }
  .resolved-row td { opacity: 0.55; }
"""


def _render_admin_login(wrong: bool = False, show_totp: bool = False, wrong_totp: bool = False) -> str:
    if wrong:
        err = '<p class="err">Incorrect password.</p>'
    elif wrong_totp:
        err = '<p class="err">Incorrect authenticator code.</p>'
    else:
        err = ""
    totp_field = (
        '\n      <label for="totp">Authenticator code</label>'
        '\n      <input id="totp" type="text" name="totp" class="totp-inp"'
        ' inputmode="numeric" maxlength="6" pattern="[0-9]*"'
        ' autocomplete="one-time-code" placeholder="000000"/>'
    ) if show_totp else ""
    theme_init = """
<script>
(function(){
  const s=localStorage.getItem('optiping-theme');
  const d=window.matchMedia('(prefers-color-scheme:dark)').matches;
  if(s==='dark'||(! s&&d)) document.documentElement.setAttribute('data-theme','dark');
})();
</script>"""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>OptiPing Admin</title>
  <link rel="icon" href="/favicon.ico" type="image/jpeg"/>
  <style>{_ADMIN_CSS}</style>
  {theme_init}
</head>
<body>
<div class="container">
  <div class="card">
    <h2>Admin Login</h2>
    <p style="font-size:0.85rem;color:var(--muted);margin-bottom:1rem;">
      This page is not linked from the public status page.
    </p>
    {err}
    <form method="POST" action="/admin/login">
      <label for="pw">Admin password</label>
      <input id="pw" type="password" name="password" autofocus autocomplete="current-password"/>
      {totp_field}
      <button class="btn" type="submit">Sign in</button>
    </form>
    <a href="/" style="display:inline-block;margin-top:1rem;font-size:0.85rem">&#8592; Back to status page</a>
  </div>
</div>
</body>
</html>"""


def _render_admin_dashboard(incidents: list) -> str:
    sev_opts = ["investigating", "identified", "monitoring", "resolved"]

    def sev_badge(s: str) -> str:
        return f'<span class="sev sev-{s}">{s}</span>'

    rows = ""
    for inc in incidents:
        from datetime import datetime
        created = datetime.fromtimestamp(inc["created_at"]).strftime("%Y-%m-%d %H:%M")
        updated = datetime.fromtimestamp(inc["updated_at"]).strftime("%Y-%m-%d %H:%M")
        resolved_cell = (
            datetime.fromtimestamp(inc["resolved_at"]).strftime("%Y-%m-%d %H:%M")
            if inc.get("resolved_at") else "—"
        )
        tr_cls = " class=\"resolved-row\"" if inc.get("resolved_at") else ""
        actions = ""
        if not inc.get("resolved_at"):
            actions = (
                f'<form method="POST" action="/api/incidents/{inc["id"]}/resolve" style="display:inline">'
                f'<button class="btn-sm btn-danger" type="submit">Resolve</button>'
                f'</form>'
            )
        actions += (
            f' <button class="btn-sm btn-danger" '
            f"onclick=\"deleteIncident({inc['id']})\" type=\"button\">Delete</button>"
        )
        body_escaped = str(inc.get("body") or "").replace("&", "&amp;").replace("<", "&lt;")
        rows += f"""<tr{tr_cls}>
  <td>{inc["id"]}</td>
  <td><strong>{str(inc["title"]).replace("&","&amp;").replace("<","&lt;")}</strong>
      {"<br><small>" + body_escaped + "</small>" if body_escaped else ""}</td>
  <td>{sev_badge(inc["severity"])}</td>
  <td>{created}</td>
  <td>{updated}</td>
  <td>{resolved_cell}</td>
  <td>{actions}</td>
</tr>"""

    sev_options = "".join(
        f'<option value="{s}">{s.capitalize()}</option>' for s in sev_opts[:3]
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>OptiPing Admin</title>
  <link rel="icon" href="/favicon.ico" type="image/jpeg"/>
  <style>{_ADMIN_CSS}</style>
  <script>
  (function(){{
    const s=localStorage.getItem('optiping-theme');
    const d=window.matchMedia('(prefers-color-scheme:dark)').matches;
    if(s==='dark'||(!s&&d)) document.documentElement.setAttribute('data-theme','dark');
  }})();
  </script>
</head>
<body>
<div class="container">
  <div class="nav">
    <span class="nav-title">OptiPing Admin</span>
    <div style="display:flex;gap:0.75rem;align-items:center">
      <a href="/">&#8592; Status page</a>
      <a href="/admin/2fa-setup">2FA Setup</a>
      <form method="POST" action="/admin/logout" style="display:inline">
        <button class="btn-sm" type="submit">Sign out</button>
      </form>
    </div>
  </div>

  <h2>Post Incident</h2>
  <form id="inc-form">
    <div class="form-row">
      <input class="inp-title" id="inc-title" type="text" placeholder="Incident title&hellip;" maxlength="200" required/>
      <select id="inc-sev">{sev_options}</select>
    </div>
    <div class="form-row">
      <textarea class="inp-body" id="inc-body" rows="2" placeholder="Details (optional)&hellip;"></textarea>
      <button class="btn" type="submit">Post</button>
    </div>
    <p id="inc-msg" style="font-size:0.85rem;margin-top:0.4rem"></p>
  </form>

  <h2>Incidents</h2>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Title / Body</th><th>Severity</th>
        <th>Created</th><th>Updated</th><th>Resolved</th><th></th>
      </tr>
    </thead>
    <tbody id="inc-table">{rows}</tbody>
  </table>
</div>
<script>
document.getElementById('inc-form').addEventListener('submit', async e => {{
  e.preventDefault();
  const title = document.getElementById('inc-title').value.trim();
  const sev   = document.getElementById('inc-sev').value;
  const body  = document.getElementById('inc-body').value.trim();
  const msg   = document.getElementById('inc-msg');
  if (!title) return;
  const r = await fetch('/api/incidents', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{title, severity: sev, body}}),
  }});
  if (r.ok) {{
    msg.style.color = 'var(--up)';
    msg.textContent = 'Incident posted. Reloading\u2026';
    setTimeout(() => location.reload(), 800);
  }} else {{
    msg.style.color = 'var(--down)';
    msg.textContent = 'Failed (' + r.status + ')';
  }}
}});

async function deleteIncident(id) {{
  if (!confirm('Permanently delete this incident? This cannot be undone.')) return;
  const r = await fetch('/api/incidents/' + id, {{ method: 'DELETE' }});
  if (r.ok) {{
    location.reload();
  }} else {{
    alert('Delete failed (' + r.status + ')');
  }}
}}
</script>
</body>
</html>"""


def _qr_img_tag(data: str) -> str:
    import base64
    import io
    import qrcode
    import qrcode.image.svg
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgFillImage)
    buf = io.BytesIO()
    img.save(buf)
    b64 = base64.b64encode(buf.getvalue()).decode()
    return f'<img src="data:image/svg+xml;base64,{b64}" width="200" height="200" style="display:block;background:#fff;padding:8px;border-radius:4px" alt="TOTP QR code"/>'


def _render_2fa_setup(totp_secret: str, issuer: str) -> str:
    theme_init = """
<script>
(function(){
  const s=localStorage.getItem('optiping-theme');
  const d=window.matchMedia('(prefers-color-scheme:dark)').matches;
  if(s==='dark'||(! s&&d)) document.documentElement.setAttribute('data-theme','dark');
})();
</script>"""
    if not totp_secret:
        body = """
  <div class="card" style="max-width:480px">
    <h2>2FA Setup</h2>
    <p>Two-factor authentication is <strong>not configured</strong>.</p>
    <p style="font-size:0.85rem;color:var(--muted);margin:0.75rem 0">To enable it:</p>
    <ol style="padding-left:1.2rem;font-size:0.88rem;line-height:2.2">
      <li>Generate a secret key:<br>
        <code>python3 -c "import pyotp; print(pyotp.random_base32())"</code>
      </li>
      <li>Add it to <code>config.toml</code> under <code>[auth]</code>:<br>
        <code>totp_secret = "&lt;your-secret-here&gt;"</code>
      </li>
      <li>Restart OptiPing, then return here to scan the QR code.</li>
    </ol>
    <a href="/admin" style="font-size:0.85rem;margin-top:1rem;display:inline-block">&#8592; Back to dashboard</a>
  </div>"""
    else:
        totp = pyotp.TOTP(totp_secret)
        uri = totp.provisioning_uri(name="admin", issuer_name=issuer)
        try:
            qr_svg = _qr_img_tag(uri)
        except Exception:
            qr_svg = '<p style="color:var(--down)">QR render failed — scan the URI manually.</p>'
        body = f"""
  <div class="card" style="max-width:420px">
    <h2>2FA Setup</h2>
    <p style="color:var(--up);font-weight:600;margin-bottom:0.5rem">&#10003; 2FA is active</p>
    <p style="font-size:0.85rem;color:var(--muted);margin-bottom:1rem">
      Scan with Google Authenticator, Authy, or any TOTP app.
    </p>
    <div style="display:flex;justify-content:center;margin-bottom:1.25rem">
      {qr_svg}
    </div>
    <p style="font-size:0.8rem;color:var(--muted);margin-bottom:0.25rem">Manual entry (Base32 secret):</p>
    <code style="display:block;word-break:break-all;padding:0.4rem 0.6rem;
      background:var(--section-bg);border:1px solid var(--border);
      border-radius:4px;font-size:0.9rem;margin-bottom:1rem">{totp_secret}</code>
    <a href="/admin" style="font-size:0.85rem">&#8592; Back to dashboard</a>
  </div>"""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>OptiPing Admin &mdash; 2FA Setup</title>
  <link rel="icon" href="/favicon.ico" type="image/jpeg"/>
  <style>{_ADMIN_CSS}</style>
  {theme_init}
</head>
<body>
<div class="container">
  {body}
</div>
</body>
</html>"""
