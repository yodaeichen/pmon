"""Patchmonitor – Schwachstellen-Dashboard für Action1, NAS und Linux."""
import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from . import __version__
from .config import settings
from .db import SessionLocal, init_db
from .models import Source, utcnow
from .risk import PRIORITIES, priority, severity_de
from .security import csrf_token

log = logging.getLogger("patchmonitor")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

BASE = Path(__file__).parent
TZ = ZoneInfo(os.environ.get("DISPLAY_TZ", "Europe/Berlin"))
templates = Jinja2Templates(directory=str(BASE / "templates"))


def fmt_dt(value, fmt="%d.%m.%Y %H:%M"):
    if not value:
        return "–"
    if isinstance(value, datetime):
        return value.replace(tzinfo=ZoneInfo("UTC")).astimezone(TZ).strftime(fmt)
    return str(value)


def ago(value):
    if not value:
        return "nie"
    delta = utcnow() - value
    s = int(delta.total_seconds())
    if s < 0:
        return "gleich"
    if s < 90:
        return "gerade eben"
    if s < 3600:
        return f"vor {s // 60} Min."
    if s < 86400:
        return f"vor {s // 3600} Std."
    return f"vor {s // 86400} Tg."


templates.env.filters["lookup"] = lambda ids, m: sorted(m.get(i, "") for i in ids)
templates.env.globals.update(
    version=__version__, PRIORITIES=PRIORITIES, priority=priority, severity_de=severity_de,
    fmt_dt=fmt_dt, ago=ago, repo=settings.repo,
)


# ------------------------------------------------------------ Scheduler
async def scheduler() -> None:
    from . import scanner

    last_feed = None
    await asyncio.sleep(10)
    while True:
        try:
            now = utcnow()
            db = SessionLocal()
            try:
                due = [s.id for s in db.query(Source).filter(Source.enabled.is_(True)).all()
                       if (s.next_run is None or s.next_run <= now) and not scanner.is_running(s.id)]
            finally:
                db.close()
            for sid in due:
                await asyncio.to_thread(scanner.run_source, sid)
            if last_feed is None or now - last_feed > timedelta(hours=12):
                last_feed = now
                await asyncio.to_thread(scanner.refresh_feeds)
        except Exception:  # noqa: BLE001
            log.exception("Scheduler-Fehler")
        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from .bootstrap import ensure_admin

    ensure_admin()
    task = asyncio.create_task(scheduler()) if settings.scheduler_enabled else None
    yield
    if task:
        task.cancel()


app = FastAPI(title="Patchmonitor", version=__version__, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


app.add_middleware(SessionMiddleware, secret_key=settings.secret_key, session_cookie="pmon_session",
                   max_age=12 * 3600, same_site="lax", https_only=False)


# Nach SessionMiddleware registriert = äußere Schicht, sieht also das Sitzungs-Cookie
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
    # Sitzungs-Cookie nur über HTTPS senden, wenn der Reverse Proxy HTTPS meldet
    if request.url.scheme == "https":
        cookies = response.headers.getlist("set-cookie")
        if cookies:
            del response.headers["set-cookie"]
            for c in cookies:
                if "secure" not in c.lower():
                    c += "; Secure"
                response.headers.append("set-cookie", c)
    return response


app.mount("/static", StaticFiles(directory=str(BASE / "static")), name="static")

from . import web  # noqa: E402

app.include_router(web.router)


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"status": "ok", "version": __version__}


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 303 and exc.headers and exc.headers.get("Location"):
        return RedirectResponse(exc.headers["Location"], status_code=303)
    if request.url.path.startswith("/static"):
        return HTMLResponse("Nicht gefunden", status_code=exc.status_code)
    user = web.current_user(request)
    if not user and exc.status_code in (401, 403, 404):
        return RedirectResponse("/login", status_code=303)
    titles = {400: "Ungültige Anfrage", 403: "Keine Berechtigung", 404: "Nicht gefunden"}
    message = exc.detail if exc.status_code != 404 else "Diese Seite gibt es nicht (mehr)."
    return templates.TemplateResponse(request, "error.html", {
        "user": user, "title": titles.get(exc.status_code, "Fehler"), "message": message,
        "csrf": csrf_token(request.session), "path": request.url.path}, status_code=exc.status_code)
