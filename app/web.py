"""Web-Oberfläche (Seiten und Formulare)."""
import csv
import io
import json
from collections import Counter, defaultdict
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from sqlalchemy.orm import Session

from . import notify, scanner, settings_store
from .collectors import action1
from .collectors.base import CollectorError
from .db import get_db
from .models import ROLES, Cve, Device, Finding, ScanRun, Software, Source, Tenant, User, utcnow
from .remediation import steps as remediation_steps
from .remediation import vendor_link
from .risk import PRIORITIES, priority, sort_key
from .security import (check_csrf, csrf_token, decrypt_json, encrypt_json, hash_password, throttle,
                       verify_password)

router = APIRouter()

SOURCE_KINDS = {
    "action1": {"label": "Action1", "hint": "Windows-, macOS- und Linux-Endpoints inkl. CVEs aus Action1"},
    "synology": {"label": "Synology NAS", "hint": "DSM-Version und Pakete per SSH, Abgleich mit der NVD"},
    "qnap": {"label": "QNAP NAS", "hint": "QTS/QuTS-hero-Version und Apps per SSH, Abgleich mit der NVD"},
    "linux": {"label": "Linux / Proxmox", "hint": "Paketliste per SSH, Abgleich mit OSV.dev"},
}
KIND_LABELS = {"windows": "Windows", "mac": "macOS", "linux": "Linux", "proxmox": "Proxmox VE",
               "synology": "Synology", "qnap": "QNAP"}


# ------------------------------------------------------------ Hilfen
def current_user(request: Request) -> User | None:
    uid = request.session.get("uid")
    if not uid:
        return None
    from .db import SessionLocal

    db = SessionLocal()
    try:
        u = db.get(User, uid)
        if u and u.is_active and request.session.get("pwv") == u.password_hash[-12:]:
            _ = list(u.tenants)
            return u
    finally:
        db.close()
    return None


class NeedLogin(Exception):
    pass


def require_user(request: Request) -> User:
    u = current_user(request)
    if not u:
        raise HTTPException(status_code=303, headers={"Location": "/login?next=" + request.url.path})
    return u


def require_manager(user: User = Depends(require_user)) -> User:
    if not user.can_manage:
        raise HTTPException(status_code=403, detail="Keine Berechtigung")
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Nur für Administratoren")
    return user


async def csrf_ok(request: Request) -> None:
    form = await request.form()
    if not check_csrf(request.session, form.get("csrf")):
        raise HTTPException(status_code=400, detail="Sitzung abgelaufen – bitte Seite neu laden.")


def visible_tenants(db: Session, user: User) -> list[Tenant]:
    q = db.query(Tenant).order_by(Tenant.name)
    ids = {t.id for t in user.tenants}
    if ids:
        return [t for t in q.all() if t.id in ids]
    if user.role == "leser":
        return []
    return q.all()


def render(request: Request, name: str, ctx: dict, status: int = 200):
    ctx.setdefault("user", None)
    ctx["csrf"] = csrf_token(request.session)
    ctx["flash"] = request.session.pop("flash", None)
    ctx["path"] = request.url.path
    return _templates().TemplateResponse(request, name, ctx, status_code=status)


def _templates():
    from .main import templates

    return templates


def flash(request: Request, msg: str, kind: str = "ok") -> None:
    request.session["flash"] = {"msg": msg, "kind": kind}


def back(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def open_findings(db: Session, tenant_ids: list[int], tenant: int | None = None):
    q = (db.query(Finding).join(Device, Finding.device_id == Device.id)
         .filter(Finding.status == "open", Device.tenant_id.in_(tenant_ids or [-1])))
    if tenant:
        q = q.filter(Device.tenant_id == tenant)
    return q


# ------------------------------------------------------------ Anmeldung
@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/"):
    if current_user(request):
        return back("/")
    return render(request, "login.html", {"next": next})


@router.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...),
                next: str = Form("/"), db: Session = Depends(get_db), _=Depends(csrf_ok)):
    ip = request.client.host if request.client else "?"
    if throttle.blocked(username, ip):
        return render(request, "login.html", {"next": next, "error":
                      "Zu viele Fehlversuche – bitte 10 Minuten warten."}, 429)
    u = db.query(User).filter(User.username == username.strip()).first()
    if not u or not u.is_active or not verify_password(password, u.password_hash):
        throttle.fail(username, ip)
        return render(request, "login.html", {"next": next, "error": "Benutzername oder Passwort falsch."}, 401)
    throttle.reset(username, ip)
    request.session.clear()
    request.session["uid"] = u.id
    request.session["pwv"] = u.password_hash[-12:]
    u.last_login = utcnow()
    db.commit()
    if not next.startswith("/") or next.startswith("//"):
        next = "/"
    return back(next)


@router.post("/logout")
async def logout(request: Request, _=Depends(csrf_ok)):
    request.session.clear()
    return back("/login")


@router.get("/konto", response_class=HTMLResponse)
def konto(request: Request, user: User = Depends(require_user)):
    return render(request, "konto.html", {"user": user, "title": "Mein Konto"})


@router.post("/konto")
async def konto_save(request: Request, current: str = Form(...), new: str = Form(...), repeat: str = Form(...),
                     user: User = Depends(require_user), db: Session = Depends(get_db), _=Depends(csrf_ok)):
    u = db.get(User, user.id)
    if not verify_password(current, u.password_hash):
        flash(request, "Aktuelles Passwort ist falsch.", "err")
    elif len(new) < 10 or new != repeat:
        flash(request, "Neues Passwort: mindestens 10 Zeichen und zweimal gleich eingeben.", "err")
    else:
        u.password_hash = hash_password(new)
        db.commit()
        request.session["pwv"] = u.password_hash[-12:]
        flash(request, "Passwort geändert.")
    return back("/konto")


# ------------------------------------------------------------ Dashboard
@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    tenants = visible_tenants(db, user)
    tids = [t.id for t in tenants]
    findings = open_findings(db, tids).all()
    devices = db.query(Device).filter(Device.tenant_id.in_(tids or [-1])).all()
    stale_days = int(settings_store.get(db, "stale_days") or 7)
    stale_before = utcnow() - timedelta(days=stale_days)

    by_prio = Counter(priority(f.cve) for f in findings)
    kev_findings = [f for f in findings if f.cve and f.cve.kev]
    affected = {f.device_id for f in findings}
    stale = [d for d in devices if d.last_seen and d.last_seen < stale_before]

    # Je Kunde
    per_tenant = []
    dev_by_tenant = Counter(d.tenant_id for d in devices)
    f_by_tenant: dict[int, list] = defaultdict(list)
    for f in findings:
        f_by_tenant[f.device.tenant_id].append(f)
    for t in tenants:
        fl = f_by_tenant.get(t.id, [])
        c = Counter(priority(f.cve) for f in fl)
        light = "rot" if c["sofort"] else "gelb" if c["hoch"] else "gruen"
        per_tenant.append({"t": t, "devices": dev_by_tenant.get(t.id, 0), "open": len(fl), "c": c,
                           "light": light, "affected": len({f.device_id for f in fl})})
    per_tenant.sort(key=lambda x: ({"rot": 0, "gelb": 1, "gruen": 2}[x["light"]], -x["open"]))

    # Top-Risiken je CVE
    groups: dict[str, dict] = {}
    for f in findings:
        g = groups.setdefault(f.cve_id, {"cve": f.cve, "devices": set(), "products": set(), "tenants": set()})
        g["devices"].add(f.device_id)
        if f.product:
            g["products"].add(f.product)
        g["tenants"].add(f.device.tenant_id)
    top = sorted(groups.values(), key=lambda g: (sort_key(g["cve"]), -len(g["devices"])))[:10]

    sources = db.query(Source).order_by(Source.name).all() if user.can_manage else []
    runs = (db.query(ScanRun).order_by(ScanRun.started.desc()).limit(6).all()) if user.can_manage else []
    return render(request, "dashboard.html", {
        "user": user, "title": "Übersicht", "tenants": per_tenant, "top": top,
        "kpi": {"open": len(findings), "cves": len(groups), "sofort": by_prio["sofort"],
                "kev": len({f.cve_id for f in kev_findings}), "affected": len(affected),
                "devices": len(devices), "stale": len(stale)},
        "by_prio": by_prio, "sources": sources, "runs": runs, "stale_days": stale_days,
        "tenant_names": {t.id: t.name for t in tenants},
    })


# ------------------------------------------------------- Schwachstellen
@router.get("/schwachstellen", response_class=HTMLResponse)
def vulns(request: Request, kunde: int | None = None, prio: str = "", kev: str = "", q: str = "",
          quelle: str = "", user: User = Depends(require_user), db: Session = Depends(get_db)):
    tenants = visible_tenants(db, user)
    findings = open_findings(db, [t.id for t in tenants], kunde).all()
    groups: dict[str, dict] = {}
    for f in findings:
        if quelle and f.origin != quelle:
            continue
        g = groups.setdefault(f.cve_id, {"cve": f.cve, "devices": set(), "products": set(),
                                         "tenants": set(), "fixes": set(), "first": f.first_seen})
        g["devices"].add(f.device_id)
        g["tenants"].add(f.device.tenant_id)
        if f.product:
            g["products"].add(f.product)
        if f.fixed_version:
            g["fixes"].add(f.fixed_version)
        g["first"] = min(g["first"], f.first_seen)
    rows = list(groups.values())
    if prio:
        rows = [g for g in rows if priority(g["cve"]) == prio]
    if kev:
        rows = [g for g in rows if g["cve"] and g["cve"].kev]
    if q:
        ql = q.lower()
        rows = [g for g in rows if ql in g["cve"].id.lower() or any(ql in p.lower() for p in g["products"])
                or ql in (g["cve"].description or "").lower()]
    rows.sort(key=lambda g: (sort_key(g["cve"]), -len(g["devices"])))
    return render(request, "vulns.html", {
        "user": user, "title": "Schwachstellen", "rows": rows[:1000], "total": len(rows),
        "tenants": tenants, "tenant_names": {t.id: t.name for t in tenants},
        "f": {"kunde": kunde, "prio": prio, "kev": kev, "q": q, "quelle": quelle},
    })


@router.get("/schwachstellen/{cve_id}", response_class=HTMLResponse)
def vuln_detail(request: Request, cve_id: str, user: User = Depends(require_user), db: Session = Depends(get_db)):
    cve = db.get(Cve, cve_id.upper()) or db.get(Cve, cve_id)
    if not cve:
        raise HTTPException(404)
    tids = [t.id for t in visible_tenants(db, user)]
    rows = (db.query(Finding).join(Device, Finding.device_id == Device.id)
            .filter(Finding.cve_id == cve.id, Device.tenant_id.in_(tids or [-1]))
            .order_by(Finding.status, Device.name).all())
    if not rows and not user.can_manage:
        raise HTTPException(404)
    items = []
    for f in rows:
        items.append({"f": f, "d": f.device, "steps": remediation_steps(f, f.device, cve),
                      "vendor": vendor_link(f.device)})
    first_open = next((i for i in items if i["f"].status == "open"), items[0] if items else None)
    refs = json.loads(cve.references_json or "[]")
    console = settings_store.get(db, "action1_console_url")
    return render(request, "vuln_detail.html", {
        "user": user, "title": cve.id, "cve": cve, "items": items, "refs": refs,
        "prio": priority(cve), "main_steps": first_open["steps"] if first_open else [],
        "console": console, "kinds": KIND_LABELS,
    })


@router.post("/funde/{fid}/status")
async def finding_status(request: Request, fid: int, status: str = Form(...), note: str = Form(""),
                         user: User = Depends(require_manager), db: Session = Depends(get_db),
                         _=Depends(csrf_ok)):
    f = db.get(Finding, fid)
    tids = {t.id for t in visible_tenants(db, user)}
    if not f or f.device.tenant_id not in tids:
        raise HTTPException(404)
    if status in ("open", "accepted"):
        f.status = status
        f.note = note.strip()[:1000]
        db.commit()
        flash(request, "Als akzeptiertes Risiko markiert." if status == "accepted" else "Wieder geöffnet.")
    return back(f"/schwachstellen/{f.cve_id}")


@router.get("/export/schwachstellen.csv")
def export_csv(kunde: int | None = None, user: User = Depends(require_user), db: Session = Depends(get_db)):
    tids = [t.id for t in visible_tenants(db, user)]
    rows = open_findings(db, tids, kunde).all()
    rows.sort(key=lambda f: (f.device.tenant.name if f.device.tenant else "", sort_key(f.cve)))
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["Kunde", "Gerät", "Typ", "CVE", "Priorität", "CVSS", "EPSS", "Aktiv ausgenutzt", "Produkt",
                "Installiert", "Behoben in / Update", "Quelle", "Erstmals gesehen"])
    for f in rows:
        c = f.cve
        w.writerow([f.device.tenant.name if f.device.tenant else "", f.device.name,
                    KIND_LABELS.get(f.device.kind, f.device.kind), f.cve_id, PRIORITIES[priority(c)]["label"],
                    c.cvss if c and c.cvss is not None else "", f"{c.epss:.3f}" if c and c.epss is not None else "",
                    "ja" if c and c.kev else "nein", f.product, f.installed_version, f.fixed_version, f.origin,
                    f.first_seen.strftime("%Y-%m-%d") if f.first_seen else ""])
    data = "﻿" + buf.getvalue()  # BOM, damit Excel Umlaute richtig liest
    return StreamingResponse(iter([data]), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": "attachment; filename=pmon-schwachstellen.csv"})


# --------------------------------------------------------------- Geräte
@router.get("/geraete", response_class=HTMLResponse)
def devices(request: Request, kunde: int | None = None, typ: str = "", q: str = "",
            user: User = Depends(require_user), db: Session = Depends(get_db)):
    tenants = visible_tenants(db, user)
    tids = [t.id for t in tenants]
    qry = db.query(Device).filter(Device.tenant_id.in_(tids or [-1]))
    if kunde:
        qry = qry.filter(Device.tenant_id == kunde)
    if typ:
        qry = qry.filter(Device.kind == typ)
    devs = qry.order_by(Device.name).all()
    if q:
        devs = [d for d in devs if q.lower() in d.name.lower() or q.lower() in (d.address or "").lower()]
    counts: dict[int, Counter] = defaultdict(Counter)
    for f in open_findings(db, tids, kunde).all():
        counts[f.device_id][priority(f.cve)] += 1
    stale_days = int(settings_store.get(db, "stale_days") or 7)
    return render(request, "devices.html", {
        "user": user, "title": "Geräte", "devices": devs, "counts": counts, "tenants": tenants,
        "kinds": KIND_LABELS, "f": {"kunde": kunde, "typ": typ, "q": q},
        "stale_before": utcnow() - timedelta(days=stale_days),
    })


@router.get("/geraete/{did}", response_class=HTMLResponse)
def device_detail(request: Request, did: int, sw: str = "", user: User = Depends(require_user),
                  db: Session = Depends(get_db)):
    d = db.get(Device, did)
    if not d or d.tenant_id not in {t.id for t in visible_tenants(db, user)}:
        raise HTTPException(404)
    findings = db.query(Finding).filter(Finding.device_id == d.id).all()
    open_f = sorted([f for f in findings if f.status == "open"], key=lambda f: sort_key(f.cve))
    other = sorted([f for f in findings if f.status != "open"], key=lambda f: f.last_seen or utcnow(), reverse=True)
    sq = db.query(Software).filter(Software.device_id == d.id)
    if sw:
        sq = sq.filter(Software.name.ilike(f"%{sw}%"))
    software = sq.order_by(Software.name).limit(1500).all()
    return render(request, "device_detail.html", {
        "user": user, "title": d.name, "d": d, "open": open_f, "other": other[:100],
        "software": software, "sw": sw, "kinds": KIND_LABELS, "vendor": vendor_link(d),
        "sw_total": db.query(Software).filter(Software.device_id == d.id).count(),
    })


# ---------------------------------------------------------------- Kunden
@router.get("/kunden", response_class=HTMLResponse)
def tenants_page(request: Request, user: User = Depends(require_manager), db: Session = Depends(get_db)):
    tenants = db.query(Tenant).order_by(Tenant.name).all()
    dev_count = Counter(d.tenant_id for d in db.query(Device.tenant_id).all())
    return render(request, "tenants.html", {"user": user, "title": "Kunden", "tenants": tenants,
                                            "dev_count": dev_count})


@router.post("/kunden")
async def tenant_save(request: Request, tid: int | None = Form(None), name: str = Form(...),
                      note: str = Form(""), action1_org_id: str = Form(""),
                      user: User = Depends(require_manager), db: Session = Depends(get_db), _=Depends(csrf_ok)):
    t = db.get(Tenant, tid) if tid else Tenant()
    if t is None:
        raise HTTPException(404)
    t.name, t.note, t.action1_org_id = name.strip()[:160], note.strip(), action1_org_id.strip() or None
    db.add(t)
    db.commit()
    flash(request, f"Kunde „{t.name}“ gespeichert.")
    return back("/kunden")


@router.post("/kunden/{tid}/loeschen")
async def tenant_delete(request: Request, tid: int, user: User = Depends(require_admin),
                        db: Session = Depends(get_db), _=Depends(csrf_ok)):
    t = db.get(Tenant, tid)
    if t:
        for d in db.query(Device).filter(Device.tenant_id == t.id).all():
            db.query(Finding).filter(Finding.device_id == d.id).delete()
            db.query(Software).filter(Software.device_id == d.id).delete()
            db.delete(d)
        db.query(Source).filter(Source.tenant_id == t.id).update({Source.tenant_id: None})
        db.delete(t)
        db.commit()
        flash(request, "Kunde samt Geräten und Funden gelöscht.")
    return back("/kunden")


# ---------------------------------------------------------------- Quellen
def _source_form_ctx(request, user, db, src, kind, cfg, sec_keys, error=None):
    return render(request, "source_form.html", {
        "user": user, "title": "Quelle" if src and src.id else "Neue Quelle", "src": src, "kind": kind,
        "kinds": SOURCE_KINDS, "cfg": cfg, "sec_keys": sec_keys, "regions": action1.REGIONS,
        "tenants": db.query(Tenant).order_by(Tenant.name).all(), "error": error,
    })


@router.get("/quellen", response_class=HTMLResponse)
def sources_page(request: Request, user: User = Depends(require_manager), db: Session = Depends(get_db)):
    sources = db.query(Source).order_by(Source.name).all()
    dev_count = Counter(d.source_id for d in db.query(Device.source_id).all())
    return render(request, "sources.html", {"user": user, "title": "Quellen", "sources": sources,
                                            "kinds": SOURCE_KINDS, "dev_count": dev_count,
                                            "running": {s.id for s in sources if scanner.is_running(s.id)}})


@router.get("/quellen/neu", response_class=HTMLResponse)
def source_new(request: Request, typ: str = "", user: User = Depends(require_manager), db: Session = Depends(get_db)):
    if typ not in SOURCE_KINDS:
        return render(request, "source_pick.html", {"user": user, "title": "Neue Quelle", "kinds": SOURCE_KINDS})
    defaults = {"region": "eu", "inventory": True, "only_open": True, "port": 22, "os": "qts"}
    return _source_form_ctx(request, user, db, None, typ, defaults, set())


@router.get("/quellen/{sid}", response_class=HTMLResponse)
def source_edit(request: Request, sid: int, user: User = Depends(require_manager), db: Session = Depends(get_db)):
    src = db.get(Source, sid)
    if not src:
        raise HTTPException(404)
    return _source_form_ctx(request, user, db, src, src.kind, json.loads(src.config_json or "{}"),
                            set(decrypt_json(src.secret_enc).keys()))


SECRET_FIELDS = {"client_id", "client_secret", "password", "private_key", "passphrase"}
CONFIG_FIELDS = {"region", "base_url", "org_ids", "host", "port", "username", "display_name", "os", "cpe_map"}
BOOL_FIELDS = {"inventory", "only_open"}


@router.post("/quellen/speichern")
async def source_save(request: Request, user: User = Depends(require_manager), db: Session = Depends(get_db),
                      _=Depends(csrf_ok)):
    form = await request.form()
    sid = form.get("sid")
    kind = form.get("kind", "")
    if kind not in SOURCE_KINDS:
        raise HTTPException(400)
    src = db.get(Source, int(sid)) if sid else Source(kind=kind)
    cfg = json.loads(src.config_json or "{}") if src.id else {}
    sec = decrypt_json(src.secret_enc) if src.id else {}
    src.name = (form.get("name") or SOURCE_KINDS[kind]["label"]).strip()[:160]
    tid = form.get("tenant_id")
    src.tenant_id = int(tid) if tid else None
    src.enabled = form.get("enabled") == "on"
    try:
        src.interval_minutes = max(15, min(10080, int(form.get("interval_minutes") or 60)))
    except ValueError:
        src.interval_minutes = 60
    old_host = (cfg.get("host"), cfg.get("port"))
    for k in CONFIG_FIELDS:
        if k in form:
            cfg[k] = str(form.get(k)).strip()
    for k in BOOL_FIELDS:
        cfg[k] = form.get(k) == "on"
    if (cfg.get("host"), cfg.get("port")) != old_host:
        cfg.pop("host_key", None)  # anderer Host → Schlüssel neu lernen
    for k in SECRET_FIELDS:
        v = form.get(k)
        if v:
            sec[k] = str(v).strip() if k != "private_key" else str(v).replace("\r\n", "\n").strip() + "\n"
        if form.get(f"clear_{k}") == "on":
            sec.pop(k, None)
    error = None
    if kind == "action1" and not (sec.get("client_id") and sec.get("client_secret")):
        error = "Client-ID und Client-Secret sind erforderlich."
    if kind != "action1":
        if not cfg.get("host") or not cfg.get("username"):
            error = "Host und SSH-Benutzer sind erforderlich."
        elif not (sec.get("password") or sec.get("private_key")):
            error = "Bitte Passwort oder privaten SSH-Schlüssel angeben."
        elif not src.tenant_id:
            error = "Bitte einen Kunden zuordnen."
    src.config_json = json.dumps(cfg)
    src.secret_enc = encrypt_json(sec)
    if error:
        db.rollback()
        return _source_form_ctx(request, user, db, src if src.id else None, kind, cfg, set(sec.keys()), error)
    if not src.id:
        src.next_run = utcnow()
    db.add(src)
    db.commit()
    flash(request, f"Quelle „{src.name}“ gespeichert.")
    return back(f"/quellen/{src.id}")


@router.post("/quellen/{sid}/scan")
async def source_scan(request: Request, sid: int, user: User = Depends(require_manager),
                      db: Session = Depends(get_db), _=Depends(csrf_ok)):
    src = db.get(Source, sid)
    if not src:
        raise HTTPException(404)
    if scanner.start_scan(src.id):
        flash(request, f"Scan für „{src.name}“ gestartet – das kann einige Minuten dauern.")
    else:
        flash(request, "Für diese Quelle läuft bereits ein Scan.", "err")
    return back(request.headers.get("referer") or "/quellen")


@router.post("/quellen/{sid}/test")
async def source_test(request: Request, sid: int, user: User = Depends(require_manager),
                      db: Session = Depends(get_db), _=Depends(csrf_ok)):
    src = db.get(Source, sid)
    if not src:
        raise HTTPException(404)
    cfg, sec = json.loads(src.config_json or "{}"), decrypt_json(src.secret_enc)
    try:
        if src.kind == "action1":
            msg = action1.test_connection(cfg, sec)
        else:
            from .collectors.ssh import run_sections

            out, new_key = run_sections(cfg, sec, {"id": "id; uname -a"}, 15)
            if new_key:
                cfg["host_key"] = new_key
                src.config_json = json.dumps(cfg)
                db.commit()
            msg = "Verbindung ok – " + (out.get("id", "").splitlines()[0][:200] if out.get("id") else "")
            if new_key:
                msg += f" · Host-Schlüssel gespeichert ({new_key.split(' ')[0]})"
        flash(request, msg)
    except CollectorError as exc:
        flash(request, str(exc), "err")
    return back(f"/quellen/{sid}")


@router.post("/quellen/{sid}/hostkey")
async def source_hostkey_reset(request: Request, sid: int, user: User = Depends(require_manager),
                               db: Session = Depends(get_db), _=Depends(csrf_ok)):
    src = db.get(Source, sid)
    if src:
        cfg = json.loads(src.config_json or "{}")
        cfg.pop("host_key", None)
        src.config_json = json.dumps(cfg)
        db.commit()
        flash(request, "Host-Schlüssel zurückgesetzt – beim nächsten Kontakt wird der neue gespeichert.")
    return back(f"/quellen/{sid}")


@router.post("/quellen/{sid}/loeschen")
async def source_delete(request: Request, sid: int, user: User = Depends(require_manager),
                        db: Session = Depends(get_db), _=Depends(csrf_ok)):
    src = db.get(Source, sid)
    if src:
        for d in db.query(Device).filter(Device.source_id == src.id).all():
            db.query(Finding).filter(Finding.device_id == d.id).delete()
            db.query(Software).filter(Software.device_id == d.id).delete()
            db.delete(d)
        db.query(ScanRun).filter(ScanRun.source_id == src.id).delete()
        db.delete(src)
        db.commit()
        flash(request, "Quelle samt ihrer Geräte gelöscht.")
    return back("/quellen")


@router.get("/protokoll", response_class=HTMLResponse)
def runs_page(request: Request, user: User = Depends(require_manager), db: Session = Depends(get_db)):
    runs = db.query(ScanRun).order_by(ScanRun.started.desc()).limit(200).all()
    return render(request, "runs.html", {"user": user, "title": "Scan-Protokoll", "runs": runs})


# ----------------------------------------------------------- Einstellungen
@router.get("/einstellungen", response_class=HTMLResponse)
def settings_page(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    return render(request, "settings.html", {"user": user, "title": "Einstellungen",
                                             "s": settings_store.get_all(db),
                                             "sec": set(settings_store.get_secrets(db).keys()),
                                             "prios": PRIORITIES})


@router.post("/einstellungen")
async def settings_save(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db),
                        _=Depends(csrf_ok)):
    form = await request.form()
    vals = {
        "smtp_host": form.get("smtp_host", "").strip(),
        "smtp_port": int(form.get("smtp_port") or 587),
        "smtp_starttls": form.get("smtp_starttls") == "on",
        "smtp_user": form.get("smtp_user", "").strip(),
        "smtp_from": form.get("smtp_from", "").strip(),
        "smtp_to": form.get("smtp_to", "").strip(),
        "webhook_url": form.get("webhook_url", "").strip(),
        "notify_enabled": form.get("notify_enabled") == "on",
        "notify_min_priority": form.get("notify_min_priority") if form.get("notify_min_priority") in ("sofort", "hoch") else "hoch",
        "stale_days": max(1, int(form.get("stale_days") or 7)),
        "action1_console_url": form.get("action1_console_url", "").strip().rstrip("/"),
    }
    settings_store.set_many(db, vals)
    settings_store.set_secrets(db, {k: form.get(k, "").strip() for k in settings_store.SECRET_KEYS})
    for k in settings_store.SECRET_KEYS:
        if form.get(f"clear_{k}") == "on":
            settings_store.clear_secret(db, k)
    flash(request, "Einstellungen gespeichert.")
    return back("/einstellungen")


@router.post("/einstellungen/test")
async def settings_test(request: Request, what: str = Form(...), user: User = Depends(require_admin),
                        db: Session = Depends(get_db), _=Depends(csrf_ok)):
    cfg, sec = settings_store.get_all(db), settings_store.get_secrets(db)
    try:
        if what == "mail":
            notify.send_mail(cfg, sec, "pmon Testnachricht", "Wenn du das liest, funktioniert der Mailversand.")
            flash(request, f"Testmail an {cfg.get('smtp_to')} gesendet.")
        elif what == "webhook":
            import httpx

            headers = {"Content-Type": "application/json"}
            if sec.get("webhook_secret"):
                headers["X-Pmon-Secret"] = sec["webhook_secret"]
            httpx.post(cfg["webhook_url"], content=notify.test_payload(), headers=headers,
                       timeout=15).raise_for_status()
            flash(request, "Webhook erfolgreich aufgerufen.")
        elif what == "feeds":
            import threading

            threading.Thread(target=scanner.refresh_feeds, daemon=True).start()
            flash(request, "KEV, EPSS und NVD-Details werden im Hintergrund aktualisiert.")
    except Exception as exc:  # noqa: BLE001
        flash(request, f"Fehlgeschlagen: {exc}", "err")
    return back("/einstellungen")


# ---------------------------------------------------------------- Benutzer
@router.get("/benutzer", response_class=HTMLResponse)
def users_page(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    return render(request, "users.html", {"user": user, "title": "Benutzer",
                                          "users": db.query(User).order_by(User.username).all(),
                                          "roles": ROLES, "tenants": db.query(Tenant).order_by(Tenant.name).all()})


@router.post("/benutzer")
async def user_save(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db),
                    _=Depends(csrf_ok)):
    form = await request.form()
    uid = form.get("uid")
    u = db.get(User, int(uid)) if uid else User()
    username = (form.get("username") or "").strip()
    if not uid:
        if not username or db.query(User).filter(User.username == username).first():
            flash(request, "Benutzername fehlt oder ist schon vergeben.", "err")
            return back("/benutzer")
        u.username = username
    u.display_name = (form.get("display_name") or "").strip()
    role = form.get("role")
    if role in ROLES and not (u.id == user.id and role != "admin"):
        u.role = role
    u.is_active = form.get("is_active") == "on" or u.id == user.id
    pw = form.get("password") or ""
    if pw:
        if len(pw) < 10:
            flash(request, "Passwort muss mindestens 10 Zeichen haben.", "err")
            return back("/benutzer")
        u.password_hash = hash_password(pw)
    elif not uid:
        flash(request, "Für neue Benutzer ist ein Passwort nötig.", "err")
        return back("/benutzer")
    ids = {int(x) for x in form.getlist("tenants")}
    u.tenants = [t for t in db.query(Tenant).all() if t.id in ids]
    db.add(u)
    db.commit()
    if u.id == user.id:
        request.session["pwv"] = u.password_hash[-12:]
    flash(request, f"Benutzer „{u.username}“ gespeichert.")
    return back("/benutzer")


@router.post("/benutzer/{uid}/loeschen")
async def user_delete(request: Request, uid: int, user: User = Depends(require_admin),
                      db: Session = Depends(get_db), _=Depends(csrf_ok)):
    if uid == user.id:
        flash(request, "Du kannst dich nicht selbst löschen.", "err")
    else:
        u = db.get(User, uid)
        if u:
            db.delete(u)
            db.commit()
            flash(request, "Benutzer gelöscht.")
    return back("/benutzer")
