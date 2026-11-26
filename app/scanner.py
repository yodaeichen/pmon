"""Scan-Ablauf: Quelle abfragen → Geräte/Software/Funde speichern → anreichern → benachrichtigen."""
import json
import logging
import threading
from datetime import timedelta

import httpx
from sqlalchemy.orm import Session

from . import notify, settings_store
from .collectors import action1, linux, nas
from .collectors.base import CollectorError, CollectResult, FindingData, ScanCancelled
from .config import settings
from .db import session_scope
from .enrich import feeds
from .models import Cve, Device, Finding, OsvCache, ScanRun, Software, Source, Tenant, utcnow
from .risk import PRIORITIES, priority, severity_from_score
from .security import decrypt_json

log = logging.getLogger("pmon.scan")
_lock = threading.Lock()
_running: set[int] = set()
_cancel: dict[int, threading.Event] = {}


def is_running(source_id: int) -> bool:
    return source_id in _running


def request_cancel(source_id: int) -> bool:
    """Abbruch anfordern; der Scan stoppt an der nächsten Prüfstelle."""
    ev = _cancel.get(source_id)
    if source_id not in _running or ev is None:
        return False
    ev.set()
    return True


def is_cancelling(source_id: int) -> bool:
    ev = _cancel.get(source_id)
    return bool(ev and ev.is_set())


def _stopper(source_id: int):
    ev = _cancel.get(source_id)

    def check() -> None:
        if ev is not None and ev.is_set():
            raise ScanCancelled()
    return check


def start_scan(source_id: int) -> bool:
    """Scan im Hintergrund starten (für „Jetzt scannen")."""
    if source_id in _running:
        return False
    threading.Thread(target=run_source, args=(source_id,), daemon=True).start()
    return True


# ------------------------------------------------------------- Sammeln
def collect_for(src: Source, should_stop=None) -> tuple[CollectResult, str | None]:
    cfg = json.loads(src.config_json or "{}")
    sec = decrypt_json(src.secret_enc)
    stop = should_stop or (lambda: None)
    if src.kind == "action1":
        return action1.collect(cfg, sec, settings.http_timeout, should_stop=stop), None
    if src.kind in ("synology", "qnap"):
        return nas.collect(src.kind, cfg, sec, should_stop=stop)
    if src.kind == "linux":
        return linux.collect(cfg, sec, should_stop=stop)
    raise CollectorError(f"Unbekannter Quellentyp {src.kind}")


def run_source(source_id: int) -> None:
    if source_id in _running:
        return
    _cancel[source_id] = threading.Event()
    _running.add(source_id)
    try:
        with _lock:
            _run(source_id)
    except Exception:  # noqa: BLE001
        log.exception("Scan %s fehlgeschlagen", source_id)
    finally:
        _running.discard(source_id)
        _cancel.pop(source_id, None)


def _run(source_id: int) -> None:
    with session_scope() as db:
        src = db.get(Source, source_id)
        if not src:
            return
        run = ScanRun(source_id=src.id)
        db.add(run)
        src.last_status = "laeuft"
        db.commit()
        started = utcnow()
        stop = _stopper(source_id)
        phase = "Abfrage der Quelle"
        try:
            stop()
            result, new_key = collect_for(src, stop)
            if new_key:
                cfg = json.loads(src.config_json or "{}")
                cfg["host_key"] = new_key
                src.config_json = json.dumps(cfg)
            phase = "Abgleich mit den Schwachstellen-Datenbanken"
            stats = store(db, src, result, started, stop)
            phase = "Nachladen von CVE-Details (Funde sind bereits gespeichert)"
            sec = settings_store.get_secrets(db)
            enrich(db, nvd_key=sec.get("nvd_api_key"), should_stop=stop)
            sent = maybe_notify(db)
            msgs = sorted(result.messages, key=lambda m: not m.startswith("Hinweis"))  # Hinweise zuerst
            msg = "; ".join(msgs[:8])
            msg += f" – {stats['new']} neu, {stats['resolved']} behoben"
            if sent:
                msg += f" ({sent})"
            run.status, run.message = "ok", msg
            run.devices, run.new_findings, run.resolved_findings = stats["devices"], stats["new"], stats["resolved"]
            src.last_status, src.last_message = "ok", msg
        except ScanCancelled:
            db.rollback()  # halbfertige Änderungen verwerfen
            msg = f"Vom Benutzer abgebrochen während: {phase}."
            run.status, run.message = "abgebrochen", msg
            src.last_status, src.last_message = "abgebrochen", msg
        except CollectorError as exc:
            db.rollback()
            run.status, run.message = "fehler", str(exc)
            src.last_status, src.last_message = "fehler", str(exc)
        except Exception as exc:  # noqa: BLE001
            log.exception("Scan-Fehler")
            db.rollback()
            run.status, run.message = "fehler", f"Interner Fehler: {exc}"
            src.last_status, src.last_message = "fehler", f"Interner Fehler: {exc}"
        finally:
            run.finished = utcnow()
            src.last_run = run.finished
            src.next_run = run.finished + timedelta(minutes=max(15, src.interval_minutes or 60))
            db.commit()


# ------------------------------------------------------------ Speichern
def _tenant_for(db: Session, src: Source, dev) -> Tenant:
    if src.tenant_id and (src.kind != "action1" or not dev.tenant_ref):
        return src.tenant
    if dev.tenant_ref:
        t = db.query(Tenant).filter(Tenant.action1_org_id == dev.tenant_ref).first()
        if t:
            return t
        if src.tenant_id:
            return src.tenant
        t = Tenant(name=dev.tenant_name or dev.tenant_ref, action1_org_id=dev.tenant_ref,
                   note="Automatisch aus Action1 angelegt")
        db.add(t)
        db.flush()
        return t
    t = db.query(Tenant).filter(Tenant.name == "Ohne Kunde").first()
    if not t:
        t = Tenant(name="Ohne Kunde")
        db.add(t)
        db.flush()
    return t


def _ensure_cve(db: Session, cache: dict, cve_id: str, cvss=None, severity="") -> Cve:
    cve = cache.get(cve_id) or db.get(Cve, cve_id)
    if cve is None:
        cve = Cve(id=cve_id, cvss=cvss, severity=(severity or severity_from_score(cvss) or "").upper())
        db.add(cve)
    elif cve.cvss is None and cvss is not None:
        cve.cvss = cvss
        cve.severity = (severity or severity_from_score(cvss)).upper()
    cache[cve_id] = cve
    return cve


def store(db: Session, src: Source, result: CollectResult, started, should_stop=None) -> dict:
    stop = should_stop or (lambda: None)
    stats = {"devices": 0, "new": 0, "resolved": 0}
    cve_cache: dict[str, Cve] = {}
    sec = settings_store.get_secrets(db)
    nvd = None
    seen_device_ids = []
    for d in result.devices:
        stop()
        tenant = _tenant_for(db, src, d)
        dev = db.query(Device).filter_by(source_id=src.id, external_id=d.external_id).first()
        if dev is None:
            dev = Device(source_id=src.id, external_id=d.external_id, name=d.name)
            db.add(dev)
        dev.tenant_id = tenant.id
        dev.name = d.name or dev.name
        for attr in ("kind", "os", "os_version", "model", "address"):
            val = getattr(d, attr)
            if val:
                setattr(dev, attr, val)
        dev.online = d.online
        dev.last_seen = d.last_seen or (utcnow() if src.kind != "action1" else dev.last_seen)
        dev.last_scan = utcnow()
        if d.raw:
            dev.raw_json = json.dumps(d.raw, default=str)[:20000]
        db.flush()
        seen_device_ids.append(dev.id)
        stats["devices"] += 1

        if d.software:
            db.query(Software).filter(Software.device_id == dev.id).delete()
            for name, version, vendor, eco in d.software[:20000]:
                db.add(Software(device_id=dev.id, name=name[:300], version=(version or "")[:120],
                                vendor=(vendor or "")[:200], ecosystem=eco))

        findings: list[FindingData] = list(d.findings)
        # NAS: Firmware/Pakete gegen NVD
        if d.cpe_queries:
            nvd = nvd or feeds.Nvd(sec.get("nvd_api_key"), stop)
            for q in d.cpe_queries:
                try:
                    for hit in nvd.match_cpe(q.cpe, q.version):
                        c = _ensure_cve(db, cve_cache, hit["id"], hit["cvss"], hit["severity"])
                        _apply_nvd(c, hit)
                        findings.append(FindingData(cve_id=hit["id"], product=q.label.rsplit(" ", 1)[0],
                                                    installed_version=q.version, fixed_version=hit["fixed"],
                                                    origin="nvd"))
                except httpx.HTTPError as exc:
                    result.complete = False
                    result.messages.append(f"NVD-Abfrage für {q.label} fehlgeschlagen: {exc}")
        # Linux: Pakete gegen OSV
        if d.osv_ecosystem and d.osv_packages:
            try:
                findings.extend(_osv_findings(db, d.osv_ecosystem, d.osv_packages, stop))
            except httpx.HTTPError as exc:
                result.complete = False
                result.messages.append(f"OSV-Abfrage fehlgeschlagen: {exc}")

        for f in findings:
            cve = _ensure_cve(db, cve_cache, f.cve_id, f.cvss, f.severity)
            row = db.query(Finding).filter_by(device_id=dev.id, cve_id=cve.id, product=f.product[:300]).first()
            if row is None:
                row = Finding(device_id=dev.id, source_id=src.id, cve_id=cve.id, product=f.product[:300],
                              first_seen=utcnow())
                db.add(row)
                stats["new"] += 1
            elif row.status == "resolved":
                row.status, row.resolved_at, row.notified = "open", None, False
                stats["new"] += 1
            row.installed_version = (f.installed_version or "")[:200]
            row.fixed_version = (f.fixed_version or "")[:300]
            row.origin = f.origin
            row.vendor_status = f.vendor_status[:60]
            row.last_seen = utcnow()
        db.flush()
    if nvd:
        nvd.close()

    # Nicht mehr gemeldete Funde der gescannten Geräte gelten als behoben
    if result.complete and seen_device_ids:
        q = db.query(Finding).filter(Finding.device_id.in_(seen_device_ids), Finding.status == "open",
                                     Finding.last_seen < started)
        if result.keep_cves:
            q = q.filter(Finding.cve_id.notin_(result.keep_cves))
        for row in q.all():
            row.status, row.resolved_at = "resolved", utcnow()
            stats["resolved"] += 1
    db.commit()
    return stats


def _apply_nvd(c: Cve, data: dict) -> None:
    c.description = data.get("description") or c.description
    if data.get("cvss") is not None:
        c.cvss = data["cvss"]
        c.severity = data.get("severity") or severity_from_score(data["cvss"])
    c.vector = data.get("vector") or c.vector
    c.cwe = data.get("cwe") or c.cwe
    c.published = data.get("published") or c.published
    c.references_json = json.dumps(data.get("references") or [])
    c.nvd_fetched_at = utcnow()


def _osv_findings(db: Session, ecosystem: str, packages, stop=lambda: None) -> list[FindingData]:
    hits = feeds.osv_query(ecosystem, list(packages))
    versions = dict(packages)
    out: list[FindingData] = []
    with feeds.client() as http:
        for pkg, ids in hits.items():
            for vid in ids:
                stop()
                cached = db.get(OsvCache, vid)
                if cached and (utcnow() - cached.fetched_at).days < 3:
                    vuln = json.loads(cached.data)
                else:
                    try:
                        vuln = feeds.osv_vuln(http, vid)
                    except httpx.HTTPError:
                        continue
                    db.merge(OsvCache(id=vid, data=json.dumps(vuln), fetched_at=utcnow()))
                fixed = feeds.osv_fixed(vuln, pkg, ecosystem)
                if not fixed:
                    continue  # Ohne verfügbares Update nicht als Fund werten
                for cve_id in feeds.osv_cve_ids(vuln) or [vid]:
                    out.append(FindingData(cve_id=cve_id, product=pkg, installed_version=versions.get(pkg, ""),
                                           fixed_version=fixed, origin="osv"))
    # Doppelte (gleiche CVE über DSA und DEBIAN-CVE) zusammenfassen
    uniq = {}
    for f in out:
        uniq.setdefault((f.cve_id, f.product), f)
    return list(uniq.values())


# ------------------------------------------------------------ Anreichern
def enrich(db: Session, nvd_key: str | None = None, nvd_limit: int | None = None, should_stop=None) -> None:
    stop = should_stop or (lambda: None)
    open_ids = {r[0] for r in db.query(Finding.cve_id).filter(Finding.status == "open").distinct()}
    if not open_ids:
        return
    # 1) KEV
    kev = feeds.load_kev()
    for cve in db.query(Cve).filter(Cve.id.in_(open_ids)).all():
        k = kev.get(cve.id)
        if k and not cve.kev:
            # Neu als „aktiv ausgenutzt" gelistet → erneut benachrichtigen
            db.query(Finding).filter(Finding.cve_id == cve.id, Finding.status == "open").update(
                {Finding.notified: False})
        cve.kev = bool(k)
        if k:
            cve.kev_date_added = k.get("dateAdded", "")
            cve.kev_due = k.get("dueDate", "")
            cve.kev_ransomware = k.get("knownRansomwareCampaignUse", "")
            cve.kev_action = k.get("requiredAction", "")
            cve.kev_name = k.get("vulnerabilityName", "")
    db.commit()
    # 2) EPSS (täglich)
    stale = utcnow() - timedelta(hours=20)
    need = [c.id for c in db.query(Cve).filter(Cve.id.in_(open_ids)).all()
            if not c.epss_fetched_at or c.epss_fetched_at < stale]
    if need:
        scores = feeds.epss(need)
        for cid in need:
            c = db.get(Cve, cid)
            if cid in scores:
                c.epss, c.epss_percentile = scores[cid]
            c.epss_fetched_at = utcnow()
        db.commit()
    # 3) NVD-Details (rate-limitiert, Rest beim nächsten Lauf)
    limit = nvd_limit if nvd_limit is not None else (300 if nvd_key else 40)
    missing = [c for c in db.query(Cve).filter(Cve.id.in_(open_ids), Cve.nvd_fetched_at.is_(None))
               .limit(limit).all() if feeds.CVE_RE.fullmatch(c.id)]
    if missing:
        nvd = feeds.Nvd(nvd_key, stop)
        try:
            for c in missing:
                stop()
                try:
                    data = nvd.cve(c.id)
                except httpx.HTTPError:
                    break
                if data:
                    _apply_nvd(c, data)
                else:
                    c.nvd_fetched_at = utcnow()
                db.commit()
        finally:
            nvd.close()


# ---------------------------------------------------------- Benachrichtigen
def maybe_notify(db: Session) -> str:
    cfg = settings_store.get_all(db)
    if not cfg.get("notify_enabled"):
        return ""
    max_rank = PRIORITIES[cfg.get("notify_min_priority") or "hoch"]["rank"]
    rows = db.query(Finding).filter(Finding.status == "open", Finding.notified.is_(False)).all()
    due = [f for f in rows if PRIORITIES[priority(f.cve)]["rank"] <= max_rank]
    for f in rows:
        f.notified = True
    db.commit()
    if not due:
        return ""
    return notify.send(db, due[:100])


def cleanup_stale() -> None:
    """Nach einem Neustart: Läufe, die noch als „läuft" markiert sind, als abgebrochen kennzeichnen."""
    with session_scope() as db:
        msg = "Abgebrochen: Der Dienst wurde während des Scans neu gestartet."
        for run in db.query(ScanRun).filter(ScanRun.status == "laeuft").all():
            run.status, run.message, run.finished = "abgebrochen", msg, run.finished or utcnow()
        for src in db.query(Source).filter(Source.last_status == "laeuft").all():
            src.last_status, src.last_message = "abgebrochen", msg


def refresh_feeds() -> None:
    """Täglich: KEV/EPSS aktualisieren, offene NVD-Details nachladen."""
    with session_scope() as db:
        sec = settings_store.get_secrets(db)
        feeds.load_kev(force=True)
        enrich(db, nvd_key=sec.get("nvd_api_key"))
        maybe_notify(db)
