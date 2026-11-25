"""Benachrichtigung per E-Mail (SMTP, z. B. mailcow) und Webhook."""
import json
import smtplib
import ssl
from email.message import EmailMessage

import httpx

from . import settings_store
from .risk import PRIORITIES, priority


def _lines(findings, base_url: str) -> list[str]:
    out = []
    for f in findings:
        cve = f.cve
        p = PRIORITIES[priority(cve)]["label"]
        kev = " [AKTIV AUSGENUTZT]" if cve and cve.kev else ""
        score = f"CVSS {cve.cvss}" if cve and cve.cvss is not None else "CVSS –"
        dev = f.device.name if f.device else "?"
        tenant = f.device.tenant.name if f.device and f.device.tenant else ""
        link = f" {base_url}/schwachstellen/{f.cve_id}" if base_url else ""
        out.append(f"- [{p}] {f.cve_id}{kev} – {f.product or 'unbekannt'} auf {dev} ({tenant}), {score}{link}")
    return out


def send(db, findings) -> str:
    cfg = settings_store.get_all(db)
    sec = settings_store.get_secrets(db)
    if not findings:
        return ""
    from .config import settings

    base_url = settings.base_url
    subject = f"pmon: {len(findings)} neue Schwachstelle(n) mit hoher Priorität"
    body = "\n".join(["Neue Funde seit dem letzten Scan:", ""] + _lines(findings, base_url)
                     + ["", "— pmon · MB-IT Solutions"])
    results = []
    if cfg.get("smtp_host") and cfg.get("smtp_to"):
        try:
            send_mail(cfg, sec, subject, body)
            results.append("E-Mail gesendet")
        except Exception as exc:  # noqa: BLE001
            results.append(f"E-Mail fehlgeschlagen: {exc}")
    if cfg.get("webhook_url"):
        try:
            payload = {
                "event": "pmon.new_findings",
                "title": subject,
                "text": body,
                "findings": [{
                    "cve": f.cve_id, "product": f.product, "device": f.device.name if f.device else "",
                    "tenant": f.device.tenant.name if f.device and f.device.tenant else "",
                    "cvss": f.cve.cvss if f.cve else None, "kev": bool(f.cve and f.cve.kev),
                    "epss": f.cve.epss if f.cve else None, "priority": priority(f.cve),
                    "fixed_version": f.fixed_version,
                } for f in findings],
            }
            headers = {}
            if sec.get("webhook_secret"):
                headers["X-Pmon-Secret"] = sec["webhook_secret"]
            httpx.post(cfg["webhook_url"], json=payload, headers=headers, timeout=15).raise_for_status()
            results.append("Webhook gesendet")
        except Exception as exc:  # noqa: BLE001
            results.append(f"Webhook fehlgeschlagen: {exc}")
    return "; ".join(results)


def send_mail(cfg: dict, sec: dict, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.get("smtp_from") or cfg.get("smtp_user")
    msg["To"] = cfg["smtp_to"]
    msg.set_content(body)
    port = int(cfg.get("smtp_port") or 587)
    ctx = ssl.create_default_context()
    if port == 465:
        server = smtplib.SMTP_SSL(cfg["smtp_host"], port, context=ctx, timeout=20)
    else:
        server = smtplib.SMTP(cfg["smtp_host"], port, timeout=20)
        if cfg.get("smtp_starttls", True):
            server.starttls(context=ctx)
    with server:
        if cfg.get("smtp_user"):
            server.login(cfg["smtp_user"], sec.get("smtp_password", ""))
        server.send_message(msg)


def test_payload() -> str:
    return json.dumps({"event": "pmon.test", "title": "pmon Testnachricht",
                       "text": "Wenn du das liest, funktioniert der Webhook."})
