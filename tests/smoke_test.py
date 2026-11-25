"""Durchlauftest ohne Internet: Action1, NVD, KEV, EPSS und OSV werden simuliert.

  python tests/smoke_test.py
"""
import json
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="pmon-test-")
os.environ["SCHEDULER"] = "false"
os.environ["ADMIN_PASSWORD"] = "Test-Passwort-123"

import httpx  # noqa: E402

# ------------------------------------------------------------ Simulierte APIs
KEV = {"vulnerabilities": [{"cveID": "CVE-2024-1111", "dateAdded": "2024-05-01", "dueDate": "2024-05-22",
                            "knownRansomwareCampaignUse": "Known", "requiredAction": "Apply mitigations per vendor instructions.",
                            "vulnerabilityName": "7-Zip Remote Code Execution"}]}


def nvd_cve(cid, score, desc, cfg=None):
    return {"cve": {"id": cid, "published": "2024-04-01T10:00:00.000",
                    "descriptions": [{"lang": "en", "value": desc}],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                        "baseScore": score, "baseSeverity": "CRITICAL" if score >= 9 else "HIGH",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"}]}],
                    "references": [{"url": "https://example.org/advisory", "tags": ["Vendor Advisory"]}],
                    "configurations": cfg or []}}


STATE = {"second": False}


def handler(request: httpx.Request) -> httpx.Response:
    u = request.url
    path = u.path
    if u.host.endswith("action1.com"):
        if path.endswith("/oauth2/token"):
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        assert request.headers.get("authorization") == "Bearer tok"
        if path.endswith("/organizations"):
            return httpx.Response(200, json={"items": [{"id": "org1", "name": "Frisch Motorgeräte"}], "total_items": 1})
        if path.endswith("/endpoints/managed/org1"):
            return httpx.Response(200, json={"items": [
                {"id": "ep1", "name": "PC-BUERO-01", "OS": "Windows 11 Pro", "last_seen": "2026-11-25T08:00:00Z",
                 "online_status": "ONLINE"},
                {"id": "ep2", "name": "PC-WERKSTATT", "OS": "Windows 10 Pro", "last_seen": "2026-10-01T08:00:00Z",
                 "online_status": "OFFLINE"}], "total_items": 2})
        if path.endswith("/vulnerabilities/org1"):
            assert u.params.get("remediation_status") == "All_except_control_applied"
            items = [{"cve_id": "CVE-2024-1111", "cvss_score": 9.8, "base_severity": "Critical",
                      "remediation_status": "Overdue"}]
            if not STATE["second"]:
                items.append({"cve_id": "CVE-2024-2222", "cvss_score": 5.3, "base_severity": "Medium",
                              "remediation_status": "Due later"})
            return httpx.Response(200, json={"items": items, "total_items": len(items)})
        if path.endswith("/CVE-2024-1111/endpoints"):
            return httpx.Response(200, json={"items": [{"endpoint_id": "ep1", "endpoint_name": "PC-BUERO-01",
                "software": [{"product_name": "7-Zip", "versions": [{"version": "23.01"}],
                              "available_updates": [{"name": "7-Zip 24.08 (x64)"}]}]}], "total_items": 1})
        if path.endswith("/CVE-2024-2222/endpoints"):
            return httpx.Response(200, json={"items": [{"endpoint_id": "ep2", "endpoint_name": "PC-WERKSTATT",
                "software": [{"product_name": "Notepad++", "versions": [{"version": "8.5"}], "available_updates": []}]}]})
        if "/apps/org1/data/" in path:
            return httpx.Response(200, json={"items": [{"name": "7-Zip", "version": "23.01", "vendor": "Igor Pavlov"}],
                                             "total_items": 1})
        return httpx.Response(404)
    if u.host == "www.cisa.gov":
        return httpx.Response(200, json=KEV)
    if u.host == "api.first.org":
        ids = u.params.get("cve", "").split(",")
        return httpx.Response(200, json={"data": [{"cve": c, "epss": "0.42" if c == "CVE-2024-1111" else "0.003",
                                                   "percentile": "0.97"} for c in ids]})
    if u.host == "services.nvd.nist.gov":
        if u.params.get("virtualMatchString", "").startswith("cpe:2.3:o:synology:diskstation_manager"):
            assert u.params["versionStart"] == "7.2.1-69057-5"
            cfg = [{"nodes": [{"cpeMatch": [{"vulnerable": True,
                    "criteria": "cpe:2.3:o:synology:diskstation_manager:*:*:*:*:*:*:*:*",
                    "versionEndExcluding": "7.2.2-72806"}]}]}]
            return httpx.Response(200, json={"totalResults": 1, "resultsPerPage": 1,
                                             "vulnerabilities": [nvd_cve("CVE-2024-3333", 8.1, "DSM flaw.", cfg)]})
        if u.params.get("virtualMatchString"):
            return httpx.Response(200, json={"totalResults": 0, "resultsPerPage": 0, "vulnerabilities": []})
        cid = u.params.get("cveId")
        return httpx.Response(200, json={"vulnerabilities": [nvd_cve(cid, 9.8 if cid.endswith("1111") else 6.5,
                                                                     f"Description of {cid}.")]})
    if u.host == "api.osv.dev":
        if path.endswith("/querybatch"):
            body = json.loads(request.content)
            res = []
            for q in body["queries"]:
                assert q["package"]["ecosystem"] == "Debian:12"
                res.append({"vulns": [{"id": "DSA-5555-1"}]} if q["package"]["name"] == "openssl" else {})
            return httpx.Response(200, json={"results": res})
        if path.endswith("/vulns/DSA-5555-1"):
            return httpx.Response(200, json={"id": "DSA-5555-1", "aliases": ["CVE-2024-4444"], "affected": [
                {"package": {"name": "openssl", "ecosystem": "Debian:12"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.15-1~deb12u1"}]}]}]})
    return httpx.Response(404)


transport = httpx.MockTransport(handler)

from app.collectors import action1, linux, nas  # noqa: E402
from app.enrich import feeds  # noqa: E402

action1._transport = transport
feeds._transport = transport
_orig_nvd_init = feeds.Nvd.__init__


def _fast_nvd_init(self, api_key=None):
    _orig_nvd_init(self, api_key)
    self.delay = 0


feeds.Nvd.__init__ = _fast_nvd_init

# --- SSH simulieren
SYNO = {
    "version": 'majorversion="7"\nminorversion="2"\nproductversion="7.2.1"\nbuildnumber="69057"\nsmallfixnumber="5"',
    "hw": "DS920+", "synoinfo": 'unique="synology_geminilake_920+"', "hostname": "nas-frisch",
    "packages": "== /var/packages/SurveillanceStation/INFO\npackage=\"SurveillanceStation\"\nversion=\"9.2.0-11289\"\n"
                "displayname=\"Surveillance Station\"\n== /var/packages/HyperBackup/INFO\npackage=\"HyperBackup\"\nversion=\"4.1.0-3718\"",
}
DEB = {
    "osrelease": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"',
    "hostname": "pve-eichen", "machineid": "abc123", "pve": "pve-manager/8.2.4/faa83925 (running kernel: 6.8.8-2-pve)",
    "dpkg": "ii \topenssl\t3.0.14-1~deb12u2\topenssl\t3.0.14-1~deb12u2\nii \tlibssl3\t3.0.14-1~deb12u2\topenssl\t3.0.14-1~deb12u2\n"
            "ii \tbash\t5.2.15-2+b7\tbash\t5.2.15-2",
}


def fake_ssh(config, secrets, sections, timeout=20):
    data = SYNO if "packages" in sections else DEB
    return {k: data.get(k, "") for k in sections}, "ssh-ed25519 AAAATESTKEY"


nas.run_sections = fake_ssh
linux.run_sections = fake_ssh

# ------------------------------------------------------------ Test
from fastapi.testclient import TestClient  # noqa: E402

from app import scanner  # noqa: E402
from app.db import SessionLocal  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Cve, Device, Finding, Source  # noqa: E402


def csrf(html: str) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', html)
    assert m, "kein CSRF-Token"
    return m.group(1)


def main():
    with TestClient(app, base_url="https://pmon.test") as c:
        r = c.get("/", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login"), r.status_code
        r = c.get("/login")
        tok = csrf(r.text)
        r = c.post("/login", data={"username": "admin", "password": "falsch", "csrf": tok})
        assert r.status_code == 401
        r = c.post("/login", data={"username": "admin", "password": "Test-Passwort-123", "csrf": tok},
                   follow_redirects=False)
        assert r.status_code == 303, r.text
        assert "secure" in r.headers.get("set-cookie", "").lower(), "Cookie ohne Secure trotz HTTPS"
        r = c.get("/")
        assert r.status_code == 200 and "Sicherheitslage" in r.text
        tok = csrf(r.text)

        # Kunde für NAS/Linux
        r = c.post("/kunden", data={"name": "LG Eichen", "csrf": tok})
        assert r.status_code == 200 and "LG Eichen" in r.text

        # Quellen anlegen
        r = c.post("/quellen/speichern", data={"kind": "action1", "name": "Action1 EU", "region": "eu",
                   "client_id": "id", "client_secret": "geheim", "only_open": "on", "inventory": "on",
                   "enabled": "on", "interval_minutes": "60", "csrf": tok})
        assert r.status_code == 200 and "gespeichert" in r.text, r.text[:400]
        db = SessionLocal()
        from app.models import Tenant

        eichen = db.query(Tenant).filter_by(name="LG Eichen").one()
        db.close()
        r = c.post("/quellen/speichern", data={"kind": "synology", "name": "NAS", "host": "10.0.0.5", "port": "22",
                   "username": "pmon", "password": "x", "tenant_id": str(eichen.id), "csrf": tok})
        assert "gespeichert" in r.text
        r = c.post("/quellen/speichern", data={"kind": "linux", "name": "PVE", "host": "10.0.0.2", "port": "22",
                   "username": "pmon", "password": "x", "tenant_id": str(eichen.id), "csrf": tok})
        assert "gespeichert" in r.text
        r = c.post("/quellen/speichern", data={"kind": "linux", "name": "Ohne Kunde", "host": "10.0.0.3",
                   "username": "pmon", "password": "x", "csrf": tok})
        assert "Bitte einen Kunden zuordnen" in r.text

        db = SessionLocal()
        ids = [s.id for s in db.query(Source).order_by(Source.id).all()]
        db.close()
        for sid in ids:
            scanner.run_source(sid)
        db = SessionLocal()
        for s in db.query(Source).all():
            assert s.last_status == "ok", (s.name, s.last_message)
        names = sorted(d.name for d in db.query(Device).all())
        assert names == ["PC-BUERO-01", "PC-WERKSTATT", "nas-frisch", "pve-eichen"], names
        assert db.query(Tenant).filter_by(action1_org_id="org1").count() == 1
        cve = db.get(Cve, "CVE-2024-1111")
        assert cve.kev and cve.epss == 0.42 and cve.description.startswith("Description"), vars(cve)
        f_dsm = db.query(Finding).filter_by(cve_id="CVE-2024-3333").one()
        assert f_dsm.product == "DSM" and f_dsm.fixed_version == "ab 7.2.2-72806", (f_dsm.product, f_dsm.fixed_version)
        f_ssl = db.query(Finding).filter_by(cve_id="CVE-2024-4444").one()
        assert f_ssl.product == "openssl" and f_ssl.fixed_version == "3.0.15-1~deb12u1"
        pve = db.query(Device).filter_by(name="pve-eichen").one()
        assert pve.kind == "proxmox"
        syn = db.query(Source).filter_by(kind="synology").one()
        assert json.loads(syn.config_json)["host_key"] == "ssh-ed25519 AAAATESTKEY"
        db.close()

        # Seiten
        r = c.get("/")
        assert "CVE-2024-1111" in r.text and "Frisch Motorgeräte" in r.text and "Aktiv ausgenutzt" in r.text
        r = c.get("/schwachstellen?prio=sofort")
        assert "CVE-2024-1111" in r.text and "CVE-2024-2222" not in r.text
        r = c.get("/schwachstellen/CVE-2024-1111")
        assert "7-Zip 24.08" in r.text and "Ransomware" in r.text and "Action1" in r.text
        r = c.get("/schwachstellen/CVE-2024-3333")
        assert "Systemsteuerung → Aktualisieren" in r.text and "Synology Security Advisories" in r.text
        r = c.get("/schwachstellen/CVE-2024-4444")
        assert "apt full-upgrade" in r.text
        db = SessionLocal()
        did = db.query(Device).filter_by(name="nas-frisch").one().id
        db.close()
        r = c.get(f"/geraete/{did}")
        assert "Surveillance Station" in r.text and "DS920+" in r.text
        for url in ("/geraete", "/kunden", "/quellen", "/quellen/neu", "/quellen/neu?typ=qnap", f"/quellen/{ids[0]}",
                    "/protokoll", "/einstellungen", "/benutzer", "/konto"):
            r = c.get(url)
            assert r.status_code == 200, (url, r.status_code, r.text[:300])
        r = c.get("/export/schwachstellen.csv")
        assert r.status_code == 200 and "CVE-2024-1111" in r.text and "Frisch" in r.text

        # Zweiter Lauf: CVE-2024-2222 verschwindet → behoben
        STATE["second"] = True
        scanner.run_source(ids[0])
        db = SessionLocal()
        resolved = [f.cve_id for f in db.query(Finding).filter_by(status="resolved").all()]
        assert resolved == ["CVE-2024-2222"], resolved
        db.close()

        # Risiko akzeptieren
        db = SessionLocal()
        fid = db.query(Finding).filter_by(cve_id="CVE-2024-4444").one().id
        db.close()
        r = c.post(f"/funde/{fid}/status", data={"status": "accepted", "note": "Gerät ausgemustert", "csrf": tok})
        assert "akzeptiert" in r.text.lower()

        # Einstellungen
        r = c.post("/einstellungen", data={"smtp_host": "mail.example.org", "smtp_port": "587", "notify_enabled": "on",
                   "notify_min_priority": "hoch", "stale_days": "7", "nvd_api_key": "abc", "csrf": tok})
        assert "gespeichert" in r.text and "Leer lassen = unverändert" in r.text

        # Leser mit nur LG Eichen
        r = c.post("/benutzer", data={"username": "kunde", "role": "leser", "password": "Kunde-Passwort-1",
                   "tenants": str(eichen.id), "is_active": "on", "csrf": tok})
        assert "gespeichert" in r.text
        r = c.post("/logout", data={"csrf": tok})
        r = c.get("/login")
        tok2 = csrf(r.text)
        r = c.post("/login", data={"username": "kunde", "password": "Kunde-Passwort-1", "csrf": tok2})
        assert r.status_code == 200 and "LG Eichen" in r.text and "Frisch" not in r.text
        assert "CVE-2024-1111" not in c.get("/schwachstellen").text
        assert c.get("/quellen").status_code == 403
        assert c.get("/schwachstellen/CVE-2024-1111").status_code == 404
        # CSRF-Schutz
        assert c.post("/logout", data={"csrf": "falsch"}).status_code == 400
    print("Alle Tests erfolgreich.")


if __name__ == "__main__":
    main()
