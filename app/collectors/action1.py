"""Action1 REST API 3.0 – Endpoints, Schwachstellen und (optional) Software-Inventar.

Pfade wie im offiziellen PowerShell-Modul PSAction1:
  POST /oauth2/token
  GET  /organizations
  GET  /endpoints/managed/{org}
  GET  /vulnerabilities/{org}
  GET  /vulnerabilities/{org}/{cve}/endpoints
  GET  /apps/{org}/data/{endpoint}
Antworten sind seitenweise ({items, total_items, next_page}, Parameter from/limit).
"""
from datetime import datetime, timezone

import httpx

from .base import CollectorError, CollectResult, DeviceData, FindingData, no_stop, wait

REGIONS = {
    "eu": ("Europa", "https://app.eu.action1.com/api/3.0"),
    "na": ("Nordamerika", "https://app.action1.com/api/3.0"),
    "na-2": ("Nordamerika 2", "https://app.na-2.action1.com/api/3.0"),
    "uk": ("Großbritannien", "https://app.uk.action1.com/api/3.0"),
    "au": ("Australien", "https://app.au.action1.com/api/3.0"),
}
PAGE = 200
_transport: httpx.BaseTransport | None = None  # für Tests austauschbar


def _first(d: dict, *keys, default=""):
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return default


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        ts = value / 1000 if value > 10_000_000_000 else value
        return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
    s = str(value).strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d_%H-%M-%S", "%m/%d/%Y %H:%M:%S"):
        try:
            dt = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s, fmt)
            if dt.tzinfo:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            return dt
        except ValueError:
            continue
    return None


class Action1Client:
    def __init__(self, base_url: str, client_id: str, client_secret: str,
                 timeout: float = 30, transport: httpx.BaseTransport | None = None, should_stop=no_stop):
        self.should_stop = should_stop
        self.base = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.http = httpx.Client(timeout=timeout, transport=transport or _transport,
                                 headers={"Accept": "application/json",
                                          "User-Agent": "pmon"})
        self.token = None

    def close(self):
        self.http.close()

    def login(self):
        r = self.http.post(f"{self.base}/oauth2/token",
                           data={"client_id": self.client_id, "client_secret": self.client_secret})
        if r.status_code in (400, 401, 403):
            raise CollectorError("Action1 hat die API-Zugangsdaten abgelehnt (Client-ID/Secret oder Region prüfen).")
        r.raise_for_status()
        self.token = r.json().get("access_token")
        if not self.token:
            raise CollectorError("Action1 hat kein Zugriffstoken geliefert.")

    def get(self, path: str, params: dict | None = None):
        if not self.token:
            self.login()
        url = path if path.startswith("http") else f"{self.base}{path}"
        relogged = False
        for attempt in range(3):
            self.should_stop()
            r = self.http.get(url, params=params, headers={"Authorization": f"Bearer {self.token}"})
            if r.status_code == 401 and not relogged:
                relogged = True
                self.login()
                continue
            if r.status_code == 404:
                return None
            if r.status_code in (429, 500, 502, 503, 504) and attempt < 2:
                wait(2 if attempt == 0 else 5, self.should_stop)  # kurzzeitige Störung abwarten
                continue
            r.raise_for_status()
            return r.json()
        r.raise_for_status()
        return None

    def paged(self, path: str, params: dict | None = None, max_items: int = 50_000, page_size: int = PAGE):
        params = dict(params or {})
        offset = 0
        seen = 0
        page = self.get(path, {**params, "limit": page_size})
        while page:
            items = page.get("items") if isinstance(page, dict) else page
            if not items:
                return
            for it in items:
                yield it
            seen += len(items)
            if seen >= max_items:
                return
            total = page.get("total_items") if isinstance(page, dict) else None
            nxt = page.get("next_page") if isinstance(page, dict) else None
            if isinstance(total, int) or (isinstance(total, str) and str(total).isdigit()):
                offset += len(items)
                if offset >= int(total):
                    return
                page = self.get(path, {**params, "from": offset, "limit": page_size})
            elif nxt:
                page = self.get(nxt)
            else:
                return


def collect(config: dict, secrets: dict, timeout: float = 30,
            transport: httpx.BaseTransport | None = None, should_stop=no_stop) -> CollectResult:
    region = config.get("region", "eu")
    base = config.get("base_url") or REGIONS.get(region, REGIONS["eu"])[1]
    if not secrets.get("client_id") or not secrets.get("client_secret"):
        raise CollectorError("Client-ID und Client-Secret fehlen.")
    cli = Action1Client(base, secrets["client_id"], secrets["client_secret"], timeout, transport, should_stop)
    res = CollectResult()
    try:
        orgs = list(cli.paged("/organizations"))
        wanted = {o.strip() for o in (config.get("org_ids") or "").split(",") if o.strip()}
        if wanted:
            orgs = [o for o in orgs if str(o.get("id")) in wanted]
        if not orgs:
            raise CollectorError("Keine Action1-Organisation gefunden (Berechtigungen der API-Zugangsdaten prüfen).")

        for org in orgs:
            org_id = str(org.get("id"))
            org_name = _first(org, "name", "Name", default=org_id)
            devices: dict[str, DeviceData] = {}
            skipped: list[str] = []
            for ep in cli.paged(f"/endpoints/managed/{org_id}"):
                ep_id = str(_first(ep, "id", "endpoint_id"))
                if not ep_id:
                    continue
                status = str(_first(ep, "online_status", "status", "connection_status")).lower()
                online = None
                if status:
                    online = status in ("online", "connected", "true", "1")
                os_name = _first(ep, "OS", "os", "platform")
                devices[ep_id] = DeviceData(
                    external_id=ep_id,
                    name=_first(ep, "name", "device_name", "endpoint_name", default=ep_id),
                    kind=_kind_from_os(os_name),
                    os=str(os_name),
                    os_version=str(_first(ep, "os_version", "OS_version", "version")),
                    model=str(_first(ep, "model", "manufacturer")),
                    address=str(_first(ep, "address", "ip_address", "IP")),
                    online=online,
                    last_seen=_parse_dt(_first(ep, "last_seen", "last_seen_time", default=None)),
                    tenant_ref=org_id,
                    tenant_name=org_name,
                    raw={k: ep.get(k) for k in list(ep)[:40]},
                )

            params = {}
            if config.get("only_open", True):
                params["remediation_status"] = "All_except_control_applied"
            for vul in cli.paged(f"/vulnerabilities/{org_id}", params):
                cve = str(_first(vul, "cve_id", "id")).upper()
                if not cve.startswith("CVE-"):
                    continue
                cvss = vul.get("cvss_score")
                try:
                    cvss = float(cvss) if cvss not in (None, "") else None
                except (TypeError, ValueError):
                    cvss = None
                status = str(_first(vul, "remediation_status"))
                affected = _affected(cli, org_id, cve)
                if affected is None:
                    skipped.append(cve)
                    continue
                for aff in affected:
                    ep_id = str(_first(aff, "endpoint_id", "id"))
                    dev = devices.get(ep_id)
                    if dev is None:
                        dev = devices[ep_id] = DeviceData(
                            external_id=ep_id, name=_first(aff, "endpoint_name", default=ep_id),
                            tenant_ref=org_id, tenant_name=org_name)
                    softwares = aff.get("software") or [{}]
                    for sw in softwares:
                        versions = [str(v.get("version")) for v in (sw.get("versions") or [])
                                    if isinstance(v, dict) and v.get("version")]
                        updates = []
                        for u in sw.get("available_updates") or []:
                            if isinstance(u, dict):
                                updates.append(str(u.get("name") or u.get("version") or ""))
                        dev.findings.append(FindingData(
                            cve_id=cve,
                            product=str(sw.get("product_name") or ""),
                            installed_version="; ".join(versions),
                            fixed_version="; ".join(u for u in updates if u),
                            origin="action1",
                            vendor_status=status,
                            cvss=cvss,
                            severity=str(_first(vul, "base_severity", "severity")),
                        ))

            if config.get("inventory", True):
                for ep_id, dev in devices.items():
                    try:
                        for app in cli.paged(f"/apps/{org_id}/data/{ep_id}", max_items=5000):
                            name = _first(app, "name", "Name", "product_name", "application_name")
                            if not name:
                                continue
                            dev.software.append((
                                str(name),
                                str(_first(app, "version", "Version")),
                                str(_first(app, "vendor", "Vendor", "publisher", "Publisher")),
                                "",
                            ))
                    except httpx.HTTPError as exc:
                        res.messages.append(f"Software-Inventar für {dev.name} nicht abrufbar: {exc}")
            res.devices.extend(devices.values())
            res.messages.append(f"{org_name}: {len(devices)} Geräte")
            if skipped:
                # Funde dieser CVEs nicht als „behoben" werten, alle anderen normal abgleichen
                res.keep_cves.update(skipped)
                liste = ", ".join(skipped[:5]) + (f" und {len(skipped) - 5} weitere" if len(skipped) > 5 else "")
                res.messages.append(f"Hinweis: Action1 lieferte für {len(skipped)} CVE(s) einen Serverfehler, "
                                    f"übersprungen: {liste}")
    except httpx.HTTPStatusError as exc:
        raise CollectorError(f"Action1-API antwortet mit {exc.response.status_code}: {exc.request.url.path}") from exc
    except httpx.HTTPError as exc:
        raise CollectorError(f"Action1-API nicht erreichbar: {exc}") from exc
    finally:
        cli.close()
    return res


def _affected(cli: Action1Client, org_id: str, cve: str) -> list | None:
    """Betroffene Endpoints einer CVE; None, wenn Action1 dauerhaft einen Fehler liefert."""
    path = f"/vulnerabilities/{org_id}/{cve}/endpoints"
    for size in (PAGE, 50):
        try:
            return list(cli.paged(path, page_size=size))
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code < 500:
                raise
    return None


def test_connection(config: dict, secrets: dict, timeout: float = 15) -> str:
    region = config.get("region", "eu")
    base = config.get("base_url") or REGIONS.get(region, REGIONS["eu"])[1]
    cli = Action1Client(base, secrets.get("client_id", ""), secrets.get("client_secret", ""), timeout)
    try:
        orgs = list(cli.paged("/organizations"))
        names = ", ".join(str(_first(o, "name", default=o.get("id"))) for o in orgs[:10])
        return f"Verbindung ok – {len(orgs)} Organisation(en): {names}"
    except httpx.HTTPError as exc:
        raise CollectorError(f"Action1-API nicht erreichbar: {exc}") from exc
    finally:
        cli.close()


def _kind_from_os(os_name) -> str:
    s = str(os_name).lower()
    if "windows" in s:
        return "windows"
    if "mac" in s or "darwin" in s:
        return "mac"
    if any(x in s for x in ("linux", "ubuntu", "debian", "red hat", "rhel")):
        return "linux"
    return ""
