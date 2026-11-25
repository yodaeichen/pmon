"""Öffentliche Schwachstellen-Quellen: NVD, CISA KEV, FIRST EPSS, OSV.dev."""
import json
import re
import time
from datetime import datetime

import httpx

from ..config import settings

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
OSV_URL = "https://api.osv.dev/v1"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

_transport: httpx.BaseTransport | None = None  # für Tests austauschbar


def client() -> httpx.Client:
    return httpx.Client(timeout=settings.http_timeout, transport=_transport,
                        headers={"User-Agent": "pmon (+https://github.com/%s)" % settings.repo})


# ------------------------------------------------------------------ NVD
class Nvd:
    def __init__(self, api_key: str | None = None):
        self.api_key = api_key or None
        self.delay = 0.8 if self.api_key else 6.5  # NVD: 50 bzw. 5 Anfragen / 30 s
        self._last = 0.0
        self.http = client()

    def close(self):
        self.http.close()

    def _get(self, params: dict) -> dict:
        wait = self.delay - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        headers = {"apiKey": self.api_key} if self.api_key else {}
        for attempt in range(3):
            self._last = time.time()
            r = self.http.get(NVD_URL, params=params, headers=headers)
            if r.status_code in (403, 429, 503) and attempt < 2:
                time.sleep(10 * (attempt + 1))
                continue
            r.raise_for_status()
            return r.json()
        return {}

    def cve(self, cve_id: str) -> dict | None:
        data = self._get({"cveId": cve_id})
        vulns = data.get("vulnerabilities") or []
        return parse_nvd_cve(vulns[0]["cve"]) if vulns else None

    def match_cpe(self, cpe_prefix: str, version: str) -> list[dict]:
        """CVEs, deren CPE-Konfiguration die gegebene Version einschließt."""
        out, start = [], 0
        while True:
            data = self._get({
                "virtualMatchString": cpe_prefix,
                "versionStart": version, "versionStartType": "including",
                "versionEnd": version, "versionEndType": "including",
                "resultsPerPage": 2000, "startIndex": start,
            })
            for v in data.get("vulnerabilities") or []:
                cve = v["cve"]
                parsed = parse_nvd_cve(cve)
                parsed["fixed"] = fixed_from_config(cve, cpe_prefix)
                out.append(parsed)
            total = data.get("totalResults", 0)
            start += data.get("resultsPerPage", 0) or 2000
            if start >= total or not data.get("vulnerabilities"):
                return out


def parse_nvd_cve(cve: dict) -> dict:
    desc = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    cvss, sev, vector = None, "", ""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if items:
            primary = next((m for m in items if m.get("type") == "Primary"), items[0])
            data = primary.get("cvssData", {})
            cvss = data.get("baseScore")
            sev = data.get("baseSeverity") or primary.get("baseSeverity", "")
            vector = data.get("vectorString", "")
            break
    cwes = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            if d.get("value", "").startswith("CWE-"):
                cwes.append(d["value"])
    refs = [{"url": r.get("url"), "tags": r.get("tags", [])} for r in (cve.get("references") or [])[:25]]
    pub = cve.get("published")
    try:
        published = datetime.fromisoformat(pub.replace("Z", "")) if pub else None
    except ValueError:
        published = None
    return {"id": cve.get("id"), "description": desc, "cvss": cvss, "severity": (sev or "").upper(),
            "vector": vector, "cwe": ", ".join(sorted(set(cwes))), "published": published,
            "references": refs}


def fixed_from_config(cve: dict, cpe_prefix: str) -> str:
    fixes = set()
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if m.get("vulnerable") and m.get("criteria", "").startswith(cpe_prefix):
                    if m.get("versionEndExcluding"):
                        fixes.add(f"ab {m['versionEndExcluding']}")
                    elif m.get("versionEndIncluding"):
                        fixes.add(f"neuer als {m['versionEndIncluding']}")
    return "; ".join(sorted(fixes))


# ------------------------------------------------------------------ KEV
def load_kev(force: bool = False) -> dict[str, dict]:
    cache = settings.data_dir / "kev.json"
    if not force and cache.exists() and time.time() - cache.stat().st_mtime < 20 * 3600:
        data = json.loads(cache.read_text())
    else:
        try:
            with client() as http:
                r = http.get(KEV_URL)
                r.raise_for_status()
                data = r.json()
            cache.write_text(json.dumps(data))
        except (httpx.HTTPError, ValueError):
            if not cache.exists():
                return {}
            data = json.loads(cache.read_text())
    return {v["cveID"]: v for v in data.get("vulnerabilities", []) if v.get("cveID")}


# ----------------------------------------------------------------- EPSS
def epss(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    out: dict[str, tuple[float, float]] = {}
    ids = [c for c in cve_ids if CVE_RE.fullmatch(c)]
    with client() as http:
        for i in range(0, len(ids), 80):
            chunk = ids[i:i + 80]
            try:
                r = http.get(EPSS_URL, params={"cve": ",".join(chunk)})
                r.raise_for_status()
                for row in r.json().get("data", []):
                    out[row["cve"]] = (float(row.get("epss", 0)), float(row.get("percentile", 0)))
            except (httpx.HTTPError, ValueError, KeyError):
                continue
    return out


# ------------------------------------------------------------------ OSV
def osv_query(ecosystem: str, packages: list[tuple[str, str]]) -> dict[str, list[str]]:
    """Paketname -> Liste von OSV-IDs."""
    result: dict[str, list[str]] = {}
    with client() as http:
        for i in range(0, len(packages), 500):
            chunk = packages[i:i + 500]
            body = {"queries": [{"package": {"name": n, "ecosystem": ecosystem}, "version": v}
                                for n, v in chunk]}
            r = http.post(f"{OSV_URL}/querybatch", json=body)
            r.raise_for_status()
            for (name, _), res in zip(chunk, r.json().get("results", [])):
                ids = [v["id"] for v in res.get("vulns") or []]
                if ids:
                    result[name] = ids
    return result


def osv_vuln(http: httpx.Client, vuln_id: str) -> dict:
    r = http.get(f"{OSV_URL}/vulns/{vuln_id}")
    r.raise_for_status()
    return r.json()


def osv_fixed(vuln: dict, name: str, ecosystem: str) -> str:
    fixes = set()
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name") != name:
            continue
        if pkg.get("ecosystem") and not pkg["ecosystem"].startswith(ecosystem.split(":")[0]):
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixes.add(ev["fixed"])
    return "; ".join(sorted(fixes))


def osv_cve_ids(vuln: dict) -> list[str]:
    ids = set(CVE_RE.findall(" ".join([vuln.get("id", "")] + (vuln.get("aliases") or [])
                                      + (vuln.get("upstream") or []))))
    return sorted(ids)
