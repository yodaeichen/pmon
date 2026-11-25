#!/usr/bin/env bash
# Patchmonitor – Proxy-Host im Nginx Proxy Manager per API anlegen oder aktualisieren.
#
#   TARGET_HOST=172.15.15.60 bash -c "$(curl -fsSL https://raw.githubusercontent.com/yodaeichen/patchmonitor/main/scripts/npm-proxy.sh)"
#
# Variablen: NPM_URL (z. B. http://172.15.15.10:81), NPM_EMAIL, NPM_PASSWORD, DOMAIN, TARGET_HOST,
#            TARGET_PORT (8000), CERT_ID (sonst automatisch passendes/Wildcard-Zertifikat),
#            ACCESS_LIST (Name einer NPM-Zugriffsliste, z. B. „Nur intern“)
# Fehlende Werte werden abgefragt; das Passwort wird nirgends gespeichert.
set -euo pipefail

DOMAIN="${DOMAIN:-pmon.mbit.solutions}"
TARGET_PORT="${TARGET_PORT:-8000}"
ask() { local a=""; if [ -r /dev/tty ]; then read -r -p "$1" a </dev/tty || true; fi; printf '%s' "$a"; }
asks() { local a=""; if [ -r /dev/tty ]; then read -r -s -p "$1" a </dev/tty || true; echo >/dev/tty; fi; printf '%s' "$a"; }

command -v python3 >/dev/null || { echo "python3 wird benötigt." >&2; exit 1; }
[ -n "${NPM_URL:-}" ]      || NPM_URL="$(ask "Adresse der NPM-Verwaltung (z. B. http://172.15.15.10:81): ")"
[ -n "${NPM_EMAIL:-}" ]    || NPM_EMAIL="$(ask "NPM-Benutzer (E-Mail): ")"
[ -n "${NPM_PASSWORD:-}" ] || NPM_PASSWORD="$(asks "NPM-Passwort: ")"
[ -n "${TARGET_HOST:-}" ]  || TARGET_HOST="$(ask "IP des Patchmonitor-Containers: ")"
if [ -z "${ACCESS_LIST+x}" ]; then
  ACCESS_LIST="$(ask "Name einer NPM-Zugriffsliste (leer = keine): ")"
fi
[ -n "$NPM_URL" ] && [ -n "$NPM_EMAIL" ] && [ -n "$NPM_PASSWORD" ] && [ -n "$TARGET_HOST" ] \
  || { echo "Angaben unvollständig – abgebrochen." >&2; exit 1; }

export NPM_URL NPM_EMAIL NPM_PASSWORD DOMAIN TARGET_HOST TARGET_PORT ACCESS_LIST
export CERT_ID="${CERT_ID:-}"
python3 - <<'PY'
import json, os, sys, urllib.request, urllib.error

base = os.environ["NPM_URL"].rstrip("/")
domain = os.environ["DOMAIN"].strip().lower()

def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode() or "null"
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        msg = e.read().decode(errors="replace")[:400]
        sys.exit(f"NPM antwortet {e.code} auf {method} {path}: {msg}")
    except urllib.error.URLError as e:
        sys.exit(f"NPM nicht erreichbar ({base}): {e.reason}")

tok = call("POST", "/api/tokens", {"identity": os.environ["NPM_EMAIL"], "secret": os.environ["NPM_PASSWORD"]})
token = (tok or {}).get("token")
if not token:
    sys.exit("Anmeldung am NPM fehlgeschlagen (bei aktivierter Zwei-Faktor-Anmeldung den Proxy-Host bitte von Hand anlegen).")

# Zertifikat: genau passend oder Wildcard der übergeordneten Domain
cert_id = os.environ.get("CERT_ID") or ""
if not cert_id:
    parent = "*." + domain.split(".", 1)[1] if "." in domain else ""
    best = None
    for c in call("GET", "/api/nginx/certificates", token=token) or []:
        names = [n.lower() for n in c.get("domain_names", [])]
        if domain in names or parent in names:
            if best is None or str(c.get("expires_on", "")) > str(best.get("expires_on", "")):
                best = c
    if best:
        cert_id = best["id"]
        print(f"Zertifikat gefunden: {', '.join(best.get('domain_names', []))} (ID {cert_id})")
    else:
        print("Kein passendes Zertifikat gefunden – Proxy-Host wird ohne SSL angelegt. In NPM ein Zertifikat zuweisen!")
cert_id = int(cert_id) if str(cert_id).isdigit() else 0

acl_id = 0
acl_name = os.environ.get("ACCESS_LIST", "").strip()
if acl_name:
    for a in call("GET", "/api/nginx/access-lists", token=token) or []:
        if a.get("name", "").lower() == acl_name.lower():
            acl_id = a["id"]
    if not acl_id:
        print(f"Zugriffsliste „{acl_name}“ nicht gefunden – ohne Zugriffsliste weiter.")

payload = {
    "domain_names": [domain],
    "forward_scheme": "http",
    "forward_host": os.environ["TARGET_HOST"],
    "forward_port": int(os.environ["TARGET_PORT"]),
    "access_list_id": acl_id,
    "certificate_id": cert_id,
    "ssl_forced": bool(cert_id),
    "http2_support": bool(cert_id),
    "hsts_enabled": False,
    "hsts_subdomains": False,
    "block_exploits": True,
    "caching_enabled": False,
    "allow_websocket_upgrade": True,
    "advanced_config": "",
    "meta": {"letsencrypt_agree": False, "dns_challenge": False},
    "locations": [],
}
existing = None
for h in call("GET", "/api/nginx/proxy-hosts", token=token) or []:
    if domain in [n.lower() for n in h.get("domain_names", [])]:
        existing = h
if existing:
    call("PUT", f"/api/nginx/proxy-hosts/{existing['id']}", payload, token)
    print(f"Proxy-Host {domain} aktualisiert → http://{payload['forward_host']}:{payload['forward_port']}")
else:
    call("POST", "/api/nginx/proxy-hosts", payload, token)
    print(f"Proxy-Host {domain} angelegt → http://{payload['forward_host']}:{payload['forward_port']}")
PY
