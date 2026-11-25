# pmon – Patch- & Schwachstellenmonitor

**Schwachstellen-Dashboard für kleine IT-Umgebungen.** pmon sammelt installierte Software und bekannte Sicherheitslücken aus **Action1**, von **Synology- und QNAP-NAS** sowie von **Linux-Servern und Proxmox**. Es reichert die Funde mit **CISA KEV**, **FIRST EPSS** und der **NVD** an und zeigt pro Kunde verständlich, was zuerst zu tun ist und wie.

Ein Open-Source-Projekt von [MB-IT Solutions](https://www.mbit.solutions) · powered by [yodaeichen](https://github.com/yodaeichen)

![Übersicht](docs/screenshot-uebersicht.png)

## Funktionen

- **Action1 als Datenquelle:** Endpoints, CVEs mit betroffener Software und verfügbaren Updates sowie optional das Software-Inventar über die offizielle REST-API 3.0. Action1-Organisationen werden automatisch zu Kunden.
- **Synology & QNAP per SSH:** Firmware (DSM, QTS, QuTS hero) und installierte Pakete. Der Abgleich läuft per CPE gegen die NVD und liefert die Version, ab der die Lücke behoben ist.
- **Linux / Proxmox per SSH:** Die Paketliste (Debian, Ubuntu, AlmaLinux, Rocky, Alpine) wird gegen OSV.dev geprüft. Als Fund zählt nur, wofür es ein Update gibt.
- **Priorisierung:** Die Stufen sind *Sofort*, *Hoch*, *Mittel* und *Niedrig*. „Sofort“ gilt für aktiv ausgenutzte Lücken (CISA KEV) oder kritische Lücken mit hoher Angriffswahrscheinlichkeit (EPSS).
- **Abhilfe auf Deutsch:** Je nach Gerätetyp gibt es konkrete Schritte, z. B. Update über Action1, DSM aktualisieren oder `apt full-upgrade`. Dazu kommen Links zu NVD, CISA und Hersteller.
- **Kunden & Rechte:** Es gibt drei Rollen: Administrator, Techniker und Leser. Leser-Zugänge sind auf einzelne Kunden beschränkbar, z. B. für Kunden selbst.
- **Benachrichtigung** per E-Mail (SMTP, z. B. mailcow) oder Webhook (z. B. DIVERA Gateway, Teams, n8n). Gemeldet werden neue Funde mit hoher Priorität.
- **CSV-Export,** Risiko akzeptieren mit Begründung, Scan-Protokoll.
- **Sicherheit:**
  - Zugangsdaten werden verschlüsselt gespeichert (Fernet).
  - SSH-Host-Schlüssel werden geprüft (TOFU).
  - CSRF-Schutz, Login-Sperre, CSP und `Secure`-Cookies hinter HTTPS.
  - Keine externen Schriften oder CDNs.

## Installation auf Proxmox (Einzeiler)

Auf dem Proxmox-Host als root:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/yodaeichen/pmon/main/proxmox/install.sh)"
```

Wie bei den Proxmox Helper Scripts öffnet sich ein Auswahldialog:

- **Standard:** nächste freie ID, 2 Kerne, 1 GB RAM, 8 GB, DHCP. Danach nur noch die Frage nach dem Nginx Proxy Manager.
- **Erweitert:** Jeder Wert wird einzeln abgefragt und geprüft:
  - Container-ID, Hostname, Debian 13 oder 12, unprivilegiert oder privilegiert, root-Passwort
  - Kerne, RAM, Swap, Festplatte
  - Speicher und Bridge (Auswahlliste mit freiem Platz bzw. IP)
  - feste IP mit Gateway oder DHCP, VLAN, DNS-Server, Autostart
  - Domain, Port, GitHub-Zweig
  - NPM-Zugang und Zugriffsliste

Am Ende zeigt eine Zusammenfassung alle Werte, erst dann wird installiert. „Abbrechen“ in jedem Dialog beendet das Skript, ohne etwas anzulegen.

Das Skript legt einen Debian-LXC an, installiert pmon als systemd-Dienst auf Port 8000 und zeigt den ersten Zugang. Auf Wunsch richtet es gleich den Proxy-Host im **Nginx Proxy Manager** ein.

**Ohne Rückfragen** (z. B. für Automatisierung) mit `MODE=auto` und Variablen:

```bash
MODE=auto CTID=120 IP=172.15.15.60/24 GW=172.15.15.1 bash -c "$(curl -fsSL https://raw.githubusercontent.com/yodaeichen/pmon/main/proxmox/install.sh)"
```

| Variable | Standard | Bedeutung |
|---|---|---|
| `MODE` | Auswahl | `default`, `advanced` oder `auto` (ohne Dialoge) |
| `CTID` | nächste freie | Container-ID |
| `CT_HOSTNAME` | `pmon` | Hostname |
| `DEBIAN_VERSION` | `13` | `13` oder `12` |
| `UNPRIVILEGED` | `1` | `0` = privilegierter Container |
| `CORES` / `RAM` / `SWAP` / `DISK` | `2` / `1024` / `512` / `8` | Ressourcen (MB, GB) |
| `STORAGE` / `TEMPLATE_STORAGE` | `local-lvm` / erster passender | Speicher |
| `BRIDGE` / `VLAN` | `vmbr0` / – | Netzwerk |
| `IP` / `GW` / `DNS` | `dhcp` / – / – | z. B. `IP=172.15.15.60/24` |
| `ONBOOT` | `1` | Autostart |
| `DOMAIN` / `PORT` | `pmon.mbit.solutions` / `8000` | Adresse und interner Port |
| `NPM_SETUP` | `no` bei `auto` | `yes` mit `NPM_URL`, `NPM_EMAIL`, `NPM_PASSWORD`, `ACCESS_LIST` |

### Nginx Proxy Manager (Einzeiler)

Auf einem Rechner, der die NPM-Verwaltung erreicht (z. B. dem Proxmox-Host):

```bash
TARGET_HOST=172.15.15.60 bash -c "$(curl -fsSL https://raw.githubusercontent.com/yodaeichen/pmon/main/scripts/npm-proxy.sh)"
```

Das Skript meldet sich per API am NPM an und legt den Proxy-Host `pmon.mbit.solutions` an oder aktualisiert ihn. Dabei geschieht Folgendes:

- Ein vorhandenes Wildcard-Zertifikat `*.mbit.solutions` wird gefunden und zugewiesen.
- „Force SSL“ wird aktiviert.
- Auf Wunsch wird eine Zugriffsliste gesetzt, z. B. „nur intern“.

### Aktualisieren

```bash
pct exec <CTID> -- pmon-update
```

Ausführliche Anleitung mit Netzplan, Firewall-Regeln und Einrichtung der Quellen: **[docs/INSTALLATION.md](docs/INSTALLATION.md)**

## Ohne Proxmox

- **Debian/Ubuntu:**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/yodaeichen/pmon/main/scripts/setup.sh | bash
  ```
- **Docker:** `docker compose up -d` startet auf Port 8000. Der erste Zugang steht im Log.

## Entwicklung

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
DATA_DIR=./data .venv/bin/uvicorn app.main:app --reload
.venv/bin/python tests/smoke_test.py   # Durchlauftest ohne Internet
```

Aufbau:

- `app/collectors/`: Action1, SSH (Synology, QNAP, Linux)
- `app/enrich/feeds.py`: NVD, KEV, EPSS, OSV
- `app/scanner.py`: Ablauf und Abgleich
- `app/web.py`: Oberfläche

## Datenquellen & Lizenzen

- Schwachstellendaten: [NVD](https://nvd.nist.gov) (NIST), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [FIRST EPSS](https://www.first.org/epss), [OSV.dev](https://osv.dev). Die Nutzung erfolgt nach deren Bedingungen. *This product uses data from the NVD API but is not endorsed or certified by the NVD.*
- Action1 ist eine Marke der Action1 Corporation. pmon ist kein offizielles Action1-Produkt und nutzt nur deren öffentliche API.
- Schriften Archivo und IBM Plex Sans: SIL Open Font License. Icons: Lucide (ISC).
- pmon selbst: [MIT-Lizenz](LICENSE).

Gefällt dir das Projekt? [Unterstütze es auf GitHub Sponsors](https://github.com/sponsors/yodaeichen) ♥
