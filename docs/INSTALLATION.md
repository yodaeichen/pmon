# Installationsvorschlag – pmon unter pmon.mbit.solutions

Dieser Vorschlag beschreibt den Betrieb als eigener LXC auf Proxmox, erreichbar über den vorhandenen Nginx Proxy Manager (NPM) mit dem Wildcard-Zertifikat `*.mbit.solutions`.

## 1. Zielbild

```
 Browser ──HTTPS──▶ Nginx Proxy Manager ──HTTP :8000──▶ LXC „pmon“ (Debian)
 (intern, Pi-hole)   pmon.mbit.solutions                   │
                     Wildcard-Zertifikat                   ├──HTTPS──▶ Action1-API (app.eu.action1.com)
                                                           ├──HTTPS──▶ NVD, CISA KEV, FIRST EPSS, OSV.dev
                                                           ├──SSH :22─▶ Synology / QNAP (Verwaltungsnetz)
                                                           └──SSH :22─▶ Linux-Server, Proxmox-Hosts
```

| Baustein | Vorschlag |
|---|---|
| Container | Debian 13 (bzw. 12), unprivilegiert, `nesting=1`, Autostart |
| Ressourcen | 2 Kerne, 1 GB RAM, 512 MB Swap, 8 GB Platte (reicht für mehrere hundert Geräte) |
| Netz | Verwaltungs-/Server-Netz, **feste IP** (oder DHCP-Reservierung), da NPM auf die IP weiterleitet |
| Dienst | systemd `pmon.service`, läuft als eigener Benutzer `pmon`, Port 8000 |
| Daten | `/var/lib/pmon` (SQLite-Datenbank, KEV-Zwischenspeicher) |
| Konfiguration | `/etc/pmon.env` (Schlüssel, Domain), nur root und Dienstbenutzer lesbar |
| Programm | `/opt/pmon` (Git-Checkout + Python-venv) |

## 2. Vorbereitung

1. **Feste IP festlegen**, z. B. `172.15.15.60/24` mit Gateway `172.15.15.1`, im Netz, das NPM erreicht.
2. **DNS:** Im Pi-hole unter *Local DNS → DNS Records* `pmon.mbit.solutions` auf die **IP des NPM** zeigen lassen, nicht auf den Container. Von außen sollte das Dashboard nicht erreichbar sein. Einen öffentlichen DNS-Eintrag braucht es dank Wildcard-Zertifikat nicht.
3. **Action1:** In der Konsole unter *API Credentials* Client-ID und Secret anlegen. Am besten über einen eigenen Benutzer mit möglichst wenigen Rechten (Lesen von Endpoints, Schwachstellen, Software). Die Region steht in der Adresse der Konsole, z. B. `app.eu.action1.com`.
4. **NVD-API-Schlüssel** (kostenlos, optional): https://nvd.nist.gov/developers/request-an-api-key. Ohne Schlüssel funktioniert alles, die NVD-Abfragen sind dann aber etwa zehnmal langsamer.

## 3. Installation (Einzeiler)

Auf dem Proxmox-Host (z. B. `pve-eichen`) als root:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/yodaeichen/pmon/main/proxmox/install.sh)"
```

Ablauf:

1. Im Auswahldialog **Erweitert** wählen. Die wichtigsten Werte:
   - **Container-ID:** frei wählbar, belegte IDs werden abgelehnt
   - **Speicher:** z. B. `local-lvm` oder dein ZFS-Pool
   - **Bridge:** vmbr0/vmbr1 mit VLAN-Tag des Server-Netzes
   - **Feste IP** `172.15.15.60/24`, Gateway `172.15.15.1`
   - **DNS** = Pi-hole
2. Bei der Frage nach dem **Nginx Proxy Manager** „Ja“ wählen und die Zugangsdaten angeben:
   - NPM-Adresse, z. B. `http://172.15.15.10:81`
   - Benutzer und Passwort
   - optional eine Zugriffsliste, z. B. „Nur intern“

   Das Passwort wird nicht gespeichert.
3. Die Zusammenfassung prüfen und bestätigen. Ab jetzt läuft alles ohne Rückfragen:
   - Debian-Vorlage laden, Container anlegen und starten
   - pmon installieren (`scripts/setup.sh`)
   - Proxy-Host `pmon.mbit.solutions` mit Wildcard-Zertifikat und „Force SSL“ anlegen

Wer keine Dialoge möchte, setzt `MODE=auto` und gibt die Werte als Variablen vor (Tabelle im README).

Der erste Zugang (Benutzer `admin` + Zufallspasswort) wird angezeigt und liegt zusätzlich im Container unter `/root/pmon-zugang.txt`.

### NPM später oder erneut einrichten

```bash
TARGET_HOST=172.15.15.60 bash -c "$(curl -fsSL https://raw.githubusercontent.com/yodaeichen/pmon/main/scripts/npm-proxy.sh)"
```

Optional mit `ACCESS_LIST="Nur intern"`: Dann wird eine vorhandene NPM-Zugriffsliste zugewiesen, z. B. eine, die nur `172.15.15.0/24` und das VPN zulässt.

**Manuell im NPM:**

- Proxy Host `pmon.mbit.solutions` → `http://172.15.15.60:8000`
- *Block Common Exploits* an
- SSL-Zertifikat `*.mbit.solutions`
- *Force SSL* und *HTTP/2* an

## 4. Härtung nach der Installation

1. `https://pmon.mbit.solutions` öffnen, als `admin` anmelden. Unter **Mein Konto** das Passwort ändern.
2. Zugangsdatei im Container löschen: `pct exec <CTID> -- rm /root/pmon-zugang.txt`.
3. In `/etc/pmon.env` `TRUSTED_PROXIES=*` durch die IP des NPM ersetzen. Danach den Dienst neu starten: `pct exec <CTID> -- systemctl restart pmon`.
4. Firewall (OPNsense):
   - **Zum Container** nur Port 8000 vom NPM zulassen.
   - **Vom Container** zulassen:
     - HTTPS ins Internet für Action1, NVD, CISA, FIRST und OSV
     - SSH (22) zu den NAS-Systemen und Servern
     - SMTP (587) zu mailcow
5. **Backup:** Den Container in den regulären vzdump-Job aufnehmen. Wichtig sind `/var/lib/pmon` **und** `/etc/pmon.env`. Ohne `FERNET_KEY` lassen sich die gespeicherten Zugangsdaten nicht mehr entschlüsseln.

## 5. Quellen einrichten

### Action1
*Quellen → Neue Quelle → Action1*

1. Region **Europa** wählen und Client-ID/Secret eintragen.
2. Das Feld **Kunde** leer lassen: Jede Action1-Organisation wird automatisch als Kunde angelegt.
3. Nach dem Speichern **Verbindung testen**, dann **Jetzt scannen**.

Das empfohlene Intervall ist 60 Minuten. Mit Software-Inventar sind es mehr API-Aufrufe, bei sehr vielen Geräten also eher 240 Minuten.

### Synology
1. Auf dem NAS einen eigenen Benutzer anlegen, z. B. `pmon`. Für SSH muss er in der Gruppe *administrators* sein.
2. Unter *Systemsteuerung → Terminal & SNMP* SSH aktivieren, am besten nur aus dem Verwaltungsnetz.
3. In pmon *Neue Quelle → Synology NAS* anlegen: Host, Benutzer, Passwort oder SSH-Schlüssel, Kunde.
4. pmon liest nur:
   - `/etc.defaults/VERSION`
   - Modell
   - `/var/packages/*/INFO`

### QNAP
1. Unter *Systemsteuerung → Netzwerk- & Dateidienste → Telnet/SSH* SSH aktivieren. Einen eigenen Administrator verwenden.
2. In der Quelle **QTS** oder **QuTS hero** wählen.
3. pmon liest:
   - `getcfg System …` (Version, Build, Modell)
   - `/etc/config/qpkg.conf`

### Linux / Proxmox
1. Auf dem Server einen normalen Benutzer ohne sudo anlegen. Den öffentlichen Schlüssel in `~/.ssh/authorized_keys` eintragen.
2. pmon liest nur `/etc/os-release` und die Paketliste (`dpkg-query`, `rpm` bzw. `apk`).
3. Auf Proxmox-Hosts werden die Debian-Pakete geprüft. Die Proxmox-eigenen Pakete (pve-*, proxmox-kernel) kennt OSV nicht. Für Proxmox-Updates weiterhin PatchMon bzw. `apt list --upgradable` nutzen.

## 6. Benachrichtigung

Unter *Einstellungen*:

- **E-Mail über mailcow:**
  - `mail.mbit.solutions`, Port 587, STARTTLS
  - Benutzer `noreply@mbit.solutions`
  - Empfänger z. B. `info@mbit.solutions`
- **Webhook:** z. B. eine Webhook-Quelle im DIVERA Gateway oder ein Teams-/n8n-Webhook. Der JSON-Inhalt enthält `title`, `text` und die Liste `findings`.
- **Schwelle:** „Sofort“ oder „Sofort und Hoch“. Jeder Fund wird nur einmal gemeldet. Taucht eine Lücke später neu in der CISA-KEV-Liste auf, wird erneut gemeldet.

## 7. Betrieb

| Aufgabe | Befehl |
|---|---|
| Aktualisieren | `pct exec <CTID> -- pmon-update` |
| Protokoll ansehen | `pct exec <CTID> -- journalctl -u pmon -f` |
| Neustart | `pct exec <CTID> -- systemctl restart pmon` |
| Admin-Passwort zurücksetzen | `pct exec <CTID> -- bash -c 'cd /opt/pmon && set -a && . /etc/pmon.env && .venv/bin/python -m app.bootstrap reset-password admin'` |

## 8. Grenzen der Version 1.0

- Action1 liefert CVEs vor allem für Windows. Linux-Endpoints in Action1 erscheinen mit Inventar, aber für deren CVEs ist die SSH-Quelle „Linux“ genauer.
- **NAS-Abgleich über die NVD:**
  - Die NVD ordnet Versionen manchmal ungenau zu, Fehlalarme sind also möglich. Im Zweifel mit der Hersteller-Meldung vergleichen.
  - Gegen die NVD geprüft werden nur die Firmware und die bekannten Pakete. Weitere ergänzt du über „Zusätzliche CPE-Zuordnung“.
- Gerätetypen ohne SSH (Switches, Drucker, USV) sind für eine spätere Version per SNMP bzw. Netzwerk-Scan vorgesehen.
