#!/usr/bin/env bash
# pmon – Installer für Proxmox VE (auf dem Host als root):
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/yodaeichen/pmon/main/proxmox/install.sh)"
#
# Interaktiv mit Auswahldialogen („Standard" oder „Erweitert"), wie die Proxmox Helper Scripts.
# Ohne Rückfragen: MODE=auto und Werte als Variablen vorgeben, z. B.
#   MODE=auto CTID=120 IP=172.15.15.60/24 GW=172.15.15.1 bash -c "$(curl -fsSL …/install.sh)"
set -euo pipefail
shopt -s inherit_errexit  # Abbruch in Dialogen (Befehlsersetzung) beendet das ganze Skript

# ------------------------------------------------------------- Vorgaben
APP="pmon"
REPO="${REPO:-yodaeichen/pmon}"
BRANCH="${BRANCH:-main}"
MODE="${MODE:-}"                    # leer = fragen | default | advanced | auto
DOMAIN="${DOMAIN:-pmon.mbit.solutions}"
PORT="${PORT:-8000}"
CT_HOSTNAME="${CT_HOSTNAME:-pmon}"
DEBIAN_VERSION="${DEBIAN_VERSION:-13}"
UNPRIVILEGED="${UNPRIVILEGED:-1}"
CT_PASSWORD="${CT_PASSWORD:-}"
CORES="${CORES:-2}"
RAM="${RAM:-1024}"
SWAP="${SWAP:-512}"
DISK="${DISK:-8}"
BRIDGE="${BRIDGE:-}"
VLAN="${VLAN:-}"
IP="${IP:-dhcp}"
GW="${GW:-}"
DNS="${DNS:-}"
ONBOOT="${ONBOOT:-1}"
CT_LOCALE="${CT_LOCALE:-de_DE.UTF-8}"
TIMEZONE="${TIMEZONE:-Europe/Berlin}"
STORAGE="${STORAGE:-}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-}"
NPM_SETUP="${NPM_SETUP:-}"          # yes | no (leer = je nach Modus)
NPM_URL="${NPM_URL:-}"
NPM_EMAIL="${NPM_EMAIL:-}"
NPM_PASSWORD="${NPM_PASSWORD:-}"
ACCESS_LIST="${ACCESS_LIST:-}"
RAW="https://raw.githubusercontent.com/${REPO}/${BRANCH}"
BACKTITLE="pmon · MB-IT Solutions · github.com/${REPO}"

# ------------------------------------------------------------- Ausgabe
BL=$'\033[36m'; GN=$'\033[1;92m'; RD=$'\033[01;31m'; YW=$'\033[33m'; BD=$'\033[1m'; CL=$'\033[m'
msg_info()  { printf '  %s⏳%s %s\n' "$YW" "$CL" "$*"; }
msg_ok()    { printf '  %s✔%s  %s\n' "$GN" "$CL" "$*"; }
msg_warn()  { printf '  %s!%s  %s\n' "$YW" "$CL" "$*"; }
msg_error() { printf '  %s✖%s  %s\n' "$RD" "$CL" "$*" >&2; }
die()       { msg_error "$*"; exit 1; }
cancelled() { clear >&2 2>/dev/null || true; msg_warn "Abgebrochen – es wurde nichts verändert." >&2; exit 130; }

header() {
  clear 2>/dev/null || true
  printf '\n%s  ┌──────────────────────────────────────────────┐\n' "$BL$BD"
  printf '  │   PMON  ·  Patch- & Schwachstellenmonitor    │\n'
  printf '  └──────────────────────────────────────────────┘%s\n' "$CL"
  printf '  MB-IT Solutions · powered by yodaeichen\n\n'
}

# ------------------------------------------------------------- Dialoge
# whiptail schreibt die Auswahl auf stderr → Kanäle tauschen
wt() { whiptail --backtitle "$BACKTITLE" "$@" 3>&1 1>&2 2>&3; }

input() {  # Titel Text Vorgabe
  wt --title "$1" --inputbox "$2" 11 68 "$3" || cancelled
}

input_num() {  # Titel Text Vorgabe Min Max
  local v
  while true; do
    v="$(input "$1" "$2" "$3")"
    if [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge "$4" ] && [ "$v" -le "$5" ]; then printf '%s' "$v"; return; fi
    wt --title "Ungültige Eingabe" --msgbox "Bitte eine Zahl zwischen $4 und $5 eingeben." 8 60 || true
  done
}

yesno() {  # Titel Text [defaultno]
  if [ "${3:-}" = "no" ]; then whiptail --backtitle "$BACKTITLE" --title "$1" --defaultno --yesno "$2" 11 68
  else whiptail --backtitle "$BACKTITLE" --title "$1" --yesno "$2" 11 68; fi
}

valid_cidr() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; }
valid_ip()   { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

# ------------------------------------------------------------- Erkennung
storage_list() {  # Inhaltstyp → Zeilen „Name Typ FreiGB"
  pvesm status -content "$1" 2>/dev/null | awk 'NR>1 && $3=="active" {printf "%s %s %.1f\n", $1, $2, $6/1024/1024}'
}

detect_defaults() {
  CTID="${CTID:-$(pvesh get /cluster/nextid)}"
  if [ -z "$STORAGE" ]; then
    if storage_list rootdir | awk '{print $1}' | grep -qx local-lvm; then STORAGE=local-lvm
    else STORAGE="$(storage_list rootdir | awk 'NR==1{print $1}')"; fi
  fi
  [ -n "$TEMPLATE_STORAGE" ] || TEMPLATE_STORAGE="$(storage_list vztmpl | awk 'NR==1{print $1}')"
  if [ -z "$BRIDGE" ]; then
    if ip -o link show vmbr0 >/dev/null 2>&1; then BRIDGE=vmbr0
    else BRIDGE="$(ip -o link show type bridge 2>/dev/null | awk -F': ' 'NR==1{print $2}')"; fi
  fi
  [ -n "$STORAGE" ] || die "Kein aktiver Speicher für Container gefunden."
  [ -n "$TEMPLATE_STORAGE" ] || die "Kein aktiver Speicher für Vorlagen (vztmpl) gefunden."
  [ -n "$BRIDGE" ] || die "Keine Netzwerk-Bridge gefunden."
}

pick_storage() {  # Inhaltstyp Titel Vorgabe
  local items=() name type free n=0
  while read -r name type free; do
    items+=("$name" "${type}, ${free} GB frei" "$([ "$name" = "$3" ] && echo ON || echo OFF)")
    n=$((n + 1))
  done < <(storage_list "$1")
  [ "$n" -gt 0 ] || die "Kein Speicher für $1 gefunden."
  if [ "$n" -eq 1 ]; then printf '%s' "${items[0]}"; return; fi
  wt --title "$2" --radiolist "Mit Leertaste wählen, mit Enter bestätigen:" 16 68 "$n" "${items[@]}" || cancelled
}

pick_bridge() {
  local items=() b n=0
  while read -r b; do
    [ -n "$b" ] || continue
    items+=("$b" "$(ip -4 -o addr show "$b" 2>/dev/null | awk '{print $4}' | head -1)" "$([ "$b" = "$BRIDGE" ] && echo ON || echo OFF)")
    n=$((n + 1))
  done < <(ip -o link show type bridge 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1)
  if [ "$n" -le 1 ]; then printf '%s' "$BRIDGE"; return; fi
  wt --title "Netzwerk-Bridge" --radiolist "Über welche Bridge soll der Container angebunden werden?" 16 68 "$n" "${items[@]}" || cancelled
}

# ------------------------------------------------------------- Erweitert
advanced_settings() {
  local v
  # Container-ID
  while true; do
    v="$(input_num "Container-ID" "ID des neuen Containers:" "$CTID" 100 999999999)"
    if pct status "$v" >/dev/null 2>&1 || qm status "$v" >/dev/null 2>&1; then
      wt --title "Belegt" --msgbox "ID $v ist bereits vergeben." 8 50 || true
    else CTID="$v"; break; fi
  done
  # Hostname
  while true; do
    v="$(input "Hostname" "Hostname des Containers:" "$CT_HOSTNAME")"
    if [[ "$v" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then CT_HOSTNAME="$v"; break; fi
    wt --title "Ungültig" --msgbox "Nur Buchstaben, Ziffern und Bindestrich." 8 50 || true
  done
  # Debian
  DEBIAN_VERSION="$(wt --title "Betriebssystem" --radiolist "Debian-Version des Containers:" 12 68 2 \
    "13" "Debian 13 „Trixie“ (empfohlen)" "$([ "$DEBIAN_VERSION" = 13 ] && echo ON || echo OFF)" \
    "12" "Debian 12 „Bookworm“" "$([ "$DEBIAN_VERSION" = 12 ] && echo ON || echo OFF)")" || cancelled
  # Typ
  UNPRIVILEGED="$(wt --title "Container-Typ" --radiolist "Art des Containers:" 12 68 2 \
    "1" "Unprivilegiert (empfohlen)" "$([ "$UNPRIVILEGED" = 1 ] && echo ON || echo OFF)" \
    "0" "Privilegiert" "$([ "$UNPRIVILEGED" = 0 ] && echo ON || echo OFF)")" || cancelled
  # root-Passwort
  while true; do
    v="$(wt --title "root-Passwort" --passwordbox "Passwort für root im Container (leer = keins, Zugriff dann über „pct enter“):" 11 68)" || cancelled
    [ -z "$v" ] && { CT_PASSWORD=""; break; }
    if [ "${#v}" -lt 8 ]; then wt --title "Zu kurz" --msgbox "Mindestens 8 Zeichen." 8 40 || true; continue; fi
    local v2
    v2="$(wt --title "root-Passwort" --passwordbox "Passwort wiederholen:" 9 68)" || cancelled
    [ "$v" = "$v2" ] && { CT_PASSWORD="$v"; break; }
    wt --title "Abweichung" --msgbox "Die Passwörter stimmen nicht überein." 8 50 || true
  done
  # Ressourcen
  CORES="$(input_num "CPU" "Anzahl CPU-Kerne:" "$CORES" 1 64)"
  RAM="$(input_num "Arbeitsspeicher" "RAM in MB (empfohlen ab 1024):" "$RAM" 256 65536)"
  SWAP="$(input_num "Swap" "Swap in MB:" "$SWAP" 0 65536)"
  DISK="$(input_num "Festplatte" "Größe der Festplatte in GB (empfohlen ab 8):" "$DISK" 4 2048)"
  STORAGE="$(pick_storage rootdir "Speicher für den Container" "$STORAGE")"
  TEMPLATE_STORAGE="$(pick_storage vztmpl "Speicher für die Debian-Vorlage" "$TEMPLATE_STORAGE")"
  # Netzwerk
  BRIDGE="$(pick_bridge)"
  local mode
  mode="$(wt --title "IP-Adresse" --radiolist "Wie bekommt der Container seine Adresse?\n\nFür den Reverse Proxy ist eine feste IP empfehlenswert." 14 68 2 \
    "static" "Feste IP-Adresse (empfohlen)" "$([ "$IP" != dhcp ] && echo ON || echo OFF)" \
    "dhcp" "DHCP" "$([ "$IP" = dhcp ] && echo ON || echo OFF)")" || cancelled
  if [ "$mode" = "dhcp" ]; then IP="dhcp"; GW=""
  else
    while true; do
      v="$(input "Feste IP" "IP-Adresse mit Präfix (z. B. 172.15.15.60/24):" "$([ "$IP" = dhcp ] && echo "" || echo "$IP")")"
      valid_cidr "$v" && { IP="$v"; break; }
      wt --title "Ungültig" --msgbox "Format: 172.15.15.60/24" 8 50 || true
    done
    while true; do
      v="$(input "Gateway" "Gateway (z. B. 172.15.15.1):" "${GW:-${IP%.*}.1}")"
      valid_ip "$v" && { GW="$v"; break; }
      wt --title "Ungültig" --msgbox "Bitte eine IPv4-Adresse eingeben." 8 50 || true
    done
  fi
  while true; do
    v="$(input "VLAN" "VLAN-Tag (leer = kein VLAN):" "$VLAN")"
    if [ -z "$v" ] || { [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 1 ] && [ "$v" -le 4094 ]; }; then VLAN="$v"; break; fi
    wt --title "Ungültig" --msgbox "VLAN 1–4094 oder leer." 8 50 || true
  done
  while true; do
    v="$(input "DNS-Server" "DNS-Server, z. B. dein Pi-hole (leer = wie Proxmox-Host):" "$DNS")"
    if [ -z "$v" ] || valid_ip "$v"; then DNS="$v"; break; fi
    wt --title "Ungültig" --msgbox "Bitte eine IPv4-Adresse oder leer." 8 50 || true
  done
  CT_LOCALE="$(wt --title "Sprache" --radiolist "Systemsprache im Container:" 12 68 2 \
    "de_DE.UTF-8" "Deutsch (empfohlen)" "$([ "$CT_LOCALE" = de_DE.UTF-8 ] && echo ON || echo OFF)" \
    "en_US.UTF-8" "Englisch" "$([ "$CT_LOCALE" = en_US.UTF-8 ] && echo ON || echo OFF)")" || cancelled
  while true; do
    v="$(input "Zeitzone" "Zeitzone des Containers:" "$TIMEZONE")"
    [ -f "/usr/share/zoneinfo/$v" ] && { TIMEZONE="$v"; break; }
    wt --title "Unbekannt" --msgbox "Zeitzone „$v“ gibt es nicht (Beispiel: Europe/Berlin)." 8 60 || true
  done
  if yesno "Autostart" "Container beim Start des Proxmox-Hosts automatisch starten?"; then ONBOOT=1; else ONBOOT=0; fi
  # Anwendung
  DOMAIN="$(input "Domain" "Unter welcher Adresse wird pmon erreichbar sein?" "$DOMAIN")"
  PORT="$(input_num "Port" "Interner Port der Anwendung:" "$PORT" 1024 65535)"
  BRANCH="$(input "GitHub-Zweig" "Welcher Stand soll installiert werden?" "$BRANCH")"
  RAW="https://raw.githubusercontent.com/${REPO}/${BRANCH}"
  npm_settings
}

npm_settings() {
  if yesno "Nginx Proxy Manager" "Proxy-Host ${DOMAIN} nach der Installation automatisch im Nginx Proxy Manager anlegen?\n\nEin passendes Zertifikat (z. B. *.mbit.solutions) wird automatisch zugewiesen." no; then
    NPM_SETUP=yes
    NPM_URL="$(input "NPM-Adresse" "Adresse der NPM-Verwaltung:" "${NPM_URL:-http://}")"
    NPM_EMAIL="$(input "NPM-Benutzer" "E-Mail-Adresse des NPM-Benutzers:" "$NPM_EMAIL")"
    NPM_PASSWORD="$(wt --title "NPM-Passwort" --passwordbox "Passwort (wird nicht gespeichert):" 9 68)" || cancelled
    ACCESS_LIST="$(input "Zugriffsliste" "Name einer NPM-Zugriffsliste, z. B. „Nur intern“ (leer = keine):" "$ACCESS_LIST")"
  else
    NPM_SETUP=no
  fi
}

summary_text() {
  cat <<EOF
Container-ID:   ${CTID}   Hostname: ${CT_HOSTNAME}
System:         Debian ${DEBIAN_VERSION}, $([ "$UNPRIVILEGED" = 1 ] && echo unprivilegiert || echo privilegiert)
Ressourcen:     ${CORES} Kerne, ${RAM} MB RAM, ${SWAP} MB Swap, ${DISK} GB
Speicher:       ${STORAGE} (Vorlage: ${TEMPLATE_STORAGE})
Netzwerk:       ${BRIDGE}${VLAN:+, VLAN ${VLAN}}, IP ${IP}${GW:+, GW ${GW}}${DNS:+, DNS ${DNS}}
Autostart:      $([ "$ONBOOT" = 1 ] && echo ja || echo nein)
Sprache/Zeit:   ${CT_LOCALE}, ${TIMEZONE}
Adresse:        https://${DOMAIN} → Port ${PORT}
NPM einrichten: $([ "$NPM_SETUP" = yes ] && echo "ja (${NPM_URL})" || echo nein)
Quelle:         github.com/${REPO} (${BRANCH})
EOF
}

# ------------------------------------------------------------- Start
header
[ "$(id -u)" -eq 0 ] || die "Bitte als root auf dem Proxmox-Host ausführen."
command -v pct >/dev/null && command -v pveam >/dev/null || die "Das ist kein Proxmox-VE-Host (pct/pveam fehlen)."
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
[ "$ARCH" = "amd64" ] || [ "$ARCH" = "arm64" ] || die "Architektur ${ARCH} wird nicht unterstützt."
detect_defaults

INTERACTIVE=0
if [ "$MODE" != "auto" ] && [ -t 0 ] && [ -t 1 ] && command -v whiptail >/dev/null; then INTERACTIVE=1; fi

if [ "$INTERACTIVE" = 1 ]; then
  if [ -z "$MODE" ]; then
    MODE="$(wt --title "$APP – Installation" --menu "Einstellungen für den neuen Container:" 14 68 3 \
      "default"  "Standard  (ID ${CTID}, ${CORES} Kerne, ${RAM} MB, ${DISK} GB, DHCP)" \
      "advanced" "Erweitert (alle Werte selbst festlegen)" \
      "exit"     "Abbrechen")" || cancelled
  fi
  [ "$MODE" = "exit" ] && cancelled
  if [ "$MODE" = "advanced" ]; then advanced_settings
  else [ -n "$NPM_SETUP" ] || npm_settings; fi
  yesno "$APP – Zusammenfassung" "$(summary_text)\n\nJetzt installieren?" || cancelled
  header
else
  [ -n "$NPM_SETUP" ] || NPM_SETUP=no
  if pct status "$CTID" >/dev/null 2>&1; then die "Container $CTID existiert bereits – CTID=… setzen."; fi
  printf '%s\n\n' "$(summary_text)"
fi
if pct status "$CTID" >/dev/null 2>&1; then die "Container $CTID existiert bereits."; fi
[ "$IP" = "dhcp" ] && msg_warn "IP per DHCP – für den Reverse Proxy besser eine DHCP-Reservierung einrichten."

# Befehle im Container während der Installation: C.UTF-8 ist immer vorhanden.
# Die eingestellte Sprache (z. B. de_DE.UTF-8) erzeugt setup.sh erst und setzt sie als Standard.
ct_exec() {
  pct exec "$CTID" -- env LANG=C.UTF-8 LC_ALL=C.UTF-8 LANGUAGE= \
    DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none "$@" </dev/null
}

# ------------------------------------------------------------- Vorlage
msg_info "Suche Debian-${DEBIAN_VERSION}-Vorlage"
pveam update >/dev/null 2>&1 || msg_warn "pveam update fehlgeschlagen – nutze vorhandene Liste"
# Nur Vorlagen passend zur Architektur des Hosts (Proxmox listet amd64 und arm64)
TEMPLATE="$(pveam available --section system 2>/dev/null \
  | awk -v p="debian-${DEBIAN_VERSION}-standard_" -v a="_${ARCH}.tar" 'index($2, p) == 1 && index($2, a) > 0 {print $2}' \
  | sort -V | tail -1)"
[ -n "$TEMPLATE" ] || die "Keine Vorlage für Debian ${DEBIAN_VERSION} (${ARCH}) gefunden."
if ! pveam list "$TEMPLATE_STORAGE" 2>/dev/null | grep -qF "vztmpl/${TEMPLATE}"; then
  msg_info "Lade ${TEMPLATE}"
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE" >/dev/null || die "Download der Vorlage fehlgeschlagen."
fi
msg_ok "Vorlage ${TEMPLATE}"

# ------------------------------------------------------------- Container
NET="name=eth0,bridge=${BRIDGE},ip=${IP}"
[ -n "$GW" ] && NET="${NET},gw=${GW}"
[ -n "$VLAN" ] && NET="${NET},tag=${VLAN}"
OPTS=(--hostname "$CT_HOSTNAME" --cores "$CORES" --memory "$RAM" --swap "$SWAP"
      --rootfs "${STORAGE}:${DISK}" --net0 "$NET" --unprivileged "$UNPRIVILEGED" --features nesting=1
      --onboot "$ONBOOT" --ostype debian --tags pmon
      --description "pmon – https://github.com/${REPO}")
[ -n "$DNS" ] && OPTS+=(--nameserver "$DNS")
[ -n "$CT_PASSWORD" ] && OPTS+=(--password "$CT_PASSWORD")

msg_info "Lege Container ${CTID} an"
pct create "$CTID" "${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE}" "${OPTS[@]}" >/dev/null || die "pct create fehlgeschlagen."
msg_ok "Container ${CTID} angelegt"
if ! pct start "$CTID"; then
  msg_error "Container ${CTID} startet nicht – er wird wieder entfernt."
  pct destroy "$CTID" --purge >/dev/null 2>&1 || true
  die "Start fehlgeschlagen. Details: pct start ${CTID} --debug (vor dem Löschen) bzw. journalctl -xe"
fi
msg_ok "Container gestartet"

msg_info "Warte auf Netzwerk"
for i in $(seq 1 40); do
  if ct_exec getent hosts github.com >/dev/null 2>&1; then break; fi
  [ "$i" -eq 40 ] && die "Container ${CTID} hat kein Netzwerk/DNS – Bridge, VLAN und Gateway prüfen."
  sleep 2
done
msg_ok "Netzwerk bereit"

msg_info "Installiere Grundpakete"
ct_exec bash -c "apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null"
msg_ok "Grundpakete installiert"

msg_info "Installiere ${APP} (dauert ein paar Minuten)"
ct_exec env REPO="$REPO" BRANCH="$BRANCH" DOMAIN="$DOMAIN" PORT="$PORT" \
  SET_SYSTEM_LOCALE=1 CT_LOCALE="$CT_LOCALE" TIMEZONE="$TIMEZONE" \
  bash -c "curl -fsSL '${RAW}/scripts/setup.sh' -o /root/pmon-setup.sh && bash /root/pmon-setup.sh" \
  || die "Installation im Container fehlgeschlagen – Ausgabe oben prüfen."
msg_ok "${APP} installiert"

CT_IP="$(ct_exec hostname -I | awk '{print $1}')"
ACCESS="$(ct_exec cat /root/pmon-zugang.txt 2>/dev/null || true)"

# ------------------------------------------------------------- NPM
if [ "$NPM_SETUP" = "yes" ]; then
  msg_info "Richte Proxy-Host im Nginx Proxy Manager ein"
  if NPM_URL="$NPM_URL" NPM_EMAIL="$NPM_EMAIL" NPM_PASSWORD="$NPM_PASSWORD" ACCESS_LIST="$ACCESS_LIST" \
     TARGET_HOST="$CT_IP" TARGET_PORT="$PORT" DOMAIN="$DOMAIN" \
     bash -c "$(curl -fsSL "${RAW}/scripts/npm-proxy.sh")" </dev/null; then
    msg_ok "Proxy-Host ${DOMAIN} eingerichtet"
  else
    msg_warn "NPM-Einrichtung fehlgeschlagen – später mit dem NPM-Einzeiler wiederholen."
  fi
fi

# ------------------------------------------------------------- Fertig
echo
msg_ok "${GN}${APP} läuft:${CL} http://${CT_IP}:${PORT}"
[ "$NPM_SETUP" = "yes" ] && msg_ok "Über den Reverse Proxy: https://${DOMAIN}"
[ -n "$ACCESS" ] && printf '\n%s\n' "$ACCESS" | sed 's/^/    /'
cat <<EOF

  ${BD}Nächste Schritte${CL}
  1. DNS: ${DOMAIN} auf die IP des Nginx Proxy Managers zeigen lassen (Pi-hole: Local DNS Records).
EOF
if [ "$NPM_SETUP" != "yes" ]; then
cat <<EOF
     Proxy-Host anlegen:
     TARGET_HOST=${CT_IP} bash -c "\$(curl -fsSL ${RAW}/scripts/npm-proxy.sh)"
EOF
fi
cat <<EOF
  2. Anmelden, Passwort ändern, unter Quellen Action1 einrichten.
  3. Zugangsdatei löschen:  pct exec ${CTID} -- rm /root/pmon-zugang.txt

  Aktualisieren:  pct exec ${CTID} -- pmon-update
  Protokoll:      pct exec ${CTID} -- journalctl -u pmon -f

EOF
