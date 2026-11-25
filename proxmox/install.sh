#!/usr/bin/env bash
# Patchmonitor – Einzeiler für Proxmox VE (auf dem Host als root):
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/yodaeichen/patchmonitor/main/proxmox/install.sh)"
#
# Anpassbar über Variablen vor dem Befehl, z. B.:
#   CTID=120 IP=172.15.15.60/24 GW=172.15.15.1 bash -c "$(curl -fsSL …/install.sh)"
set -euo pipefail

REPO="${REPO:-yodaeichen/patchmonitor}"
BRANCH="${BRANCH:-main}"
DOMAIN="${DOMAIN:-pmon.mbit.solutions}"
CT_HOSTNAME="${CT_HOSTNAME:-patchmonitor}"
CORES="${CORES:-2}"
RAM="${RAM:-1024}"
SWAP="${SWAP:-512}"
DISK="${DISK:-8}"
BRIDGE="${BRIDGE:-vmbr0}"
VLAN="${VLAN:-}"
IP="${IP:-dhcp}"
GW="${GW:-}"
DNS="${DNS:-}"
PORT="${PORT:-8000}"
STORAGE="${STORAGE:-}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-}"
NPM_SETUP="${NPM_SETUP:-ask}"   # ask | yes | no
RAW="https://raw.githubusercontent.com/${REPO}/${BRANCH}"

c_b=$'\033[1;34m'; c_g=$'\033[1;32m'; c_r=$'\033[1;31m'; c_y=$'\033[1;33m'; c_0=$'\033[0m'
say()  { printf '%s==>%s %s\n' "$c_b" "$c_0" "$*"; }
ok()   { printf '%s ✓ %s %s\n' "$c_g" "$c_0" "$*"; }
warn() { printf '%s ! %s %s\n' "$c_y" "$c_0" "$*"; }
die()  { printf '%sFehler:%s %s\n' "$c_r" "$c_0" "$*" >&2; exit 1; }
ask()  { local a=""; if [ -r /dev/tty ]; then read -r -p "$1" a </dev/tty || true; fi; printf '%s' "$a"; }

[ "$(id -u)" -eq 0 ] || die "Bitte als root auf dem Proxmox-Host ausführen."
command -v pct >/dev/null && command -v pveam >/dev/null || die "Das ist kein Proxmox-VE-Host (pct/pveam fehlen)."

CTID="${CTID:-$(pvesh get /cluster/nextid)}"
if pct status "$CTID" >/dev/null 2>&1; then die "Container $CTID existiert bereits – andere CTID wählen."; fi

if [ -z "$STORAGE" ]; then
  if pvesm status -content rootdir 2>/dev/null | awk 'NR>1{print $1}' | grep -qx local-lvm; then STORAGE=local-lvm
  else STORAGE="$(pvesm status -content rootdir 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}')"; fi
fi
[ -n "$STORAGE" ] || die "Kein Speicher für Container gefunden – STORAGE=… setzen."
if [ -z "$TEMPLATE_STORAGE" ]; then
  TEMPLATE_STORAGE="$(pvesm status -content vztmpl 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}')"
fi
[ -n "$TEMPLATE_STORAGE" ] || die "Kein Speicher für Vorlagen (vztmpl) gefunden – TEMPLATE_STORAGE=… setzen."

cat <<EOF

  ${c_b}Patchmonitor – Installation als LXC${c_0}
  ------------------------------------------------
  Container-ID   ${CTID}  (Hostname ${CT_HOSTNAME})
  Ressourcen     ${CORES} Kerne, ${RAM} MB RAM, ${DISK} GB auf ${STORAGE}
  Netzwerk       ${BRIDGE}${VLAN:+, VLAN ${VLAN}}, IP ${IP}${GW:+, Gateway ${GW}}
  Domain         https://${DOMAIN}  (über Nginx Proxy Manager)
  Quelle         github.com/${REPO} (${BRANCH})

EOF
if [ "$IP" = "dhcp" ]; then
  warn "IP per DHCP – für den Reverse Proxy besser eine feste IP (IP=…/24 GW=…) oder eine DHCP-Reservierung."
fi
a="$(ask "Fortfahren? [J/n] ")"
case "${a,,}" in n|nein) die "Abgebrochen." ;; esac

say "Debian-Vorlage suchen"
pveam update >/dev/null 2>&1 || warn "pveam update fehlgeschlagen – nutze vorhandene Liste"
TEMPLATE=""
for v in 13 12; do
  TEMPLATE="$(pveam available --section system 2>/dev/null | awk -v p="debian-${v}-standard" '$2 ~ "^"p {print $2}' | sort -V | tail -1)"
  [ -n "$TEMPLATE" ] && break
done
[ -n "$TEMPLATE" ] || die "Keine Debian-Vorlage gefunden."
if ! pveam list "$TEMPLATE_STORAGE" 2>/dev/null | grep -q "$TEMPLATE"; then
  say "Lade $TEMPLATE"
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE" >/dev/null
fi
ok "Vorlage $TEMPLATE"

NET="name=eth0,bridge=${BRIDGE},ip=${IP}"
[ -n "$GW" ] && NET="${NET},gw=${GW}"
[ -n "$VLAN" ] && NET="${NET},tag=${VLAN}"
EXTRA=()
[ -n "$DNS" ] && EXTRA+=(--nameserver "$DNS")

say "Container $CTID anlegen"
pct create "$CTID" "${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE}" \
  --hostname "$CT_HOSTNAME" --cores "$CORES" --memory "$RAM" --swap "$SWAP" \
  --rootfs "${STORAGE}:${DISK}" --net0 "$NET" --unprivileged 1 --features nesting=1 \
  --onboot 1 --ostype debian --tags "patchmonitor" \
  --description "Patchmonitor – https://github.com/${REPO}" "${EXTRA[@]}" >/dev/null
pct start "$CTID"
ok "Container gestartet"

say "Warte auf Netzwerk"
for i in $(seq 1 40); do
  if pct exec "$CTID" -- getent hosts github.com >/dev/null 2>&1 </dev/null; then break; fi
  [ "$i" -eq 40 ] && die "Container $CTID hat kein Netzwerk/DNS – Bridge, VLAN und Gateway prüfen."
  sleep 2
done
ok "Netzwerk bereit"

say "Grundpakete installieren"
pct exec "$CTID" -- bash -c "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null" </dev/null

say "Patchmonitor installieren (dauert ein paar Minuten)"
pct exec "$CTID" -- env REPO="$REPO" BRANCH="$BRANCH" DOMAIN="$DOMAIN" PORT="$PORT" \
  bash -c "curl -fsSL '${RAW}/scripts/setup.sh' -o /root/patchmonitor-setup.sh && bash /root/patchmonitor-setup.sh" </dev/null

CT_IP="$(pct exec "$CTID" -- hostname -I </dev/null | awk '{print $1}')"
ACCESS="$(pct exec "$CTID" -- cat /root/patchmonitor-zugang.txt </dev/null 2>/dev/null || true)"

echo
ok "Patchmonitor läuft in Container ${CTID}: ${c_g}http://${CT_IP}:${PORT}${c_0}"
[ -n "$ACCESS" ] && printf '\n%s\n' "$ACCESS"

# --- Optional: Nginx Proxy Manager gleich mit einrichten
if [ "$NPM_SETUP" = "ask" ]; then
  a="$(ask "Proxy-Host ${DOMAIN} im Nginx Proxy Manager jetzt anlegen? [j/N] ")"
  case "${a,,}" in j|ja|y|yes) NPM_SETUP=yes ;; *) NPM_SETUP=no ;; esac
fi
if [ "$NPM_SETUP" = "yes" ]; then
  TARGET_HOST="$CT_IP" TARGET_PORT="$PORT" DOMAIN="$DOMAIN" \
    bash -c "$(curl -fsSL "${RAW}/scripts/npm-proxy.sh")" || warn "NPM-Einrichtung fehlgeschlagen – später erneut mit dem NPM-Einzeiler."
else
  cat <<EOF

  Reverse Proxy später einrichten (auf einem Rechner, der NPM erreicht):
    TARGET_HOST=${CT_IP} bash -c "\$(curl -fsSL ${RAW}/scripts/npm-proxy.sh)"
EOF
fi

cat <<EOF

  ${c_b}Nächste Schritte${c_0}
  1. DNS: ${DOMAIN} auf die IP des Nginx Proxy Managers zeigen lassen (Pi-hole: Local DNS Records).
  2. https://${DOMAIN} öffnen, mit admin anmelden, Passwort ändern.
  3. Quellen → Neue Quelle → Action1 (API Credentials aus der Action1-Konsole).
  4. Danach in Container ${CTID}: rm /root/patchmonitor-zugang.txt

  Aktualisieren:  pct exec ${CTID} -- patchmonitor-update
  Protokoll:      pct exec ${CTID} -- journalctl -u patchmonitor -f

EOF
