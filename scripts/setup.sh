#!/usr/bin/env bash
# pmon – Installation/Aktualisierung auf Debian 12/13 oder Ubuntu 22.04+
# Läuft im LXC (vom Proxmox-Einzeiler aufgerufen) oder direkt auf einer VM.
# Mehrfach ausführbar: aktualisiert Code und Abhängigkeiten, Daten bleiben erhalten.
set -euo pipefail
# Einheitliche Sprache, damit apt/perl nicht über fehlende Locales klagen
export LANG=C.UTF-8 LC_ALL=C.UTF-8 LANGUAGE=
export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none

REPO="${REPO:-yodaeichen/pmon}"
BRANCH="${BRANCH:-main}"
REPO_URL="${REPO_URL:-https://github.com/${REPO}.git}"
APP_DIR="${APP_DIR:-/opt/pmon}"
DATA_DIR="${DATA_DIR:-/var/lib/pmon}"
ENV_FILE="${ENV_FILE:-/etc/pmon.env}"
DOMAIN="${DOMAIN:-pmon.mbit.solutions}"
PORT="${PORT:-8000}"
# Nur im eigenen Container (vom Proxmox-Installer gesetzt): Systemsprache und Zeitzone einstellen
SET_SYSTEM_LOCALE="${SET_SYSTEM_LOCALE:-0}"
CT_LOCALE="${CT_LOCALE:-de_DE.UTF-8}"
TIMEZONE="${TIMEZONE:-Europe/Berlin}"
SVC_USER="pmon"
ACCESS_FILE="/root/pmon-zugang.txt"

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mFehler:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Bitte als root ausführen."
command -v apt-get >/dev/null || die "Nur Debian/Ubuntu werden unterstützt."

say "Pakete installieren"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv git ca-certificates curl locales tzdata >/dev/null

if [ "$SET_SYSTEM_LOCALE" = "1" ]; then
  say "Sprache ${CT_LOCALE} und Zeitzone ${TIMEZONE} einstellen"
  if ! grep -qE "^${CT_LOCALE}( |$)" /etc/locale.gen 2>/dev/null; then
    if grep -qE "^# *${CT_LOCALE}( |$)" /etc/locale.gen 2>/dev/null; then
      sed -i -E "s/^# *(${CT_LOCALE})( |$)/\\1\\2/" /etc/locale.gen
    else
      echo "${CT_LOCALE} UTF-8" >> /etc/locale.gen
    fi
  fi
  locale-gen >/dev/null
  update-locale LANG="${CT_LOCALE}" LANGUAGE="${CT_LOCALE%%.*}:${CT_LOCALE%%_*}"
  if [ -f "/usr/share/zoneinfo/${TIMEZONE}" ]; then
    ln -sf "/usr/share/zoneinfo/${TIMEZONE}" /etc/localtime
    echo "${TIMEZONE}" > /etc/timezone
  fi
fi

if ! id "$SVC_USER" >/dev/null 2>&1; then
  say "Dienstbenutzer $SVC_USER anlegen"
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SVC_USER"
fi
install -d -m 750 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR"

say "Code holen ($REPO_URL, Zweig $BRANCH)"
if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" fetch -q origin "$BRANCH"
  git -C "$APP_DIR" reset -q --hard "origin/$BRANCH"
else
  rm -rf "$APP_DIR"
  git clone -q --depth 1 --branch "$BRANCH" "$REPO_URL" "$APP_DIR"
fi

say "Python-Umgebung einrichten"
[ -x "$APP_DIR/.venv/bin/python" ] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip >/dev/null
"$APP_DIR/.venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

if [ ! -f "$ENV_FILE" ]; then
  say "Konfiguration $ENV_FILE erzeugen"
  SECRET_KEY="$("$APP_DIR/.venv/bin/python" -c 'import secrets;print(secrets.token_urlsafe(48))')"
  FERNET_KEY="$("$APP_DIR/.venv/bin/python" -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')"
  umask 027
  cat > "$ENV_FILE" <<EOF
# pmon – Konfiguration. Schlüssel NICHT verlieren: FERNET_KEY entschlüsselt
# die gespeicherten Zugangsdaten (API-Secrets, SSH-Passwörter).
SECRET_KEY=${SECRET_KEY}
FERNET_KEY=${FERNET_KEY}
DATA_DIR=${DATA_DIR}
BASE_URL=https://${DOMAIN}
PORT=${PORT}
# Wem X-Forwarded-* geglaubt wird – am besten die IP des Nginx Proxy Managers eintragen
TRUSTED_PROXIES=*
REPO=${REPO}
BRANCH=${BRANCH}
DISPLAY_TZ=${TIMEZONE}
EOF
  chown root:"$SVC_USER" "$ENV_FILE"
  chmod 640 "$ENV_FILE"
fi

say "Datenbank vorbereiten"
(
  set -a; . "$ENV_FILE"; set +a
  cd "$APP_DIR"
  ADMIN_PASSWORD_FILE="$ACCESS_FILE" "$APP_DIR/.venv/bin/python" -m app.bootstrap init >/dev/null
)
chown -R "$SVC_USER:$SVC_USER" "$DATA_DIR"

say "Dienst einrichten"
cat > /etc/systemd/system/pmon.service <<EOF
[Unit]
Description=pmon – Schwachstellen-Dashboard
After=network-online.target
Wants=network-online.target

[Service]
User=${SVC_USER}
Group=${SVC_USER}
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port \${PORT} --proxy-headers --forwarded-allow-ips \${TRUSTED_PROXIES}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF

cat > /usr/local/bin/pmon-update <<EOF
#!/usr/bin/env bash
# pmon auf den neuesten Stand von GitHub bringen
set -euo pipefail
set -a; . ${ENV_FILE}; set +a
export REPO BRANCH
exec bash ${APP_DIR}/scripts/setup.sh "\$@"
EOF
chmod 755 /usr/local/bin/pmon-update

if ! command -v systemctl >/dev/null || [ ! -d /run/systemd/system ]; then
  die "Kein systemd gefunden: Programm installiert, aber kein Dienst eingerichtet."
fi
systemctl daemon-reload
systemctl enable -q pmon
systemctl restart pmon

say "Warte auf den Start"
ok=""
for _ in $(seq 1 30); do
  if curl -fs "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[ -n "$ok" ] || die "pmon antwortet nicht – siehe: journalctl -u pmon -n 50"

VERSION="$(curl -fs "http://127.0.0.1:${PORT}/healthz" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
say "pmon ${VERSION} läuft: http://${IP}:${PORT}  (später: https://${DOMAIN})"
if [ -f "$ACCESS_FILE" ]; then
  echo "    Erster Zugang steht in ${ACCESS_FILE} – nach der ersten Anmeldung Passwort ändern und Datei löschen."
fi
