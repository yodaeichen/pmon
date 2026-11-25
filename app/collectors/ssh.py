"""SSH-Hilfen: ein Aufruf pro Gerät, Host-Schlüssel wird beim ersten Kontakt gemerkt (TOFU)."""
import base64
import io
import socket

import paramiko

from .base import CollectorError

MARK = "@@PM@@"


class _TofuPolicy(paramiko.MissingHostKeyPolicy):
    """Unbekannten Schlüssel annehmen und merken – nur wenn noch keiner gespeichert ist."""

    def __init__(self):
        self.seen = None

    def missing_host_key(self, client, hostname, key):
        self.seen = f"{key.get_name()} {key.get_base64()}"


def _load_key(text: str, passphrase: str | None):
    errors = []
    for cls in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return cls.from_private_key(io.StringIO(text), password=passphrase or None)
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
    raise CollectorError("Privater SSH-Schlüssel konnte nicht gelesen werden.")


def run_sections(config: dict, secrets: dict, sections: dict[str, str],
                 timeout: float = 20) -> tuple[dict[str, str], str | None]:
    """Führt mehrere Befehle in einer Sitzung aus.

    Rückgabe: (Ausgabe je Abschnitt, neu gelernter Host-Schlüssel oder None)
    """
    host = (config.get("host") or "").strip()
    if not host:
        raise CollectorError("Kein Host angegeben.")
    port = int(config.get("port") or 22)
    user = (config.get("username") or "").strip()
    if not user:
        raise CollectorError("Kein SSH-Benutzer angegeben.")

    client = paramiko.SSHClient()
    policy = _TofuPolicy()
    known = (config.get("host_key") or "").strip()
    if known:
        try:
            ktype, kdata = known.split(" ", 1)
            key = paramiko.PKey.from_type_string(ktype, base64.b64decode(kdata))
            hk_name = host if port == 22 else f"[{host}]:{port}"
            client.get_host_keys().add(hk_name, ktype, key)
        except Exception as exc:  # noqa: BLE001
            raise CollectorError(f"Gespeicherter Host-Schlüssel ist ungültig: {exc}") from exc
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(policy)

    pkey = None
    if secrets.get("private_key"):
        pkey = _load_key(secrets["private_key"], secrets.get("passphrase"))
    try:
        client.connect(host, port=port, username=user, password=secrets.get("password") or None,
                       pkey=pkey, timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                       look_for_keys=False, allow_agent=False)
    except paramiko.BadHostKeyException as exc:
        raise CollectorError(
            "Der Host-Schlüssel hat sich geändert! Möglicher Angriff oder Neuinstallation – "
            "prüfen und gespeicherten Schlüssel in der Quelle zurücksetzen.") from exc
    except paramiko.SSHException as exc:
        if "not found in known_hosts" in str(exc):
            raise CollectorError("Host-Schlüssel stimmt nicht mit dem gespeicherten überein.") from exc
        raise CollectorError(f"SSH-Fehler: {exc}") from exc
    except paramiko.AuthenticationException as exc:
        raise CollectorError("SSH-Anmeldung fehlgeschlagen (Benutzer/Passwort/Schlüssel prüfen).") from exc
    except (socket.error, OSError) as exc:
        raise CollectorError(f"{host}:{port} nicht erreichbar: {exc}") from exc

    script = "\n".join(f"echo '{MARK}{name}'\n{{ {cmd} ; }} 2>/dev/null" for name, cmd in sections.items())
    try:
        _, stdout, _ = client.exec_command(f"sh -c {_quote(script)}", timeout=timeout * 3)
        out = stdout.read().decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        raise CollectorError(f"Befehle auf {host} fehlgeschlagen: {exc}") from exc
    finally:
        client.close()
    return parse_sections(out), policy.seen


def parse_sections(out: str) -> dict[str, str]:
    result: dict[str, list[str]] = {}
    current = None
    for line in out.splitlines():
        if line.startswith(MARK):
            current = line[len(MARK):].strip()
            result[current] = []
        elif current is not None:
            result[current].append(line)
    return {k: "\n".join(v).strip() for k, v in result.items()}


def _quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"
