"""Erster Admin-Benutzer und Kommandozeilen-Helfer.

  python -m app.bootstrap reset-password <benutzer>
"""
import os
import sys
from pathlib import Path

from .db import init_db, session_scope
from .models import User
from .security import hash_password, random_password


def ensure_admin() -> str | None:
    """Legt beim ersten Start „admin" mit Zufallspasswort an. Rückgabe: Passwort oder None."""
    with session_scope() as db:
        if db.query(User).count():
            return None
        pw = os.environ.get("ADMIN_PASSWORD") or random_password()
        db.add(User(username="admin", display_name="Administrator", password_hash=hash_password(pw),
                    role="admin"))
    target = os.environ.get("ADMIN_PASSWORD_FILE")
    if target:
        p = Path(target)
        p.write_text(f"Patchmonitor – erster Zugang\nBenutzer: admin\nPasswort: {pw}\n"
                     "Bitte nach der ersten Anmeldung ändern und diese Datei löschen.\n")
        p.chmod(0o600)
    print(f"[patchmonitor] Admin-Benutzer angelegt: admin / {pw}", flush=True)
    return pw


def reset_password(username: str) -> None:
    pw = random_password()
    with session_scope() as db:
        u = db.query(User).filter(User.username == username).first()
        if not u:
            sys.exit(f"Benutzer {username} nicht gefunden")
        u.password_hash = hash_password(pw)
        u.is_active = True
    print(f"Neues Passwort für {username}: {pw}")


if __name__ == "__main__":
    init_db()
    if len(sys.argv) >= 2 and sys.argv[1] == "init":
        if not ensure_admin():
            print("Es gibt bereits Benutzer – nichts geändert.")
    elif len(sys.argv) == 3 and sys.argv[1] == "reset-password":
        reset_password(sys.argv[2])
    else:
        print(__doc__)
