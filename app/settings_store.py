"""Einstellungen in der Datenbank (Benachrichtigung, API-Schlüssel, Schwellwerte)."""
import json

from sqlalchemy.orm import Session

from .models import Setting
from .security import decrypt_json, encrypt_json

DEFAULTS: dict = {
    "smtp_host": "",
    "smtp_port": 587,
    "smtp_starttls": True,
    "smtp_user": "",
    "smtp_from": "",
    "smtp_to": "",
    "webhook_url": "",
    "notify_min_priority": "hoch",  # sofort | hoch
    "notify_enabled": False,
    "stale_days": 7,
    "action1_console_url": "https://app.eu.action1.com",
}
SECRET_KEYS = {"smtp_password", "nvd_api_key", "webhook_secret"}


def get_all(db: Session) -> dict:
    data = dict(DEFAULTS)
    for row in db.query(Setting).all():
        if row.key == "_secrets":
            continue
        try:
            data[row.key] = json.loads(row.value)
        except ValueError:
            data[row.key] = row.value
    return data


def get(db: Session, key: str):
    return get_all(db).get(key)


def set_many(db: Session, values: dict) -> None:
    for key, value in values.items():
        row = db.get(Setting, key) or Setting(key=key)
        row.value = json.dumps(value)
        db.merge(row)
    db.commit()


def get_secrets(db: Session) -> dict:
    row = db.get(Setting, "_secrets")
    return decrypt_json(row.value) if row else {}


def set_secrets(db: Session, values: dict) -> None:
    """Leere Werte lassen das bisherige Geheimnis unverändert."""
    current = get_secrets(db)
    for key, value in values.items():
        if key in SECRET_KEYS and value:
            current[key] = value
    row = db.get(Setting, "_secrets") or Setting(key="_secrets")
    row.value = encrypt_json(current)
    db.merge(row)
    db.commit()


def clear_secret(db: Session, key: str) -> None:
    current = get_secrets(db)
    current.pop(key, None)
    row = db.get(Setting, "_secrets") or Setting(key="_secrets")
    row.value = encrypt_json(current)
    db.merge(row)
    db.commit()
