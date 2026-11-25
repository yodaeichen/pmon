"""Einstellungen aus Umgebungsvariablen (im Container: /etc/patchmonitor.env)."""
import os
import secrets
from pathlib import Path


class Settings:
    def __init__(self) -> None:
        self.data_dir = Path(os.environ.get("DATA_DIR", "./data")).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.database_url = os.environ.get(
            "DATABASE_URL", f"sqlite:///{self.data_dir / 'patchmonitor.db'}"
        )
        # SECRET_KEY signiert die Sitzungs-Cookies, FERNET_KEY verschlüsselt
        # gespeicherte Zugangsdaten (API-Secrets, SSH-Passwörter/-Schlüssel).
        self.secret_key = os.environ.get("SECRET_KEY") or self._persisted("secret_key")
        self.fernet_key = os.environ.get("FERNET_KEY") or self._persisted("fernet_key", fernet=True)
        self.base_url = os.environ.get("BASE_URL", "").rstrip("/")
        self.scheduler_enabled = os.environ.get("SCHEDULER", "true").lower() == "true"
        self.http_timeout = float(os.environ.get("HTTP_TIMEOUT", "30"))
        self.repo = os.environ.get("REPO", "yodaeichen/patchmonitor")

    def _persisted(self, name: str, fernet: bool = False) -> str:
        """Fallback für Entwicklung/Docker: Schlüssel einmalig erzeugen und ablegen."""
        path = self.data_dir / f".{name}"
        if path.exists():
            return path.read_text().strip()
        if fernet:
            from cryptography.fernet import Fernet

            value = Fernet.generate_key().decode()
        else:
            value = secrets.token_urlsafe(48)
        path.write_text(value)
        path.chmod(0o600)
        return value


settings = Settings()
