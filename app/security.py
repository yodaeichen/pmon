"""Passwörter, Verschlüsselung gespeicherter Zugangsdaten, CSRF und Login-Sperre."""
import base64
import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict

from cryptography.fernet import Fernet, InvalidToken

from .config import settings

# ---------------------------------------------------------------- Passwörter
_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        _N, _R, _P, base64.b64encode(salt).decode(), base64.b64encode(dk).decode()
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt_b64, dk_b64 = stored.split("$")
        dk = hashlib.scrypt(
            password.encode(),
            salt=base64.b64decode(salt_b64),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=32,
        )
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))
    except Exception:
        return False


def random_password(length: int = 16) -> str:
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ------------------------------------------------- Verschlüsselte Geheimnisse
_fernet = Fernet(settings.fernet_key.encode())


def encrypt_json(data: dict) -> str:
    if not data:
        return ""
    return _fernet.encrypt(json.dumps(data).encode()).decode()


def decrypt_json(token: str) -> dict:
    if not token:
        return {}
    try:
        return json.loads(_fernet.decrypt(token.encode()).decode())
    except (InvalidToken, ValueError):
        return {}


# ------------------------------------------------------------------- CSRF
def csrf_token(session: dict) -> str:
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return tok


def check_csrf(session: dict, sent: str | None) -> bool:
    expected = session.get("csrf")
    return bool(expected and sent and hmac.compare_digest(expected, sent))


# ------------------------------------------------------------ Login-Sperre
class LoginThrottle:
    """Nach 5 Fehlversuchen je Benutzer+IP 10 Minuten Sperre (im Speicher)."""

    def __init__(self, limit: int = 5, window: int = 600) -> None:
        self.limit = limit
        self.window = window
        self._fails: dict[str, list[float]] = defaultdict(list)

    def _key(self, user: str, ip: str) -> str:
        return f"{user.lower()}|{ip}"

    def blocked(self, user: str, ip: str) -> bool:
        now = time.time()
        k = self._key(user, ip)
        self._fails[k] = [t for t in self._fails[k] if now - t < self.window]
        return len(self._fails[k]) >= self.limit

    def fail(self, user: str, ip: str) -> None:
        self._fails[self._key(user, ip)].append(time.time())

    def reset(self, user: str, ip: str) -> None:
        self._fails.pop(self._key(user, ip), None)


throttle = LoginThrottle()
