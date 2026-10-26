import base64
import hashlib
import hmac
import time
from collections import defaultdict

from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import settings

SESSION_COOKIE = "vpn_admin_session"

_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(settings.secret_key.encode()).digest()))
_serializer = URLSafeTimedSerializer(settings.secret_key, salt="vpn-admin-session")


def encrypt(value: str) -> str:
    return _fernet.encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    try:
        return _fernet.decrypt(value.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Cannot decrypt stored secret: SECRET_KEY was changed?") from exc


def check_credentials(username: str, password: str) -> bool:
    user_ok = hmac.compare_digest(username.encode(), settings.admin_username.encode())
    pass_ok = hmac.compare_digest(password.encode(), settings.admin_password.encode())
    return user_ok and pass_ok


def make_session(username: str) -> str:
    return _serializer.dumps({"u": username})


def read_session(token: str | None) -> str | None:
    if not token:
        return None
    try:
        data = _serializer.loads(token, max_age=settings.session_hours * 3600)
    except (BadSignature, SignatureExpired):
        return None
    return data.get("u")


def require_admin(request: Request) -> str:
    user = read_session(request.cookies.get(SESSION_COOKIE))
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизован")
    return user


class LoginThrottle:
    """Blocks an IP for a while after too many failed logins."""

    def __init__(self, max_attempts: int = 5, window: int = 300):
        self.max_attempts = max_attempts
        self.window = window
        self._failures: dict[str, list[float]] = defaultdict(list)

    def _recent(self, ip: str) -> list[float]:
        now = time.time()
        attempts = [t for t in self._failures[ip] if now - t < self.window]
        self._failures[ip] = attempts
        return attempts

    def is_blocked(self, ip: str) -> bool:
        return len(self._recent(ip)) >= self.max_attempts

    def fail(self, ip: str) -> None:
        self._recent(ip).append(time.time())

    def reset(self, ip: str) -> None:
        self._failures.pop(ip, None)


login_throttle = LoginThrottle()
