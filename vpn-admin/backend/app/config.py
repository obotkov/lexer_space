import os
from dataclasses import dataclass
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    admin_username: str
    admin_password: str
    secret_key: str
    data_dir: Path
    static_dir: Path
    cache_ttl: int
    session_hours: int
    cookie_secure: bool
    # Optional panel to create on first start (filled by install.sh)
    xui_url: str
    xui_username: str
    xui_password: str
    xui_api_token: str
    xui_verify_tls: bool
    # Where updates come from: GitHub repository, branch and the project folder inside it
    update_repo: str
    update_branch: str
    update_path: str


def load_settings() -> Settings:
    secret = os.getenv("SECRET_KEY", "")
    if len(secret) < 16:
        raise RuntimeError("SECRET_KEY is not set or too short (min 16 chars). Run install.sh or fill .env")
    password = os.getenv("ADMIN_PASSWORD", "")
    if not password:
        raise RuntimeError("ADMIN_PASSWORD is not set. Run install.sh or fill .env")

    return Settings(
        admin_username=os.getenv("ADMIN_USERNAME", "admin"),
        admin_password=password,
        secret_key=secret,
        data_dir=Path(os.getenv("DATA_DIR", "/data")),
        static_dir=Path(os.getenv("STATIC_DIR", Path(__file__).resolve().parent.parent / "static")),
        cache_ttl=int(os.getenv("CACHE_TTL", "30")),
        session_hours=int(os.getenv("SESSION_HOURS", "24")),
        cookie_secure=_bool("COOKIE_SECURE", False),
        xui_url=os.getenv("XUI_URL", ""),
        xui_username=os.getenv("XUI_USERNAME", ""),
        xui_password=os.getenv("XUI_PASSWORD", ""),
        xui_api_token=os.getenv("XUI_API_TOKEN", ""),
        xui_verify_tls=_bool("XUI_VERIFY_TLS", True),
        update_repo=os.getenv("UPDATE_REPO", "obotkov/lexer_space"),
        update_branch=os.getenv("UPDATE_BRANCH", "main"),
        update_path=os.getenv("UPDATE_PATH", "vpn-admin"),
    )


settings = load_settings()
