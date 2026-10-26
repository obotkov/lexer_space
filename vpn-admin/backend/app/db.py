import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass

from .config import settings
from .security import decrypt, encrypt

DB_PATH = settings.data_dir / "vpn_admin.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS panels (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    url           TEXT    NOT NULL,
    username      TEXT    NOT NULL,
    password_enc  TEXT    NOT NULL,
    verify_tls    INTEGER NOT NULL DEFAULT 1,
    sub_base_url  TEXT    NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    api_token_enc TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hosters (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    provider        TEXT    NOT NULL,
    name            TEXT    NOT NULL,
    credentials_enc TEXT    NOT NULL,
    created_at      INTEGER NOT NULL
);
"""

# Columns added after the first release: (name, definition)
MIGRATIONS = [
    ("api_token_enc", "TEXT NOT NULL DEFAULT ''"),
]


@dataclass
class Panel:
    id: int
    name: str
    url: str
    username: str
    password: str
    verify_tls: bool
    sub_base_url: str
    created_at: int
    api_token: str = ""

    @property
    def auth_mode(self) -> str:
        return "token" if self.api_token else "password"

    def public(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "username": self.username,
            "verify_tls": self.verify_tls,
            "sub_base_url": self.sub_base_url,
            "created_at": self.created_at,
            "auth_mode": self.auth_mode,
        }


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.executescript(SCHEMA)
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(panels)")}
        for name, definition in MIGRATIONS:
            if name not in existing:
                conn.execute(f"ALTER TABLE panels ADD COLUMN {name} {definition}")


def _row_to_panel(row: sqlite3.Row) -> Panel:
    return Panel(
        id=row["id"],
        name=row["name"],
        url=row["url"],
        username=row["username"],
        password=decrypt(row["password_enc"]),
        verify_tls=bool(row["verify_tls"]),
        sub_base_url=row["sub_base_url"],
        created_at=row["created_at"],
        api_token=decrypt(row["api_token_enc"]) if row["api_token_enc"] else "",
    )


def list_panels() -> list[Panel]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM panels ORDER BY id").fetchall()
    return [_row_to_panel(r) for r in rows]


def get_panel(panel_id: int) -> Panel | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM panels WHERE id = ?", (panel_id,)).fetchone()
    return _row_to_panel(row) if row else None


def create_panel(name: str, url: str, username: str, password: str, verify_tls: bool, sub_base_url: str,
                 api_token: str = "") -> Panel:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO panels (name, url, username, password_enc, verify_tls, sub_base_url, created_at, "
            "api_token_enc) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (name, url, username, encrypt(password), int(verify_tls), sub_base_url, int(time.time()),
             encrypt(api_token) if api_token else ""),
        )
        panel_id = cur.lastrowid
    return get_panel(panel_id)


def update_panel(panel_id: int, name: str, url: str, username: str, password: str | None, verify_tls: bool,
                 sub_base_url: str, api_token: str | None) -> Panel | None:
    """password / api_token: None keeps the stored value, "" clears the token."""
    fields = {"name": name, "url": url, "username": username, "verify_tls": int(verify_tls),
              "sub_base_url": sub_base_url}
    if password:
        fields["password_enc"] = encrypt(password)
    if api_token is not None:
        fields["api_token_enc"] = encrypt(api_token) if api_token else ""
    assignments = ", ".join(f"{k}=?" for k in fields)
    with connect() as conn:
        conn.execute(f"UPDATE panels SET {assignments} WHERE id=?", (*fields.values(), panel_id))
    return get_panel(panel_id)


def delete_panel(panel_id: int) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM panels WHERE id = ?", (panel_id,))
    return cur.rowcount > 0


def count_panels() -> int:
    with connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM panels").fetchone()[0]


# ---------- hosting accounts (VPN API Hoster) ----------

@dataclass
class Hoster:
    id: int
    provider: str
    name: str
    credentials: dict
    created_at: int


def _row_to_hoster(row: sqlite3.Row) -> Hoster:
    return Hoster(id=row["id"], provider=row["provider"], name=row["name"],
                  credentials=json.loads(decrypt(row["credentials_enc"]) or "{}"), created_at=row["created_at"])


def list_hosters() -> list[Hoster]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM hosters ORDER BY id").fetchall()
    return [_row_to_hoster(r) for r in rows]


def get_hoster(hoster_id: int) -> Hoster | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM hosters WHERE id = ?", (hoster_id,)).fetchone()
    return _row_to_hoster(row) if row else None


def create_hoster(provider: str, name: str, credentials: dict) -> Hoster:
    with connect() as conn:
        cur = conn.execute("INSERT INTO hosters (provider, name, credentials_enc, created_at) VALUES (?, ?, ?, ?)",
                           (provider, name, encrypt(json.dumps(credentials)), int(time.time())))
        hoster_id = cur.lastrowid
    return get_hoster(hoster_id)


def update_hoster(hoster_id: int, name: str, credentials: dict) -> Hoster | None:
    with connect() as conn:
        conn.execute("UPDATE hosters SET name=?, credentials_enc=? WHERE id=?",
                     (name, encrypt(json.dumps(credentials)), hoster_id))
    return get_hoster(hoster_id)


def delete_hoster(hoster_id: int) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM hosters WHERE id = ?", (hoster_id,))
    return cur.rowcount > 0
