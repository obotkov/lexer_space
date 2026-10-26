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
    created_at    INTEGER NOT NULL
);
"""


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

    def public(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "username": self.username,
            "verify_tls": self.verify_tls,
            "sub_base_url": self.sub_base_url,
            "created_at": self.created_at,
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
    )


def list_panels() -> list[Panel]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM panels ORDER BY id").fetchall()
    return [_row_to_panel(r) for r in rows]


def get_panel(panel_id: int) -> Panel | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM panels WHERE id = ?", (panel_id,)).fetchone()
    return _row_to_panel(row) if row else None


def create_panel(name: str, url: str, username: str, password: str, verify_tls: bool, sub_base_url: str) -> Panel:
    with connect() as conn:
        cur = conn.execute(
            "INSERT INTO panels (name, url, username, password_enc, verify_tls, sub_base_url, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, url, username, encrypt(password), int(verify_tls), sub_base_url, int(time.time())),
        )
        panel_id = cur.lastrowid
    return get_panel(panel_id)


def update_panel(panel_id: int, name: str, url: str, username: str, password: str | None, verify_tls: bool,
                 sub_base_url: str) -> Panel | None:
    with connect() as conn:
        if password:
            conn.execute(
                "UPDATE panels SET name=?, url=?, username=?, password_enc=?, verify_tls=?, sub_base_url=? WHERE id=?",
                (name, url, username, encrypt(password), int(verify_tls), sub_base_url, panel_id),
            )
        else:
            conn.execute(
                "UPDATE panels SET name=?, url=?, username=?, verify_tls=?, sub_base_url=? WHERE id=?",
                (name, url, username, int(verify_tls), sub_base_url, panel_id),
            )
    return get_panel(panel_id)


def delete_panel(panel_id: int) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM panels WHERE id = ?", (panel_id,))
    return cur.rowcount > 0


def count_panels() -> int:
    with connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM panels").fetchone()[0]
