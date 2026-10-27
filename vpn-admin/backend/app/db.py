import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field

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

CREATE TABLE IF NOT EXISTS provisions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    hoster_id    INTEGER NOT NULL,
    panel_id     INTEGER NOT NULL,
    name         TEXT    NOT NULL,
    region       TEXT    NOT NULL,
    plan         TEXT    NOT NULL,
    project      TEXT    NOT NULL DEFAULT '',
    ssh_keys     TEXT    NOT NULL DEFAULT '[]',
    server_id    TEXT    NOT NULL DEFAULT '',
    ip           TEXT    NOT NULL DEFAULT '',
    port         INTEGER NOT NULL,
    base_path    TEXT    NOT NULL,
    username     TEXT    NOT NULL,
    secrets_enc  TEXT    NOT NULL,
    cert_pem     TEXT    NOT NULL,
    cert_pin     TEXT    NOT NULL,
    node_id      INTEGER,
    step         TEXT    NOT NULL,
    state        TEXT    NOT NULL,
    error        TEXT    NOT NULL DEFAULT '',
    log          TEXT    NOT NULL DEFAULT '[]',
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hosters (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    provider        TEXT    NOT NULL,
    name            TEXT    NOT NULL,
    credentials_enc TEXT    NOT NULL,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_accounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    provider        TEXT    NOT NULL,
    name            TEXT    NOT NULL,
    credentials_enc TEXT    NOT NULL,
    created_at      INTEGER NOT NULL
);
"""

# Columns added after a table first shipped: table -> [(name, definition)]
MIGRATIONS = {
    "panels": [("api_token_enc", "TEXT NOT NULL DEFAULT ''")],
    "provisions": [("labels", "TEXT NOT NULL DEFAULT '{}'"), ("domain", "TEXT NOT NULL DEFAULT ''"),
                   ("cert_mode", "TEXT NOT NULL DEFAULT ''"), ("replaces", "INTEGER NOT NULL DEFAULT 0"),
                   ("in_place", "INTEGER NOT NULL DEFAULT 0"), ("dns_account_id", "INTEGER NOT NULL DEFAULT 0"),
                   ("dns_zone_id", "TEXT NOT NULL DEFAULT ''"), ("dns_record_id", "TEXT NOT NULL DEFAULT ''"),
                   ("site_template", "TEXT NOT NULL DEFAULT ''"), ("sub_port", "INTEGER NOT NULL DEFAULT 0")],
}


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
        for table, columns in MIGRATIONS.items():
            existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            for name, definition in columns:
                if name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


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


# ---------- DNS accounts (Cloudflare) ----------

@dataclass
class DnsAccount:
    id: int
    provider: str
    name: str
    credentials: dict
    created_at: int


def _row_to_dns_account(row: sqlite3.Row) -> DnsAccount:
    return DnsAccount(id=row["id"], provider=row["provider"], name=row["name"],
                      credentials=json.loads(decrypt(row["credentials_enc"]) or "{}"), created_at=row["created_at"])


def list_dns_accounts() -> list[DnsAccount]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM dns_accounts ORDER BY id").fetchall()
    return [_row_to_dns_account(r) for r in rows]


def get_dns_account(account_id: int) -> DnsAccount | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM dns_accounts WHERE id = ?", (account_id,)).fetchone()
    return _row_to_dns_account(row) if row else None


def create_dns_account(provider: str, name: str, credentials: dict) -> DnsAccount:
    with connect() as conn:
        cur = conn.execute("INSERT INTO dns_accounts (provider, name, credentials_enc, created_at) VALUES (?, ?, ?, ?)",
                           (provider, name, encrypt(json.dumps(credentials)), int(time.time())))
        account_id = cur.lastrowid
    return get_dns_account(account_id)


def update_dns_account(account_id: int, name: str, credentials: dict) -> DnsAccount | None:
    with connect() as conn:
        conn.execute("UPDATE dns_accounts SET name=?, credentials_enc=? WHERE id=?",
                     (name, encrypt(json.dumps(credentials)), account_id))
    return get_dns_account(account_id)


def delete_dns_account(account_id: int) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM dns_accounts WHERE id = ?", (account_id,))
    return cur.rowcount > 0


# ---------- new servers ordered through a hosting account ----------

@dataclass
class Provision:
    id: int
    hoster_id: int
    panel_id: int
    name: str
    region: str
    plan: str
    project: str
    ssh_keys: list
    server_id: str
    ip: str
    port: int
    base_path: str
    username: str
    secrets: dict  # node panel password, the admin's SSH key for this server, the TLS key until installed
    cert_pem: str
    cert_pin: str
    node_id: int | None
    step: str
    state: str
    error: str
    log: list
    created_at: int
    updated_at: int
    labels: dict = field(default_factory=dict)  # readable region and plan, e.g. a country instead of an ID
    domain: str = ""  # wanted address of the node panel; empty = its IP
    cert_mode: str = ""  # certificate the panel ended up with: "domain" / "ip" (Let's Encrypt) or "self"
    replaces: int = 0  # reinstall: the job whose server this one takes over
    in_place: int = 0  # reinstall by the hosting on the same server (the IP stays) instead of a new server
    dns_account_id: int = 0  # Cloudflare account that keeps the domain's A record; 0 = the user does it
    dns_zone_id: str = ""
    dns_record_id: str = ""
    site_template: str = ""  # decoy page nginx shows on port 80 of the node; "" = none
    sub_port: int = 0  # subscription port of the node panel instead of 3x-ui's well-known 2096; 0 = left as is


_JSON_FIELDS = {"ssh_keys", "log", "labels"}


def _row_to_provision(row: sqlite3.Row) -> Provision:
    values = {k: row[k] for k in row.keys() if k != "secrets_enc"}
    for key in _JSON_FIELDS:
        values[key] = json.loads(values[key])
    return Provision(**values, secrets=json.loads(decrypt(row["secrets_enc"])))


def list_provisions() -> list[Provision]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM provisions ORDER BY id DESC").fetchall()
    return [_row_to_provision(r) for r in rows]


def get_provision(provision_id: int) -> Provision | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM provisions WHERE id = ?", (provision_id,)).fetchone()
    return _row_to_provision(row) if row else None


def create_provision(**fields) -> Provision:
    now = int(time.time())
    fields = {**fields, "created_at": now, "updated_at": now}
    fields["secrets_enc"] = encrypt(json.dumps(fields.pop("secrets")))
    for key in _JSON_FIELDS & fields.keys():
        fields[key] = json.dumps(fields[key])
    with connect() as conn:
        cur = conn.execute(f"INSERT INTO provisions ({', '.join(fields)}) VALUES ({', '.join('?' * len(fields))})",
                           tuple(fields.values()))
        provision_id = cur.lastrowid
    return get_provision(provision_id)


def update_provision(provision_id: int, **fields) -> None:
    fields["updated_at"] = int(time.time())
    if "secrets" in fields:
        fields["secrets_enc"] = encrypt(json.dumps(fields.pop("secrets")))
    for key in _JSON_FIELDS & fields.keys():
        fields[key] = json.dumps(fields[key])
    with connect() as conn:
        conn.execute(f"UPDATE provisions SET {', '.join(f'{k}=?' for k in fields)} WHERE id=?",
                     (*fields.values(), provision_id))


def delete_provision(provision_id: int) -> bool:
    with connect() as conn:
        cur = conn.execute("DELETE FROM provisions WHERE id = ?", (provision_id,))
    return cur.rowcount > 0
