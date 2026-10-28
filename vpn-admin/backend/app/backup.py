"""Backup of the admin's settings: one file, encrypted with a password the user chooses.

The stored secrets are encrypted with this install's SECRET_KEY, which another install does not have, so the
backup carries them decrypted inside a payload of its own: Fernet with a key derived from the password by
scrypt. Outside the payload the file says only what it holds and how many of each.

An import replaces each chosen section as a whole and keeps the ids, so references between sections (a
created server's hoster, main panel and Cloudflare account) stay right. The database is copied aside first.
"""

import base64
import json
import os
import sqlite3
import time
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import db, site, system
from .security import decrypt, encrypt

FORMAT = "vpn-admin-backup"
VERSION = 1
MIN_PASSWORD = 8
KEEP_SNAPSHOTS = 3
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}

# section -> (title, tables); app settings of a section are the keys with its prefix
SECTIONS: dict[str, dict[str, Any]] = {
    "panels": {"title": "Главные серверы 3x-ui", "tables": ["panels"]},
    "hosters": {"title": "Хостинги (VPN API Hoster)", "tables": ["hosters"]},
    "dns": {"title": "Cloudflare (DNS)", "tables": ["dns_accounts"]},
    "cdn": {"title": "CDN", "tables": ["cdn_accounts"]},
    "templates": {"title": "Подключения", "tables": ["connection_templates"], "settings": "connections."},
    "provisions": {"title": "Созданные серверы", "tables": ["provisions"], "needs": ["panels", "hosters"]},
    "site": {"title": "Свой шаблон сайта-заглушки", "tables": []},
}
NAME_COLUMNS = {"panels": "name", "hosters": "name", "dns_accounts": "name", "cdn_accounts": "name",
                "connection_templates": "remark", "provisions": "name"}


class BackupError(Exception):
    pass


def _key(password: str, salt: bytes) -> bytes:
    return base64.urlsafe_b64encode(Scrypt(salt=salt, length=32, **SCRYPT).derive(password.encode()))


def _columns(conn: sqlite3.Connection, table: str) -> dict[str, sqlite3.Row]:
    return {row["name"]: row for row in conn.execute(f"PRAGMA table_info({table})")}


def _dump_table(conn: sqlite3.Connection, table: str) -> list[dict]:
    """Rows with every *_enc column decrypted under its plain name."""
    out = []
    for row in conn.execute(f"SELECT * FROM {table} ORDER BY id"):
        item = {}
        for name in row.keys():
            value = row[name]
            if name.endswith("_enc"):
                item[name[:-4]] = decrypt(value) if value else ""
            else:
                item[name] = value
        out.append(item)
    return out


def _collect(sections: list[str]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    with db.connect() as conn:
        for key in sections:
            spec = SECTIONS[key]
            part: dict[str, Any] = {table: _dump_table(conn, table) for table in spec["tables"]}
            if spec.get("settings"):
                part["settings"] = {row["key"]: row["value"] for row in conn.execute(
                    "SELECT key, value FROM app_settings WHERE key LIKE ?", (spec["settings"] + "%",))}
            data[key] = part
    if "site" in sections:
        data["site"] = {"custom_html": site.CUSTOM_FILE.read_text() if site.CUSTOM_FILE.exists() else ""}
    return data


def _counts(data: dict[str, Any]) -> dict[str, int]:
    counts = {}
    for key, part in data.items():
        if key == "site":
            counts[key] = 1 if part.get("custom_html") else 0
        else:
            counts[key] = sum(len(part.get(table) or []) for table in SECTIONS[key]["tables"])
    return counts


def export(password: str, sections: list[str] | None = None) -> dict[str, Any]:
    if len(password) < MIN_PASSWORD:
        raise BackupError(f"Пароль бекапа — не короче {MIN_PASSWORD} символов")
    sections = [s for s in (sections or list(SECTIONS)) if s in SECTIONS]
    if not sections:
        raise BackupError("Не выбрано ни одного раздела")
    data = _collect(sections)
    salt = os.urandom(16)
    payload = Fernet(_key(password, salt)).encrypt(json.dumps(data, ensure_ascii=False).encode()).decode()
    return {"format": FORMAT, "version": VERSION, "app_version": system.current_version().get("version", ""),
            "created_at": int(time.time()), "sections": _counts(data),
            "kdf": {"name": "scrypt", "salt": base64.b64encode(salt).decode(), **SCRYPT}, "payload": payload}


def _open(backup: dict[str, Any], password: str) -> dict[str, Any]:
    if not isinstance(backup, dict) or backup.get("format") != FORMAT:
        raise BackupError("Это не файл бекапа VPN Admin")
    if not isinstance(backup.get("version"), int) or backup["version"] > VERSION:
        raise BackupError("Бекап сделан более новой версией админки: сначала обновите её в разделе «Система»")
    kdf = backup.get("kdf") or {}
    if kdf.get("name") != "scrypt":
        raise BackupError("Неизвестный способ шифрования бекапа")
    try:
        salt = base64.b64decode(kdf["salt"])
        key = base64.urlsafe_b64encode(Scrypt(salt=salt, length=32, n=int(kdf["n"]), r=int(kdf["r"]),
                                              p=int(kdf["p"])).derive(password.encode()))
        data = json.loads(Fernet(key).decrypt(str(backup["payload"]).encode()))
    except InvalidToken as exc:
        raise BackupError("Неверный пароль бекапа (или файл повреждён)") from exc
    except (KeyError, ValueError, TypeError) as exc:
        raise BackupError("Файл бекапа повреждён") from exc
    if not isinstance(data, dict):
        raise BackupError("Файл бекапа повреждён")
    return {k: v for k, v in data.items() if k in SECTIONS and isinstance(v, dict)}


def _names(key: str, part: dict[str, Any]) -> list[str]:
    if key == "site":
        return ["свой шаблон"] if part.get("custom_html") else []
    names = []
    for table in SECTIONS[key]["tables"]:
        column = NAME_COLUMNS[table]
        for row in part.get(table) or []:
            label = str(row.get(column) or row.get("id"))
            if table in ("hosters", "dns_accounts", "cdn_accounts"):
                label = f"{label} ({row.get('provider', '')})"
            names.append(label)
    return names


def preview(backup: dict[str, Any], password: str) -> dict[str, Any]:
    """What the file holds, by section, next to what the admin has now; nothing is changed."""
    data = _open(backup, password)
    current = _counts(_collect(list(data)))
    return {"app_version": backup.get("app_version", ""), "created_at": backup.get("created_at", 0),
            "sections": [{"key": key, "title": SECTIONS[key]["title"], "items": _names(key, data[key]),
                          "current": current.get(key, 0), "needs": SECTIONS[key].get("needs", [])}
                         for key in SECTIONS if key in data]}


def _snapshot() -> str:
    """Copy of the database as it was before the import, the last few kept next to it."""
    path = db.DB_PATH.with_name(f"{db.DB_PATH.stem}.before-import-{time.strftime('%Y%m%d-%H%M%S')}.db")
    with db.connect() as conn:
        target = sqlite3.connect(path)
        try:
            conn.backup(target)
        finally:
            target.close()
    old = sorted(db.DB_PATH.parent.glob(f"{db.DB_PATH.stem}.before-import-*.db"))
    for extra in old[:-KEEP_SNAPSHOTS]:
        extra.unlink(missing_ok=True)
    return path.name


def _restore_table(conn: sqlite3.Connection, table: str, rows: list[dict]) -> None:
    """Rows of a backup from this or an older version: missing columns take their defaults, unknown ones
    (a newer version that kept the format) are left out, secrets are encrypted with this install's key."""
    columns = _columns(conn, table)
    conn.execute(f"DELETE FROM {table}")
    for row in rows:
        values: dict[str, Any] = {}
        for name, value in row.items():
            if f"{name}_enc" in columns:
                values[f"{name}_enc"] = encrypt(value) if value else ""
            elif name in columns and not name.endswith("_enc"):
                values[name] = value
        if table == "provisions" and values.get("state") == "running":
            # its task ran in the admin the backup came from; here it waits for «Повторить»
            values["state"], values["error"] = "failed", "Задание прервано: восстановлено из бекапа"
        missing = [n for n, c in columns.items() if c["notnull"] and c["dflt_value"] is None and not c["pk"]
                   and n not in values]
        if missing:
            raise BackupError(f"В бекапе у записи таблицы {table} нет полей: {', '.join(missing)}")
        names = list(values)
        conn.execute(f"INSERT INTO {table} ({', '.join(names)}) VALUES ({', '.join('?' * len(names))})",
                     [values[n] for n in names])
    # new rows must not reuse an id the backup holds
    conn.execute("DELETE FROM sqlite_sequence WHERE name = ?", (table,))
    if rows:
        conn.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)",
                     (table, max(int(r.get("id") or 0) for r in rows)))


def restore(backup: dict[str, Any], password: str, sections: list[str]) -> dict[str, Any]:
    data = _open(backup, password)
    chosen = [key for key in SECTIONS if key in sections and key in data]
    if not chosen:
        raise BackupError("Не выбрано ни одного раздела из этого бекапа")
    for key in chosen:
        lacking = [n for n in SECTIONS[key].get("needs", []) if n not in chosen]
        if lacking:
            raise BackupError(f"«{SECTIONS[key]['title']}» восстанавливаются только вместе с разделами: "
                              + ", ".join(f"«{SECTIONS[n]['title']}»" for n in lacking))
    if any(p.state == "running" for p in db.list_provisions()):
        raise BackupError("Сейчас идёт задание в блоке «Новые серверы»: дождитесь его окончания, затем восстановите")
    snapshot = _snapshot()
    with db.connect() as conn:  # one transaction: either every section or none
        for key in chosen:
            spec, part = SECTIONS[key], data[key]
            for table in spec["tables"]:
                rows = part.get(table) or []
                if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
                    raise BackupError(f"Файл бекапа повреждён (раздел «{spec['title']}»)")
                _restore_table(conn, table, rows)
            if spec.get("settings"):
                conn.execute("DELETE FROM app_settings WHERE key LIKE ?", (spec["settings"] + "%",))
                for k, v in (part.get("settings") or {}).items():
                    if str(k).startswith(spec["settings"]):
                        conn.execute("INSERT INTO app_settings (key, value) VALUES (?, ?)", (str(k), str(v)))
    if "site" in chosen:
        html = str(data["site"].get("custom_html") or "")
        if html:
            site.CUSTOM_FILE.write_text(html)
        else:
            site.CUSTOM_FILE.unlink(missing_ok=True)
    return {"restored": [{"key": k, "title": SECTIONS[k]["title"], "count": _counts({k: data[k]})[k]} for k in chosen],
            "snapshot": snapshot}
