"""Client management on 3x-ui panels: create, update, extend, reset traffic, delete.

Every operation takes a list of client references (panel, inbound, email) so the
same code serves a single client, a whole subscription or a bulk selection.
Each reference is processed independently and gets its own ok/error result.
"""

import base64
import logging
import secrets
import time
import uuid
from collections import defaultdict
from typing import Any, Awaitable, Callable

from pydantic import BaseModel, Field

from . import db
from .aggregator import overview_cache, pool
from .xui import XUIClient, XUIError, client_key, parse_json_field

log = logging.getLogger("vpn_admin.clients")

SUPPORTED_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}
DAY_MS = 86_400_000

ERROR_HINTS = {
    "no client remained in Inbound": "Нельзя удалить последнего клиента узла: 3x-ui требует хотя бы одного",
}


class ClientRef(BaseModel):
    panel_id: int
    inbound_id: int
    email: str


class ClientChanges(BaseModel):
    """Only fields that are set get changed."""
    enable: bool | None = None
    total: int | None = Field(None, ge=0, description="traffic limit, bytes; 0 = unlimited")
    expiry_time: int | None = Field(None, description="ms timestamp; 0 = never; negative = days after first use")
    limit_ip: int | None = Field(None, ge=0)
    comment: str | None = None
    tg_id: str | None = None


class CreateTarget(BaseModel):
    panel_id: int
    inbound_id: int


class ClientCreate(BaseModel):
    targets: list[CreateTarget] = Field(min_length=1)
    email: str = Field(min_length=1, max_length=100)
    sub_id: str = ""
    enable: bool = True
    total: int = Field(0, ge=0)
    expiry_time: int = 0
    limit_ip: int = Field(0, ge=0)
    comment: str = ""
    tg_id: str = ""
    flow: str | None = None  # vless only; None = take it from existing clients of the inbound


class Skip(Exception):
    """Nothing to do for this client; reported as success with a note."""


def _hint(message: str) -> str:
    for needle, hint in ERROR_HINTS.items():
        if needle in message:
            return hint
    return message


def _tg_value(tg_id: str, sample: Any) -> Any:
    """Newer 3x-ui stores tgId as int64, older as string: keep whatever the panel already uses."""
    if isinstance(sample, str):
        return tg_id
    return int(tg_id) if tg_id.strip().isdigit() else 0


def _find_client(inbound: dict, email: str) -> tuple[dict, dict]:
    settings = parse_json_field(inbound.get("settings"))
    for raw in settings.get("clients") or []:
        if raw.get("email") == email:
            stats = next((s for s in inbound.get("clientStats") or [] if s.get("email") == email), {})
            return raw, stats
    raise XUIError(f"Клиент {email} не найден в узле")


Op = Callable[[XUIClient, dict, dict, dict], Awaitable[None]]


async def _apply(refs: list[ClientRef], op: Op) -> list[dict]:
    """Runs `op(xui, inbound, raw_client, stats)` for every ref, sequentially per panel."""
    by_panel: dict[int, list[ClientRef]] = defaultdict(list)
    for ref in refs:
        by_panel[ref.panel_id].append(ref)

    results = []
    for panel_id, panel_refs in by_panel.items():
        panel = db.get_panel(panel_id)
        if not panel:
            results += [{**r.model_dump(), "ok": False, "error": "Сервер не найден"} for r in panel_refs]
            continue
        xui = await pool.get(panel)
        inbounds: dict[int, dict] = {}
        for ref in panel_refs:
            try:
                if ref.inbound_id not in inbounds:
                    inbounds[ref.inbound_id] = await xui.inbound(ref.inbound_id)
                inbound = inbounds[ref.inbound_id]
                raw, stats = _find_client(inbound, ref.email)
                await op(xui, inbound, raw, stats)
                results.append({**ref.model_dump(), "ok": True, "error": None})
            except Skip as skip:
                results.append({**ref.model_dump(), "ok": True, "error": None, "note": str(skip)})
            except XUIError as exc:
                log.warning("%s on %s/%s/%s: %s", op.__name__, panel.name, ref.inbound_id, ref.email, exc)
                results.append({**ref.model_dump(), "ok": False, "error": _hint(str(exc))})

    overview_cache.invalidate()
    return results


async def update_clients(refs: list[ClientRef], changes: ClientChanges) -> list[dict]:
    async def update(xui: XUIClient, inbound: dict, raw: dict, _stats: dict) -> None:
        new = dict(raw)
        if changes.enable is not None:
            new["enable"] = changes.enable
        if changes.total is not None:
            new["totalGB"] = changes.total
        if changes.expiry_time is not None:
            new["expiryTime"] = changes.expiry_time
        if changes.limit_ip is not None:
            new["limitIp"] = changes.limit_ip
        if changes.comment is not None:
            new["comment"] = changes.comment
        if changes.tg_id is not None:
            new["tgId"] = _tg_value(changes.tg_id, raw.get("tgId"))
        await xui.update_client(inbound["id"], client_key(inbound["protocol"], raw), new)

    return await _apply(refs, update)


def extended_expiry(current: int, days: int, now_ms: int) -> int:
    if current < 0:  # "N days after first connection" — not started yet, just add days
        return current - days * DAY_MS
    if current > now_ms:
        return current + days * DAY_MS
    return now_ms + days * DAY_MS  # already expired: count from today


async def extend_clients(refs: list[ClientRef], days: int) -> list[dict]:
    now_ms = int(time.time() * 1000)

    async def extend(xui: XUIClient, inbound: dict, raw: dict, stats: dict) -> None:
        # stats hold the real expiry once a delayed-start client has connected
        current = int(stats.get("expiryTime") if stats.get("expiryTime") is not None else raw.get("expiryTime") or 0)
        if current == 0:
            raise Skip("бессрочный, пропущен")
        new = {**raw, "expiryTime": extended_expiry(current, days, now_ms), "enable": True}
        await xui.update_client(inbound["id"], client_key(inbound["protocol"], raw), new)

    return await _apply(refs, extend)


async def reset_traffic(refs: list[ClientRef]) -> list[dict]:
    async def reset(xui: XUIClient, inbound: dict, raw: dict, _stats: dict) -> None:
        await xui.reset_client_traffic(inbound["id"], raw["email"])

    return await _apply(refs, reset)


async def delete_clients(refs: list[ClientRef]) -> list[dict]:
    async def delete(xui: XUIClient, inbound: dict, raw: dict, _stats: dict) -> None:
        await xui.delete_client(inbound["id"], client_key(inbound["protocol"], raw))

    return await _apply(refs, delete)


def _new_credentials(protocol: str, inbound_settings: dict, flow: str | None) -> dict:
    existing = inbound_settings.get("clients") or []
    if protocol == "vless":
        if flow is None:
            flow = existing[0].get("flow", "") if existing else ""
        return {"id": str(uuid.uuid4()), "flow": flow}
    if protocol == "vmess":
        return {"id": str(uuid.uuid4()), "security": "auto"}
    if protocol == "trojan":
        return {"password": secrets.token_urlsafe(12)}
    # shadowsocks: 2022 ciphers need a base64 key of the cipher's size, method is inherited from the inbound
    method = inbound_settings.get("method", "")
    if method.startswith("2022-"):
        size = 16 if "aes-128" in method else 32
        return {"method": "", "password": base64.b64encode(secrets.token_bytes(size)).decode()}
    return {"method": method, "password": secrets.token_urlsafe(16)}


async def create_clients(body: ClientCreate) -> dict:
    sub_id = body.sub_id.strip() or secrets.token_hex(8)
    email = body.email.strip()
    per_panel_count: dict[int, int] = defaultdict(int)
    results = []

    for target in body.targets:
        # 3x-ui requires a panel-wide unique email: second inbound on the same panel gets a suffix
        per_panel_count[target.panel_id] += 1
        n = per_panel_count[target.panel_id]
        target_email = email if n == 1 else f"{email}-{n}"
        result = {**target.model_dump(), "email": target_email, "ok": False, "error": None}
        results.append(result)

        panel = db.get_panel(target.panel_id)
        if not panel:
            result["error"] = "Сервер не найден"
            continue
        xui = await pool.get(panel)
        try:
            inbound = await xui.inbound(target.inbound_id)
            protocol = inbound.get("protocol", "")
            if protocol not in SUPPORTED_PROTOCOLS:
                raise XUIError(f"Протокол {protocol} не поддерживается")
            settings = parse_json_field(inbound.get("settings"))
            existing = settings.get("clients") or []
            client = {
                **_new_credentials(protocol, settings, body.flow),
                "email": target_email,
                "enable": body.enable,
                "limitIp": body.limit_ip,
                "totalGB": body.total,
                "expiryTime": body.expiry_time,
                "tgId": _tg_value(body.tg_id, existing[0].get("tgId") if existing else None),
                "subId": sub_id,
                "comment": body.comment,
                "reset": 0,
            }
            await xui.add_client(target.inbound_id, client)
            result["ok"] = True
        except XUIError as exc:
            log.warning("create %s on %s/%s: %s", target_email, panel.name, target.inbound_id, exc)
            result["error"] = _hint(str(exc))

    overview_cache.invalidate()
    return {"sub_id": sub_id, "results": results}
