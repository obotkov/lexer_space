"""Client management on 3x-ui panels: create, update, extend, reset traffic, delete.

Every operation takes a list of client references (panel, inbound, email) so the
same code serves a single client, a whole subscription or a bulk selection.
Each reference is processed independently and gets its own ok/error result.

Every operation has two implementations: legacy panels address a client inside
one inbound, v3 panels address the client record by email (the change applies
to all inbounds it is attached to, so refs are deduplicated by email).
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
from .xui import XUIClient, XUIError, client_key, parse_json_field, v3_record_to_client

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


def _apply_changes(client: dict, changes: "ClientChanges") -> dict:
    """Same field names in legacy inbound clients and v3 client records."""
    new = dict(client)
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
        new["tgId"] = _tg_value(changes.tg_id, client.get("tgId"))
    return new


LegacyOp = Callable[[XUIClient, dict, dict, dict], Awaitable[None]]  # (xui, inbound, raw client, stats)
V3Op = Callable[[XUIClient, dict], Awaitable[None]]  # (xui, client record)


async def _run(ref: ClientRef, panel_name: str, action: Callable[[], Awaitable[None]]) -> dict:
    try:
        await action()
        return {**ref.model_dump(), "ok": True, "error": None}
    except Skip as skip:
        return {**ref.model_dump(), "ok": True, "error": None, "note": str(skip)}
    except XUIError as exc:
        log.warning("%s/%s/%s: %s", panel_name, ref.inbound_id, ref.email, exc)
        return {**ref.model_dump(), "ok": False, "error": _hint(str(exc))}


async def _apply(refs: list[ClientRef], legacy_op: LegacyOp, v3_op: V3Op) -> list[dict]:
    """Runs the operation for every ref, sequentially per panel."""
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
        try:
            await xui.ensure_ready()
        except XUIError as exc:
            results += [{**r.model_dump(), "ok": False, "error": str(exc)} for r in panel_refs]
            continue

        if xui.is_v3:
            unique: dict[str, ClientRef] = {}  # one call per client record
            for ref in panel_refs:
                unique.setdefault(ref.email, ref)
            for ref in unique.values():
                async def action(email=ref.email):
                    record = (await xui.v3_client(email)).get("client")
                    if not record:
                        raise XUIError(f"Клиент {email} не найден")
                    await v3_op(xui, record)
                results.append(await _run(ref, panel.name, action))
            continue

        inbounds: dict[int, dict] = {}
        for ref in panel_refs:
            async def action(ref=ref):
                if ref.inbound_id not in inbounds:
                    inbounds[ref.inbound_id] = await xui.inbound(ref.inbound_id)
                inbound = inbounds[ref.inbound_id]
                raw, stats = _find_client(inbound, ref.email)
                await legacy_op(xui, inbound, raw, stats)
            results.append(await _run(ref, panel.name, action))

    overview_cache.invalidate()
    return results


async def update_clients(refs: list[ClientRef], changes: ClientChanges) -> list[dict]:
    async def legacy(xui: XUIClient, inbound: dict, raw: dict, _stats: dict) -> None:
        await xui.update_client(inbound["id"], client_key(inbound["protocol"], raw), _apply_changes(raw, changes))

    async def v3(xui: XUIClient, record: dict) -> None:
        await xui.v3_update_client(record["email"], _apply_changes(v3_record_to_client(record), changes))

    return await _apply(refs, legacy, v3)


def extended_expiry(current: int, days: int, now_ms: int) -> int:
    if current == 0:
        raise Skip("бессрочный, пропущен")
    if current < 0:  # "N days after first connection" — not started yet, just add days
        return current - days * DAY_MS
    if current > now_ms:
        return current + days * DAY_MS
    return now_ms + days * DAY_MS  # already expired: count from today


async def extend_clients(refs: list[ClientRef], days: int) -> list[dict]:
    now_ms = int(time.time() * 1000)

    async def legacy(xui: XUIClient, inbound: dict, raw: dict, stats: dict) -> None:
        # stats hold the real expiry once a delayed-start client has connected
        current = int(stats.get("expiryTime") if stats.get("expiryTime") is not None else raw.get("expiryTime") or 0)
        new = {**raw, "expiryTime": extended_expiry(current, days, now_ms), "enable": True}
        await xui.update_client(inbound["id"], client_key(inbound["protocol"], raw), new)

    async def v3(xui: XUIClient, record: dict) -> None:
        new = {**v3_record_to_client(record), "enable": True,
               "expiryTime": extended_expiry(int(record.get("expiryTime") or 0), days, now_ms)}
        await xui.v3_update_client(record["email"], new)

    return await _apply(refs, legacy, v3)


async def reset_traffic(refs: list[ClientRef]) -> list[dict]:
    async def legacy(xui: XUIClient, inbound: dict, raw: dict, _stats: dict) -> None:
        await xui.reset_client_traffic(inbound["id"], raw["email"])

    async def v3(xui: XUIClient, record: dict) -> None:
        await xui.v3_reset_traffic(record["email"])

    return await _apply(refs, legacy, v3)


async def delete_clients(refs: list[ClientRef]) -> list[dict]:
    async def legacy(xui: XUIClient, inbound: dict, raw: dict, _stats: dict) -> None:
        await xui.delete_client(inbound["id"], client_key(inbound["protocol"], raw))

    async def v3(xui: XUIClient, record: dict) -> None:
        await xui.v3_delete_client(record["email"])

    return await _apply(refs, legacy, v3)


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


def _common_fields(body: "ClientCreate", email: str, sub_id: str, tg_sample: Any) -> dict:
    return {
        "email": email,
        "enable": body.enable,
        "limitIp": body.limit_ip,
        "totalGB": body.total,
        "expiryTime": body.expiry_time,
        "tgId": _tg_value(body.tg_id, tg_sample),
        "subId": sub_id,
        "comment": body.comment,
        "reset": 0,
    }


async def _create_legacy(xui: XUIClient, body: "ClientCreate", targets: list[CreateTarget], email: str,
                         sub_id: str) -> list[dict]:
    results = []
    for n, target in enumerate(targets, start=1):
        # legacy 3x-ui requires a panel-wide unique email: second inbound on the same panel gets a suffix
        target_email = email if n == 1 else f"{email}-{n}"
        result = {**target.model_dump(), "email": target_email, "ok": False, "error": None}
        results.append(result)
        try:
            inbound = await xui.inbound(target.inbound_id)
            protocol = inbound.get("protocol", "")
            if protocol not in SUPPORTED_PROTOCOLS:
                raise XUIError(f"Протокол {protocol} не поддерживается")
            settings = parse_json_field(inbound.get("settings"))
            existing = settings.get("clients") or []
            client = {**_new_credentials(protocol, settings, body.flow),
                      **_common_fields(body, target_email, sub_id, existing[0].get("tgId") if existing else None)}
            await xui.add_client(target.inbound_id, client)
            result["ok"] = True
        except XUIError as exc:
            log.warning("create %s on %s: %s", target_email, target.inbound_id, exc)
            result["error"] = _hint(str(exc))
    return results


async def _create_v3(xui: XUIClient, body: "ClientCreate", targets: list[CreateTarget], email: str,
                     sub_id: str) -> list[dict]:
    """v3: one record attached to all chosen inbounds; the panel generates UUIDs and the protocols' own keys itself."""
    inbound_ids = [t.inbound_id for t in targets]
    # one password serves all of the user's inbounds: a 16-byte base64 key suits Trojan and Shadowsocks 2022
    # (aes-128) alike, so the user can later be added to either on any server
    client = {**_common_fields(body, email, sub_id, 0), "password": base64.b64encode(secrets.token_bytes(16)).decode()}
    try:
        flow = body.flow
        if flow is None:
            # reuse the flow (e.g. xtls-rprx-vision for Reality) of clients already on these inbounds
            flow = next((r.get("flow") for r in await xui.v3_clients()
                         if r.get("flow") and set(r.get("inboundIds") or []) & set(inbound_ids)), "")
        if flow:
            client["flow"] = flow
        await xui.v3_add_client(client, inbound_ids)
        error = None
    except XUIError as exc:
        log.warning("create %s on %s: %s", email, inbound_ids, exc)
        error = _hint(str(exc))
    return [{**t.model_dump(), "email": email, "ok": error is None, "error": error} for t in targets]


async def create_clients(body: ClientCreate) -> dict:
    sub_id = body.sub_id.strip() or secrets.token_hex(8)
    email = body.email.strip()
    by_panel: dict[int, list[CreateTarget]] = defaultdict(list)
    for target in body.targets:
        by_panel[target.panel_id].append(target)

    results = []
    for panel_id, targets in by_panel.items():
        panel = db.get_panel(panel_id)
        if not panel:
            results += [{**t.model_dump(), "email": email, "ok": False, "error": "Сервер не найден"} for t in targets]
            continue
        xui = await pool.get(panel)
        try:
            await xui.ensure_ready()
        except XUIError as exc:
            results += [{**t.model_dump(), "email": email, "ok": False, "error": str(exc)} for t in targets]
            continue
        create = _create_v3 if xui.is_v3 else _create_legacy
        results += await create(xui, body, targets, email, sub_id)

    overview_cache.invalidate()
    return {"sub_id": sub_id, "results": results}
