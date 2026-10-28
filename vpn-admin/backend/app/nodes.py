"""Nodes: remote 3x-ui servers attached to a main 3x-ui v3 panel (Nodes page of 3x-ui).

The main panel keeps the list, probes every node (heartbeat with CPU, memory,
Xray/panel versions, latency) and syncs inbounds and clients to them. This module
reads and edits that list through /panel/api/nodes/* of each connected v3 panel.
Legacy (2.x) panels have no nodes.

Adding a node is also the hook for automation: POST /api/nodes with the new
server's address and API token.
"""

import asyncio
import time
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from . import db
from .aggregator import overview_cache, pool
from .xui import XUIError, node_view

LATEST_TTL = 6 * 3600
_latest: dict[str, Any] = {"version": None, "at": 0.0}


class NodeIn(BaseModel):
    """What the admin sends; mapped onto 3x-ui's NodeMutationRequest."""
    name: str = Field(min_length=1, max_length=100)
    remark: str = ""
    scheme: Literal["http", "https"] = "https"
    address: str = Field(min_length=1)
    port: int = Field(2053, ge=1, le=65535)
    base_path: str = "/"
    enable: bool = True
    allow_private_address: bool = False
    tls_verify_mode: Literal["verify", "skip", "pin"] = "verify"
    pinned_cert_sha256: str = ""
    api_token: str = ""  # empty on update = keep the stored token
    inbound_sync_mode: Literal["all", "selected"] = "all"
    inbound_tags: list[str] = []


class NodeError(Exception):
    pass


def _to_request(body: NodeIn, node_id: int = 0) -> dict[str, Any]:
    base_path = "/" + body.base_path.strip().strip("/")
    request = {
        "id": node_id,
        "name": body.name.strip(),
        "remark": body.remark.strip(),
        "scheme": body.scheme,
        "address": body.address.strip(),
        "port": body.port,
        "basePath": base_path if base_path == "/" else base_path + "/",
        "enable": body.enable,
        "allowPrivateAddress": body.allow_private_address,
        "tlsVerifyMode": body.tls_verify_mode,
        "pinnedCertSha256": body.pinned_cert_sha256.strip() if body.tls_verify_mode == "pin" else "",
        "inboundSyncMode": body.inbound_sync_mode,
        "inboundTags": body.inbound_tags if body.inbound_sync_mode == "selected" else [],
        "outboundTag": "",
    }
    if body.api_token.strip():
        request["apiToken"] = body.api_token.strip()  # omitted = keep the stored token
    return request


async def latest_panel_version() -> str | None:
    """Latest 3x-ui release, to flag nodes that can be updated (cached, GitHub limits anonymous calls)."""
    if time.time() - _latest["at"] < LATEST_TTL:
        return _latest["version"]
    try:
        async with httpx.AsyncClient(timeout=8, headers={"User-Agent": "vpn-admin"}) as http:
            resp = await http.get("https://api.github.com/repos/MHSanaei/3x-ui/releases/latest")
            version = resp.json().get("tag_name") if resp.status_code == 200 else None
    except (httpx.HTTPError, ValueError):
        version = None
    # a failed lookup is retried in 5 minutes instead of being cached for hours
    _latest.update(version=version or _latest["version"],
                   at=time.time() if version else time.time() - LATEST_TTL + 300)
    return _latest["version"]


async def main_panel(panel_id: int):
    panel = db.get_panel(panel_id)
    if not panel:
        raise NodeError("Сервер не найден")
    xui = await pool.get(panel)
    try:
        await xui.ensure_ready()
    except XUIError as exc:
        raise NodeError(str(exc)) from exc
    if not xui.is_v3:
        raise NodeError("Узлы есть только в 3x-ui v3: эта панель старше")
    return panel, xui


async def list_all() -> dict[str, Any]:
    latest = await latest_panel_version()

    async def one(panel: db.Panel) -> dict[str, Any]:
        out = {"panel_id": panel.id, "panel_name": panel.name, "ok": False, "supported": True, "error": None,
               "nodes": []}
        xui = await pool.get(panel)
        try:
            await xui.ensure_ready()
            if not xui.is_v3:
                out["supported"] = False
                return out
            out["nodes"] = [node_view(n, latest) for n in await xui.v3_nodes()]
            out["ok"] = True
        except XUIError as exc:
            out["error"] = str(exc)
        return out

    panels = await asyncio.gather(*(one(p) for p in db.list_panels()))
    # nodes the admin installed run 3x-ui in Docker, where the panel's self-updater cannot replace itself
    docker = {(p.panel_id, p.node_id) for p in db.list_provisions() if p.node_id and p.state != "deleted"}
    for p in panels:
        for n in p["nodes"]:
            n["docker"] = (p["panel_id"], n["id"]) in docker
    nodes = [n for p in panels for n in p["nodes"]]
    latencies = [n["latency_ms"] for n in nodes if n["status"] == "online" and n["latency_ms"]]
    return {
        "panels": panels,
        "latest_panel_version": latest,
        "totals": {
            "nodes": len(nodes),
            "online": sum(n["status"] == "online" for n in nodes),
            "offline": sum(n["enable"] and n["status"] != "online" for n in nodes),
            "disabled": sum(not n["enable"] for n in nodes),
            "avg_latency_ms": round(sum(latencies) / len(latencies)) if latencies else None,
            "clients": sum(n["clients"] for n in nodes),
            "online_clients": sum(n["online"] for n in nodes),
        },
    }


async def _call(panel_id: int, action) -> Any:
    _, xui = await main_panel(panel_id)
    try:
        result = await action(xui)
    except XUIError as exc:
        raise NodeError(str(exc)) from exc
    overview_cache.invalidate()  # nodes bring their inbounds and clients into the main panel
    return result


async def add(panel_id: int, body: NodeIn) -> dict[str, Any]:
    if not body.api_token.strip():
        raise NodeError("Укажите API-токен узла: он создаётся в 3x-ui на самом узле (Настройки → Безопасность → API Token)")
    return await _call(panel_id, lambda xui: xui.v3_node_add(_to_request(body)))


async def get(panel_id: int, node_id: int) -> dict[str, Any] | None:
    """The node as the main panel has it; None when the panel no longer knows this id.
    Read from the list: only it carries the inbound and client counts."""
    _, xui = await main_panel(panel_id)
    try:
        listed = await xui.v3_nodes()
    except XUIError as exc:
        raise NodeError(str(exc)) from exc
    node = next((n for n in listed if n.get("id") == node_id), None)
    return node_view(node, None) if node else None


async def update(panel_id: int, node_id: int, body: NodeIn) -> None:
    await _call(panel_id, lambda xui: xui.v3_node_update(node_id, _to_request(body, node_id)))


async def delete(panel_id: int, node_id: int) -> None:
    await _call(panel_id, lambda xui: xui.v3_node_delete(node_id))


async def set_enable(panel_id: int, node_id: int, enable: bool) -> None:
    await _call(panel_id, lambda xui: xui.v3_node_set_enable(node_id, enable))


UPDATE_ERRORS = {"node is offline": "узел не в сети", "node is disabled": "узел выключен",
                 "node not found": "узла нет в основной панели"}


async def update_panels(panel_id: int, ids: list[int]) -> list[dict[str, Any]]:
    """Start the 3x-ui self-update on these nodes through the main panel; the nodes restart on their own, the
    new version shows up with their next heartbeat."""
    results = await _call(panel_id, lambda xui: xui.v3_nodes_update_panel(ids))
    return [{"id": r.get("id"), "name": r.get("name") or "", "ok": bool(r.get("ok")),
             "error": UPDATE_ERRORS.get(r.get("error") or "", r.get("error") or "")}
            for r in results if isinstance(r, dict)]


async def probe(panel_id: int, node_id: int) -> dict[str, Any]:
    return await _call(panel_id, lambda xui: xui.v3_node_probe(node_id))


async def test(panel_id: int, body: NodeIn, node_id: int = 0) -> dict[str, Any]:
    """Unsaved connection check. On edit with an empty token the panel uses the stored one."""
    _, xui = await main_panel(panel_id)
    try:
        return await xui.v3_node_test(_to_request(body, node_id))
    except XUIError as exc:
        raise NodeError(str(exc)) from exc


async def inbound_options(panel_id: int, body: NodeIn, node_id: int = 0) -> list[dict[str, Any]]:
    _, xui = await main_panel(panel_id)
    try:
        return await xui.v3_node_inbounds(_to_request(body, node_id))
    except XUIError as exc:
        raise NodeError(str(exc)) from exc
