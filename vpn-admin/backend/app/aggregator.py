"""Collects inbounds, clients and subscriptions from every connected 3x-ui panel
and folds them into one normalized overview.

A "client row" is what the UI lists: on legacy panels one row per client of an
inbound, on v3 panels one row per client record (which may sit on several inbounds).
"""

import asyncio
import time
from typing import Any

from . import db
from .config import settings
from .xui import XUIClient, XUIError, node_view, parse_json_field, subscription_base

# the admin's own clients on the panels (probe.PROBE_EMAIL checks the connects): not users, so out of every list
SERVICE_EMAILS = {"vpn-admin-probe"}


class ClientPool:
    """Keeps one logged-in XUIClient per panel so we don't log in on every refresh."""

    def __init__(self):
        self._clients: dict[int, tuple[tuple, XUIClient]] = {}

    async def get(self, panel: db.Panel) -> XUIClient:
        signature = (panel.url, panel.username, panel.password, panel.verify_tls, panel.api_token)
        cached = self._clients.get(panel.id)
        if cached and cached[0] == signature:
            return cached[1]
        if cached:
            await cached[1].close()
        client = XUIClient(panel.url, panel.username, panel.password, panel.verify_tls, panel.api_token)
        self._clients[panel.id] = (signature, client)
        return client

    async def drop(self, panel_id: int) -> None:
        cached = self._clients.pop(panel_id, None)
        if cached:
            await cached[1].close()

    async def close_all(self) -> None:
        for _, client in self._clients.values():
            await client.close()
        self._clients.clear()


pool = ClientPool()


def client_status(enable: bool, up: int, down: int, total: int, expiry_time: int, now_ms: int) -> str:
    if expiry_time > 0 and expiry_time <= now_ms:
        return "expired"
    if total > 0 and up + down >= total:
        return "depleted"
    if not enable:
        return "disabled"
    return "active"


def _client_secret(protocol: str, raw: dict) -> str:
    if protocol in ("vmess", "vless"):
        return raw.get("id", "")
    return raw.get("password", "") or raw.get("id", "")


async def _fetch_panel(panel: db.Panel) -> dict[str, Any]:
    client = await pool.get(panel)
    result: dict[str, Any] = {"panel": panel, "ok": False, "error": None, "inbounds": [], "v3_clients": None,
                              "onlines": [], "status": None, "sub_base": panel.sub_base_url.strip(),
                              "api_version": None, "children": []}
    try:
        result["inbounds"] = await client.inbounds()
        if client.is_v3:
            result["v3_clients"] = await client.v3_clients()
        result["api_version"] = client.api_version
        result["ok"] = True
    except XUIError as exc:
        result["error"] = str(exc)
        return result

    async def optional(coro):
        try:
            return await coro
        except XUIError:
            return None

    async def no_nodes():
        return []

    onlines, status, sub_settings, children = await asyncio.gather(
        optional(client.onlines()), optional(client.server_status()), optional(client.settings()),
        optional(client.v3_nodes() if client.is_v3 else no_nodes()),
    )
    result["onlines"] = onlines or []
    result["children"] = children or []
    result["status"] = status
    if not result["sub_base"] and sub_settings:
        result["sub_base"] = subscription_base(client.host, sub_settings)
    elif result["sub_base"] and not result["sub_base"].endswith("/"):
        result["sub_base"] += "/"
    return result


def _short_status(status: dict | None) -> dict | None:
    if not status:
        return None
    mem = status.get("mem") or {}
    xray = status.get("xray") or {}
    return {
        "cpu": status.get("cpu"),
        "mem_current": mem.get("current"),
        "mem_total": mem.get("total"),
        "uptime": status.get("uptime"),
        "xray_state": xray.get("state"),
        "xray_version": xray.get("version"),
    }


def _children(item: dict[str, Any]) -> list[dict[str, Any]]:
    """Nodes (child servers) of a v3 main panel; their traffic is the sum of the inbounds they host."""
    traffic: dict[int, list[int]] = {}
    for inbound in item["inbounds"]:
        node_id = inbound.get("nodeId")
        if node_id:
            sums = traffic.setdefault(node_id, [0, 0])
            sums[0] += int(inbound.get("up") or 0)
            sums[1] += int(inbound.get("down") or 0)
    children = []
    for raw in item["children"]:
        node = node_view(raw, None)
        node["up"], node["down"] = traffic.get(node["id"], [0, 0])
        children.append(node)
    return children


def _row(panel: db.Panel, api: str, inbounds: list[dict], *, email: str, protocol: str, secret: str, sub_id: str,
         sub_base: str, enable: bool, up: int, down: int, total: int, expiry: int, limit_ip: int, tg_id: Any,
         comment: str, online: bool, last_online: int, now_ms: int) -> dict:
    return {
        "panel_id": panel.id,
        "panel_name": panel.name,
        "api": api,
        "inbound_id": inbounds[0].get("id") if inbounds else 0,
        "inbound_ids": [i.get("id") for i in inbounds],
        "inbound_remarks": [i.get("remark") or str(i.get("port")) for i in inbounds],
        "inbound_remark": ", ".join(i.get("remark") or str(i.get("port")) for i in inbounds),
        "protocol": protocol,
        "email": email,
        "secret": secret,
        "sub_id": sub_id,
        "sub_url": sub_base + sub_id if sub_id and sub_base else "",
        "enable": enable,
        "up": up,
        "down": down,
        "total": total,
        "expiry_time": expiry,
        "limit_ip": limit_ip,
        "tg_id": tg_id or "",
        "comment": comment or "",
        "online": online,
        "last_online": last_online,
        "status": client_status(enable, up, down, total, expiry, now_ms),
    }


def _legacy_rows(item: dict[str, Any], now_ms: int) -> list[dict]:
    """Legacy panels: clients are stored inside each inbound's settings."""
    online = set(item["onlines"])
    rows = []
    for inbound in item["inbounds"]:
        protocol = inbound.get("protocol", "")
        stats_by_email = {s.get("email"): s for s in (inbound.get("clientStats") or [])}
        for raw in parse_json_field(inbound.get("settings")).get("clients") or []:
            email = raw.get("email", "")
            stats = stats_by_email.get(email) or {}
            rows.append(_row(
                item["panel"], "legacy", [inbound], email=email, protocol=protocol,
                secret=_client_secret(protocol, raw), sub_id=raw.get("subId") or "", sub_base=item["sub_base"],
                enable=bool(raw.get("enable", True)) and bool(stats.get("enable", True)),
                up=int(stats.get("up") or 0), down=int(stats.get("down") or 0),
                total=int(stats.get("total") or raw.get("totalGB") or 0),
                expiry=int(stats.get("expiryTime") or raw.get("expiryTime") or 0),
                limit_ip=int(raw.get("limitIp") or 0), tg_id=raw.get("tgId"), comment=raw.get("comment"),
                online=email in online, last_online=int(stats.get("lastOnline") or 0), now_ms=now_ms,
            ))
    return rows


def _v3_rows(item: dict[str, Any], now_ms: int) -> list[dict]:
    """v3 panels: one client record per email, attached to any number of inbounds."""
    online = set(item["onlines"])
    inbounds_by_id = {i.get("id"): i for i in item["inbounds"]}
    rows = []
    for rec in item["v3_clients"]:
        email = rec.get("email", "")
        traffic = rec.get("traffic") or {}
        attached = [inbounds_by_id[i] for i in rec.get("inboundIds") or [] if i in inbounds_by_id]
        protocol = ", ".join(sorted({i.get("protocol", "") for i in attached}))
        rows.append(_row(
            item["panel"], "v3", attached, email=email, protocol=protocol,
            secret=rec.get("uuid") or rec.get("password") or rec.get("auth") or "", sub_id=rec.get("subId") or "",
            sub_base=item["sub_base"],
            enable=bool(rec.get("enable", True)) and bool(traffic.get("enable", True)),
            up=int(traffic.get("up") or 0), down=int(traffic.get("down") or 0),
            total=int(rec.get("totalGB") or traffic.get("total") or 0),
            expiry=int(traffic.get("expiryTime") or rec.get("expiryTime") or 0),
            limit_ip=int(rec.get("limitIp") or 0), tg_id=rec.get("tgId"), comment=rec.get("comment"),
            online=email in online, last_online=int(traffic.get("lastOnline") or 0), now_ms=now_ms,
        ))
    return rows


def build_overview(fetched: list[dict[str, Any]]) -> dict[str, Any]:
    now_ms = int(time.time() * 1000)
    panels_out, nodes, clients = [], [], []
    subs: dict[str, dict[str, Any]] = {}

    for item in fetched:
        panel: db.Panel = item["panel"]
        rows = _v3_rows(item, now_ms) if item["v3_clients"] is not None else _legacy_rows(item, now_ms)
        rows = [r for r in rows if r["email"] not in SERVICE_EMAILS]
        clients += rows

        per_inbound: dict[Any, list[dict]] = {}
        for r in rows:
            for inbound_id in r["inbound_ids"]:
                per_inbound.setdefault(inbound_id, []).append(r)

        # a v3 main panel runs inbounds on its nodes too: name the server that actually hosts each one
        node_names = {n.get("id"): n.get("name") or f"узел #{n.get('id')}" for n in item["children"]}
        for inbound in item["inbounds"]:
            stream = parse_json_field(inbound.get("streamSettings"))
            attached = per_inbound.get(inbound.get("id"), [])
            node_id = inbound.get("nodeId") or 0
            nodes.append({
                "panel_id": panel.id,
                "panel_name": panel.name,
                "node_id": node_id,
                "server": node_names.get(node_id, f"узел #{node_id}") if node_id else panel.name,
                "id": inbound.get("id"),
                "remark": inbound.get("remark", ""),
                "protocol": inbound.get("protocol", ""),
                "port": inbound.get("port"),
                "listen": inbound.get("listen", ""),
                "network": stream.get("network", ""),
                "security": stream.get("security", ""),
                "enable": bool(inbound.get("enable", True)),
                "up": int(inbound.get("up") or 0),
                "down": int(inbound.get("down") or 0),
                "total": int(inbound.get("total") or 0),
                "expiry_time": int(inbound.get("expiryTime") or 0),
                "clients": len(attached),
                "online": sum(r["online"] for r in attached),
            })

        for r in rows:
            if not r["sub_id"]:
                continue
            sub = subs.setdefault(r["sub_id"], {
                "sub_id": r["sub_id"], "urls": {}, "emails": set(), "panels": set(), "nodes": [],
                "up": 0, "down": 0, "online": False, "statuses": set(), "expiry_time": 0,
                "comment": "", "tg_id": "",
            })
            if r["sub_url"]:
                sub["urls"][panel.name] = r["sub_url"]
            sub["emails"].add(r["email"])
            sub["panels"].add(panel.name)
            sub["nodes"] += [f"{panel.name}: {remark}" for remark in r["inbound_remarks"]]
            sub["up"] += r["up"]
            sub["down"] += r["down"]
            sub["online"] = sub["online"] or r["online"]
            sub["statuses"].add(r["status"])
            if r["expiry_time"] > 0 and (sub["expiry_time"] == 0 or r["expiry_time"] < sub["expiry_time"]):
                sub["expiry_time"] = r["expiry_time"]
            sub["comment"] = sub["comment"] or r["comment"]
            sub["tg_id"] = sub["tg_id"] or r["tg_id"]

        panels_out.append({
            **panel.public(),
            "children": _children(item),
            "ok": item["ok"],
            "error": item["error"],
            "api_version": item["api_version"],
            "status": _short_status(item["status"]),
            "nodes": len(item["inbounds"]),
            "up": sum(int(i.get("up") or 0) for i in item["inbounds"]),
            "down": sum(int(i.get("down") or 0) for i in item["inbounds"]),
            "clients": len(rows),
            "online": len(set(item["onlines"]) - SERVICE_EMAILS),
            "sub_base": item["sub_base"],
        })

    subscriptions = []
    for sub in subs.values():
        statuses = sub.pop("statuses")
        subscriptions.append({
            **sub,
            "urls": [{"panel": name, "url": url} for name, url in sub["urls"].items()],
            "emails": sorted(sub["emails"]),
            "panels": sorted(sub["panels"]),
            "status": "active" if "active" in statuses else sorted(statuses)[0],
        })
    subscriptions.sort(key=lambda s: s["sub_id"])

    # One user = one subscription; clients without subId are counted by email
    users: dict[str, set[str]] = {}
    for c in clients:
        users.setdefault(c["sub_id"] or f"email:{c['email']}", set()).add(c["status"])
    online_users = {c["sub_id"] or f"email:{c['email']}" for c in clients if c["online"]}

    totals = {
        "panels": len(panels_out),
        "panels_ok": sum(p["ok"] for p in panels_out),
        "nodes": len(nodes),
        "nodes_enabled": sum(n["enable"] for n in nodes),
        "clients": len(clients),
        "users": len(users),
        "users_active": sum("active" in s for s in users.values()),
        "users_online": len(online_users),
        "users_expired": sum("active" not in s and "expired" in s for s in users.values()),
        "users_disabled": sum("active" not in s and "expired" not in s for s in users.values()),
        "subscriptions": len(subscriptions),
        "traffic_up": sum(n["up"] for n in nodes),
        "traffic_down": sum(n["down"] for n in nodes),
    }

    return {
        "generated_at": int(time.time()),
        "totals": totals,
        "panels": panels_out,
        "nodes": nodes,
        "clients": clients,
        "subscriptions": subscriptions,
    }


class OverviewCache:
    def __init__(self, ttl: int):
        self.ttl = ttl
        self._data: dict[str, Any] | None = None
        self._at = 0.0
        self._lock = asyncio.Lock()

    def invalidate(self) -> None:
        self._data = None

    async def get(self, force: bool = False) -> dict[str, Any]:
        async with self._lock:
            if not force and self._data and time.time() - self._at < self.ttl:
                return self._data
            fetched = await asyncio.gather(*(_fetch_panel(p) for p in db.list_panels()))
            self._data = build_overview(list(fetched))
            self._at = time.time()
            return self._data


overview_cache = OverviewCache(settings.cache_ttl)
