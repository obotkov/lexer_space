"""Collects inbounds, clients and subscriptions from every connected 3x-ui panel
and folds them into one normalized overview."""

import asyncio
import time
from typing import Any

from . import db
from .config import settings
from .xui import XUIClient, XUIError, parse_json_field, subscription_base


class ClientPool:
    """Keeps one logged-in XUIClient per panel so we don't log in on every refresh."""

    def __init__(self):
        self._clients: dict[int, tuple[tuple, XUIClient]] = {}

    async def get(self, panel: db.Panel) -> XUIClient:
        signature = (panel.url, panel.username, panel.password, panel.verify_tls)
        cached = self._clients.get(panel.id)
        if cached and cached[0] == signature:
            return cached[1]
        if cached:
            await cached[1].close()
        client = XUIClient(panel.url, panel.username, panel.password, panel.verify_tls)
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
    result: dict[str, Any] = {"panel": panel, "ok": False, "error": None, "inbounds": [], "onlines": [],
                              "status": None, "sub_base": panel.sub_base_url.strip()}
    try:
        result["inbounds"] = await client.inbounds()
        result["ok"] = True
    except XUIError as exc:
        result["error"] = str(exc)
        return result

    async def optional(coro):
        try:
            return await coro
        except XUIError:
            return None

    onlines, status, sub_settings = await asyncio.gather(
        optional(client.onlines()), optional(client.server_status()), optional(client.settings())
    )
    result["onlines"] = onlines or []
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


def build_overview(fetched: list[dict[str, Any]]) -> dict[str, Any]:
    now_ms = int(time.time() * 1000)
    panels_out, nodes, clients = [], [], []
    subs: dict[str, dict[str, Any]] = {}

    for item in fetched:
        panel: db.Panel = item["panel"]
        online_emails = set(item["onlines"])
        panel_clients = 0

        for inbound in item["inbounds"]:
            protocol = inbound.get("protocol", "")
            inbound_settings = parse_json_field(inbound.get("settings"))
            stream = parse_json_field(inbound.get("streamSettings"))
            stats_by_email = {s.get("email"): s for s in (inbound.get("clientStats") or [])}
            raw_clients = inbound_settings.get("clients") or []
            node_online = 0

            for raw in raw_clients:
                email = raw.get("email", "")
                stats = stats_by_email.get(email) or {}
                up, down = int(stats.get("up") or 0), int(stats.get("down") or 0)
                total = int(stats.get("total") or raw.get("totalGB") or 0)
                expiry = int(stats.get("expiryTime") or raw.get("expiryTime") or 0)
                enable = bool(raw.get("enable", True)) and bool(stats.get("enable", True))
                online = email in online_emails
                node_online += online
                sub_id = raw.get("subId") or ""
                sub_url = item["sub_base"] + sub_id if sub_id and item["sub_base"] else ""
                c = {
                    "panel_id": panel.id,
                    "panel_name": panel.name,
                    "inbound_id": inbound.get("id"),
                    "inbound_remark": inbound.get("remark", ""),
                    "protocol": protocol,
                    "email": email,
                    "secret": _client_secret(protocol, raw),
                    "sub_id": sub_id,
                    "sub_url": sub_url,
                    "enable": enable,
                    "up": up,
                    "down": down,
                    "total": total,
                    "expiry_time": expiry,
                    "limit_ip": int(raw.get("limitIp") or 0),
                    "tg_id": raw.get("tgId") or "",
                    "comment": raw.get("comment") or "",
                    "online": online,
                    "last_online": int(stats.get("lastOnline") or 0),
                    "status": client_status(enable, up, down, total, expiry, now_ms),
                }
                clients.append(c)

                if sub_id:
                    sub = subs.setdefault(sub_id, {
                        "sub_id": sub_id, "urls": {}, "emails": set(), "panels": set(), "nodes": [],
                        "up": 0, "down": 0, "online": False, "statuses": set(), "expiry_time": 0,
                        "comment": "", "tg_id": "",
                    })
                    if sub_url:
                        sub["urls"][panel.name] = sub_url
                    sub["emails"].add(email)
                    sub["panels"].add(panel.name)
                    sub["nodes"].append(f"{panel.name}: {inbound.get('remark') or inbound.get('port')}")
                    sub["up"] += up
                    sub["down"] += down
                    sub["online"] = sub["online"] or online
                    sub["statuses"].add(c["status"])
                    if expiry > 0 and (sub["expiry_time"] == 0 or expiry < sub["expiry_time"]):
                        sub["expiry_time"] = expiry
                    sub["comment"] = sub["comment"] or c["comment"]
                    sub["tg_id"] = sub["tg_id"] or c["tg_id"]

            panel_clients += len(raw_clients)
            nodes.append({
                "panel_id": panel.id,
                "panel_name": panel.name,
                "id": inbound.get("id"),
                "remark": inbound.get("remark", ""),
                "protocol": protocol,
                "port": inbound.get("port"),
                "listen": inbound.get("listen", ""),
                "network": stream.get("network", ""),
                "security": stream.get("security", ""),
                "enable": bool(inbound.get("enable", True)),
                "up": int(inbound.get("up") or 0),
                "down": int(inbound.get("down") or 0),
                "total": int(inbound.get("total") or 0),
                "expiry_time": int(inbound.get("expiryTime") or 0),
                "clients": len(raw_clients),
                "online": node_online,
            })

        panels_out.append({
            **panel.public(),
            "ok": item["ok"],
            "error": item["error"],
            "status": _short_status(item["status"]),
            "nodes": len(item["inbounds"]),
            "clients": panel_clients,
            "online": len(online_emails),
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
