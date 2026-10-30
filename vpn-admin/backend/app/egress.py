"""An outgoing route for the services the admin's own server cannot reach directly (Cloudflare's addresses are cut off
in some networks): a local proxy through one of the connects, by the Xray inside the image and the check's service
client. Only the clients that ask for it use it (Cloudflare, NetGrid); everything else goes directly.
"""

import asyncio
import json
import logging
import secrets
import time
from typing import Any

import httpx

from . import db
from .neterrors import describe

log = logging.getLogger("vpn-admin.egress")

SETTING = "egress.route"
ALIVE_EVERY = 15  # a dead Xray comes back this soon
LINK_EVERY = 300  # the connect's settings may change: its link is compared this often
CHECK_TIMEOUT = httpx.Timeout(15.0, connect=10.0)
# only the answer matters: any HTTP status means the service was reached
CHECKS = {"Cloudflare": "https://api.cloudflare.com/client/v4/", "NetGrid": "https://billing.netgrid.host/api/v1/ext"}

_lock = asyncio.Lock()
_wake = asyncio.Event()
# xray: the running proxy; url: its address; wanted/link: what it runs; error: why it is not running
_state: dict[str, Any] = {"xray": None, "url": None, "wanted": None, "link": "", "error": "", "remark": "", "server": "",
                          "started_at": 0, "link_at": 0.0}


def selected() -> dict[str, int] | None:
    raw = db.get_app_setting(SETTING)
    route = json.loads(raw) if raw else None
    return route if route and route.get("inbound_id") else None


def _alive() -> bool:
    xray = _state["xray"]
    return bool(xray and xray.proc and xray.proc.returncode is None)


def proxy() -> str | None:
    """For httpx: the proxy of the route, None to go directly. A route that is down also means directly: nothing to
    lose, and the error says about the route (note)."""
    return _state["url"] if _alive() else None


def note() -> str:
    """To add to an error of a client that goes through the route."""
    if _alive():
        return f" (запрос шёл через коннект «{_state['remark']}» на сервере {_state['server']}: проверьте его в «Системе»)"
    if selected():
        return f" (исходящий маршрут не работает: {_state['error'] or 'запускается'})"
    return " (напрямую: при блокировке выберите исходящий маршрут в «Системе»)"


async def _stop() -> None:
    xray, _state["xray"], _state["url"] = _state["xray"], None, None
    if xray:
        await xray.stop()


async def _link(route: dict[str, int]) -> tuple[Any, str, str]:
    """The service client's link to the connect, the connect's name and the server it is on."""
    from . import probe  # it needs the clients that need this module
    from .aggregator import pool
    from .xray_links import LinkError, parse
    from .xui import XUIError

    panel = db.get_panel(route["panel_id"])
    if not panel:
        raise RuntimeError("сервер этого коннекта удалён из админки")
    try:
        xui = await pool.get(panel)
        await xui.ensure_ready()
        inbounds = await xui.inbounds()
        inbound = next((i for i in inbounds if i.get("id") == route["inbound_id"]), None)
        if not inbound:
            raise RuntimeError("коннект удалён: выберите другой")
        urls = await xui.v3_client_links(probe.PROBE_EMAIL)
        nodes = {n.get("id"): n for n in await xui.v3_nodes()}
    except XUIError as exc:
        raise RuntimeError(f"не получить ссылку у панели «{panel.name}»: {exc}") from exc
    for url in urls:
        try:
            link = parse(url)
        except LinkError:
            continue
        if probe._match(link, inbounds) is inbound:
            view = probe._inbound_view(panel, inbound, nodes)
            return link, view["remark"], view["server"]
    raise RuntimeError("служебного клиента ещё нет на этом коннекте: дождитесь проверки коннектов")


async def _sync() -> None:
    from . import probe

    async with _lock:
        route = selected()
        if not route:
            await _stop()
            _state.update(wanted=None, link="", error="", remark="", server="", started_at=0)
            return
        same = route == _state["wanted"]
        if same and _alive() and time.monotonic() - _state["link_at"] < LINK_EVERY:
            return
        if not same:
            await _stop()
            _state.update(wanted=route, link="", remark="", server="", started_at=0)
        try:
            link, remark, server = await _link(route)
        except (RuntimeError, OSError, ValueError) as exc:
            if not _alive():
                _state["error"] = str(exc)
            log.warning("egress link: %s", exc)  # a running proxy stays on its last link
            return
        _state.update(link_at=time.monotonic(), remark=remark, server=server)
        if _alive() and link.url == _state["link"]:
            return
        await _stop()
        account = {"user": secrets.token_urlsafe(12), "pass": secrets.token_urlsafe(24)}
        xray = probe.Xray([link], accounts=[account])
        error = await xray.start()
        if error:
            await xray.stop()
            _state.update(error=f"Xray не запустился: {error}", link="")
            return
        _state.update(xray=xray, link=link.url, error="", started_at=int(time.time()),
                      url=f"http://{account['user']}:{account['pass']}@127.0.0.1:{xray.ports[0]}")
        log.info("egress route through %s on %s", remark, server)


async def loop() -> None:
    while True:
        try:
            await _sync()
        except Exception:  # noqa: BLE001 - the route is retried, the admin goes on without it
            log.exception("egress route failed")
        try:
            await asyncio.wait_for(_wake.wait(), ALIVE_EVERY)
        except asyncio.TimeoutError:
            pass
        _wake.clear()


async def shutdown() -> None:
    await _stop()


async def choose(panel_id: int, inbound_id: int) -> None:
    db.set_app_setting(SETTING, json.dumps({"panel_id": panel_id, "inbound_id": inbound_id} if inbound_id else None))
    await _sync()


def view() -> dict[str, Any]:
    from . import probe

    options, seen = [], set()
    for panel in probe.snapshot()["panels"]:
        for item in panel["items"]:
            key = (panel["panel_id"], item.get("inbound_id"))
            if item.get("inbound_id") and item.get("status") in ("ok", "fail") and key not in seen:
                seen.add(key)
                options.append({"panel_id": key[0], "inbound_id": key[1], "remark": item["remark"],
                                "server": item.get("server", ""), "status": item["status"], "ms": item.get("ms")})
    return {"selected": selected(), "running": _alive(), "error": _state["error"], "remark": _state["remark"],
            "server": _state["server"], "started_at": _state["started_at"], "options": options}


async def check() -> list[dict[str, Any]]:
    """Whether the services the route is for answer now, the way their clients go."""
    async with httpx.AsyncClient(proxy=proxy(), timeout=CHECK_TIMEOUT, headers={"User-Agent": "vpn-admin"}) as http:
        async def one(name: str, url: str) -> dict[str, Any]:
            started = time.perf_counter()
            try:
                resp = await http.get(url)
            except httpx.HTTPError as exc:
                return {"name": name, "ok": False, "error": describe(exc)}
            return {"name": name, "ok": True, "status": resp.status_code,
                    "ms": round((time.perf_counter() - started) * 1000)}

        return list(await asyncio.gather(*(one(n, u) for n, u in CHECKS.items())))
