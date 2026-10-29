"""Connection checks: every connect of every main 3x-ui v3 panel, tested through Xray-core the way a client
would use it.

The admin keeps a service client (PROBE_EMAIL) on each main panel, attached to every enabled connect,
including the ones on its nodes. Each round takes that client's share links from the panel, starts one Xray
with a local HTTP proxy per link and fetches TEST_URL through each: the first request opens the tunnel
(handshake, TLS/Reality, the server's own connection out), the second goes through the open tunnel, which is
the delay a user feels. A link that fails gets the reason from Xray's log.
"""

import asyncio
import base64
import json
import logging
import os
import re
import secrets
import shutil
import socket
import time
from collections import deque
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import db, hosters
from .aggregator import SERVICE_EMAILS, overview_cache, pool
from .xray_links import Link, LinkError, parse
from .xui import XUIClient, XUIError, parse_json_field

log = logging.getLogger("vpn-admin.probe")

PROBE_EMAIL = "vpn-admin-probe"
assert PROBE_EMAIL in SERVICE_EMAILS
INTERVAL = int(os.getenv("PROBE_INTERVAL", "180"))
TIMEOUT = 10.0
TEST_URL = os.getenv("PROBE_URL", "https://www.gstatic.com/generate_204")
XRAY = os.getenv("XRAY_BIN") or shutil.which("xray") or "/usr/local/bin/xray"
HISTORY = 3600 // INTERVAL  # an hour of points per connect
PARALLEL = 8
# protocols 3x-ui gives share links for that Xray can dial as a client
CHECKED = {"vless", "vmess", "trojan", "shadowsocks", "hysteria"}
SKIP_REASONS = {"mtproto": "MTProto — не Xray, не проверяется", "wireguard": "WireGuard — Xray не умеет, не проверяется",
                "amneziawg": "AmneziaWG — Xray не умеет, не проверяется", "tuic": "TUIC — Xray не умеет, не проверяется"}
# links of connects Xray can't dial (AmneziaVPN's vpn:// holds a whole WireGuard config, private key included):
# they are left out, and the connect itself shows as not checked
UNDIALED = {"vpn", "wireguard", "wg", "awg", "amneziawg", "tuic", "tg"}

_state: dict[str, Any] = {"checked_at": 0, "duration": 0.0, "error": None, "panels": []}
_history: dict[str, deque] = {}
_lock = asyncio.Lock()
_kick = asyncio.Event()
_attached_at: dict[int, float] = {}  # panel id -> when the service client last went onto new connects
# nodes get a new client from the main panel with a delay and reload Xray for it
SETTLE = 60
# where each server is: its IP and the hosting account it sits on, refreshed rarely (the hostings' APIs are slow)
WHERE_TTL = 1800
RESOLVE_TIMEOUT = 3.0
_hosting: dict[str, Any] = {"at": -WHERE_TTL, "by_ip": {}}
_resolved: dict[str, tuple[float, str]] = {}


def kick() -> None:
    """Run a round soon, e.g. after a panel was added or connections were rolled out."""
    _kick.set()


def snapshot() -> dict[str, Any]:
    return {**_state, "running": _lock.locked(), "interval": INTERVAL, "url": TEST_URL,
            "xray": os.path.exists(XRAY)}


# ---------- service client ----------

def _probe_client() -> dict[str, Any]:
    # one password for all protocols, as the admin gives its users: suits Trojan and Shadowsocks 2022 (aes-128)
    return {"email": PROBE_EMAIL, "enable": True, "subId": PROBE_EMAIL, "limitIp": 0, "totalGB": 0, "expiryTime": 0,
            "tgId": 0, "reset": 0, "comment": "служебный клиент VPN Admin: проверка коннектов, не удалять",
            "password": base64.b64encode(secrets.token_bytes(16)).decode()}


async def _ensure_client(xui: XUIClient, inbounds: list[dict]) -> tuple[dict[int, str], set[int]]:
    """Attach the service client to every enabled connect it can be checked on. Returns {inbound id: error} for the
    ones the panel refused and the ids it was attached to just now. Lists and counters of the overview leave the
    client out (aggregator.SERVICE_EMAILS)."""
    wanted = [i["id"] for i in inbounds if i.get("enable", True) and i.get("protocol") in CHECKED]
    record = next((r for r in await xui.v3_clients() if r.get("email") == PROBE_EMAIL), None)
    if record is None:
        client = _probe_client()
        flow = next((r.get("flow") for r in await xui.v3_clients() if r.get("flow")), "")
        if flow:  # Reality over TCP wants the same flow as the users; 3x-ui leaves it out of the other links
            client["flow"] = flow
        await xui.v3_add_client(client, wanted)
        log.info("service client added to %d connects", len(wanted))
        overview_cache.invalidate()
        return {}, set(wanted)
    missing = [i for i in wanted if i not in (record.get("inboundIds") or [])]
    if not missing:
        return {}, set()
    result = await xui.v3_bulk_attach([PROBE_EMAIL], missing)
    overview_cache.invalidate()
    attached = PROBE_EMAIL in (result.get("attached") or [])
    errors = "; ".join(str(e) for e in result.get("errors") or [])
    if attached and not errors:
        return {}, set(missing)
    return {i: errors or "3x-ui не добавила служебного клиента" for i in missing}, set()


# ---------- matching links to connects ----------

def _match(link: Link, inbounds: list[dict]) -> dict | None:
    """3x-ui names a link "<connect remark>-<email>" (plus the External Proxy remark) and puts the connect's port
    in it unless an External Proxy leads elsewhere: the longest remark that starts the link's name wins, the port
    breaks ties."""
    best, score = None, (-1, False)
    for inbound in inbounds:
        if inbound.get("protocol") != link.protocol:
            continue
        remark = inbound.get("remark") or ""
        prefix = len(remark) if remark and link.remark.startswith(remark) else 0
        same_port = inbound.get("port") == link.port
        if not prefix and not same_port:
            continue
        if (prefix, same_port) > score:
            best, score = inbound, (prefix, same_port)
    return best


# ---------- Xray ----------

def _free_ports(count: int) -> list[int]:
    socks = [socket.socket() for _ in range(count)]
    try:
        for s in socks:
            s.bind(("127.0.0.1", 0))
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


def _config(links: list[Link], ports: list[int]) -> dict[str, Any]:
    inbounds, outbounds, rules = [], [{"tag": "block", "protocol": "blackhole"}], []
    for n, (link, port) in enumerate(zip(links, ports)):
        inbounds.append({"tag": f"in-{n}", "listen": "127.0.0.1", "port": port, "protocol": "http", "settings": {}})
        outbounds.append({"tag": f"out-{n}", **link.outbound})
        rules.append({"type": "field", "inboundTag": [f"in-{n}"], "outboundTag": f"out-{n}"})
    return {"log": {"loglevel": "info"}, "inbounds": inbounds, "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}}


class Xray:
    def __init__(self, links: list[Link]):
        self.links = links
        self.ports = _free_ports(len(links))
        self.proc: asyncio.subprocess.Process | None = None
        self.lines: list[str] = []
        self._reader: asyncio.Task | None = None

    async def start(self) -> str | None:
        """None once every proxy listens, else what Xray said when it refused the config."""
        self.proc = await asyncio.create_subprocess_exec(
            XRAY, "run", "-c", "stdin:", stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT)
        self.proc.stdin.write(json.dumps(_config(self.links, self.ports)).encode())
        self.proc.stdin.close()
        self._reader = asyncio.create_task(self._read())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.proc.returncode is not None:
                await self._reader
                return _start_error(self.lines)
            if all(_listening(p) for p in self.ports):
                return None
            await asyncio.sleep(0.05)
        return "Xray не запустился за 5 секунд"

    async def _read(self) -> None:
        assert self.proc and self.proc.stdout
        async for raw in self.proc.stdout:
            self.lines.append(raw.decode(errors="replace").rstrip())

    async def stop(self) -> None:
        if self.proc and self.proc.returncode is None:
            self.proc.kill()
            await self.proc.wait()
        if self._reader:
            await asyncio.gather(self._reader, return_exceptions=True)

    def reason(self, n: int) -> str:
        """The last failure Xray logged for the connections that went out through link n."""
        ids = {m.group(1) for line in self.lines if (m := re.search(r"\[(\d+)\] app/dispatcher: taking detour \[out-"
                                                                     rf"{n}\]", line))}
        failures = [line for line in self.lines if any(f"[{i}]" in line for i in ids)
                    and re.search(r"fail|error|timeout|refused|reset|invalid|closed", line, re.I)
                    # what the admin's own shutdown of Xray or httpx giving up leaves in the log
                    and not re.search(r"use of closed network connection|context canceled", line)]
        return humanize(failures[-1]) if failures else ""


def _listening(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.2)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _start_error(lines: list[str]) -> str:
    text = next((line for line in reversed(lines) if "Failed to start" in line or "failed to" in line.lower()),
                lines[-1] if lines else "Xray завершился без сообщения")
    return text.split("> ", 1)[-1][:300]


_HINTS = [
    # the CDN answered, but its edge could not reach the node: the source port, its TLS or the node itself
    (r"bad status code: ?50[234]", "CDN не достучался до сервера-источника: закрыт порт подключения в файрволе "
                                   "сервера, не работает инбаунд или узел недоступен"),
    (r"tls: internal error", "CDN не отдал сертификат на имя подключения: у облака он ещё не на всех серверах "
                             "(сразу после выпуска) или выпуск не удался"),
    (r"i/o timeout|context deadline exceeded|timed? ?out", "нет ответа от сервера (таймаут)"),
    (r"connection refused", "порт закрыт: сервер отклонил подключение"),
    (r"no such host|lookup .* (server misbehaving|no such host)", "адрес сервера не найден в DNS"),
    (r"REALITY: processed invalid connection|reality verification failed|REALITY.*failed", "Reality: сервер не принял ключ или SNI"),
    (r"certificate|x509|pinned", "TLS: сертификат сервера не прошёл проверку"),
    (r"connection reset|broken pipe|EOF", "соединение сброшено сервером"),
    (r"invalid user|not a valid user|authentication failed|auth", "сервер не принял клиента"),
    (r"network is unreachable|no route to host", "сервер недоступен по сети"),
]


def humanize(line: str) -> str:
    """'... > proxy/vless/outbound: ... > dial tcp 1.2.3.4:443: i/o timeout' -> a short reason in Russian."""
    chain = [part.strip() for part in re.split(r"\s>\s", line) if part.strip()]
    chain = [p for p in chain if "all retry attempts failed" not in p] or chain
    detail = re.sub(r"^(\S+/)+\S+: ", "", chain[-1] if chain else line)
    detail = re.sub(r"^\d{4}/\d\d/\d\d \S+ \[\w+\] (\[\d+\] )?", "", detail).strip("[] ")
    for pattern, hint in _HINTS:
        if re.search(pattern, line, re.I):
            return f"{hint} · {detail[:160]}"
    return detail[:200]


async def _measure(port: int) -> tuple[float | None, float | None, str]:
    """(tunnel open + first answer ms, answer through the open tunnel ms, error)."""
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", timeout=TIMEOUT) as http:
        try:
            started = time.perf_counter()
            first = await http.get(TEST_URL)
            connect = (time.perf_counter() - started) * 1000
            if first.status_code >= 400:
                return None, None, f"тестовый адрес ответил HTTP {first.status_code}"
            started = time.perf_counter()
            await http.get(TEST_URL)
            return connect, (time.perf_counter() - started) * 1000, ""
        except httpx.TimeoutException:
            return None, None, f"нет ответа за {TIMEOUT:.0f} с"
        except httpx.HTTPError as exc:
            return None, None, f"{exc.__class__.__name__}: {exc}"[:200] or exc.__class__.__name__


async def _check_links(links: list[Link]) -> list[dict[str, Any]]:
    """Every link through one Xray; when it refuses the whole config, each link through its own, so one link it
    cannot build does not hide the others."""
    if not links:
        return []
    xray = Xray(links)
    error = await xray.start()
    if error:
        await xray.stop()
        if len(links) == 1:
            return [{"ok": False, "error": f"Xray не принял настройки ссылки: {error}"}]
        return [(await _check_links([link]))[0] for link in links]
    try:
        gate = asyncio.Semaphore(PARALLEL)

        async def one(port: int):
            async with gate:
                return await _measure(port)

        measured = await asyncio.gather(*(one(p) for p in xray.ports))
        await asyncio.sleep(0.2)  # the last log lines of failed connections
    finally:
        await xray.stop()
    results = []
    for n, (connect, delay, error) in enumerate(measured):
        if delay is not None:
            results.append({"ok": True, "ms": round(delay), "connect_ms": round(connect or 0)})
        else:
            reason = xray.reason(n)
            results.append({"ok": False, "error": reason or error, "detail": error if reason else ""})
    return results


# ---------- a round ----------

def _inbound_view(panel: db.Panel, inbound: dict, nodes: dict[int, dict]) -> dict[str, Any]:
    stream = parse_json_field(inbound.get("streamSettings"))
    node_id = inbound.get("nodeId") or 0
    node = nodes.get(node_id) or {}
    return {"inbound_id": inbound.get("id"), "remark": inbound.get("remark") or str(inbound.get("port")),
            "protocol": inbound.get("protocol", ""), "network": stream.get("network", ""),
            "security": stream.get("security", ""), "port": inbound.get("port"),
            "server": (node.get("name") or f"узел #{node_id}") if node_id else panel.name,
            "server_host": (node.get("address") or "") if node_id else (urlsplit(panel.url).hostname or ""),
            "server_kind": "node" if node_id else "main", "enable": bool(inbound.get("enable", True))}


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in host else socket.AF_INET, host)
        return True
    except OSError:
        return False


async def _ip(host: str) -> str:
    """The server's IPv4: the address itself, or what its domain points at (cached for WHERE_TTL)."""
    if not host or _is_ip(host):
        return host
    cached = _resolved.get(host)
    if cached and time.monotonic() - cached[0] < WHERE_TTL:
        return cached[1]
    try:
        found = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, None, family=socket.AF_INET),
                                       RESOLVE_TIMEOUT)
        ip = found[0][4][0] if found else ""
    except (OSError, asyncio.TimeoutError):
        ip = ""
    _resolved[host] = (time.monotonic(), ip)
    return ip


async def _hosting_by_ip() -> dict[str, dict[str, Any]]:
    """IP -> hosting account, from the hostings' server lists, and from the created servers for the rest."""
    if time.monotonic() - _hosting["at"] >= WHERE_TTL:
        by_ip: dict[str, dict[str, Any]] = {}
        try:
            for h in await hosters.list_all():
                for server in h.get("servers") or []:
                    for ip in server.get("ipv4") or []:
                        by_ip.setdefault(ip, {"id": h["id"], "name": h["name"], "provider": h["provider"]})
        except Exception:  # noqa: BLE001 - the check goes on without the hostings
            log.warning("hosting lists for the connection check failed", exc_info=True)
        _hosting.update(at=time.monotonic(), by_ip=by_ip)
    by_ip = dict(_hosting["by_ip"])
    accounts = {h.id: h for h in db.list_hosters()}
    for p in db.list_provisions():
        h = accounts.get(p.hoster_id)
        if p.ip and h and p.state != "deleted":
            by_ip.setdefault(p.ip, {"id": h.id, "name": h.name, "provider": h.provider})
    return by_ip


def _provider_title(provider: str) -> str:
    return hosters.PROVIDERS.get(provider, {}).get("title", provider)


async def _panel(panel: db.Panel, now: int) -> dict[str, Any]:
    out: dict[str, Any] = {"panel_id": panel.id, "panel": panel.name, "error": None, "items": []}
    xui = await pool.get(panel)
    try:
        await xui.ensure_ready()
        if not xui.is_v3:
            out["error"] = "проверка коннектов работает с 3x-ui v3"
            return out
        inbounds = await xui.inbounds()
        nodes = {n.get("id"): n for n in await xui.v3_nodes()}
        refused, fresh = await _ensure_client(xui, inbounds)
        if fresh:
            _attached_at[panel.id] = time.monotonic()
        raw_links = await xui.v3_client_links(PROBE_EMAIL)
    except XUIError as exc:
        out["error"] = str(exc)
        return out

    items: list[dict[str, Any]] = []
    links: list[Link] = []
    linked: list[dict[str, Any]] = []
    seen: set[int] = set()
    for url in raw_links:
        scheme = url.split("://", 1)[0].lower() if "://" in url else ""
        if scheme in UNDIALED:
            continue
        try:
            link = parse(url)
        except LinkError as exc:
            remark = url.split("#", 1)[1][:60] if "#" in url else (scheme or "ссылка")  # never the link's body
            items.append({"key": f"{panel.id}:link:{len(items)}", "remark": remark, "status": "fail",
                          "error": str(exc), "server": "", "server_kind": "main", "protocol": scheme})
            continue
        inbound = _match(link, inbounds)
        view = _inbound_view(panel, inbound, nodes) if inbound else {
            "inbound_id": None, "remark": link.remark, "protocol": link.protocol, "network": link.network,
            "security": link.security, "port": link.port, "server": link.host, "server_host": link.host,
            "server_kind": "main", "enable": True}
        n = sum(1 for i in linked if i["inbound_id"] == view["inbound_id"])  # External Proxy: several links each
        item = {**view, "key": f"{panel.id}:{view['inbound_id']}:{n}", "address": f"{link.host}:{link.port}",
                "link_remark": link.remark}
        if inbound:
            seen.add(inbound["id"])
        links.append(link)
        linked.append(item)

    for item, result in zip(linked, await _check_links(links)):
        if result["ok"]:
            item.update(status="ok", ms=result["ms"], connect_ms=result["connect_ms"], error="")
        else:
            item.update(status="fail", ms=None, error=result["error"], detail=result.get("detail", ""))
            if time.monotonic() - _attached_at.get(panel.id, -SETTLE) < SETTLE:
                # try again before calling it broken
                item["error"] = "служебный клиент только что добавлен, узел мог ещё не применить его — проверю ещё раз"
                asyncio.get_running_loop().call_later(30, kick)
        items.append(item)

    for inbound in inbounds:
        if inbound.get("id") in seen:
            continue
        view = _inbound_view(panel, inbound, nodes)
        item = {**view, "key": f"{panel.id}:{inbound.get('id')}:0", "ms": None}
        if not view["enable"]:
            item.update(status="off", error="коннект выключен")
        elif view["protocol"] not in CHECKED:
            item.update(status="skip", error=SKIP_REASONS.get(view["protocol"], f"{view['protocol']} не проверяется"))
        elif inbound.get("id") in refused:
            item.update(status="fail", error=f"служебный клиент не добавлен: {refused[inbound['id']]}")
        else:
            item.update(status="fail", error="3x-ui не выдала ссылку на этот коннект")
        items.append(item)

    hosts = sorted({i.get("server_host") or "" for i in items} - {""})
    ips = dict(zip(hosts, await asyncio.gather(*(_ip(h) for h in hosts))))
    by_ip = await _hosting_by_ip()
    for item in items:
        ip = ips.get(item.pop("server_host", "") or "", "")
        hosting = by_ip.get(ip)
        item["server_ip"] = ip
        item["hoster"] = {**hosting, "title": _provider_title(hosting["provider"])} if hosting else None
        history = _history.setdefault(item["key"], deque(maxlen=HISTORY))
        if item["status"] in ("ok", "fail"):
            point = {"t": now, "ms": item.get("ms")}
            if item["status"] == "fail":  # why it failed, so an unstable connect shows its reasons afterwards
                point["error"] = (item.get("error") or "")[:200]
            history.append(point)
        item["history"] = list(history)
    order = {"main": 0, "node": 1}
    items.sort(key=lambda i: (order.get(i.get("server_kind"), 2), i.get("server") or "", i.get("port") or 0))
    out["items"] = items
    return out


async def run_round() -> dict[str, Any]:
    async with _lock:
        started = time.monotonic()
        now = int(time.time())
        if not os.path.exists(XRAY):
            _state.update(checked_at=now, error=f"Xray-core не найден ({XRAY}): обновите админку", panels=[])
            return snapshot()
        panels = await asyncio.gather(*(_panel(p, now) for p in db.list_panels()), return_exceptions=True)
        result = []
        for panel in panels:
            if isinstance(panel, BaseException):
                log.error("connection check failed", exc_info=panel)
                continue
            result.append(panel)
        _state.update(checked_at=now, duration=round(time.monotonic() - started, 1), error=None, panels=result)
        live = {i["key"] for p in result for i in p["items"]}
        for key in [k for k in _history if k not in live]:
            del _history[key]
    return snapshot()


async def loop() -> None:
    await asyncio.sleep(10)  # let the panels' sessions come up with the first overview
    while True:
        _kick.clear()
        try:
            await run_round()
        except Exception:  # noqa: BLE001 - one bad round must not stop the checks for good
            log.exception("connection check round failed")
        try:
            await asyncio.wait_for(_kick.wait(), INTERVAL)
            await asyncio.sleep(5)  # a kick right after a change: give the panel a moment to apply it
        except asyncio.TimeoutError:
            pass
