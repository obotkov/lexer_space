"""Ping from the admin's own server to every 3x-ui server it shows: the main panels and their nodes.

ICMP echo through an unprivileged ping socket (Docker and most systems allow it), a raw socket
(root with NET_RAW) as the second try; where neither is allowed, or the host drops ICMP, the time
of a TCP connect to the panel's port stands in for it.
"""

import asyncio
import itertools
import os
import socket
import struct
import sys
import time
from typing import Any
from urllib.parse import urlsplit

from .aggregator import overview_cache

COUNT = 4
INTERVAL = 0.2
TIMEOUT = 1.5  # after the last echo request
CACHE_TTL = 15

_cache: dict[str, Any] = {"at": 0.0, "data": None}
_idents = itertools.count(os.getpid())
_lock = asyncio.Lock()


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _icmp_socket(v6: bool) -> tuple[socket.socket, bool]:
    family, proto = (socket.AF_INET6, socket.IPPROTO_ICMPV6) if v6 else (socket.AF_INET, socket.IPPROTO_ICMP)
    try:
        return socket.socket(family, socket.SOCK_DGRAM, proto), False
    except OSError:
        return socket.socket(family, socket.SOCK_RAW, proto), True  # PermissionError without NET_RAW


async def _icmp(ip: str) -> list[float | None]:
    """Round-trip times in ms of COUNT echo requests, None for each lost one."""
    v6 = ":" in ip
    sock, raw = _icmp_socket(v6)
    sock.setblocking(False)
    echo, reply = (128, 129) if v6 else (8, 0)
    ident = next(_idents) & 0xFFFF  # its own per target: a raw socket sees every echo reply of the host
    # a Linux ping socket puts its own identifier in and gets only its own replies
    check_ident = raw or sys.platform != "linux"
    loop = asyncio.get_running_loop()
    sent: dict[int, float] = {}
    times: list[float | None] = [None] * COUNT
    done = asyncio.Event()

    async def receive() -> None:
        while True:
            data = await loop.sock_recv(sock, 2048)
            now = time.perf_counter()
            if not v6 and data and data[0] >> 4 == 4:  # a raw IPv4 socket (and macOS) hands over the IP header
                data = data[(data[0] & 0x0F) * 4:]
            if len(data) < 8 or data[0] != reply:
                continue
            _, _, _, rid, seq = struct.unpack("!BBHHH", data[:8])
            if (check_ident and rid != ident) or seq not in sent or times[seq] is not None:
                continue
            times[seq] = round((now - sent[seq]) * 1000, 1)
            if all(t is not None for t in times):
                done.set()

    receiver = asyncio.create_task(receive())
    try:
        for seq in range(COUNT):
            payload = struct.pack("!d", time.time()) + b"vpn-admin"
            header = struct.pack("!BBHHH", echo, 0, 0, ident, seq)
            packet = struct.pack("!BBHHH", echo, 0, 0 if v6 else _checksum(header + payload), ident, seq) + payload
            sent[seq] = time.perf_counter()
            sock.sendto(packet, (ip, 0))  # never blocks for a packet this small; uvloop has no sock_sendto
            if seq < COUNT - 1:
                await asyncio.sleep(INTERVAL)
        try:
            await asyncio.wait_for(done.wait(), TIMEOUT)
        except asyncio.TimeoutError:
            pass
    finally:
        receiver.cancel()
        sock.close()
    return times


async def _tcp(ip: str, port: int) -> list[float | None]:
    times: list[float | None] = []
    for _ in range(COUNT - 1):
        start = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), TIMEOUT)
        except (OSError, asyncio.TimeoutError):
            times.append(None)
            continue
        times.append(round((time.perf_counter() - start) * 1000, 1))
        writer.close()
    return times


async def _resolve(host: str) -> str:
    infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM), 5)
    addresses = [info[4][0] for info in infos]
    return next((a for a in addresses if ":" not in a), addresses[0])  # IPv4 first, as clients mostly connect


async def _measure(target: dict[str, Any]) -> dict[str, Any]:
    out = {**target, "ip": "", "method": "", "avg_ms": None, "min_ms": None, "max_ms": None, "loss": None,
           "error": ""}
    try:
        out["ip"] = ip = await _resolve(target["host"])
    except (OSError, asyncio.TimeoutError, IndexError):
        out["error"] = f"имя {target['host']} не найдено в DNS"
        return out
    times: list[float | None] = []
    try:
        times = await _icmp(ip)
        out["method"] = "icmp"
    except OSError:  # ICMP is not allowed here: TCP below
        pass
    if not any(t is not None for t in times) and target["port"]:
        times = await _tcp(ip, target["port"])  # also for hosts that drop ICMP
        out["method"] = "tcp"
    got = [t for t in times if t is not None]
    if times:
        out["loss"] = round((len(times) - len(got)) / len(times) * 100)
    if got:
        out.update(avg_ms=round(sum(got) / len(got), 1), min_ms=min(got), max_ms=max(got))
    else:
        out["error"] = "не отвечает"
    return out


def _targets(overview: dict[str, Any]) -> list[dict[str, Any]]:
    targets = []
    for panel in overview["panels"]:
        url = urlsplit(panel["url"])
        if url.hostname:
            targets.append({"kind": "main", "panel": panel["name"], "name": panel["name"], "host": url.hostname,
                            "port": url.port or (443 if url.scheme == "https" else 80), "panel_ms": None,
                            "enable": True})
        for node in panel.get("children") or []:
            if node.get("address"):
                targets.append({"kind": "node", "panel": panel["name"], "name": node["name"], "host": node["address"],
                                "port": node.get("port") or 0, "enable": node.get("enable", True),
                                # the main panel's own heartbeat latency to this node, to compare
                                "panel_ms": node.get("latency_ms") if node.get("status") == "online" else None})
    return targets


async def ping_all(force: bool = False) -> dict[str, Any]:
    async with _lock:  # one round at a time: parallel page loads share it
        if not force and _cache["data"] and time.time() - _cache["at"] < CACHE_TTL:
            return _cache["data"]
        targets = _targets(await overview_cache.get())
        results = await asyncio.gather(*(_measure(t) for t in targets))
        _cache.update(at=time.time(), data={"checked_at": int(time.time()), "targets": list(results)})
        return _cache["data"]
