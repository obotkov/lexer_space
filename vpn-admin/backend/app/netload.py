"""Network load of every 3x-ui server right now: download + upload speed of each main panel (its server
status) and each of its nodes (the main panel's heartbeat), sampled in the background so the overview
can draw the last 5 minutes as soon as it opens.
"""

import asyncio
import logging
import time
from collections import deque
from typing import Any

from . import db
from .aggregator import pool
from .xui import XUIError

log = logging.getLogger("vpn-admin.netload")

INTERVAL = 5
WINDOW = 5 * 60

_samples: deque[dict[str, Any]] = deque(maxlen=WINDOW // INTERVAL + 1)
_series: dict[str, dict[str, Any]] = {}  # key -> name, panel, kind; the servers seen inside the window
# sample times run on the monotonic clock: a wall clock stepped by NTP must not send the chart backwards
_epoch = time.time() - time.monotonic()


async def _panel(panel: db.Panel) -> dict[str, float]:
    """bytes/sec (down + up) of the panel's own server and of each of its nodes; {} when it does not answer."""
    xui = await pool.get(panel)
    values: dict[str, float] = {}
    try:
        await xui.ensure_ready()
        status, nodes = await asyncio.gather(
            xui.server_status(), xui.v3_nodes() if xui.is_v3 else asyncio.sleep(0, []), return_exceptions=True)
    except XUIError:
        return values
    if isinstance(status, dict):
        io = status.get("netIO") or {}
        key = f"{panel.id}:main"
        values[key] = float(io.get("up") or 0) + float(io.get("down") or 0)
        _series[key] = {"name": panel.name, "panel": panel.name, "kind": "main"}
    if isinstance(nodes, list):
        for node in nodes:
            if not node.get("enable", True):
                continue
            key = f"{panel.id}:node:{node.get('id')}"
            # a node that misses its heartbeat has no speed to show: a gap rather than a false zero
            if node.get("status") == "online":
                values[key] = float(node.get("netUp") or 0) + float(node.get("netDown") or 0)
            _series[key] = {"name": node.get("name", ""), "panel": panel.name, "kind": "node"}
    return values


async def sample() -> None:
    at = int(_epoch + time.monotonic())
    panels = db.list_panels()
    results = await asyncio.gather(*(_panel(p) for p in panels), return_exceptions=True)
    values: dict[str, float] = {}
    for result in results:
        if isinstance(result, dict):
            values.update(result)
    _samples.append({"t": at, "values": values})


async def loop() -> None:
    while True:
        started = time.monotonic()
        try:
            await sample()
        except Exception:  # noqa: BLE001 - one bad round must not stop the chart for good
            log.exception("network load sample failed")
        await asyncio.sleep(max(1.0, INTERVAL - (time.monotonic() - started)))


def snapshot() -> dict[str, Any]:
    seen = {key for s in _samples for key in s["values"]}
    keys = [k for k in _series if k in seen]
    return {
        "interval": INTERVAL,
        "window": WINDOW,
        "series": [{"key": k, **_series[k]} for k in keys],
        "points": [{"t": s["t"], "values": {k: s["values"].get(k) for k in keys}} for s in _samples],
    }
