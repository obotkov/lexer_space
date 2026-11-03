"""Traffic by day: 3x-ui keeps only running totals per inbound, so the admin takes them every few minutes and adds
what grew since to the hour, per server (the main panel or one of its nodes). Days are made of hours in the browser,
in the viewer's time zone. The history starts when the admin starts taking it.
"""

import asyncio
import logging
import time
from typing import Any

from . import db
from .aggregator import overview_cache

log = logging.getLogger("vpn-admin.traffic")

INTERVAL = 300
KEEP_DAYS = 120


def _hour(t: float) -> int:
    return int(t) // 3600 * 3600


def sample(overview: dict[str, Any], now: float | None = None) -> None:
    """What every inbound counted since the last time, onto the current hour. A counter that went down was reset
    (by hand or monthly): all it counted since then is new. An inbound seen first only gives its starting point."""
    hour = _hour(now or time.time())
    last = db.traffic_counters()
    counters, grown = {}, {}
    names = {p["id"]: p["name"] for p in overview["panels"]}
    ok = {p["id"] for p in overview["panels"] if p.get("ok")}
    for n in overview["nodes"]:
        if n["panel_id"] not in ok:
            continue
        key = (n["panel_id"], n["id"])
        up, down = int(n["up"]), int(n["down"])
        counters[key] = (up, down)
        if key not in last:
            continue
        before_up, before_down = last[key]
        d_up = up - before_up if up >= before_up else up
        d_down = down - before_down if down >= before_down else down
        if d_up or d_down:
            server = (n["panel_id"], n.get("node_id") or 0)
            row = grown.setdefault(server, [0, 0, n.get("server") or names.get(n["panel_id"], "")])
            row[0] += d_up
            row[1] += d_down
    db.add_traffic(hour, [(panel_id, node_id, name, up, down) for (panel_id, node_id), (up, down, name) in grown.items()])
    db.set_traffic_counters(counters)
    db.prune_traffic(hour - KEEP_DAYS * 86400)


async def loop() -> None:
    while True:
        try:
            sample(await overview_cache.get())
        except Exception:  # noqa: BLE001 - a missed round only moves its traffic to the next one
            log.exception("traffic sample failed")
        await asyncio.sleep(INTERVAL)


def history(days: int) -> dict[str, Any]:
    since = _hour(time.time()) - (days + 1) * 86400  # a day more: the browser cuts days by its own time zone
    rows = db.traffic_since(since)
    return {"interval": INTERVAL, "started_at": db.traffic_started(),
            "hours": [{"t": r["hour"], "panel_id": r["panel_id"], "node_id": r["node_id"], "server": r["server"],
                       "up": r["up"], "down": r["down"]} for r in rows]}
