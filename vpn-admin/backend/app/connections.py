"""Connection templates: the inbounds every new server gets right after it joins the main panel.

A template is a kind (one of the protocols below), a remark, a port (0 = a random free one) and the
kind's options. When a server is ordered, the enabled templates are copied into the job with their
ports fixed (the install opens them in ufw); once the node is connected, each becomes an inbound of the
main 3x-ui panel bound to the node (nodeId), with fresh keys, paths and passwords, and the chosen users
are attached to all of them. The kinds and their settings follow 3X-UI KIT and 3x-ui-pro.
"""

import asyncio
import base64
import ipaddress
import json
import secrets
import socket
import ssl
import string
import time
from dataclasses import dataclass
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import BaseModel, Field, field_validator

from . import db
from .xui import XUIClient, XUIError, v3_record_to_client

PORT_RANGE = (20000, 60000)
FINGERPRINTS = ["chrome", "firefox", "safari", "ios", "edge", "random", "randomized"]
SNIFFING = {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False, "routeOnly": False}

# kind → what it is; "net" is what the port is opened for, "tls" means it needs the node's certificate
KINDS: dict[str, dict[str, Any]] = {
    "vless_reality": {"title": "VLESS REALITY", "protocol": "vless", "net": "tcp", "tls": False, "port": 443,
                      "remark": "REALITY", "note": "основной и самый устойчивый: TCP с маскировкой под чужой сайт"},
    "vless_xhttp_reality": {"title": "VLESS XHTTP + REALITY", "protocol": "vless", "net": "tcp", "tls": False,
                            "port": 0, "remark": "XHTTP",
                            "note": "если обычный REALITY не подключается: трафик похож на обычный HTTP"},
    "vless_ws_tls": {"title": "VLESS WebSocket + TLS", "protocol": "vless", "net": "tcp", "tls": True, "port": 0,
                     "remark": "VLESS-WS", "note": "работает через CDN; нужен сертификат сервера"},
    "trojan_grpc_tls": {"title": "Trojan gRPC + TLS", "protocol": "trojan", "net": "tcp", "tls": True, "port": 0,
                        "remark": "Trojan-gRPC", "note": "нужен сертификат сервера"},
    "vmess_ws_tls": {"title": "VMess WebSocket + TLS", "protocol": "vmess", "net": "tcp", "tls": True, "port": 0,
                     "remark": "VMess-WS", "note": "для старых приложений; нужен сертификат сервера"},
    "shadowsocks": {"title": "Shadowsocks 2022", "protocol": "shadowsocks", "net": "both", "tls": False, "port": 0,
                    "remark": "Shadowsocks", "note": "TCP и UDP на одном порту"},
    "hysteria2": {"title": "Hysteria2", "protocol": "hysteria", "net": "udp", "tls": True, "port": 443,
                  "remark": "Hysteria2", "note": "UDP, быстрый на плохих каналах; нужен сертификат сервера"},
    "tuic": {"title": "TUIC v5", "protocol": "tuic", "net": "udp", "tls": True, "port": 0, "remark": "TUIC",
             "note": "UDP (QUIC); нужен сертификат сервера"},
    "wireguard": {"title": "WireGuard", "protocol": "wireguard", "net": "udp", "tls": False, "port": 0,
                  "remark": "WireGuard", "note": "UDP; легко распознаётся DPI"},
    "amneziawg": {"title": "AmneziaWG", "protocol": "amneziawg", "net": "udp", "tls": False, "port": 0,
                  "remark": "AmneziaWG", "note": "WireGuard с маскировкой; приложения AmneziaVPN/AmneziaWG"},
    "mtproto": {"title": "MTProto (Telegram)", "protocol": "mtproto", "net": "tcp", "tls": False, "port": 0,
                "remark": "MTProto", "note": "прокси только для Telegram"},
    "vless_xhttp_cdn": {"title": "VLESS XHTTP через CDN", "protocol": "vless", "net": "tcp", "tls": True, "port": 0,
                        "remark": "CDN",
                        "note": "для белых списков: клиенты ходят через CDN (Yandex Cloud), IP сервера не виден; "
                                "медленнее остальных"},
}
Kind = Literal["vless_reality", "vless_xhttp_reality", "vless_ws_tls", "trojan_grpc_tls", "vmess_ws_tls",
               "shadowsocks", "hysteria2", "tuic", "wireguard", "amneziawg", "mtproto", "vless_xhttp_cdn"]

# kind → option → (default, allowed values or None for free text / numbers)
OPTIONS: dict[str, dict[str, tuple[Any, list[Any] | None]]] = {
    "vless_reality": {"sni": ("www.microsoft.com", None), "fingerprint": ("chrome", FINGERPRINTS),
                      "flow": ("xtls-rprx-vision", ["xtls-rprx-vision", ""]), "short_ids": (1, None)},
    "vless_xhttp_reality": {"sni": ("www.microsoft.com", None), "fingerprint": ("chrome", FINGERPRINTS),
                            "mode": ("auto", ["auto", "packet-up", "stream-up", "stream-one"]), "path": ("", None)},
    "vless_ws_tls": {"path": ("", None), "fingerprint": ("chrome", FINGERPRINTS)},
    "trojan_grpc_tls": {"service_name": ("", None), "fingerprint": ("chrome", FINGERPRINTS)},
    "vmess_ws_tls": {"path": ("", None), "fingerprint": ("chrome", FINGERPRINTS)},
    "shadowsocks": {"method": ("2022-blake3-aes-128-gcm", ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                                                           "2022-blake3-chacha20-poly1305"])},
    "hysteria2": {"masquerade": (True, [True, False])},
    "tuic": {"congestion": ("bbr", ["bbr", "cubic", "new_reno"])},
    "wireguard": {"mtu": (1420, None), "subnet": ("10.8.1.0/24", None)},
    "amneziawg": {"variant": ("classic", ["classic", "full"]), "subnet": ("10.8.1.0/24", None),
                  "dns": ("1.1.1.1", None)},
    "mtproto": {"domain": ("www.cloudflare.com", None)},
    # cdn_subdomain: the connection's name in the server's Cloudflare zone, which the CDN serves
    "vless_xhttp_cdn": {"cdn_account_id": (0, None), "cdn_subdomain": ("cdn-{server}", None), "path": ("", None),
                        "uplink": ("get-header", ["get-header", "post-body"]),
                        "fingerprint": ("firefox", FINGERPRINTS)},
}

# 3X-UI KIT's standard set, offered on the first visit to the section (switched off: nothing changes
# for new servers until the admin turns templates on)
DEFAULT_SET = ["vless_reality", "hysteria2", "vless_xhttp_reality", "vless_ws_tls", "trojan_grpc_tls",
               "vmess_ws_tls", "shadowsocks", "tuic", "amneziawg", "amneziawg", "mtproto"]


class TemplateError(Exception):
    pass


def _clean_options(kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, (default, allowed) in OPTIONS[kind].items():
        value = raw.get(name, default)
        if allowed is not None:
            if value not in allowed:
                raise ValueError(f"{name}: допустимо {', '.join(map(str, allowed))}")
        elif isinstance(default, int):
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise ValueError(f"{name}: нужно число") from None
        else:
            value = str(value or "").strip()
        out[name] = value
    if kind in ("vless_reality", "vless_xhttp_reality"):
        names = [s.strip() for s in out["sni"].replace(";", ",").split(",") if s.strip()]
        if not names or any(not _host_ok(n) for n in names):
            raise ValueError("sni: нужен домен сайта для маскировки, например www.microsoft.com")
        out["sni"] = ", ".join(names)
    if kind == "vless_reality" and not 1 <= out["short_ids"] <= 8:
        raise ValueError("short_ids: от 1 до 8")
    if kind in ("wireguard", "amneziawg"):
        _subnet(out["subnet"])
    if kind == "wireguard" and not 1280 <= out["mtu"] <= 1500:
        raise ValueError("mtu: от 1280 до 1500")
    if kind == "vless_xhttp_cdn":
        out["cdn_subdomain"] = out["cdn_subdomain"].strip(".").lower()
        if not out["cdn_subdomain"] or not all(c.isalnum() or c in "-.{}" for c in out["cdn_subdomain"]):
            raise ValueError("cdn_subdomain: латиница, цифры, дефис, точка и макросы вроде {server}")
        if not db.get_cdn_account(out["cdn_account_id"]):
            raise ValueError("cdn_account_id: выберите CDN-аккаунт (подключается на странице VPN API Hoster)")
    if kind == "mtproto" and not _host_ok(out["domain"]):
        raise ValueError("domain: нужен домен, например www.cloudflare.com")
    for name in ("path", "service_name"):
        if name in out and out[name] and not all(c in string.ascii_letters + string.digits + "-_./" for c in out[name]):
            raise ValueError(f"{name}: только латиница, цифры и - _ . /")
    return out


def _host_ok(name: str) -> bool:
    parts = name.split(".")
    return len(parts) >= 2 and all(p and len(p) <= 63 and all(c.isalnum() or c == "-" for c in p) for p in parts)


def _subnet(value: str) -> tuple[str, int]:
    try:
        ip, cidr = value.split("/")
        octets = [int(x) for x in ip.split(".")]
        bits = int(cidr)
    except ValueError:
        raise ValueError("subnet: нужна подсеть вида 10.0.0.0/24") from None
    if len(octets) != 4 or any(not 0 <= o <= 255 for o in octets) or not 16 <= bits <= 30:
        raise ValueError("subnet: нужна подсеть вида 10.0.0.0/24 (маска от 16 до 30)")
    return ip, bits


class TemplateIn(BaseModel):
    kind: Kind
    remark: str = Field(min_length=1, max_length=100)
    enabled: bool = True
    port: int = Field(0, ge=0, le=65535)
    options: dict[str, Any] = {}

    @field_validator("remark")
    @classmethod
    def _remark(cls, value: str) -> str:
        return value.strip()

    def cleaned(self) -> dict[str, Any]:
        return _clean_options(self.kind, self.options)


class UsersIn(BaseModel):
    mode: Literal["all", "selected", "none"] = "all"
    emails: list[str] = []


# ---------- storage ----------

def templates() -> list[db.ConnectionTemplate]:
    rows = db.list_connection_templates()
    if not rows and not db.get_app_setting("connections.seeded"):
        for i, kind in enumerate(DEFAULT_SET):
            options = {name: default for name, (default, _) in OPTIONS[kind].items()}
            remark = "{server} " + KINDS[kind]["remark"]
            if kind == "amneziawg" and DEFAULT_SET[:i].count("amneziawg"):
                # KIT has two: classic parameters (Mihomo, Keenetic) and the full 3.1 set (AmneziaVPN only)
                options.update(variant="full", subnet="10.8.2.0/24")
                remark = "{server} AmneziaWG-3.1"
            db.create_connection_template(kind=kind, remark=remark, enabled=False, port=KINDS[kind]["port"],
                                          options=options, position=i)
        db.set_app_setting("connections.seeded", "1")
        rows = db.list_connection_templates()
    return rows


def users() -> dict[str, Any]:
    raw = db.get_app_setting("connections.users")
    try:
        data = json.loads(raw) if raw else {}
    except ValueError:
        data = {}
    return UsersIn(**data).model_dump() if isinstance(data, dict) else UsersIn().model_dump()


def set_users(body: UsersIn) -> None:
    emails = sorted({e.strip() for e in body.emails if e.strip()})
    db.set_app_setting("connections.users", json.dumps({"mode": body.mode, "emails": emails}))


def public(t: db.ConnectionTemplate) -> dict[str, Any]:
    kind = KINDS[t.kind]
    return {"id": t.id, "kind": t.kind, "kind_title": kind["title"], "protocol": kind["protocol"], "net": kind["net"],
            "tls": kind["tls"], "remark": t.remark, "enabled": t.enabled, "port": t.port, "options": t.options,
            "position": t.position}


def kinds_public() -> list[dict[str, Any]]:
    return [{"kind": k, "title": v["title"], "protocol": v["protocol"], "net": v["net"], "tls": v["tls"],
             "port": v["port"], "remark": v["remark"], "note": v["note"],
             "options": {name: {"default": d, "choices": c} for name, (d, c) in OPTIONS[k].items()}}
            for k, v in KINDS.items()]


# ---------- planning: fix the ports before the server is installed ----------

def _nets(net: str) -> list[str]:
    return ["tcp", "udp"] if net == "both" else [net]


def plan(items: list[dict[str, Any]], taken: set[tuple[int, str]]) -> list[dict[str, Any]]:
    """Give every template a port: its own one, or a random free one. `taken` holds (port, net) pairs
    already in use on the server (panel, subscription, the stub's 80, existing inbounds)."""
    rng = secrets.SystemRandom()
    used = set(taken)
    out = []
    for t in items:
        nets = _nets(KINDS[t["kind"]]["net"])
        port = t["port"]
        if port and any((port, n) in used for n in nets):
            port = 0  # the fixed port is busy on this server: a random one instead
        while not port:
            candidate = rng.randrange(*PORT_RANGE)
            if not any((candidate, n) in used for n in ("tcp", "udp")):
                port = candidate
        used.update((port, n) for n in nets)
        out.append({**t, "port": port})
    return out


def snapshot(rows: list[db.ConnectionTemplate]) -> list[dict[str, Any]]:
    return [{"template_id": t.id, "kind": t.kind, "remark": t.remark, "port": t.port, "options": t.options}
            for t in rows if t.enabled]


def inbound_nets(inbound: dict[str, Any]) -> list[str]:
    """What an existing inbound occupies on its port."""
    protocol = inbound.get("protocol", "")
    if protocol in ("hysteria", "tuic", "wireguard", "amneziawg"):
        return ["udp"]
    if protocol == "shadowsocks":
        return ["tcp", "udp"]
    return ["tcp"]


def macros(server: str, region: str = "") -> dict[str, str]:
    """What the macros of a remark stand for. `region` is the label the form showed, e.g.
    "🇩🇪 Германия, Франкфурт — fra1" or VDSina's "🇳🇱 Нидерланды, Amsterdam 1, Netherlands"."""
    label = region.split(" — ")[0].strip()
    flag = ""
    while label and 0x1F1E6 <= ord(label[0]) <= 0x1F1FF:  # regional indicator letters make the flag
        flag, label = flag + label[0], label[1:]
    label = label.strip()
    country, _, rest = label.partition(", ")
    city = rest.split(", ")[0] or country
    return {"{server}": server, "{flag}": flag, "{country}": country, "{city}": city,
            "{region}": " ".join(filter(None, [flag, f"{country}, {city}" if rest else country]))}


def fill(text: str, values: dict[str, str]) -> str:
    for macro, value in values.items():
        text = text.replace(macro, value)
    return " ".join(text.split())  # an empty macro leaves no double space


def item_public(item: dict[str, Any], values: dict[str, str]) -> dict[str, Any]:
    kind = KINDS.get(item.get("kind", ""), {})
    return {"template_id": item.get("template_id"), "kind": item.get("kind"), "title": kind.get("title", item.get("kind")),
            "remark": fill(str(item.get("remark", "")), values), "port": item.get("port"),
            "net": kind.get("net", "tcp"), "inbound_id": item.get("inbound_id"), "error": item.get("error", ""),
            "cdn_domain": item.get("cdn_domain", ""), "cdn_address": item.get("cdn_address", "")}


def ufw_rules(items: list[dict[str, Any]]) -> list[str]:
    return [f"{i['port']}/{n}" for i in items for n in _nets(KINDS[i["kind"]]["net"])]


# ---------- building one inbound ----------

@dataclass
class Target:
    """What a server contributes to its inbounds."""
    server: str          # server (job) name, for {server} in remarks
    tls_name: str        # serverName for TLS: the domain, or "" for an IP certificate
    cert_file: str       # paths inside the node's 3x-ui container
    key_file: str
    pin_hex: str         # sha256 of a self-signed certificate (clients trust exactly it), else ""
    stub_html: str = ""  # decoy page for Hysteria2 masquerade
    region: str = ""     # region label, for {region}, {flag}, {country} and {city} in remarks

    @property
    def macros(self) -> dict[str, str]:
        return macros(self.server, self.region)


def _rand(n: int) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


def _x25519(urlsafe: bool) -> tuple[str, str]:
    """Reality keys are raw base64url without padding (xray x25519); WireGuard keys are standard base64."""
    key = X25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if urlsafe:
        return (base64.urlsafe_b64encode(priv).decode().rstrip("="), base64.urlsafe_b64encode(pub).decode().rstrip("="))
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def _pick(names: str) -> str:
    return secrets.choice([s.strip() for s in names.split(",") if s.strip()])


def _path(value: str) -> str:
    return "/" + (value.strip("/") or _rand(10))


def _tls(t: Target, alpn: list[str], fingerprint: str = "chrome") -> dict[str, Any]:
    if not t.cert_file:
        raise TemplateError("неизвестно, какой сертификат у сервера: переустановите его из админки")
    settings: dict[str, Any] = {"fingerprint": fingerprint}
    if t.pin_hex:
        settings["pinnedPeerCertSha256"] = [t.pin_hex]
    return {"serverName": t.tls_name, "alpn": alpn,
            "certificates": [{"certificateFile": t.cert_file, "keyFile": t.key_file}], "settings": settings}


def _reality(sni: str, fingerprint: str, short_ids: int = 1) -> dict[str, Any]:
    private, public_key = _x25519(urlsafe=True)
    return {"show": False, "xver": 0, "target": f"{sni}:443", "serverNames": [sni], "privateKey": private,
            "minClientVer": "", "maxClientVer": "", "maxTimediff": 0,
            "shortIds": [secrets.token_hex(8) for _ in range(short_ids)],
            "settings": {"publicKey": public_key, "fingerprint": fingerprint, "serverName": "", "spiderX": "/"}}


def _awg_obfuscation(variant: str) -> dict[str, Any]:
    """Junk packets and header magic of AmneziaWG, as KIT picks them; the full 3.1 set adds header protection."""
    rnd = secrets.SystemRandom().randint
    jmin, s1 = rnd(40, 89), rnd(15, 150)
    s2 = rnd(15, 150)
    while s1 + 56 == s2:
        s2 = rnd(15, 150)
    o: dict[str, Any] = {"jc": rnd(3, 6), "jmin": jmin, "jmax": jmin + rnd(50, 250), "s1": s1, "s2": s2,
                         "h1": str(rnd(5, 536870911)), "h2": str(rnd(536870912, 1073741823)),
                         "h3": str(rnd(1073741824, 1610612735)), "h4": str(rnd(1610612736, 2147483647))}
    if variant == "full":
        cp, rk, rt, ka, ha = rnd(8, 24), rnd(100, 120), rnd(3, 6), rnd(8, 12), rnd(15, 25)
        rj = rk + rnd(10, 40) + rnd(30, 60)
        # with header protection AmneziaWG advises H1–H4 = 1, 2, 3, 4
        o.update(h1="1", h2="2", h3="3", h4="4", s3=rnd(12, 55), s4=rnd(12, 27), i1=f"<r {rnd(32, 256)}>",
                 headerProtectionKey=base64.b64encode(secrets.token_bytes(32)).decode(),
                 contentPaddingAddition=f"{cp}-{cp + rnd(8, 40)}", rekeyAfterTime=f"{rk}-{rk + rnd(10, 40)}",
                 rejectAfterTime=f"{rj}-{rj + rnd(30, 90)}", rekeyTimeout=f"{rt}-{rt + rnd(1, 4)}",
                 keepaliveTimeout=f"{ka}-{ka + rnd(2, 8)}", maxHandshakeAttempts=f"{ha}-{ha + rnd(5, 25)}")
    return o


def build(item: dict[str, Any], t: Target, node_id: int) -> dict[str, Any]:
    """The /panel/api/inbounds/add body for one planned template on one node; clients are attached later."""
    kind, o = item["kind"], item["options"]
    settings: dict[str, Any]
    stream: dict[str, Any] = {"network": "tcp", "security": "none"}
    if kind == "vless_reality":
        settings = {"clients": [], "decryption": "none", "fallbacks": []}
        stream = {"network": "tcp", "security": "reality", "externalProxy": [],
                  "realitySettings": _reality(_pick(o["sni"]), o["fingerprint"], o["short_ids"]),
                  "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}}}
    elif kind == "vless_xhttp_reality":
        settings = {"clients": [], "decryption": "none"}
        stream = {"network": "xhttp", "security": "reality", "xhttpSettings": {"path": _path(o["path"]), "mode": o["mode"]},
                  "realitySettings": _reality(_pick(o["sni"]), o["fingerprint"])}
    elif kind == "vless_ws_tls":
        settings = {"clients": [], "decryption": "none"}
        stream = {"network": "ws", "security": "tls", "wsSettings": {"path": _path(o["path"])},
                  "tlsSettings": _tls(t, ["http/1.1"], o["fingerprint"])}
    elif kind == "trojan_grpc_tls":
        settings = {"clients": []}
        stream = {"network": "grpc", "security": "tls", "grpcSettings": {"serviceName": o["service_name"] or _rand(8)},
                  "tlsSettings": _tls(t, ["h2"], o["fingerprint"])}
    elif kind == "vmess_ws_tls":
        settings = {"clients": []}
        stream = {"network": "ws", "security": "tls", "wsSettings": {"path": _path(o["path"])},
                  "tlsSettings": _tls(t, ["http/1.1"], o["fingerprint"])}
    elif kind == "shadowsocks":
        size = 16 if o["method"] == "2022-blake3-aes-128-gcm" else 32
        settings = {"method": o["method"], "password": base64.b64encode(secrets.token_bytes(size)).decode(),
                    "network": "tcp,udp", "clients": []}
    elif kind == "hysteria2":
        settings = {"version": 2, "clients": []}
        hy: dict[str, Any] = {"version": 2}
        if o["masquerade"] and t.stub_html:
            # a stray HTTP/3 request gets the decoy page instead of silence
            hy["masquerade"] = {"type": "string", "content": t.stub_html, "statusCode": 200,
                                "headers": {"content-type": "text/html; charset=utf-8"}}
        stream = {"network": "hysteria", "security": "tls", "tlsSettings": _tls(t, ["h3"]), "hysteriaSettings": hy}
    elif kind == "tuic":
        _tls(t, ["h3"])  # only for its check that the server has a certificate
        settings = {"server": {"certificate": t.cert_file, "private_key": t.key_file, "congestion_control": o["congestion"],
                               "alpn": ["h3"], "udp_relay_mode": "native", "zero_rtt_handshake": False,
                               "log_level": "warn", "sni": ""},
                    "clients": []}
        stream = {}
    elif kind == "wireguard":
        ip, bits = _subnet(o["subnet"])
        settings = {"mtu": o["mtu"], "secretKey": _x25519(urlsafe=False)[0], "peers": [], "subnetIp": ip,
                    "subnetCidr": bits, "clients": []}
    elif kind == "amneziawg":
        ip, bits = _subnet(o["subnet"])
        private, public_key = _x25519(urlsafe=False)
        settings = {"server": {"privateKey": private, "publicKey": public_key, "subnetIp": ip, "subnetCidr": bits,
                               "primaryDns": o["dns"], "secondaryDns": "8.8.8.8", **_awg_obfuscation(o["variant"])},
                    "clients": []}
        stream = {}
    elif kind == "mtproto":
        settings = {"fakeTlsDomain": o["domain"], "clients": []}
        stream = {}
    elif kind == "vless_xhttp_cdn":
        host, address = item.get("cdn_domain"), item.get("cdn_address")
        if not host or not address:
            raise TemplateError(item.get("cdn_error") or "CDN-ресурс не создан")
        settings = {"clients": [], "decryption": "none"}
        xhttp: dict[str, Any] = {"path": _path(o["path"]), "host": host, "mode": "packet-up"}
        if o["uplink"] == "get-header":
            # uploads as GET requests with the data in headers, 6000 bytes each: what CDNs and filters pass most
            # easily. 3x-ui puts these into the links' "extra"; the server needs room for the base64 headers
            xhttp.update(uplinkHTTPMethod="GET", uplinkDataPlacement="header", scMaxEachPostBytes="6000",
                         serverMaxHeaderBytes=32768)
        tls = _tls(t, ["h2", "http/1.1"], o["fingerprint"])
        tls["serverName"] = host
        tls["settings"].pop("pinnedPeerCertSha256", None)  # clients see the CDN's certificate, not the server's
        stream = {"network": "xhttp", "security": "tls", "tlsSettings": tls, "xhttpSettings": xhttp,
                  # links lead to the CDN's technical address, the name stays as SNI and Host
                  "externalProxy": [{"forceTls": "same", "dest": address, "port": 443, "remark": ""}]}
    else:
        raise TemplateError(f"Неизвестный тип подключения: {kind}")
    return {"enable": True, "remark": fill(item["remark"], t.macros), "listen": "", "port": item["port"],
            "protocol": KINDS[kind]["protocol"], "settings": json.dumps(settings), "streamSettings": json.dumps(stream),
            "sniffing": json.dumps(SNIFFING), "expiryTime": 0, "total": 0, "nodeId": node_id}


def pin_hex(pin_b64: str) -> str:
    try:
        return base64.b64decode(pin_b64).hex() if pin_b64 else ""
    except ValueError:
        return ""


def check_sni(host: str, timeout: float = 6.0) -> str:
    """REALITY borrows another site's TLS: it must answer TLS 1.3 with HTTP/2. Returns "" when it does."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["h2"])
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
            if tls.selected_alpn_protocol() != "h2":
                return "сайт не поддерживает HTTP/2"
    except ssl.SSLError as exc:
        return f"TLS 1.3 не получилось: {exc.reason or exc}"
    except OSError as exc:
        return f"сайт недоступен: {exc}"
    return ""


# ---------- rolling out onto a node ----------

NODE_READY_TIMEOUT = 120


async def _wait_node_ready(xui: XUIClient, node_id: int) -> None:
    """Newer protocols (TUIC, AmneziaWG, MTProto) are refused until the node has reported its panel
    version, which takes a heartbeat after the node is added."""
    deadline = time.time() + NODE_READY_TIMEOUT
    try:
        await xui.v3_node_probe(node_id)
    except XUIError:
        pass  # the regular heartbeat gets there too
    while True:
        node = next((n for n in await xui.v3_nodes() if n.get("id") == node_id), None)
        if node is None:
            raise TemplateError("узел пропал из основной панели")
        if node.get("status") == "online" and node.get("panelVersion"):
            return
        if time.time() > deadline:
            raise TemplateError(f"узел не вышел на связь с основной панелью за {NODE_READY_TIMEOUT // 60} минуты"
                                + (f": {node['lastError']}" if node.get("lastError") else ""))
        await asyncio.sleep(5)


def chosen_clients(records: list[dict[str, Any]], users_setting: dict[str, Any]) -> list[dict[str, Any]]:
    if users_setting["mode"] == "none":
        return []
    records = [r for r in records if r.get("email")]
    if users_setting["mode"] == "selected":
        wanted = set(users_setting["emails"])
        records = [r for r in records if r["email"] in wanted]
    return records


def _ss_key_size(item: dict[str, Any]) -> int:
    """Shadowsocks 2022 takes a base64 key of the cipher's size as the user's password; 0 = any password."""
    method = item["options"].get("method", "") if item["kind"] == "shadowsocks" else ""
    return (16 if "aes-128" in method else 32) if method.startswith("2022-") else 0


def _ss_key_fits(password: str, size: int) -> bool:
    try:
        return len(base64.b64decode(password, validate=True)) == size
    except ValueError:
        return False


def _tunnel_address(record: dict[str, Any]) -> str:
    value = record.get("allowedIPs")
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value or "").split(",")[0].strip()


def _in_subnet(address: str, subnet: str) -> bool:
    try:
        return ipaddress.ip_interface(address).ip in ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return False


async def _attach(xui: XUIClient, items: list[dict[str, Any]], records: list[dict[str, Any]], log: Any) -> None:
    """3x-ui v3 keeps one password and one WireGuard address per user for all of the user's inbounds, and the
    nodes build Xray's config from that record. So:
    - Shadowsocks 2022 goes first: a user without a password gets a key that suits it (Trojan takes any
      password); a user whose password is not such a key is left out of it, or Xray on the node would not start;
    - WireGuard/AmneziaWG take only users whose address is in their subnet, or who have none yet: the first
      tunnel gives the user an address, and every later one reuses it."""
    ss = [i for i in items if _ss_key_size(i)]
    tunnels = [i for i in items if i["kind"] in ("wireguard", "amneziawg")]
    rest = [i for i in items if i not in ss and i not in tunnels]
    by_email = {r["email"]: dict(r) for r in records}
    attached: set[str] = set()
    errors: list[str] = []
    skipped: list[str] = []

    async def attach(emails: list[str], ids: list[int]) -> None:
        if not emails or not ids:
            return
        try:
            result = await xui.v3_bulk_attach(emails, ids)
        except XUIError as exc:
            errors.append(str(exc))
            return
        attached.update(result.get("attached") or [])
        errors.extend(result.get("errors") or [])

    for item in ss:
        size = _ss_key_size(item)
        fits = [e for e, r in by_email.items() if not r.get("password") or _ss_key_fits(r["password"], size)]
        if len(fits) < len(by_email):
            skipped.append(f"{item['remark']}: {len(by_email) - len(fits)} польз. — их пароль 3x-ui не подходит "
                           "Shadowsocks 2022 (у пользователя один пароль на все протоколы)")
        await attach(fits, [item["inbound_id"]])
        if fits:  # passwords given by the panel decide what the next Shadowsocks 2022 inbound accepts
            fresh = {r.get("email"): r for r in await xui.v3_clients()}
            for e in fits:
                by_email[e]["password"] = (fresh.get(e) or {}).get("password", "")
    await attach(list(by_email), [i["inbound_id"] for i in rest])
    for item in tunnels:
        subnet = item["options"]["subnet"]
        fits = [e for e, r in by_email.items() if not _tunnel_address(r) or _in_subnet(_tunnel_address(r), subnet)]
        if len(fits) < len(by_email):
            skipped.append(f"{item['remark']}: {len(by_email) - len(fits)} польз. — у них уже есть адрес WireGuard "
                           f"не из подсети {subnet} (у пользователя один адрес на все WireGuard/AmneziaWG)")
        for e in fits:  # one at a time: the first tunnel gives each user the address the later ones reuse
            await attach([e], [item["inbound_id"]])
        if fits:
            fresh = {r.get("email"): r for r in await xui.v3_clients()}
            for e in fits:
                by_email[e]["allowedIPs"] = (fresh.get(e) or {}).get("allowedIPs", "")
    log(f"Пользователи добавлены в подключения: {len(attached)} из {len(by_email)}"
        + (f"; ошибки: {'; '.join(errors[:5])}" if errors else ""))
    for note in skipped:
        log(f"Не добавлены в {note}")
    if any(i["kind"] == "vless_reality" and i["options"].get("flow") for i in items):
        await _vision(xui, [e for e in by_email if e in attached], log)


async def _vision(xui: XUIClient, emails: list[str], log: Any) -> None:
    """In 3x-ui v3 the VLESS flow belongs to the user, not to the inbound; the panel applies it to TCP REALITY/TLS
    only and leaves it out of XHTTP and WebSocket. Users who have none get xtls-rprx-vision."""
    changed = 0
    for record in await xui.v3_clients():
        if record.get("email") in emails and not record.get("flow"):
            try:
                await xui.v3_update_client(record["email"], {**v3_record_to_client(record), "flow": "xtls-rprx-vision"})
                changed += 1
            except XUIError as exc:
                log(f"Не удалось включить xtls-rprx-vision пользователю {record['email']}: {exc}")
    if changed:
        log(f"Пользователям без flow включён xtls-rprx-vision для REALITY: {changed}")


async def rollout(xui: XUIClient, node_id: int, items: list[dict[str, Any]], target: Target,
                  log: Any, save: Any) -> list[dict[str, Any]]:
    """Create the planned inbounds on the node through the main panel, then attach the chosen users.
    A failed connection is noted on its item and the rest go on: the server works either way.
    `save(items)` keeps progress on the job, so a restarted admin does not create inbounds twice."""
    await _wait_node_ready(xui, node_id)
    items = [dict(i) for i in items]
    for item in items:
        if item.get("inbound_id"):
            continue
        name = f"{fill(item['remark'], target.macros)} ({KINDS[item['kind']]['title']}, порт {item['port']})"
        try:
            created = await xui.v3_add_inbound(build(item, target, node_id))
            item.update(inbound_id=created.get("id"), error="")
            log(f"Подключение {name} создано")
        except (XUIError, TemplateError) as exc:
            item["error"] = str(exc)
            log(f"Подключение {name} не создано: {exc}")
        save(items)
    fresh = [i for i in items if i.get("inbound_id") and not i.get("attached")]
    if not fresh:
        return items
    try:
        records = chosen_clients(await xui.v3_clients(), users())
        if records:
            await _attach(xui, [{**i, "remark": fill(i["remark"], target.macros)} for i in fresh], records, log)
        else:
            log("Пользователей для подключений не выбрано: подключения созданы пустыми")
    except XUIError as exc:
        log(f"Не удалось добавить пользователей в подключения: {exc}")
    for item in fresh:
        item["attached"] = True
    save(items)
    return items
