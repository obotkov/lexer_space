"""Share links (vless://, vmess://, trojan://, ss://, hysteria2://) -> Xray outbounds.

The parameters are the common v2rayN/Xray share-link format that 3x-ui generates, so an outbound
built here is what a client that imports the same link would connect with.
"""

import base64
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit


class LinkError(ValueError):
    pass


@dataclass
class Link:
    url: str
    scheme: str
    protocol: str  # the 3x-ui inbound protocol it belongs to
    remark: str
    host: str
    port: int
    network: str
    security: str
    outbound: dict[str, Any]


PROTOCOLS = {"vless": "vless", "vmess": "vmess", "trojan": "trojan", "ss": "shadowsocks",
             "hysteria2": "hysteria", "hy2": "hysteria", "hysteria": "hysteria"}


def _b64(text: str) -> str:
    text = text.strip()
    return base64.urlsafe_b64decode(text.replace("+", "-").replace("/", "_") + "=" * (-len(text) % 4)).decode()


def _list(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _tls(q: dict[str, str], network: str) -> dict[str, Any]:
    tls: dict[str, Any] = {}
    if q.get("sni"):
        tls["serverName"] = q["sni"]
    if q.get("fp"):
        tls["fingerprint"] = q["fp"]
    if q.get("alpn"):
        tls["alpn"] = _list(q["alpn"])
    elif network == "hysteria":
        tls["alpn"] = ["h3"]
    pin = q.get("pcs") or q.get("pinSHA256")
    if pin:
        tls["pinnedPeerCertSha256"] = pin
    if q.get("vcn"):
        tls["verifyPeerCertByName"] = q["vcn"]
    if q.get("ech"):
        tls["echConfigList"] = q["ech"]
    if q.get("allowInsecure") in ("1", "true") or q.get("insecure") in ("1", "true"):
        tls["allowInsecure"] = True
    return tls


def _reality(q: dict[str, str]) -> dict[str, Any]:
    if not q.get("pbk"):
        raise LinkError("в ссылке Reality нет публичного ключа (pbk)")
    reality: dict[str, Any] = {"serverName": q.get("sni", ""), "fingerprint": q.get("fp") or "chrome",
                               "password": q["pbk"], "shortId": q.get("sid", ""), "spiderX": q.get("spx", "")}
    if q.get("pqv"):
        reality["mldsa65Verify"] = q["pqv"]
    return reality


def _stream(q: dict[str, str]) -> dict[str, Any]:
    network = {"raw": "tcp", "h2": "http"}.get(q.get("type") or "tcp", q.get("type") or "tcp")
    security = q.get("security") or "none"
    stream: dict[str, Any] = {"network": network, "security": security}
    path, host = q.get("path", ""), q.get("host", "")
    if network == "ws":
        stream["wsSettings"] = {"path": path or "/", "host": host}
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path or "/", "host": host}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": q.get("serviceName", ""), "authority": q.get("authority", ""),
                                  "multiMode": q.get("mode") == "multi"}
    elif network == "xhttp":
        xhttp: dict[str, Any] = {"path": path or "/", "host": host, "mode": q.get("mode") or "auto"}
        if q.get("extra"):
            try:
                xhttp["extra"] = json.loads(q["extra"])
            except json.JSONDecodeError as exc:
                raise LinkError("не разобрать параметр extra (XHTTP)") from exc
        stream["xhttpSettings"] = xhttp
    elif network == "kcp":
        stream["kcpSettings"] = {"header": {"type": q.get("headerType") or "none"}, "seed": q.get("seed", "")}
    elif network == "http":
        stream["httpSettings"] = {"path": path or "/", "host": _list(host)}
    elif network == "tcp" and q.get("headerType") == "http":
        stream["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": _list(path) or ["/"], "headers": {"Host": _list(host)} if host else {}}}}
    elif network != "tcp":
        raise LinkError(f"транспорт {network} не поддерживается проверкой")
    if security == "tls":
        stream["tlsSettings"] = _tls(q, network)
    elif security == "reality":
        stream["realitySettings"] = _reality(q)
    elif security != "none":
        raise LinkError(f"защита {security} не поддерживается проверкой")
    return stream


def _query(query: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}


def _host_port(parts) -> tuple[str, int]:
    try:
        port = parts.port
    except ValueError as exc:
        raise LinkError("неверный порт в ссылке") from exc
    if not parts.hostname or not port:
        raise LinkError("в ссылке нет адреса или порта")
    return parts.hostname, port


def _vmess(url: str) -> Link:
    try:
        data = json.loads(_b64(url[len("vmess://"):]))
    except (ValueError, UnicodeDecodeError) as exc:
        raise LinkError("не разобрать ссылку VMess") from exc
    q = {"type": data.get("net") or "tcp", "headerType": data.get("type") or "", "host": data.get("host") or "",
         "path": data.get("path") or "", "security": data.get("tls") or "none", "sni": data.get("sni") or "",
         "alpn": data.get("alpn") or "", "fp": data.get("fp") or "", "serviceName": data.get("path") or "",
         "mode": data.get("mode") or ""}
    if q["type"] == "grpc":
        q["path"] = ""
    host, port = str(data.get("add") or ""), int(data.get("port") or 0)
    if not host or not port:
        raise LinkError("в ссылке нет адреса или порта")
    stream = _stream(q)
    outbound = {"protocol": "vmess", "settings": {"vnext": [{"address": host, "port": port, "users": [
        {"id": data.get("id", ""), "alterId": int(data.get("aid") or 0), "security": data.get("scy") or "auto"}]}]},
        "streamSettings": stream}
    return Link(url, "vmess", "vmess", str(data.get("ps") or ""), host, port, stream["network"], stream["security"],
                outbound)


def _shadowsocks(url: str, parts, q: dict[str, str]) -> tuple[str, int, dict[str, Any]]:
    if parts.username is not None and parts.hostname:
        user = unquote(parts.username) if parts.password is None else f"{unquote(parts.username)}:{unquote(parts.password)}"
        if ":" not in user:  # SIP002: base64url(method:password)
            try:
                user = _b64(user)
            except (ValueError, UnicodeDecodeError) as exc:
                raise LinkError("не разобрать ссылку Shadowsocks") from exc
        host, port = _host_port(parts)
    else:  # legacy: ss://base64(method:password@host:port)
        try:
            decoded = _b64(url[len("ss://"):].split("#")[0].split("?")[0])
        except (ValueError, UnicodeDecodeError) as exc:
            raise LinkError("не разобрать ссылку Shadowsocks") from exc
        user, _, address = decoded.rpartition("@")
        host, _, port_text = address.rpartition(":")
        host, port = host.strip("[]"), int(port_text or 0)
    method, _, password = user.partition(":")
    if not method or not password or not host or not port:
        raise LinkError("в ссылке Shadowsocks нет метода, пароля или адреса")
    return host, port, {"protocol": "shadowsocks", "settings": {"servers": [
        {"address": host, "port": port, "method": method, "password": password}]}}


def parse(url: str) -> Link:
    url = url.strip()
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    if scheme not in PROTOCOLS:
        raise LinkError(f"ссылки {scheme or url[:12]} не поддерживаются проверкой")
    if scheme == "vmess":
        return _vmess(url)
    parts = urlsplit(url)
    q = _query(parts.query)
    remark = unquote(parts.fragment)

    if scheme == "ss":
        host, port, outbound = _shadowsocks(url, parts, q)
        return Link(url, scheme, "shadowsocks", remark, host, port, "tcp", "none", outbound)

    host, port = _host_port(parts)
    secret = unquote(parts.username or "")
    if parts.password is not None:
        secret += ":" + unquote(parts.password)
    if not secret:
        raise LinkError("в ссылке нет ключа клиента")

    if scheme in ("hysteria2", "hy2", "hysteria"):
        if scheme == "hysteria":
            raise LinkError("Hysteria v1 не поддерживается проверкой")
        stream = {"network": "hysteria", "security": "tls", "tlsSettings": _tls(q, "hysteria"),
                  "hysteriaSettings": {"version": 2, "auth": secret}}
        if q.get("obfs") == "salamander" and q.get("obfs-password"):
            stream["finalmask"] = {"udp": [{"type": "salamander", "settings": {"password": q["obfs-password"]}}]}
        elif q.get("obfs"):
            raise LinkError(f"обфускация {q['obfs']} не поддерживается проверкой")
        outbound = {"protocol": "hysteria", "settings": {"version": 2, "address": host, "port": port},
                    "streamSettings": stream}
        return Link(url, scheme, "hysteria", remark, host, port, "hysteria", "tls", outbound)

    stream = _stream(q)
    if scheme == "vless":
        user: dict[str, Any] = {"id": secret, "encryption": q.get("encryption") or "none"}
        if q.get("flow"):
            user["flow"] = q["flow"]
        settings: dict[str, Any] = {"vnext": [{"address": host, "port": port, "users": [user]}]}
    else:  # trojan
        settings = {"servers": [{"address": host, "port": port, "password": secret}]}
    return Link(url, scheme, PROTOCOLS[scheme], remark, host, port, stream["network"], stream["security"],
                {"protocol": PROTOCOLS[scheme], "settings": settings, "streamSettings": stream})
