"""Async client for the 3x-ui panel HTTP API.

Two panel generations are supported:

* legacy (2.x): cookie session from POST /login; clients live inside each
  inbound and are managed through /panel/api/inbounds/*Client* routes.
* v3 (3.x): clients are first-class records (one email, many inbounds) under
  /panel/api/clients/*. Unsafe requests of a cookie session need a CSRF token
  (GET /csrf-token, sent back as X-CSRF-Token). Alternatively the panel issues
  API tokens (Settings → Security → API Token) used as `Authorization: Bearer`,
  which needs no login and no CSRF.

When a cookie session expires the panel answers with 401/404 or an HTML login
page, in which case we log in again and retry once.
"""

import json
import re
import ssl
from typing import Any
from urllib.parse import quote, urlsplit

import httpx


class XUIError(Exception):
    pass


def normalize_url(url: str) -> str:
    """Accepts what users usually paste: with webBasePath, with /panel/ suffix, with trailing slash."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    url = url.rstrip("/")
    for suffix in ("/panel/inbounds", "/panel"):
        if url.endswith(suffix):
            url = url[: -len(suffix)]
    return url.rstrip("/")


TOKEN_REJECTED = ("API-токен не принят: проверьте, что он скопирован целиком и включён в 3x-ui "
                  "(Настройки → Безопасность → API Token). Токены есть только в 3x-ui v3.0.2 и новее")
TOKEN_SCOPE = ("У API-токена недостаточно прав: создайте в 3x-ui токен с областью Admin "
               "(Monitor и Node sync не дают читать клиентов и управлять ими)")


def _local_url(url: str) -> str:
    """Older installs reached a 3x-ui on the same server via host.docker.internal; the
    container now shares the host network, where that is simply 127.0.0.1."""
    return url.replace("://host.docker.internal", "://127.0.0.1", 1)


class XUIClient:
    def __init__(self, url: str, username: str = "", password: str = "", verify_tls: bool | ssl.SSLContext = True,
                 api_token: str = "", timeout: float = 15.0):
        self.base_url = _local_url(normalize_url(url))
        self.username = username
        self.password = password
        self.api_token = api_token.strip()
        headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
        if self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        self._http = httpx.AsyncClient(base_url=self.base_url, verify=verify_tls, timeout=timeout,
                                       follow_redirects=False, headers=headers)
        # a Bearer token is stateless: nothing to log into
        self._logged_in = bool(self.api_token)
        self._csrf: str | None = None
        self._status_route: tuple[str, str] | None = None

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    @property
    def is_v3(self) -> bool:
        """Known after the first call: tokens and CSRF only exist in 3x-ui v3."""
        return bool(self.api_token) or self._csrf is not None

    @property
    def api_version(self) -> str:
        return "v3" if self.is_v3 else "legacy"

    async def close(self) -> None:
        await self._http.aclose()

    async def _fetch_csrf(self) -> None:
        try:
            resp = await self._http.get("/csrf-token")
        except httpx.HTTPError:
            self._csrf = None
            return
        data = self._parse(resp)
        token = data.get("obj") if data and data.get("success") else None
        self._csrf = token if isinstance(token, str) and token else None

    async def login(self) -> None:
        if self.api_token:
            return
        # v3 protects /login with CSRF too; legacy panels have no /csrf-token at all
        await self._fetch_csrf()
        headers = {"X-CSRF-Token": self._csrf} if self._csrf else {}
        try:
            resp = await self._http.post("/login", data={"username": self.username, "password": self.password},
                                         headers=headers)
        except httpx.HTTPError as exc:
            raise XUIError(f"Панель недоступна: {exc.__class__.__name__}: {exc}") from exc
        data = self._parse(resp)
        if data is None:
            raise XUIError(f"Неожиданный ответ на /login (HTTP {resp.status_code}). Проверьте URL и webBasePath")
        if not data.get("success"):
            raise XUIError(f"Ошибка входа в 3x-ui: {data.get('msg') or 'неверный логин или пароль'}")
        if self._csrf:
            await self._fetch_csrf()  # the session is rotated on login, and so is its token
        self._logged_in = True

    async def ensure_ready(self) -> None:
        if not self._logged_in:
            await self.login()

    @staticmethod
    def _parse(resp: httpx.Response) -> dict | None:
        if resp.status_code in (401, 404) or resp.is_redirect:
            return None
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    async def _call(self, method: str, path: str, **kwargs) -> Any:
        await self.ensure_ready()
        for attempt in range(2):
            headers = {"X-CSRF-Token": self._csrf} if self._csrf and method != "GET" else {}
            try:
                resp = await self._http.request(method, path, headers=headers, **kwargs)
            except httpx.HTTPError as exc:
                raise XUIError(f"Панель недоступна: {exc.__class__.__name__}: {exc}") from exc
            if self.api_token and resp.status_code == 401:
                raise XUIError(TOKEN_REJECTED)
            if resp.status_code == 403 and self._csrf and attempt == 0:
                await self._fetch_csrf()  # stale CSRF token
                continue
            data = self._parse(resp)
            if data is None:
                if self.api_token:
                    raise XUIError(f"{method} {path}: HTTP {resp.status_code}. Проверьте адрес панели; "
                                   "API-токены поддерживает 3x-ui v3.0.2 и новее")
                if attempt == 0:
                    self._logged_in = False
                    await self.login()
                    continue
                raise XUIError(f"{method} {path}: HTTP {resp.status_code}")
            if not data.get("success", False):
                if resp.status_code == 403 and self.api_token:
                    raise XUIError(TOKEN_SCOPE)
                raise XUIError(f"3x-ui: {data.get('msg') or f'{method} {path} вернул ошибку'}")
            return data.get("obj")
        raise XUIError(f"{method} {path}: не удалось выполнить запрос")

    # ---------- read ----------

    async def inbounds(self) -> list[dict]:
        return await self._call("GET", "/panel/api/inbounds/list") or []

    async def inbound(self, inbound_id: int) -> dict:
        return await self._call("GET", f"/panel/api/inbounds/get/{inbound_id}") or {}

    async def onlines(self) -> list[str]:
        await self.ensure_ready()
        path = "/panel/api/clients/onlines" if self.is_v3 else "/panel/api/inbounds/onlines"
        return await self._call("POST", path) or []

    async def settings(self) -> dict:
        await self.ensure_ready()
        path = "/panel/api/setting/all" if self.is_v3 else "/panel/setting/all"
        return await self._call("POST", path) or {}

    async def server_status(self) -> dict:
        # The route moved between 3x-ui versions; remember the one that works
        routes = [("GET", "/panel/api/server/status"), ("POST", "/server/status")]
        if self._status_route:
            routes.remove(self._status_route)
            routes.insert(0, self._status_route)
        error: XUIError | None = None
        for route in routes:
            try:
                status = await self._call(*route) or {}
            except XUIError as exc:
                error = exc
                continue
            self._status_route = route
            return status
        raise error

    # ---------- legacy (2.x) client mutations ----------
    # `key` is how 3x-ui addresses a client in URLs: UUID for vless/vmess,
    # password for trojan, email for shadowsocks (see client_key()).

    async def add_client(self, inbound_id: int, client: dict) -> None:
        await self._call("POST", "/panel/api/inbounds/addClient",
                         json={"id": inbound_id, "settings": json.dumps({"clients": [client]})})

    async def update_client(self, inbound_id: int, key: str, client: dict) -> None:
        await self._call("POST", f"/panel/api/inbounds/updateClient/{quote(key, safe='')}",
                         json={"id": inbound_id, "settings": json.dumps({"clients": [client]})})

    async def delete_client(self, inbound_id: int, key: str) -> None:
        await self._call("POST", f"/panel/api/inbounds/{inbound_id}/delClient/{quote(key, safe='')}")

    async def reset_client_traffic(self, inbound_id: int, email: str) -> None:
        await self._call("POST", f"/panel/api/inbounds/{inbound_id}/resetClientTraffic/{quote(email, safe='')}")

    # ---------- v3 clients: one record per email, attached to many inbounds ----------

    async def v3_clients(self) -> list[dict]:
        return await self._call("GET", "/panel/api/clients/list") or []

    async def v3_client(self, email: str) -> dict:
        """{"client": ClientRecord, "inboundIds": [...], ...}"""
        return await self._call("GET", f"/panel/api/clients/get/{quote(email, safe='')}") or {}

    async def v3_add_client(self, client: dict, inbound_ids: list[int]) -> None:
        await self._call("POST", "/panel/api/clients/add", json={"client": client, "inboundIds": inbound_ids})

    async def v3_update_client(self, email: str, client: dict) -> None:
        await self._call("POST", f"/panel/api/clients/update/{quote(email, safe='')}", json=client)

    async def v3_delete_client(self, email: str) -> None:
        await self._call("POST", f"/panel/api/clients/del/{quote(email, safe='')}")

    async def v3_client_links(self, email: str) -> list[str]:
        """Share links of the client on all its inbounds, as its subscription gives them (also without one)."""
        return await self._call("GET", f"/panel/api/clients/links/{quote(email, safe='')}") or []

    async def v3_reset_traffic(self, email: str) -> None:
        await self._call("POST", f"/panel/api/clients/resetTraffic/{quote(email, safe='')}")


    async def set_inbound_enable(self, inbound_id: int, enable: bool) -> None:
        """v3 toggles only the flag; 2.x has no such call, so the stored inbound goes back with the new flag."""
        await self.ensure_ready()
        if self.is_v3:
            await self._call("POST", f"/panel/api/inbounds/setEnable/{inbound_id}", json={"enable": enable})
            return
        inbound = await self.inbound(inbound_id)
        if not inbound:
            raise XUIError(f"Коннект #{inbound_id} не найден")
        inbound.pop("clientStats", None)  # traffic rows are not part of the inbound's settings
        await self._call("POST", f"/panel/api/inbounds/update/{inbound_id}", json={**inbound, "enable": enable})

    async def delete_inbound(self, inbound_id: int) -> None:
        await self._call("POST", f"/panel/api/inbounds/del/{inbound_id}")

    async def v3_add_inbound(self, inbound: dict) -> dict:
        return await self._call("POST", "/panel/api/inbounds/add", json=inbound) or {}

    async def v3_bulk_attach(self, emails: list[str], inbound_ids: list[int]) -> dict:
        """Attach existing clients to inbounds: the panel fills each protocol's credentials itself."""
        return await self._call("POST", "/panel/api/clients/bulkAttach",
                                json={"emails": emails, "inboundIds": inbound_ids}) or {}

    # ---------- v3 nodes: remote 3x-ui panels managed by this (main) panel ----------

    async def v3_nodes(self) -> list[dict]:
        return await self._call("GET", "/panel/api/nodes/list") or []

    async def v3_node(self, node_id: int) -> dict:
        return await self._call("GET", f"/panel/api/nodes/get/{node_id}") or {}

    async def v3_create_api_token(self, name: str, scope: str = "node-admin") -> str:
        """Mint an API token on this panel (3x-ui v3.0.2+); the plaintext is returned only once."""
        row = await self._call("POST", "/panel/api/setting/apiTokens/create",
                               json={"name": name, "scope": scope, "expiresAt": 0}) or {}
        if not row.get("token"):
            raise XUIError("3x-ui не вернула API-токен")
        return row["token"]

    async def v3_node_add(self, node: dict) -> dict:
        return await self._call("POST", "/panel/api/nodes/add", json=node) or {}

    async def v3_node_update(self, node_id: int, node: dict) -> None:
        await self._call("POST", f"/panel/api/nodes/update/{node_id}", json=node)

    async def v3_node_delete(self, node_id: int) -> None:
        await self._call("POST", f"/panel/api/nodes/del/{node_id}")

    async def v3_node_set_enable(self, node_id: int, enable: bool) -> None:
        await self._call("POST", f"/panel/api/nodes/setEnable/{node_id}", json={"enable": enable})

    async def v3_node_test(self, node: dict) -> dict:
        """Probe connection details without saving: the same heartbeat a registered node gets."""
        return await self._call("POST", "/panel/api/nodes/test", json=node) or {}

    async def v3_nodes_update_panel(self, ids: list[int]) -> list[dict]:
        """The official 3x-ui self-updater on each node (latest stable release, then a restart); the answer says
        per node whether it started: [{"id", "name", "ok", "error"}]."""
        return await self._call("POST", "/panel/api/nodes/updatePanel", json={"ids": ids, "dev": False}) or []

    async def v3_node_probe(self, node_id: int) -> dict:
        return await self._call("POST", f"/panel/api/nodes/probe/{node_id}") or {}

    async def v3_node_inbounds(self, node: dict) -> list[dict]:
        """Inbounds of a (possibly unsaved) node, for selective import."""
        return await self._call("POST", "/panel/api/nodes/inbounds", json=node) or []


# Fields of a v3 ClientRecord that the update endpoint (model.Client) accepts as-is
_V3_CLIENT_FIELDS = (
    "email", "subId", "password", "auth", "flow", "security", "clientHostRuleIds", "limitIp", "totalGB",
    "expiryTime", "enable", "tgId", "group", "comment", "reset", "resetDay", "resetWeekday", "resetMax",
    "trafficReset", "trafficResetDay", "privateKey", "publicKey", "preSharedKey", "keepAlive",
    "forwardedPorts", "secret", "adTag", "limitHwid",
)


def v3_record_to_client(record: dict) -> dict:
    """Mirrors ClientRecord.ToClient() in 3x-ui: update replaces the whole row, so send every field back."""
    client = {k: record[k] for k in _V3_CLIENT_FIELDS if k in record and record[k] is not None}
    client["id"] = record.get("uuid", "")  # in model.Client "id" is the UUID, the numeric row id is not sent
    allowed = record.get("allowedIPs")
    if isinstance(allowed, str) and allowed:
        client["allowedIPs"] = [ip.strip() for ip in allowed.split(",") if ip.strip()]
    elif isinstance(allowed, list):
        client["allowedIPs"] = allowed
    if isinstance(record.get("reverse"), dict):
        client["reverse"] = record["reverse"]
    return client


def node_view(node: dict[str, Any], latest: str | None) -> dict[str, Any]:
    """NodeView of /panel/api/nodes/list in snake_case. net_up/net_down are throughput in bytes/sec."""
    version = node.get("panelVersion") or ""
    return {
        "id": node.get("id"),
        "name": node.get("name", ""),
        "remark": node.get("remark", ""),
        "scheme": node.get("scheme", "https"),
        "address": node.get("address", ""),
        "port": node.get("port"),
        "base_path": node.get("basePath", "/"),
        "enable": bool(node.get("enable", True)),
        "status": node.get("status") or "unknown",
        "last_error": node.get("lastError") or "",
        "last_heartbeat": node.get("lastHeartbeat") or 0,
        "latency_ms": node.get("latencyMs"),
        "cpu": node.get("cpuPct"),
        "mem": node.get("memPct"),
        "uptime": node.get("uptimeSecs"),
        "xray_version": node.get("xrayVersion") or "",
        "xray_state": node.get("xrayState") or "",
        "xray_error": node.get("xrayError") or "",
        "panel_version": version,
        "update_available": bool(latest and version and version_tuple(version) < version_tuple(latest)),
        "net_up": node.get("netUp") or 0,
        "net_down": node.get("netDown") or 0,
        "inbounds": node.get("inboundCount") or 0,
        "clients": node.get("clientCount") or 0,
        "online": node.get("onlineCount") or 0,
        "allow_private_address": bool(node.get("allowPrivateAddress")),
        "tls_verify_mode": node.get("tlsVerifyMode") or "verify",
        "pinned_cert_sha256": node.get("pinnedCertSha256") or "",
        "has_api_token": bool(node.get("hasApiToken")),
        "inbound_sync_mode": node.get("inboundSyncMode") or "all",
        "inbound_tags": node.get("inboundTags") or [],
        "transitive": bool(node.get("transitive")),
    }


def version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version)[:3])


def parse_json_field(value: Any) -> dict:
    """Legacy 3x-ui returns settings/streamSettings as JSON strings, v3 as objects."""
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def client_key(protocol: str, client: dict) -> str:
    if protocol == "trojan":
        return client.get("password", "")
    if protocol == "shadowsocks":
        return client.get("email", "")
    return client.get("id", "")


def subscription_base(panel_host: str, sub_settings: dict) -> str:
    """Rebuilds the subscription URL prefix the same way the 3x-ui web UI does."""
    if not sub_settings or not sub_settings.get("subEnable"):
        return ""
    uri = (sub_settings.get("subURI") or "").strip()
    if uri:
        return uri if uri.endswith("/") else uri + "/"
    tls = bool(sub_settings.get("subCertFile")) or bool(sub_settings.get("subKeyFile"))
    scheme = "https" if tls else "http"
    domain = (sub_settings.get("subDomain") or "").strip() or panel_host
    port = int(sub_settings.get("subPort") or 0)
    default_port = 443 if tls else 80
    host = domain if not port or port == default_port else f"{domain}:{port}"
    path = sub_settings.get("subPath") or "/sub/"
    if not path.startswith("/"):
        path = "/" + path
    if not path.endswith("/"):
        path += "/"
    return f"{scheme}://{host}{path}"
