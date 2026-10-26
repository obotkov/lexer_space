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


class XUIClient:
    def __init__(self, url: str, username: str = "", password: str = "", verify_tls: bool = True,
                 api_token: str = "", timeout: float = 15.0):
        self.base_url = normalize_url(url)
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

    async def v3_reset_traffic(self, email: str) -> None:
        await self._call("POST", f"/panel/api/clients/resetTraffic/{quote(email, safe='')}")


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
