"""Async client for the 3x-ui panel HTTP API.

Auth is cookie based: POST /login sets a session cookie that is reused for
/panel/api/* calls. When the session expires the panel answers with 401/404
or an HTML login page, in which case we log in again and retry once.
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


class XUIClient:
    def __init__(self, url: str, username: str, password: str, verify_tls: bool = True, timeout: float = 15.0):
        self.base_url = normalize_url(url)
        self.username = username
        self.password = password
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            verify=verify_tls,
            timeout=timeout,
            follow_redirects=False,
            headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
        )
        self._logged_in = False
        self._status_route: tuple[str, str] | None = None

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    async def close(self) -> None:
        await self._http.aclose()

    async def login(self) -> None:
        try:
            resp = await self._http.post("/login", data={"username": self.username, "password": self.password})
        except httpx.HTTPError as exc:
            raise XUIError(f"Панель недоступна: {exc.__class__.__name__}: {exc}") from exc
        data = self._parse(resp)
        if data is None:
            raise XUIError(f"Неожиданный ответ на /login (HTTP {resp.status_code}). Проверьте URL и webBasePath")
        if not data.get("success"):
            raise XUIError(f"Ошибка входа в 3x-ui: {data.get('msg') or 'неверный логин или пароль'}")
        self._logged_in = True

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
        if not self._logged_in:
            await self.login()
        for attempt in range(2):
            try:
                resp = await self._http.request(method, path, **kwargs)
            except httpx.HTTPError as exc:
                raise XUIError(f"Панель недоступна: {exc.__class__.__name__}: {exc}") from exc
            data = self._parse(resp)
            if data is None:
                if attempt == 0:
                    self._logged_in = False
                    await self.login()
                    continue
                raise XUIError(f"{method} {path}: HTTP {resp.status_code}")
            if not data.get("success", False):
                raise XUIError(f"3x-ui: {data.get('msg') or f'{method} {path} вернул ошибку'}")
            return data.get("obj")
        raise XUIError(f"{method} {path}: не удалось выполнить запрос")

    async def inbounds(self) -> list[dict]:
        return await self._call("GET", "/panel/api/inbounds/list") or []

    async def inbound(self, inbound_id: int) -> dict:
        return await self._call("GET", f"/panel/api/inbounds/get/{inbound_id}") or {}

    # Client mutations. `client_key` is how 3x-ui addresses a client in URLs:
    # UUID for vless/vmess, password for trojan, email for shadowsocks (see client_key()).

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

    async def onlines(self) -> list[str]:
        return await self._call("POST", "/panel/api/inbounds/onlines") or []

    async def settings(self) -> dict:
        return await self._call("POST", "/panel/setting/all") or {}

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


def parse_json_field(value: Any) -> dict:
    """3x-ui stores settings/streamSettings as JSON strings."""
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
