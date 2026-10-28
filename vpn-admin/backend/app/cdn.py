"""CDN accounts: a connection for whitelisted networks goes through a CDN whose addresses mobile operators
let through, so clients never talk to the server itself.

For each server the admin gives the connection a name in the server's Cloudflare zone (cdn-<server>),
gets a Let's Encrypt certificate for it in the CDN's cloud (the domain check passes through a Cloudflare
DNS record), creates a CDN resource for that name with the node as its HTTPS origin and points the name at
the CDN with a CNAME. Clients are given the CDN's own technical address, with the name as SNI and Host.

Yandex Cloud CDN (a service account's authorized key and a folder) and VK Cloud CDN (a user's login and
password for the API, and a project). VK Cloud issues the Let's Encrypt certificate itself, for a resource
whose name already points at the CDN, so there the CNAME comes first and the certificate after it.
Beget comes later.
"""

import asyncio
import base64
import json
import os
import re
import time
from typing import Any, Awaitable, Callable, Literal

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from pydantic import BaseModel, Field

from . import db

YC_IAM_URL = os.getenv("YC_IAM_URL", "https://iam.api.cloud.yandex.net/iam/v1/tokens")
YC_CDN_URL = os.getenv("YC_CDN_URL", "https://cdn.api.cloud.yandex.net/cdn/v1")
YC_CM_URL = os.getenv("YC_CM_URL", "https://certificate-manager.api.cloud.yandex.net/certificate-manager/v1")
YC_OPERATION_URL = os.getenv("YC_OPERATION_URL", "https://operation.api.cloud.yandex.net/operations")
TIMEOUT = httpx.Timeout(30.0, connect=10.0)
POLL_EVERY = 15
CERT_TIMEOUT = 40 * 60  # Let's Encrypt through Certificate Manager: usually minutes, sometimes half an hour
RESOURCE_TIMEOUT = 20 * 60  # Yandex: "creating a resource can take up to 15 minutes"
VK_IDENTITY_URL = os.getenv("VK_IDENTITY_URL", "https://msk.cloud.vk.ru/infra/identity/v3")
VK_CDN_URL = os.getenv("VK_CDN_URL", "")  # empty: the "cdn" endpoint from the token's catalog
VK_CDN_DEFAULT = "https://msk.cloud.vk.ru/api/cdn/api/v1"
VK_CERT_WAIT = 3 * 60  # VK Cloud: "issuing can take up to 30 minutes"; it switches HTTPS on by itself

PROVIDERS = {
    "yandex": {
        "title": "Yandex Cloud CDN",
        "available": True,
        "help": "Сервисный аккаунт в каталоге с ролями cdn.editor и certificate-manager.editor → «Создать авторизованный "
                "ключ» → скачайте JSON и вставьте его целиком. ID каталога — в консоли Yandex Cloud рядом с его именем.",
        "help_url": "https://yandex.cloud/ru/docs/iam/operations/authorized-key/create",
    },
    "vk": {
        "title": "VK Cloud CDN",
        "available": True,
        "help": "Личный кабинет VK Cloud → имя пользователя → «Настройки проекта» → «Доступ по API»: включите доступ "
                "(нужна двухфакторная аутентификация) и скопируйте Project ID. Логин и пароль — те, с которыми вы входите "
                "в VK Cloud; у пользователя должна быть роль, которой разрешён CDN (например, «Администратор проекта»).",
        "help_url": "https://cloud.vk.ru/docs/tools-for-using-services/api/rest-api/enable-api",
    },
    "beget": {"title": "Beget CDN", "available": False},
}


class CDNError(Exception):
    pass


class CdnAccountIn(BaseModel):
    provider: Literal["yandex", "vk"] = "yandex"
    name: str = Field(min_length=1, max_length=100)
    folder_id: str = ""  # Yandex
    key: str = ""  # Yandex: the authorized key JSON; empty on edit = keep the stored one
    project_id: str = ""  # VK Cloud
    username: str = ""  # VK Cloud
    password: str = ""  # VK Cloud; empty on edit = keep the stored one

    def credentials(self, stored: dict[str, str] | None = None) -> dict[str, str]:
        """What the account keeps, the empty secret fields taken from `stored`."""
        stored = stored or {}
        if self.provider == "vk":
            return {"project_id": self.project_id.strip() or stored.get("project_id", ""),
                    "username": self.username.strip() or stored.get("username", ""),
                    "password": self.password or stored.get("password", "")}
        return {"folder_id": self.folder_id.strip() or stored.get("folder_id", ""),
                "key": self.key.strip() or stored.get("key", "")}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def parse_key(raw: str) -> dict[str, str]:
    """The authorized key file of a service account: {id, service_account_id, private_key, ...}."""
    try:
        key = json.loads(raw)
    except ValueError:
        raise CDNError("Ключ должен быть JSON-файлом авторизованного ключа сервисного аккаунта") from None
    if not isinstance(key, dict) or not all(key.get(k) for k in ("id", "service_account_id", "private_key")):
        raise CDNError("В JSON нет id, service_account_id или private_key: нужен авторизованный ключ, не API-ключ")
    pem = key["private_key"]
    # Yandex puts a "PLEASE DO NOT REMOVE THIS LINE!" line before the PEM block
    pem = pem[pem.find("-----BEGIN"):] if "-----BEGIN" in pem else pem
    try:
        serialization.load_pem_private_key(pem.encode(), password=None)
    except (ValueError, TypeError):
        raise CDNError("Закрытый ключ в JSON не читается") from None
    return {"id": key["id"], "service_account_id": key["service_account_id"], "private_key": pem}


_tokens: dict[str, tuple[str, float]] = {}  # key id -> IAM token, when to renew it


class YandexCloud:
    def __init__(self, credentials: dict[str, Any]):
        self.folder = (credentials.get("folder_id") or "").strip()
        if not self.folder:
            raise CDNError("Укажите ID каталога Yandex Cloud")
        self.key = parse_key(credentials.get("key") or "")
        self.http = httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent": "vpn-admin"})

    async def close(self) -> None:
        await self.http.aclose()

    def _jwt(self) -> str:
        now = int(time.time())
        header = {"typ": "JWT", "alg": "PS256", "kid": self.key["id"]}
        claims = {"iss": self.key["service_account_id"], "aud": "https://iam.api.cloud.yandex.net/iam/v1/tokens",
                  "iat": now, "exp": now + 3600}
        signing = f"{_b64url(json.dumps(header).encode())}.{_b64url(json.dumps(claims).encode())}"
        private = serialization.load_pem_private_key(self.key["private_key"].encode(), password=None)
        signature = private.sign(signing.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                                 hashes.SHA256())
        return f"{signing}.{_b64url(signature)}"

    async def _token(self) -> str:
        token, renew_at = _tokens.get(self.key["id"], ("", 0.0))
        if token and time.time() < renew_at:
            return token
        try:
            resp = await self.http.post(YC_IAM_URL, json={"jwt": self._jwt()})
        except httpx.HTTPError as exc:
            raise CDNError(f"Yandex Cloud недоступен: {exc}") from exc
        if resp.status_code >= 400:
            raise CDNError(f"Yandex Cloud не выдал IAM-токен по ключу ({self._message(resp)}): проверьте, что ключ "
                           "не удалён и сервисный аккаунт существует")
        token = resp.json().get("iamToken", "")
        _tokens[self.key["id"]] = (token, time.time() + 3000)  # IAM tokens live up to 12 h; renew hourly
        return token

    @staticmethod
    def _message(resp: httpx.Response) -> str:
        try:
            data = resp.json()
            return data.get("message") or data.get("error") or f"HTTP {resp.status_code}"
        except ValueError:
            return f"HTTP {resp.status_code}"

    async def _request(self, method: str, url: str, params: dict | None = None, json_body: dict | None = None) -> Any:
        headers = {"Authorization": f"Bearer {await self._token()}"}
        try:
            resp = await self.http.request(method, url, params=params, json=json_body, headers=headers)
        except httpx.HTTPError as exc:
            raise CDNError(f"Yandex Cloud недоступен: {exc}") from exc
        if resp.status_code == 403:
            raise CDNError(f"Yandex Cloud: у сервисного аккаунта нет прав ({self._message(resp)}). Нужны роли "
                           "cdn.editor и certificate-manager.editor на каталог")
        if resp.status_code == 404:
            raise CDNError(f"Yandex Cloud: не найдено ({self._message(resp)})")
        if resp.status_code >= 400:
            raise CDNError(f"Yandex Cloud: {self._message(resp)}")
        return resp.json() if resp.content else {}

    async def _operation(self, op: dict, timeout: int) -> dict:
        """Wait for a long-running operation; its response on success."""
        deadline = time.time() + timeout
        while not op.get("done"):
            if time.time() > deadline:
                raise CDNError(f"Yandex Cloud: операция «{op.get('description') or op.get('id')}» не закончилась "
                               f"за {timeout // 60} минут")
            await asyncio.sleep(POLL_EVERY)
            op = await self._request("GET", f"{YC_OPERATION_URL}/{op['id']}")
        if op.get("error"):
            raise CDNError(f"Yandex Cloud: {op['error'].get('message') or op['error']}")
        return op.get("response") or {}

    async def check(self) -> dict:
        resources = await self._request("GET", f"{YC_CDN_URL}/resources", params={"folderId": self.folder})
        await self._request("GET", f"{YC_CM_URL}/certificates", params={"folderId": self.folder})
        return {"folder_id": self.folder, "resources": len(resources.get("resources") or [])}

    async def request_certificate(self, domain: str) -> str:
        name = re.sub(r"[^a-z0-9-]", "-", f"vpn-{domain}".lower())[:63].rstrip("-")
        op = await self._request("POST", f"{YC_CM_URL}/certificates/requestNew", json_body={
            "folderId": self.folder, "name": name, "domains": [domain], "challengeType": "DNS",
            "description": "vpn-admin: CDN-подключение", "labels": {"vpn-admin": "cdn"}})
        cert_id = (op.get("metadata") or {}).get("certificateId")
        if not cert_id:
            cert_id = (await self._operation(op, 120)).get("id")
        if not cert_id:
            raise CDNError("Yandex Cloud не вернул ID сертификата")
        return cert_id

    async def certificate(self, cert_id: str) -> dict:
        return await self._request("GET", f"{YC_CM_URL}/certificates/{cert_id}", params={"view": "FULL"})

    async def create_resource(self, domain: str, origin: str, cert_id: str, allow_post: bool) -> str:
        """XHTTP must not be cached: the cache is off and the name the client asked for goes on to the node (its
        inbound checks Host). GET, HEAD and OPTIONS pass by default, which is all the GET uploads need; POST
        uploads need POST, which Yandex refuses at creation, so it is allowed once the resource exists."""
        op = await self._request("POST", f"{YC_CDN_URL}/resources", json_body={
            "folderId": self.folder, "cname": domain, "origin": {"originSource": origin}, "originProtocol": "HTTPS",
            "active": True,
            "options": {
                "disableCache": {"enabled": True, "value": True},
                "hostOptions": {"forwardHostHeader": {"enabled": True, "value": True}},
            },
            "sslCertificate": {"type": "CM", "data": {"cm": {"id": cert_id}}},
            "labels": {"vpn-admin": "cdn"},
        })
        resource_id = (op.get("metadata") or {}).get("resourceId")
        if not resource_id or allow_post:
            resource_id = resource_id or (await self._operation(op, RESOURCE_TIMEOUT)).get("id")
        if not resource_id:
            raise CDNError("Yandex Cloud не вернул ID CDN-ресурса")
        if allow_post:
            await self._operation(await self._request("PATCH", f"{YC_CDN_URL}/resources/{resource_id}", json_body={
                "options": {"allowedHttpMethods": {"enabled": True, "value": ["GET", "POST", "HEAD", "OPTIONS"]}},
                "updateMask": "options.allowedHttpMethods"}), RESOURCE_TIMEOUT)
        return resource_id

    async def resource(self, resource_id: str) -> dict:
        return await self._request("GET", f"{YC_CDN_URL}/resources/{resource_id}")

    async def delete_resource(self, resource_id: str) -> None:
        await self._request("DELETE", f"{YC_CDN_URL}/resources/{resource_id}")

    async def delete_certificate(self, cert_id: str) -> None:
        await self._request("DELETE", f"{YC_CM_URL}/certificates/{cert_id}")


_vk_tokens: dict[tuple[str, str], tuple[str, str, float]] = {}  # (user, project) -> token, CDN URL, renew at


class VKCloud:
    """VK Cloud CDN: a Keystone token for the user and project, then the CDN API of that project."""

    def __init__(self, credentials: dict[str, Any]):
        self.project = (credentials.get("project_id") or "").strip()
        self.username = (credentials.get("username") or "").strip()
        self.password = credentials.get("password") or ""
        if not self.project or not self.username or not self.password:
            raise CDNError("Укажите Project ID, логин и пароль VK Cloud")
        self.http = httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent": "vpn-admin"})

    async def close(self) -> None:
        await self.http.aclose()

    @staticmethod
    def _message(resp: httpx.Response) -> str:
        try:
            data = resp.json()
        except ValueError:
            return (resp.text or "").strip()[:200] or f"HTTP {resp.status_code}"
        if isinstance(data, dict):
            error = data.get("error")
            if isinstance(error, dict):
                return error.get("message") or str(error)
            for key in ("message", "detail", "errors", "error"):
                if data.get(key):
                    return str(data[key])[:300]
        return str(data)[:300] or f"HTTP {resp.status_code}"

    async def _token(self) -> tuple[str, str]:
        cached = _vk_tokens.get((self.username, self.project))
        if cached and time.time() < cached[2]:
            return cached[0], cached[1]
        body = {"auth": {
            "identity": {"methods": ["password"], "password": {"user": {
                "name": self.username, "domain": {"name": "users"}, "password": self.password}}},
            "scope": {"project": {"id": self.project}}}}
        try:
            resp = await self.http.post(f"{VK_IDENTITY_URL.rstrip('/')}/auth/tokens", json=body)
        except httpx.HTTPError as exc:
            raise CDNError(f"VK Cloud недоступен: {exc}") from exc
        if resp.status_code == 401:
            raise CDNError("VK Cloud не пустил: неверный логин или пароль, либо в проекте не включён доступ по API")
        if resp.status_code in (403, 404):
            raise CDNError(f"VK Cloud: нет доступа к проекту {self.project} ({self._message(resp)}): проверьте Project ID "
                           "на вкладке «Доступ по API»")
        if resp.status_code >= 400:
            raise CDNError(f"VK Cloud не выдал токен: {self._message(resp)}")
        token = resp.headers.get("X-Subject-Token", "")
        if not token:
            raise CDNError("VK Cloud не выдал токен")
        url = VK_CDN_URL
        if not url:
            for service in (resp.json().get("token") or {}).get("catalog") or []:
                if service.get("type") == "cdn":
                    url = next((e["url"] for e in service.get("endpoints") or []
                                if e.get("interface") == "public" and e.get("url")), "")
            url = url or VK_CDN_DEFAULT
        _vk_tokens[(self.username, self.project)] = (token, url.rstrip("/"), time.time() + 3000)  # lives ~an hour+
        return token, url.rstrip("/")

    async def _request(self, method: str, path: str, json_body: Any = None, ok_missing: bool = False) -> Any:
        token, base = await self._token()
        try:
            resp = await self.http.request(method, f"{base}/projects/{self.project}{path}", json=json_body,
                                           headers={"X-Auth-Token": token})
        except httpx.HTTPError as exc:
            raise CDNError(f"VK Cloud недоступен: {exc}") from exc
        if resp.status_code == 401:
            _vk_tokens.pop((self.username, self.project), None)
            raise CDNError("VK Cloud: токен не принят, повторите")
        if resp.status_code == 403:
            raise CDNError(f"VK Cloud: у пользователя нет прав на CDN в проекте ({self._message(resp)})")
        if resp.status_code == 404:
            if ok_missing:
                return None
            raise CDNError(f"VK Cloud: не найдено ({self._message(resp)})")
        if resp.status_code >= 400:
            raise CDNError(f"VK Cloud: {self._message(resp)}")
        try:
            return resp.json() if resp.content else {}
        except ValueError:
            return {}

    async def check(self) -> dict:
        address = await self.address()
        resources = await self._request("GET", "/resources")
        return {"project_id": self.project, "address": address,
                "resources": len(resources) if isinstance(resources, list) else len(resources.get("results") or [])}

    async def address(self) -> str:
        """The account's own CDN name, the one every resource's domain points at (cl-….cdn.msk.vkcs.cloud)."""
        cname = ((await self._request("GET", "/clients/me")) or {}).get("cname", "").rstrip(".")
        if not cname:
            raise CDNError("VK Cloud не сообщил технический адрес CDN аккаунта")
        return cname

    async def create_resource(self, domain: str, origin: str, allow_post: bool) -> str:
        """XHTTP must not be cached and must reach the node under the name the client asked for (its inbound
        checks Host); HTTPS is switched on by the Let's Encrypt certificate once it is issued."""
        methods = ["GET", "HEAD", "OPTIONS"] + (["POST"] if allow_post else [])
        resource = await self._request("POST", "/resources", json_body={
            "cname": domain, "origin": origin, "originProtocol": "HTTPS", "active": True, "secondaryHostnames": [],
            "options": {
                "edge_cache_settings": {"enabled": True, "value": "0s", "default": "0s"},
                "browser_cache_settings": {"enabled": True, "value": "0s"},
                "forward_host_header": {"enabled": True, "value": True},
                "allowedHttpMethods": {"enabled": True, "value": methods},
            },
        })
        resource_id = (resource or {}).get("id")
        if not resource_id:
            raise CDNError("VK Cloud не вернул ID CDN-ресурса")
        return str(resource_id)

    async def resource(self, resource_id: str) -> dict:
        return await self._request("GET", f"/resources/{resource_id}")

    async def issue_certificate(self, resource_id: str) -> None:
        try:
            await self._request("POST", f"/resources/{resource_id}/ssl/le/issue")
        except CDNError as exc:
            text = str(exc).lower()
            if "already" not in text:  # already issued, or the issuing already runs
                raise

    async def delete_resource(self, resource_id: str) -> None:
        resource = await self._request("GET", f"/resources/{resource_id}", ok_missing=True)
        if resource is None:
            raise CDNError("VK Cloud: не найдено")
        if resource.get("active"):  # a resource is switched off before it can be deleted
            try:
                await self._request("PUT", f"/resources/{resource_id}", json_body={
                    "active": False, "secondaryHostnames": resource.get("secondaryHostnames") or []})
            except CDNError:
                pass
        await self._request("DELETE", f"/resources/{resource_id}")

    async def delete_certificate(self, cert_id: str) -> None:
        await self._request("DELETE", f"/sslData/{cert_id}", ok_missing=True)


CLIENTS = {"yandex": YandexCloud, "vk": VKCloud}


def _client(account: db.DnsAccount):
    if account.provider not in CLIENTS:
        raise CDNError(f"{PROVIDERS.get(account.provider, {}).get('title', account.provider)} пока не поддерживается")
    return CLIENTS[account.provider](account.credentials)


async def _with(account: db.DnsAccount, action):
    client = _client(account)
    try:
        return await action(client)
    finally:
        await client.close()


def account(account_id: int) -> db.DnsAccount:
    found = db.get_cdn_account(account_id)
    if not found:
        raise CDNError("CDN-аккаунт не найден в админке")
    return found


def public(a: db.DnsAccount) -> dict:
    return {"id": a.id, "provider": a.provider, "provider_title": PROVIDERS.get(a.provider, {}).get("title", a.provider),
            "name": a.name, "folder_id": a.credentials.get("folder_id", ""),
            "project_id": a.credentials.get("project_id", ""), "username": a.credentials.get("username", ""),
            "created_at": a.created_at}


async def check(provider: str, credentials: dict) -> dict:
    client = CLIENTS[provider](credentials)
    try:
        return await client.check()
    finally:
        await client.close()


async def list_all() -> list[dict]:
    async def one(a: db.DnsAccount) -> dict:
        out = {**public(a), "ok": False, "error": "", "resources": 0}
        try:
            out["resources"] = (await _with(a, lambda c: c.check()))["resources"]
            out["ok"] = True
        except CDNError as exc:
            out["error"] = str(exc)
        return out

    return list(await asyncio.gather(*(one(a) for a in db.list_cdn_accounts())))


# ---------- one connection's CDN: resumable, its progress saved on the item after every step ----------

PutRecord = Callable[[str, str, str], Awaitable[str]]  # (type, name, content) -> Cloudflare record ID


async def set_up(account_id: int, item: dict, domain: str, origin: str, put_record: PutRecord,
                 log: Callable[[str], None], save: Callable[[], None]) -> None:
    """Certificate for `domain` (its DNS check through Cloudflare), the CDN resource with `origin` behind it,
    and the CNAME of `domain` to the CDN. Fills item: cdn_domain, cdn_address, cdn_cert_id, cdn_resource_id,
    cdn_records (Cloudflare record IDs to delete with the server)."""
    acc = account(account_id)
    if acc.provider == "vk":
        return await _set_up_vk(acc, item, domain, origin, put_record, log, save)
    title = PROVIDERS[acc.provider]["title"]
    client = _client(acc)
    records: list[str] = item.setdefault("cdn_records", [])
    try:
        item["cdn_domain"] = domain
        if not item.get("cdn_cert_id"):
            item["cdn_cert_id"] = await client.request_certificate(domain)
            save()
            log(f"{title}: запрошен сертификат Let's Encrypt на {domain}")
        deadline, checked = time.time() + CERT_TIMEOUT, False
        while True:
            cert = await client.certificate(item["cdn_cert_id"])
            status = cert.get("status", "")
            if status == "ISSUED":
                break
            if status in ("INVALID", "REVOKED", "RENEWAL_FAILED"):
                why = "; ".join(c.get("error") or c.get("message") or "" for c in cert.get("challenges") or [])
                item.pop("cdn_cert_id")  # the next attempt asks for a new one
                save()
                raise CDNError(f"{title}: сертификат на {domain} не выпущен ({status}{': ' + why if why else ''})")
            if not checked:  # put the DNS check records in once they show up
                challenges = [c["dnsChallenge"] for c in cert.get("challenges") or [] if c.get("dnsChallenge")]
                for ch in challenges:
                    record_id = await put_record(ch.get("type") or "CNAME", ch["name"].rstrip("."), ch["value"].rstrip("."))
                    if record_id not in records:
                        records.append(record_id)
                if challenges:
                    checked = True
                    save()
                    log(f"Cloudflare: запись проверки домена {challenges[0]['name'].rstrip('.')} создана, жду, пока "
                        "Let's Encrypt выпустит сертификат (обычно 5–20 минут)")
            if time.time() > deadline:
                raise CDNError(f"{title}: сертификат на {domain} не выпущен за {CERT_TIMEOUT // 60} минут — "
                               "нажмите «Раскатать подключения», чтобы подождать ещё")
            await asyncio.sleep(POLL_EVERY)
        if not item.get("cdn_resource_id"):
            log(f"{title}: сертификат выпущен, создаю CDN-ресурс {domain} → {origin} (до 15 минут)")
            item["cdn_resource_id"] = await client.create_resource(
                domain, origin, item["cdn_cert_id"], allow_post=item["options"].get("uplink") == "post-body")
            save()
        resource = await client.resource(item["cdn_resource_id"])
        address = (resource.get("providerCname") or resource.get("provider_cname") or "").rstrip(".")
        if not address:
            raise CDNError(f"{title} не сообщил технический адрес CDN-ресурса {domain}")
        record_id = await put_record("CNAME", domain, address)
        if record_id not in records:
            records.append(record_id)
        item.update(cdn_address=address, cdn_account_id=account_id)
        save()
        log(f"{title}: CDN-ресурс {domain} готов, адрес для клиентов {address}")
    finally:
        await client.close()


async def _set_up_vk(acc: db.DnsAccount, item: dict, domain: str, origin: str, put_record: PutRecord,
                     log: Callable[[str], None], save: Callable[[], None]) -> None:
    """VK Cloud: the resource, the CNAME of `domain` to the account's CDN name, then the Let's Encrypt
    certificate, which VK Cloud checks through the CDN itself and puts on the resource when it is issued."""
    title = PROVIDERS[acc.provider]["title"]
    client = _client(acc)
    records: list[str] = item.setdefault("cdn_records", [])
    try:
        item["cdn_domain"] = domain
        address = await client.address()
        if not item.get("cdn_resource_id"):
            item["cdn_resource_id"] = await client.create_resource(
                domain, origin, allow_post=item["options"].get("uplink") == "post-body")
            save()
            log(f"{title}: создан CDN-ресурс {domain} → {origin}")
        record_id = await put_record("CNAME", domain, address)
        if record_id not in records:
            records.append(record_id)
        save()
        deadline = time.time() + RESOURCE_TIMEOUT
        while (resource := await client.resource(item["cdn_resource_id"])).get("status") == "processed":
            if time.time() > deadline:
                raise CDNError(f"{title}: CDN-ресурс {domain} не готов за {RESOURCE_TIMEOUT // 60} минут — "
                               "нажмите «Раскатать подключения», чтобы подождать ещё")
            await asyncio.sleep(POLL_EVERY)
        if resource.get("status") == "suspended":
            raise CDNError(f"{title}: CDN-ресурс {domain} приостановлен — проверьте баланс и CDN в проекте VK Cloud")
        if not resource.get("sslEnabled"):
            await client.issue_certificate(item["cdn_resource_id"])
            log(f"{title}: запрошен сертификат Let's Encrypt на {domain} (VK Cloud выпускает его до 30 минут)")
            deadline = time.time() + VK_CERT_WAIT
            while not resource.get("sslEnabled") and time.time() < deadline:
                await asyncio.sleep(POLL_EVERY)
                resource = await client.resource(item["cdn_resource_id"])
        item.update(cdn_address=address, cdn_account_id=acc.id)
        save()
        if resource.get("sslEnabled"):
            log(f"{title}: CDN-ресурс {domain} готов, адрес для клиентов {address}")
        else:
            log(f"{title}: CDN-ресурс {domain} создан, адрес для клиентов {address}. Сертификат ещё выпускается: "
                "подключение заработает, когда VK Cloud включит на ресурсе HTTPS (обычно до 30 минут)")
    finally:
        await client.close()


async def tear_down(item: dict) -> list[str]:
    """Delete the connection's CDN resource and certificate; what went wrong, for the job's log."""
    problems = []
    try:
        acc = account(item.get("cdn_account_id") or item.get("options", {}).get("cdn_account_id") or 0)
    except CDNError as exc:
        return [str(exc)] if item.get("cdn_resource_id") or item.get("cdn_cert_id") else []
    for key, action in (("cdn_resource_id", "delete_resource"), ("cdn_cert_id", "delete_certificate")):
        if item.get(key):
            try:
                await _with(acc, lambda c: getattr(c, action)(item[key]))
            except CDNError as exc:
                if "не найдено" not in str(exc):
                    problems.append(str(exc))
    return problems
