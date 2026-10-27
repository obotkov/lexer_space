"""CDN accounts: a connection for whitelisted networks goes through a CDN whose addresses mobile operators
let through, so clients never talk to the server itself.

For each server the admin gives the connection a name in the server's Cloudflare zone (cdn-<server>),
gets a Let's Encrypt certificate for it in the CDN's cloud (the domain check passes through a Cloudflare
DNS record), creates a CDN resource for that name with the node as its HTTPS origin and points the name at
the CDN with a CNAME. Clients are given the CDN's own technical address, with the name as SNI and Host.

Yandex Cloud CDN now (a service account's authorized key and a folder); VK Cloud and Beget come later.
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

PROVIDERS = {
    "yandex": {
        "title": "Yandex Cloud CDN",
        "available": True,
        "help": "Сервисный аккаунт в каталоге с ролями cdn.editor и certificate-manager.editor → «Создать авторизованный "
                "ключ» → скачайте JSON и вставьте его целиком. ID каталога — в консоли Yandex Cloud рядом с его именем.",
        "help_url": "https://yandex.cloud/ru/docs/iam/operations/authorized-key/create",
    },
    "vk": {"title": "VK Cloud CDN", "available": False},
    "beget": {"title": "Beget CDN", "available": False},
}


class CDNError(Exception):
    pass


class CdnAccountIn(BaseModel):
    provider: Literal["yandex"] = "yandex"
    name: str = Field(min_length=1, max_length=100)
    folder_id: str = ""
    key: str = ""  # the authorized key JSON; empty on edit = keep the stored one


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

    async def create_resource(self, domain: str, origin: str, cert_id: str) -> str:
        """XHTTP must not be cached: the cache is off, every method the transport uses is let through and the
        name the client asked for goes on to the node (its inbound checks Host)."""
        op = await self._request("POST", f"{YC_CDN_URL}/resources", json_body={
            "folderId": self.folder, "cname": domain, "origin": {"originSource": origin}, "originProtocol": "HTTPS",
            "active": True,
            "options": {
                "disableCache": {"enabled": True, "value": True},
                "hostOptions": {"forwardHostHeader": {"enabled": True, "value": True}},
                "allowedHttpMethods": {"enabled": True, "value": ["GET", "POST", "HEAD", "OPTIONS"]},
            },
            "sslCertificate": {"type": "CM", "data": {"cm": {"id": cert_id}}},
            "labels": {"vpn-admin": "cdn"},
        })
        resource_id = (op.get("metadata") or {}).get("resourceId")
        if not resource_id:
            resource_id = (await self._operation(op, RESOURCE_TIMEOUT)).get("id")
        if not resource_id:
            raise CDNError("Yandex Cloud не вернул ID CDN-ресурса")
        return resource_id

    async def resource(self, resource_id: str) -> dict:
        return await self._request("GET", f"{YC_CDN_URL}/resources/{resource_id}")

    async def delete_resource(self, resource_id: str) -> None:
        await self._request("DELETE", f"{YC_CDN_URL}/resources/{resource_id}")

    async def delete_certificate(self, cert_id: str) -> None:
        await self._request("DELETE", f"{YC_CM_URL}/certificates/{cert_id}")


CLIENTS = {"yandex": YandexCloud}


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
            "name": a.name, "folder_id": a.credentials.get("folder_id", ""), "created_at": a.created_at}


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
            item["cdn_resource_id"] = await client.create_resource(domain, origin, item["cdn_cert_id"])
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
