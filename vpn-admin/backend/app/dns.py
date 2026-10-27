"""Cloudflare DNS: with an API token the admin gives a new server a name in one of the account's zones.

The A record is created as soon as the server has its IP, without Cloudflare's proxy (VPN traffic and
Let's Encrypt's HTTP check must reach the server itself), follows the node to a new server on reinstall
and goes away with the server. A connection through the CDN gets a second name of its own, proxied by
Cloudflare, so its clients never see the server's IP. Tokens are stored encrypted like hosting keys.
"""

import asyncio
import os
from typing import Any

import httpx
from pydantic import BaseModel, Field

from . import db

CF_API_URL = os.getenv("CF_API_URL", "https://api.cloudflare.com/client/v4")
TIMEOUT = httpx.Timeout(20.0, connect=10.0)
TOKEN_HELP_URL = "https://dash.cloudflare.com/profile/api-tokens"
TOKEN_HELP = ("Cloudflare → My Profile → API Tokens → Create Token → шаблон «Edit zone DNS»: права Zone → DNS → Edit "
              "(и Zone → Zone → Read, он добавляется сам), в Zone Resources — нужные домены или All zones.")

# Cloudflare error codes worth explaining
CF_HINTS = {
    6003: "токен не принят: проверьте, что он скопирован целиком",
    6111: "токен не принят: проверьте, что он скопирован целиком",
    9109: "токен не принят: он недействителен или отозван",
    10000: "у токена нет прав на это действие: нужны Zone → DNS → Edit и Zone → Zone → Read",
    81057: "такая запись уже есть",
    81058: "такая запись уже есть",
}


class DNSError(Exception):
    pass


class DnsAccountIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    token: str = ""  # empty on edit = keep the stored one


class Cloudflare:
    def __init__(self, token: str):
        token = token.strip()
        if not token:
            raise DNSError("Укажите API-токен Cloudflare")
        self.http = httpx.AsyncClient(base_url=CF_API_URL, timeout=TIMEOUT,
                                      headers={"Authorization": f"Bearer {token}", "User-Agent": "vpn-admin"})

    async def close(self) -> None:
        await self.http.aclose()

    async def _request(self, method: str, path: str, params: dict | None = None, json: dict | None = None) -> Any:
        """Cloudflare answers {"success": bool, "errors": [{"code", "message"}], "result": ..., "result_info": ...}."""
        try:
            resp = await self.http.request(method, path, params=params, json=json)
        except httpx.HTTPError as exc:
            raise DNSError(f"Cloudflare недоступен: {exc}") from exc
        try:
            data = resp.json()
        except ValueError:
            raise DNSError(f"Cloudflare: HTTP {resp.status_code}") from None
        if not data.get("success") or resp.status_code >= 400:
            errors = data.get("errors") or [{}]
            code, message = errors[0].get("code"), errors[0].get("message") or f"HTTP {resp.status_code}"
            hint = CF_HINTS.get(code)
            raise DNSError(f"Cloudflare: {hint} ({message})" if hint else f"Cloudflare: {message}")
        return data

    async def zones(self) -> list[dict]:
        """Active zones the token may see, by name."""
        zones, page = [], 1
        while True:
            data = await self._request("GET", "/zones", params={"status": "active", "per_page": 50, "page": page})
            zones += [{"id": z["id"], "name": z["name"]} for z in data.get("result") or []]
            if page >= ((data.get("result_info") or {}).get("total_pages") or 1):
                return sorted(zones, key=lambda z: z["name"])
            page += 1

    async def find_a(self, zone_id: str, name: str) -> dict | None:
        data = await self._request("GET", f"/zones/{zone_id}/dns_records", params={"type": "A", "name": name})
        return next(iter(data.get("result") or []), None)

    async def upsert_a(self, zone_id: str, name: str, ip: str, proxied: bool = False) -> str:
        """Point `name` at `ip` (automatic TTL), DNS only or through Cloudflare's proxy; returns the record ID."""
        record = await self.find_a(zone_id, name)
        body = {"type": "A", "name": name, "content": ip, "ttl": 1, "proxied": proxied,
                "comment": "vpn-admin: CDN-подключение узла" if proxied else "vpn-admin: узел 3x-ui"}
        if record:
            data = await self._request("PATCH", f"/zones/{zone_id}/dns_records/{record['id']}", json=body)
        else:
            data = await self._request("POST", f"/zones/{zone_id}/dns_records", json=body)
        return data["result"]["id"]

    async def delete_record(self, zone_id: str, record_id: str) -> None:
        await self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")


async def _with_client(token: str, action):
    client = Cloudflare(token)
    try:
        return await action(client)
    finally:
        await client.close()


def _account(account_id: int) -> db.DnsAccount:
    account = db.get_dns_account(account_id)
    if not account:
        raise DNSError("Аккаунт Cloudflare не найден в админке")
    return account


def public(account: db.DnsAccount) -> dict:
    return {"id": account.id, "provider": account.provider, "name": account.name, "created_at": account.created_at}


async def check(token: str) -> list[dict]:
    """A token is good when it can list zones; a token without zones is of no use here."""
    zones = await _with_client(token, lambda c: c.zones())
    if not zones:
        raise DNSError("Cloudflare: токен не видит ни одного активного домена. Проверьте Zone Resources у токена")
    return zones


async def list_all() -> list[dict]:
    async def one(account: db.DnsAccount) -> dict:
        out = {**public(account), "ok": False, "error": "", "zones": []}
        try:
            out["zones"] = await _with_client(account.credentials.get("token", ""), lambda c: c.zones())
            out["ok"] = True
        except DNSError as exc:
            out["error"] = str(exc)
        return out

    return list(await asyncio.gather(*(one(a) for a in db.list_dns_accounts())))


async def zone_name(account_id: int, zone_id: str) -> str:
    zones = await _with_client(_account(account_id).credentials.get("token", ""), lambda c: c.zones())
    zone = next((z for z in zones if z["id"] == zone_id), None)
    if not zone:
        raise DNSError("Этот домен не найден в аккаунте Cloudflare или токен его не видит")
    return zone["name"]


async def existing_a(account_id: int, zone_id: str, name: str) -> str | None:
    """IP the name already points to, if it has an A record."""
    record = await _with_client(_account(account_id).credentials.get("token", ""),
                                lambda c: c.find_a(zone_id, name))
    return record.get("content") if record else None


async def point(account_id: int, zone_id: str, name: str, ip: str, proxied: bool = False) -> str:
    return await _with_client(_account(account_id).credentials.get("token", ""),
                              lambda c: c.upsert_a(zone_id, name, ip, proxied))


async def remove(account_id: int, zone_id: str, record_id: str) -> None:
    await _with_client(_account(account_id).credentials.get("token", ""),
                       lambda c: c.delete_record(zone_id, record_id))
