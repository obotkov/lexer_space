"""VPN API Hoster: hosting accounts (DigitalOcean, OVHcloud) whose APIs can list and,
later, create servers for new VPN nodes.

Each provider declares the credential fields it needs (rendered by the UI as a form),
checks the keys by reading the account, and lists the servers of the account in one
normalized shape. Secrets are stored encrypted in the hosters table.
"""

import asyncio
import hashlib
import json
import os
import re
import time
from typing import Any

import httpx
from pydantic import BaseModel, Field

from . import db

CACHE_TTL = 60
TIMEOUT = 15

# Overridable for tests against a local mock of the provider APIs
DO_API_URL = os.getenv("DO_API_URL", "https://api.digitalocean.com/v2")
OVH_ENDPOINTS = {
    "ovh-eu": os.getenv("OVH_EU_API_URL", "https://eu.api.ovh.com/1.0"),
    "ovh-ca": os.getenv("OVH_CA_API_URL", "https://ca.api.ovh.com/1.0"),
    "ovh-us": os.getenv("OVH_US_API_URL", "https://api.us.ovhcloud.com/1.0"),
}


class HosterError(Exception):
    def __init__(self, message: str, code: str = ""):
        super().__init__(message)
        self.code = code


class HosterIn(BaseModel):
    provider: str
    name: str = Field(min_length=1, max_length=100)
    credentials: dict[str, str] = {}  # secret fields left empty on edit keep the stored value


class HosterTestIn(HosterIn):
    name: str = ""
    hoster_id: int | None = None


# ---------- providers ----------

PROVIDERS: dict[str, dict[str, Any]] = {
    "digitalocean": {
        "title": "DigitalOcean",
        "site": "https://www.digitalocean.com",
        "fields": [
            {"key": "token", "label": "Personal Access Token", "secret": True, "placeholder": "dop_v1_…"},
        ],
        "help": "Control Panel → API → Tokens → Generate New Token. Для просмотра достаточно Read, "
                "для создания серверов нужен Full Access (или права droplet, ssh_key, account, regions, sizes).",
        "help_url": "https://cloud.digitalocean.com/account/api/tokens",
    },
    "ovh": {
        "title": "OVHcloud",
        "site": "https://www.ovhcloud.com",
        "fields": [
            {"key": "endpoint", "label": "Регион API", "options": [
                {"value": "ovh-eu", "label": "OVHcloud Europe (eu.api.ovh.com)"},
                {"value": "ovh-ca", "label": "OVHcloud Canada и остальной мир (ca.api.ovh.com)"},
                {"value": "ovh-us", "label": "OVHcloud US (api.us.ovhcloud.com)"},
            ], "default": "ovh-eu"},
            {"key": "application_key", "label": "Application Key", "secret": False},
            {"key": "application_secret", "label": "Application Secret", "secret": True},
            {"key": "consumer_key", "label": "Consumer Key", "secret": True},
        ],
        "help": "Регион API зависит от того, где зарегистрирован аккаунт OVHcloud: Европа — eu, США — us, "
                "Канада и остальные страны — ca. Все три ключа выдаёт страница createToken этого региона "
                "(ссылка ниже, уже с правами GET/POST/PUT/DELETE на /*). Срок действия выберите Unlimited.",
        "help_url": "https://eu.api.ovh.com/createToken/?GET=/*&POST=/*&PUT=/*&DELETE=/*",
        "help_urls": {
            "ovh-eu": "https://eu.api.ovh.com/createToken/?GET=/*&POST=/*&PUT=/*&DELETE=/*",
            "ovh-ca": "https://ca.api.ovh.com/createToken/?GET=/*&POST=/*&PUT=/*&DELETE=/*",
            "ovh-us": "https://api.us.ovhcloud.com/createToken/?GET=/*&POST=/*&PUT=/*&DELETE=/*",
        },
    },
}


def _server(*, id: Any, name: str, status: str, status_label: str, region: str, plan: str, ipv4: list[str],
            ipv6: list[str], created_at: str = "", kind: str = "", specs: str = "", price: str = "") -> dict:
    return {"id": str(id), "name": name, "status": status, "status_label": status_label, "region": region,
            "plan": plan, "specs": specs, "price": price, "ipv4": ipv4, "ipv6": ipv6, "created_at": created_at,
            "kind": kind}


# OVH answers {"class": "Client::Forbidden", "message": "..."}: the message is all there is to go by
OVH_ERROR_HINTS = [
    ("application key is invalid", "INVALID_KEY", "Application Key не найден на этом API"),
    ("invalid signature", "INVALID_SIGNATURE", "подпись не сошлась: проверьте Application Secret и Consumer Key"),
    ("credential does not exist", "NOT_CREDENTIAL", "Consumer Key не найден"),
    ("credential is not valid", "INVALID_CREDENTIAL",
     "Consumer Key недействителен: истёк срок или его не подтвердили входом в аккаунт OVHcloud"),
    ("has not been granted", "NOT_GRANTED_CALL", "у Consumer Key нет прав на этот запрос. Создайте новый ключ по "
     "ссылке «Получить ключ»: она запрашивает права GET/POST/PUT/DELETE на /*"),
    ("query out of time", "QUERY_TIME_OUT", "время на сервере админки сильно расходится с OVHcloud"),
]


def _http_error(resp: httpx.Response, provider: str) -> HosterError:
    try:
        data = resp.json()
        detail = data.get("message") or data.get("error") or data.get("id") or ""
        for needle, code, hint in OVH_ERROR_HINTS:
            if needle in detail.lower() or data.get("errorCode") == code:
                return HosterError(f"{provider}: {hint} ({detail})", code)
    except (ValueError, AttributeError):
        detail = resp.text[:200]
    if resp.status_code == 401:
        return HosterError(f"{provider}: ключ не принят (401){': ' + detail if detail else ''}")
    if resp.status_code == 403:
        return HosterError(f"{provider}: у ключа нет прав на это действие (403){': ' + detail if detail else ''}")
    return HosterError(f"{provider}: HTTP {resp.status_code}{': ' + detail if detail else ''}")


class DigitalOcean:
    title = "DigitalOcean"
    image = "ubuntu-24-04-x64"

    def __init__(self, credentials: dict[str, str]):
        token = credentials.get("token", "").strip()
        if not token:
            raise HosterError("Укажите токен DigitalOcean")
        self.http = httpx.AsyncClient(base_url=DO_API_URL, timeout=TIMEOUT,
                                      headers={"Authorization": f"Bearer {token}", "User-Agent": "vpn-admin"})

    async def close(self) -> None:
        await self.http.aclose()

    async def _request(self, method: str, path: str, params: dict | None = None, json: dict | None = None) -> dict:
        try:
            resp = await self.http.request(method, path, params=params, json=json)
        except httpx.HTTPError as exc:
            raise HosterError(f"DigitalOcean недоступен: {exc}") from exc
        if resp.status_code >= 400:
            raise _http_error(resp, self.title)
        return resp.json() if resp.content else {}

    async def _get(self, path: str, **params) -> dict:
        return await self._request("GET", path, params=params or None)

    async def account(self) -> dict:
        acc = (await self._get("/account")).get("account") or {}
        out = {"login": acc.get("email", ""), "name": (acc.get("team") or {}).get("name", ""),
               "status": acc.get("status", ""), "balance": None,
               "limits": f"лимит дроплетов: {acc['droplet_limit']}" if acc.get("droplet_limit") else ""}
        try:  # needs the billing:read scope on custom-scoped tokens
            bal = await self._get("/customers/my/balance")
            out["balance"] = f"${bal.get('month_to_date_balance', '0')} за месяц"
        except HosterError:
            pass
        return out

    @staticmethod
    def _droplet(d: dict) -> dict:
        status_map = {"active": "running", "off": "stopped", "archive": "stopped", "new": "pending"}
        labels = {"active": "Работает", "off": "Выключен", "archive": "В архиве", "new": "Создаётся"}
        nets = d.get("networks") or {}
        size = d.get("size") or {}
        return _server(
            id=d.get("id"), name=d.get("name", ""), kind="Droplet",
            status=status_map.get(d.get("status"), "unknown"), status_label=labels.get(d.get("status"), d.get("status", "")),
            region=(d.get("region") or {}).get("name") or (d.get("region") or {}).get("slug", ""),
            plan=d.get("size_slug", ""),
            specs=f"{d.get('vcpus', '?')} vCPU · {round((d.get('memory') or 0) / 1024, 1):g} GB · {d.get('disk', '?')} GB",
            price=f"${size['price_monthly']}/мес" if size.get("price_monthly") else "",
            ipv4=[n["ip_address"] for n in nets.get("v4") or [] if n.get("type") == "public"],
            ipv6=[n["ip_address"] for n in nets.get("v6") or [] if n.get("type") == "public"],
            created_at=d.get("created_at", ""),
        )

    async def _all(self, path: str, key: str) -> list[dict]:
        items, page = [], 1
        while True:
            data = await self._get(path, per_page=200, page=page)
            items += data.get(key) or []
            if not ((data.get("links") or {}).get("pages") or {}).get("next"):
                return items
            page += 1

    async def servers(self) -> list[dict]:
        return [self._droplet(d) for d in await self._all("/droplets", "droplets")]

    async def create_options(self, project: str | None = None) -> dict:
        regions, sizes, keys = await asyncio.gather(
            self._all("/regions", "regions"), self._all("/sizes", "sizes"), self._all("/account/keys", "ssh_keys"))
        plans = sorted((s for s in sizes if s.get("available")), key=lambda s: (s.get("price_monthly") or 0, s["slug"]))
        return {
            "projects": None, "project": None, "ssh_multiple": True,
            "regions": [{"id": r["slug"], "name": f"{r.get('name', r['slug'])} ({r['slug']})"}
                        for r in regions if r.get("available")],
            "plans": [{"id": s["slug"], "label": s["slug"],
                       "specs": f"{s.get('vcpus')} vCPU · {round((s.get('memory') or 0) / 1024, 1):g} GB · {s.get('disk')} GB"
                                + (f" · {s['transfer']:g} TB трафика" if s.get("transfer") else ""),
                       "price": f"${s['price_monthly']:g}/мес" if s.get("price_monthly") else "",
                       "regions": s.get("regions") or []} for s in plans],
            "ssh_keys": [{"id": str(k["id"]), "name": k.get("name") or k.get("fingerprint", "")} for k in keys],
        }

    async def create_server(self, *, name: str, region: str, plan: str, ssh_keys: list[str], user_data: str,
                            project: str | None = None) -> str:
        data = await self._request("POST", "/droplets", json={
            "name": name, "region": region, "size": plan, "image": self.image, "ipv6": True, "monitoring": True,
            "ssh_keys": [int(k) if k.isdigit() else k for k in ssh_keys], "user_data": user_data,
            "tags": ["vpn-admin"],
        })
        return str((data.get("droplet") or {})["id"])

    async def get_server(self, server_id: str, project: str | None = None) -> dict:
        return self._droplet((await self._get(f"/droplets/{server_id}")).get("droplet") or {})

    async def delete_server(self, server_id: str, project: str | None = None) -> None:
        await self._request("DELETE", f"/droplets/{server_id}")


class OVHcloud:
    """Classic OVH API keys: every call is signed with the application secret and consumer key.
    New servers are Public Cloud instances (hourly billing); classic VPS can only be ordered, not created."""
    title = "OVHcloud"
    images = ("Ubuntu 24.04", "Ubuntu 22.04")
    instance_labels = {"ACTIVE": "Работает", "SHUTOFF": "Выключен", "BUILD": "Создаётся", "REBOOT": "Перезагрузка",
                       "HARD_REBOOT": "Перезагрузка", "RESCUE": "Rescue", "ERROR": "Ошибка", "SHELVED": "Отложен",
                       "SHELVED_OFFLOADED": "Отложен", "STOPPED": "Выключен", "SUSPENDED": "Приостановлен"}

    def __init__(self, credentials: dict[str, str]):
        endpoint = credentials.get("endpoint") or "ovh-eu"
        if endpoint not in OVH_ENDPOINTS:
            raise HosterError(f"Неизвестный регион API OVHcloud: {endpoint}")
        self.endpoint = endpoint
        self.base = OVH_ENDPOINTS[endpoint]
        self.app_key = credentials.get("application_key", "").strip()
        self.app_secret = credentials.get("application_secret", "").strip()
        self.consumer_key = credentials.get("consumer_key", "").strip()
        if not (self.app_key and self.app_secret and self.consumer_key):
            raise HosterError("Укажите Application Key, Application Secret и Consumer Key OVHcloud")
        self.http = httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent": "vpn-admin"})
        self._time_delta: int | None = None

    async def close(self) -> None:
        await self.http.aclose()

    async def _send(self, method: str, url: str, headers: dict | None = None, content: str = "") -> httpx.Response:
        try:
            return await self.http.request(method, url, headers=headers, content=content or None)
        except httpx.HTTPError as exc:
            raise HosterError(f"OVHcloud недоступен: {exc}") from exc

    async def _timestamp(self) -> int:
        # signatures carry the API server's clock, so local clock skew does not break them
        if self._time_delta is None:
            resp = await self._send("GET", f"{self.base}/auth/time")
            if resp.status_code >= 400:
                raise _http_error(resp, self.title)
            self._time_delta = int(resp.text) - int(time.time())
        return int(time.time()) + self._time_delta

    async def _request(self, method: str, path: str, body: dict | None = None) -> Any:
        url = f"{self.base}{path}"
        content = json.dumps(body, separators=(",", ":")) if body is not None else ""
        ts = str(await self._timestamp())
        signature = "$1$" + hashlib.sha1(
            "+".join([self.app_secret, self.consumer_key, method, url, content, ts]).encode()).hexdigest()
        headers = {"X-Ovh-Application": self.app_key, "X-Ovh-Consumer": self.consumer_key,
                   "X-Ovh-Timestamp": ts, "X-Ovh-Signature": signature}
        if content:
            headers["Content-Type"] = "application/json"
        resp = await self._send(method, url, headers=headers, content=content)
        if resp.status_code >= 400:
            error = _http_error(resp, self.title)
            if error.code == "INVALID_KEY":
                raise await self._wrong_endpoint(error)
            raise error
        return resp.json() if resp.content else None

    async def _wrong_endpoint(self, error: HosterError) -> HosterError:
        """An application key exists on one API only (EU, CA or US). Find which one knows it:
        there the same call fails on the signature or credential instead of on the key."""
        for endpoint, base in OVH_ENDPOINTS.items():
            if endpoint == self.endpoint:
                continue
            try:
                ts = (await self.http.get(f"{base}/auth/time")).text.strip()
                resp = await self.http.get(f"{base}/me", headers={
                    "X-Ovh-Application": self.app_key, "X-Ovh-Consumer": "0" * 32, "X-Ovh-Timestamp": ts,
                    "X-Ovh-Signature": "$1$" + "0" * 40})
            except httpx.HTTPError:
                continue
            if "application key is invalid" not in resp.text.lower():
                label = next(o["label"] for o in PROVIDERS["ovh"]["fields"][0]["options"] if o["value"] == endpoint)
                return HosterError(f"OVHcloud: этот Application Key создан на другом API. Выберите в поле "
                                   f"«Регион API» вариант «{label}»", "WRONG_ENDPOINT")
        return HosterError(f"{error}. Проверьте, что ключ скопирован целиком и выбран регион API, "
                           "на странице которого он создан", error.code)

    async def _get(self, path: str) -> Any:
        return await self._request("GET", path)

    # (method, sample path, what to show) for every call the admin makes; a consumer key carries
    # rules like "GET /cloud/*", so a key made with narrow rights fails in the middle of the work
    REQUIRED_CALLS = [
        ("GET", "/cloud/project/p/instance", "GET /cloud/*"),
        ("POST", "/cloud/project/p/instance", "POST /cloud/*"),
        ("DELETE", "/cloud/project/p/instance/i", "DELETE /cloud/*"),
    ]

    @staticmethod
    def _granted(rules: list[dict], method: str, path: str) -> bool:
        return any(r.get("method") == method and re.fullmatch(re.escape(r.get("path", "")).replace(r"\*", ".*"), path)
                   for r in rules)

    async def account(self) -> dict:
        cred = await self._get("/auth/currentCredential")
        if cred.get("status") not in (None, "validated"):
            raise HosterError(f"OVHcloud: Consumer Key не подтверждён (статус {cred.get('status')}): откройте ссылку "
                              "подтверждения и войдите в аккаунт OVHcloud, или создайте ключ заново")
        rules = cred.get("rules") or []
        missing = [label for method, path, label in self.REQUIRED_CALLS if not self._granted(rules, method, path)]
        if missing:
            granted = ", ".join(f"{r.get('method')} {r.get('path')}" for r in rules) or "никаких"
            raise HosterError(f"OVHcloud: у Consumer Key не хватает прав: {', '.join(missing)} (сейчас: {granted}). "
                              "Создайте новый ключ по ссылке «Получить ключ»: она запрашивает права "
                              "GET/POST/PUT/DELETE на /*", "NOT_GRANTED_CALL")
        try:  # account details are nice to have, not required
            me = await self._get("/me")
        except HosterError as exc:
            if exc.code != "NOT_GRANTED_CALL":
                raise
            me = {}
        name = " ".join(x for x in (me.get("firstname"), me.get("name")) if x) or me.get("organisation", "")
        expires = (cred.get("expiration") or "")[:10]
        rights = "права ключа: " + ", ".join(f"{r.get('method')} {r.get('path')}" for r in rules)
        return {"login": me.get("nichandle", ""), "name": name if me else "без доступа к данным аккаунта (/me)",
                "status": me.get("state", ""), "balance": None,
                "limits": " · ".join(x for x in (me.get("email", ""), me.get("country", ""),
                                                 "" if me else rights, f"ключ до {expires}" if expires else "") if x)}

    async def servers(self) -> list[dict]:
        vps, cloud = await asyncio.gather(self._vps(), self._cloud(), return_exceptions=True)
        if isinstance(vps, Exception) and isinstance(cloud, Exception):
            raise vps if isinstance(vps, HosterError) else HosterError(str(vps))
        return [*(vps if isinstance(vps, list) else []), *(cloud if isinstance(cloud, list) else [])]

    async def _vps(self) -> list[dict]:
        names = await self._get("/vps")
        labels = {"running": "Работает", "stopped": "Выключен", "installing": "Установка", "rebooting": "Перезагрузка",
                  "upgrading": "Обновление", "maintenance": "Обслуживание", "rescued": "Rescue"}

        async def one(name: str) -> dict:
            info, ips = await asyncio.gather(self._get(f"/vps/{name}"), self._get(f"/vps/{name}/ips"))
            model = info.get("model") or {}
            state = info.get("state", "")
            return _server(
                id=name, name=info.get("displayName") or name, kind="VPS",
                status={"running": "running", "stopped": "stopped"}.get(state, "pending" if state in labels else "unknown"),
                status_label=labels.get(state, state), region=info.get("zone", ""),
                plan=model.get("name") or model.get("offer", ""),
                specs=f"{info.get('vcore') or model.get('vcore', '?')} vCPU · {round((info.get('memoryLimit') or model.get('memory') or 0) / 1024, 1):g} GB"
                      f" · {model.get('disk', '?')} GB",
                ipv4=[ip for ip in ips if ":" not in ip], ipv6=[ip for ip in ips if ":" in ip],
            )

        return list(await asyncio.gather(*(one(n) for n in names)))

    def _instance(self, i: dict) -> dict:
        status = i.get("status", "")
        addrs = [a for a in i.get("ipAddresses") or [] if a.get("type") == "public"]
        return _server(
            id=i.get("id"), name=i.get("name", ""), kind="Public Cloud",
            status="running" if status == "ACTIVE" else "error" if status == "ERROR"
            else "stopped" if status in ("SHUTOFF", "STOPPED", "SHELVED", "SHELVED_OFFLOADED", "SUSPENDED") else "pending",
            status_label=self.instance_labels.get(status, status), region=i.get("region", ""),
            plan=(i.get("planCode") or "").split(".")[0], created_at=i.get("created", ""),
            ipv4=[a["ip"] for a in addrs if a.get("version") == 4],
            ipv6=[a["ip"] for a in addrs if a.get("version") == 6],
        )

    async def _cloud(self) -> list[dict]:
        projects = await self._get("/cloud/project")

        async def project(pid: str) -> list[dict]:
            return [self._instance(i) for i in await self._get(f"/cloud/project/{pid}/instance")]

        return [s for chunk in await asyncio.gather(*(project(p) for p in projects)) for s in chunk]

    async def create_options(self, project: str | None = None) -> dict:
        ids = await self._get("/cloud/project")
        if not ids:
            raise HosterError("В аккаунте OVHcloud нет проектов Public Cloud: создайте проект в панели OVHcloud "
                              "(Public Cloud → Create project), серверы создаются в нём")
        infos = await asyncio.gather(*(self._get(f"/cloud/project/{p}") for p in ids))
        projects = [{"id": p, "name": info.get("description") or p} for p, info in zip(ids, infos)]
        project = project if project in ids else ids[0]
        regions, flavors, keys = await asyncio.gather(
            self._get(f"/cloud/project/{project}/region"), self._get(f"/cloud/project/{project}/flavor"),
            self._get(f"/cloud/project/{project}/sshkey"))
        plans: dict[str, dict] = {}
        for f in flavors:
            if f.get("osType") not in (None, "linux") or not f.get("available", True):
                continue
            plan = plans.setdefault(f["name"], {
                "id": f["name"], "label": f["name"], "price": "почасовая оплата", "regions": [],
                "specs": f"{f.get('vcpus')} vCPU · {round((f.get('ram') or 0) / 1024, 1):g} GB · {f.get('disk')} GB",
                "_size": (f.get("vcpus") or 0, f.get("ram") or 0)})
            plan["regions"].append(f.get("region"))
        ordered = sorted(plans.values(), key=lambda p: (p["_size"], p["id"]))  # smallest first
        for plan in ordered:
            del plan["_size"]
        return {
            "projects": projects, "project": project, "ssh_multiple": False,
            "regions": [{"id": r, "name": r} for r in sorted(regions)],
            "plans": ordered,
            "ssh_keys": [{"id": k["id"], "name": k.get("name") or k["id"]} for k in keys],
        }

    async def create_server(self, *, name: str, region: str, plan: str, ssh_keys: list[str], user_data: str,
                            project: str | None = None) -> str:
        if not project:
            raise HosterError("Не выбран проект Public Cloud OVHcloud")
        flavors, images = await asyncio.gather(
            self._get(f"/cloud/project/{project}/flavor?region={region}"),
            self._get(f"/cloud/project/{project}/image?osType=linux&region={region}"))
        flavor = next((f for f in flavors if f.get("name") == plan and f.get("region") == region), None)
        if not flavor:
            raise HosterError(f"Тариф {plan} недоступен в регионе {region}")
        image = next((i for want in self.images for i in images if i.get("name") == want), None)
        if not image:
            raise HosterError(f"В регионе {region} нет образа Ubuntu 24.04 / 22.04")
        body = {"name": name, "region": region, "flavorId": flavor["id"], "imageId": image["id"],
                "userData": user_data, "monthlyBilling": False}
        if ssh_keys:
            body["sshKeyId"] = ssh_keys[0]  # OVH takes a single key per instance
        return str((await self._request("POST", f"/cloud/project/{project}/instance", body))["id"])

    async def get_server(self, server_id: str, project: str | None = None) -> dict:
        return self._instance(await self._get(f"/cloud/project/{project}/instance/{server_id}"))

    async def delete_server(self, server_id: str, project: str | None = None) -> None:
        await self._request("DELETE", f"/cloud/project/{project}/instance/{server_id}")


CLIENTS = {"digitalocean": DigitalOcean, "ovh": OVHcloud}


# ---------- accounts ----------

def _check_provider(provider: str) -> dict:
    if provider not in PROVIDERS:
        raise HosterError(f"Неизвестный хостинг: {provider}")
    return PROVIDERS[provider]


def merge_credentials(provider: str, sent: dict[str, str], stored: dict[str, str] | None) -> dict[str, str]:
    """Keep only the provider's fields; an empty secret on edit means "keep the stored one"."""
    out = {}
    for field in _check_provider(provider)["fields"]:
        value = (sent.get(field["key"]) or "").strip()
        if not value and stored:
            value = stored.get(field["key"], "")
        out[field["key"]] = value or field.get("default", "")
    return out


def public(hoster: db.Hoster) -> dict:
    """Account without secrets: non-secret fields as is, secret ones only as "set" flags."""
    fields = PROVIDERS.get(hoster.provider, {}).get("fields", [])
    return {
        "id": hoster.id, "provider": hoster.provider, "name": hoster.name, "created_at": hoster.created_at,
        "credentials": {f["key"]: hoster.credentials.get(f["key"], "") for f in fields if not f.get("secret")},
        "secrets_set": [f["key"] for f in fields if f.get("secret") and hoster.credentials.get(f["key"])],
    }


def client_for(hoster: db.Hoster):
    _check_provider(hoster.provider)
    return CLIENTS[hoster.provider](hoster.credentials)


async def create_options(hoster: db.Hoster, project: str | None = None) -> dict:
    client = client_for(hoster)
    try:
        return await client.create_options(project)
    finally:
        await client.close()


async def check(provider: str, credentials: dict[str, str]) -> dict:
    _check_provider(provider)
    client = CLIENTS[provider](credentials)
    try:
        return await client.account()
    finally:
        await client.close()


_cache: dict[int, tuple[float, dict]] = {}


def invalidate(hoster_id: int | None = None) -> None:
    if hoster_id is None:
        _cache.clear()
    else:
        _cache.pop(hoster_id, None)


async def _load(hoster: db.Hoster) -> dict:
    out = {**public(hoster), "ok": False, "error": None, "account": None, "servers": [], "servers_error": None}
    try:
        client = CLIENTS[hoster.provider](hoster.credentials)
    except (HosterError, KeyError) as exc:
        out["error"] = str(exc)
        return out
    try:
        account, servers = await asyncio.gather(client.account(), client.servers(), return_exceptions=True)
    finally:
        await client.close()
    # one broken account must not break the page: any failure becomes its error text
    if isinstance(account, Exception):
        out["error"] = str(account) or type(account).__name__
        return out
    out["ok"], out["account"] = True, account
    if isinstance(servers, Exception):
        out["servers_error"] = str(servers) or type(servers).__name__
    else:
        out["servers"] = servers
    return out


async def list_all(refresh: bool = False) -> list[dict]:
    async def one(hoster: db.Hoster) -> dict:
        cached = _cache.get(hoster.id)
        if not refresh and cached and time.time() - cached[0] < CACHE_TTL:
            return cached[1]
        data = await _load(hoster)
        _cache[hoster.id] = (time.time(), data)
        return data

    return list(await asyncio.gather(*(one(h) for h in db.list_hosters())))
