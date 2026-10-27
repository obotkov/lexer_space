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
HOURS_PER_MONTH = 730  # how hosting companies turn an hourly rate into a month
CATALOG_TTL = 6 * 3600
TIMEOUT = 15

# Overridable for tests against a local mock of the provider APIs
DO_API_URL = os.getenv("DO_API_URL", "https://api.digitalocean.com/v2")
OVH_ENDPOINTS = {
    "ovh-eu": os.getenv("OVH_EU_API_URL", "https://eu.api.ovh.com/1.0"),
    "ovh-ca": os.getenv("OVH_CA_API_URL", "https://ca.api.ovh.com/1.0"),
    "ovh-us": os.getenv("OVH_US_API_URL", "https://api.us.ovhcloud.com/1.0"),
}
# VDSina keeps separate accounts on its international and Russian sites, priced in different currencies
VDSINA_ENDPOINTS = {
    "vdsina-com": (os.getenv("VDSINA_COM_API_URL", "https://userapi.vdsina.com/v1"), "USD"),
    "vdsina-ru": (os.getenv("VDSINA_RU_API_URL", "https://userapi.vdsina.ru/v1"), "RUB"),
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
    "vdsina": {
        "title": "VDSina",
        "site": "https://www.vdsina.com",
        "fields": [
            {"key": "endpoint", "label": "Сайт аккаунта", "options": [
                {"value": "vdsina-com", "label": "vdsina.com — цены в долларах"},
                {"value": "vdsina-ru", "label": "vdsina.ru — цены в рублях"},
            ], "default": "vdsina-com"},
            {"key": "token", "label": "API-токен", "secret": True},
        ],
        "help": "Токен — в панели VDSina, в данных пользователя аккаунта (раздел про API). Он меняется при смене "
                "пароля. Сайт выберите тот, где зарегистрирован аккаунт: у vdsina.com и vdsina.ru отдельные аккаунты.",
        "help_url": "https://www.vdsina.com/tech/api",
        "help_urls": {"vdsina-com": "https://www.vdsina.com/tech/api", "vdsina-ru": "https://www.vdsina.ru/tech/api"},
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
    ("project discovery forbidden", "DISCOVERY_PROJECT", None),  # text: OVH_DISCOVERY_HINT
]


OVH_DISCOVERY_HINT = (
    "проект Public Cloud в режиме Discovery (пробный, без способа оплаты): в нём нельзя создавать серверы. "
    "Активируйте проект в панели OVHcloud: Public Cloud → проект → «Activate project» (понадобится способ оплаты), "
    "затем нажмите «Повторить»")


def _http_error(resp: httpx.Response, provider: str) -> HosterError:
    try:
        data = resp.json()
        detail = data.get("message") or data.get("error") or data.get("id") or ""
        for needle, code, hint in OVH_ERROR_HINTS:
            if needle in detail.lower() or data.get("errorCode") == code:
                return HosterError(f"{provider}: {hint or OVH_DISCOVERY_HINT} ({detail})", code)
    except (ValueError, AttributeError):
        detail = resp.text[:200]
    if resp.status_code == 401:
        return HosterError(f"{provider}: ключ не принят (401){': ' + detail if detail else ''}")
    if resp.status_code == 403:
        return HosterError(f"{provider}: у ключа нет прав на это действие (403){': ' + detail if detail else ''}")
    return HosterError(f"{provider}: HTTP {resp.status_code}{': ' + detail if detail else ''}")


# ---------- where a region is: hosting codes -> flag, country, city ----------

COUNTRIES = {"FR": "Франция", "DE": "Германия", "GB": "Великобритания", "PL": "Польша", "IT": "Италия",
             "NL": "Нидерланды", "CA": "Канада", "US": "США", "SG": "Сингапур", "AU": "Австралия", "IN": "Индия",
             "RU": "Россия", "KZ": "Казахстан", "TR": "Турция", "FI": "Финляндия", "SE": "Швеция", "CH": "Швейцария",
             "ES": "Испания", "LV": "Латвия", "LT": "Литва", "EE": "Эстония", "BG": "Болгария", "MD": "Молдова",
             "RS": "Сербия", "GE": "Грузия", "AM": "Армения", "AE": "ОАЭ", "HK": "Гонконг", "JP": "Япония"}

# OVHcloud Public Cloud: new names (EU-WEST-PAR, AP-SOUTH-MUM-1) first, then the classic ones (GRA11, DE1)
OVH_PLACES = [
    ("EU-WEST-PAR", "FR", "Париж"), ("EU-WEST-GRA", "FR", "Гравлин"), ("EU-WEST-SBG", "FR", "Страсбург"),
    ("EU-WEST-RBX", "FR", "Рубе"), ("EU-WEST-LIM", "DE", "Лимбург"), ("EU-WEST-ERI", "GB", "Лондон"),
    ("EU-CENTRAL-WAW", "PL", "Варшава"), ("EU-SOUTH-MIL", "IT", "Милан"), ("AP-SOUTH-MUM", "IN", "Мумбаи"),
    ("AP-SOUTHEAST-SGP", "SG", "Сингапур"), ("AP-SOUTHEAST-SYD", "AU", "Сидней"), ("CA-EAST-TOR", "CA", "Торонто"),
    ("CA-EAST-BHS", "CA", "Боарнуа"), ("US-EAST-VA", "US", "Вирджиния"), ("US-WEST-OR", "US", "Орегон"),
    ("BHS", "CA", "Боарнуа"), ("GRA", "FR", "Гравлин"), ("SBG", "FR", "Страсбург"), ("RBX", "FR", "Рубе"),
    ("DE", "DE", "Франкфурт"), ("UK", "GB", "Лондон"), ("WAW", "PL", "Варшава"), ("SGP", "SG", "Сингапур"),
    ("SYD", "AU", "Сидней"), ("MUM", "IN", "Мумбаи"), ("TOR", "CA", "Торонто"), ("LIM", "DE", "Лимбург"),
    ("ERI", "GB", "Лондон"), ("PAR", "FR", "Париж"), ("MIL", "IT", "Милан"), ("VIN", "US", "Вирджиния"),
    ("HIL", "US", "Орегон"),
]

# DigitalOcean slugs: fra1, nyc3…
DO_PLACES = [
    ("nyc", "US", "Нью-Йорк"), ("sfo", "US", "Сан-Франциско"), ("atl", "US", "Атланта"), ("ams", "NL", "Амстердам"),
    ("lon", "GB", "Лондон"), ("fra", "DE", "Франкфурт"), ("tor", "CA", "Торонто"), ("sgp", "SG", "Сингапур"),
    ("blr", "IN", "Бангалор"), ("syd", "AU", "Сидней"),
]


def _flag(country: str) -> str:
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country)


def region_label(code: str, places: list[tuple[str, str, str]], with_code: bool = True) -> str:
    """"DE1" -> "🇩🇪 Германия, Франкфурт — DE1"; an unknown code stays as it is."""
    for prefix, country, city in places:
        if code.upper().startswith(prefix.upper()):
            label = f"{_flag(country)} {COUNTRIES.get(country, country)}, {city}"
            return f"{label} — {code}" if with_code else label
    return code


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
            region=region_label((d.get("region") or {}).get("slug", ""), DO_PLACES, with_code=False),
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
            "regions": sorted(({"id": r["slug"], "name": region_label(r["slug"], DO_PLACES)}
                               for r in regions if r.get("available")), key=lambda r: r["name"]),
            # hourly billing, capped at the monthly price
            "plans": [{"id": s["slug"], "label": s["slug"],
                       "specs": f"{s.get('vcpus')} vCPU · {round((s.get('memory') or 0) / 1024, 1):g} GB · {s.get('disk')} GB"
                                + (f" · {s['transfer']:g} TB трафика" if s.get("transfer") else ""),
                       "price_hour": s.get("price_hourly"), "price_month": s.get("price_monthly"),
                       "price_month_plan": None, "currency": "USD",
                       "regions": s.get("regions") or []} for s in plans],
            "ssh_keys": [{"id": str(k["id"]), "name": k.get("name") or k.get("fingerprint", "")} for k in keys],
        }

    async def create_server(self, *, name: str, region: str, plan: str, ssh_keys: list[str], user_data: str,
                            project: str | None = None, admin_key: str | None = None) -> str:
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


# when the key may not read /me: the usual subsidiary of each API
OVH_DEFAULT_SUBSIDIARY = {"ovh-eu": "FR", "ovh-ca": "WE", "ovh-us": "US"}
_catalogs: dict[str, tuple[float, dict]] = {}


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
                status_label=labels.get(state, state),
                # "Region OpenStack: os-gra7" -> GRA7
                region=region_label(info.get("zone", "").rsplit("os-", 1)[-1].upper(), OVH_PLACES, with_code=False)
                if "os-" in info.get("zone", "") else info.get("zone", ""),
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
            status_label=self.instance_labels.get(status, status),
            region=region_label(i.get("region", ""), OVH_PLACES, with_code=False),
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
        # a new project starts in Discovery mode ("project.discovery"): no servers until it is activated
        projects = [{"id": p, "name": info.get("description") or p, "discovery": "discovery" in (info.get("planCode") or "")}
                    for p, info in zip(ids, infos)]
        if project not in ids:  # by default an activated project, servers cannot be created in a Discovery one
            project = next((p["id"] for p in projects if not p["discovery"]), ids[0])
        regions, flavors, keys = await asyncio.gather(
            self._get(f"/cloud/project/{project}/region"), self._get(f"/cloud/project/{project}/flavor"),
            self._get(f"/cloud/project/{project}/sshkey"))
        catalog = await self._catalog(await self._subsidiary())
        plans: dict[str, dict] = {}
        for f in flavors:
            if f.get("osType") not in (None, "linux") or not f.get("available", True):
                continue
            codes = f.get("planCodes") or {}
            hour = catalog["prices"].get(codes.get("hourly") or f"{f['name']}.consumption")
            plan = plans.setdefault(f["name"], {
                "id": f["name"], "label": f["name"], "regions": [],
                "specs": f"{f.get('vcpus')} vCPU · {f.get('ram')} GB · {f.get('disk')} GB",  # OVH counts in GB
                # servers are created with hourly billing: a month is HOURS_PER_MONTH of them
                "price_hour": hour, "price_month": round(hour * HOURS_PER_MONTH, 2) if hour else None,
                "price_month_plan": catalog["prices"].get(codes.get("monthly") or f"{f['name']}.monthly.postpaid"),
                "currency": catalog["currency"],
                "_size": (f.get("vcpus") or 0, f.get("ram") or 0)})
            plan["regions"].append(f.get("region"))
        # cheapest first; plans without a known price after them, smallest first
        ordered = sorted(plans.values(), key=lambda p: (p["price_hour"] is None, p["price_hour"] or 0, p["_size"], p["id"]))
        for plan in ordered:
            del plan["_size"]
        return {
            "projects": projects, "project": project, "ssh_multiple": False,
            "regions": sorted(({"id": r, "name": region_label(r, OVH_PLACES)} for r in regions), key=lambda r: r["name"]),
            "plans": ordered,
            "ssh_keys": [{"id": k["id"], "name": k.get("name") or k["id"]} for k in keys],
        }

    async def _subsidiary(self) -> str:
        """Prices and currency depend on the OVHcloud subsidiary the account belongs to."""
        try:
            return (await self._get("/me")).get("ovhSubsidiary") or OVH_DEFAULT_SUBSIDIARY[self.endpoint]
        except HosterError as exc:
            if exc.code != "NOT_GRANTED_CALL":
                raise
            return OVH_DEFAULT_SUBSIDIARY[self.endpoint]

    async def _catalog(self, subsidiary: str) -> dict:
        """Public Cloud price list: planCode -> price. Public, no keys needed; a few MB, so cached."""
        url = f"{self.base}/order/catalog/public/cloud?ovhSubsidiary={subsidiary}"
        cached = _catalogs.get(url)
        if cached and time.time() - cached[0] < CATALOG_TTL:
            return cached[1]
        try:
            resp = await self.http.get(url, timeout=60)
            data = resp.json() if resp.status_code == 200 else {}
        except (httpx.HTTPError, ValueError):
            data = {}
        prices = {}
        for addon in data.get("addons") or []:
            for pricing in addon.get("pricings") or []:
                if "consumption" in (pricing.get("capacities") or []) and pricing.get("intervalUnit") in ("hour", "month"):
                    prices[addon["planCode"]] = pricing["price"] / 1e8  # the catalog counts in 10^-8 of the currency
                    break
        catalog = {"currency": (data.get("locale") or {}).get("currencyCode", ""), "prices": prices}
        if prices:  # a failed download is retried next time instead of hiding prices for hours
            _catalogs[url] = (time.time(), catalog)
        return catalog

    async def create_server(self, *, name: str, region: str, plan: str, ssh_keys: list[str], user_data: str,
                            project: str | None = None, admin_key: str | None = None) -> str:
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


class VDSina:
    """VDSina user API: token in the Authorization header, answers wrapped in {"status": "ok", "data": ...}.
    VDSina has no cloud-init, so new servers get a one-time SSH key of the admin, which installs 3x-ui over SSH."""
    title = "VDSina"
    setup = "ssh"
    images = ("Ubuntu 24.04", "Ubuntu 22.04")
    status_map = {"active": "running", "new": "pending", "block": "stopped", "notpaid": "stopped", "deleted": "stopped"}
    status_labels = {"active": "Работает", "new": "Создаётся", "block": "Заблокирован", "notpaid": "Не оплачен",
                     "deleted": "Удалён"}

    def __init__(self, credentials: dict[str, str]):
        endpoint = credentials.get("endpoint") or "vdsina-com"
        if endpoint not in VDSINA_ENDPOINTS:
            raise HosterError(f"Неизвестный сайт VDSina: {endpoint}")
        token = credentials.get("token", "").strip()
        if not token:
            raise HosterError("Укажите API-токен VDSina")
        self.endpoint = endpoint
        self.base, self.currency = VDSINA_ENDPOINTS[endpoint]
        self.token = token
        self.http = httpx.AsyncClient(base_url=self.base, timeout=TIMEOUT, headers={
            "Authorization": token, "Accept": "application/json", "User-Agent": "vpn-admin"})

    async def close(self) -> None:
        await self.http.aclose()

    async def _request(self, method: str, path: str, json: dict | None = None) -> Any:
        try:
            resp = await self.http.request(method, path, json=json)
        except httpx.HTTPError as exc:
            raise HosterError(f"VDSina недоступна: {exc}") from exc
        try:
            data = resp.json()
        except ValueError:
            data = {}
        if resp.status_code < 400 and data.get("status") == "ok":
            return data.get("data")
        detail = data.get("description") or data.get("status_msg") or resp.text[:200] or f"HTTP {resp.status_code}"
        if resp.status_code == 401:
            raise await self._wrong_site(HosterError(f"VDSina: токен не принят ({detail})", "INVALID_KEY"))
        if resp.status_code == 403:
            raise HosterError(f"VDSina: у пользователя токена нет прав на это действие ({detail})", "NOT_GRANTED_CALL")
        raise HosterError(f"VDSina: {detail}", data.get("status_msg") or "")

    async def _wrong_site(self, error: HosterError) -> HosterError:
        """Accounts of vdsina.com and vdsina.ru are separate: a token of one is unknown to the other."""
        for endpoint, (base, _) in VDSINA_ENDPOINTS.items():
            if endpoint == self.endpoint:
                continue
            try:
                resp = await self.http.get(f"{base}/account")
            except httpx.HTTPError:
                continue
            if resp.status_code == 200:
                label = next(o["label"] for o in PROVIDERS["vdsina"]["fields"][0]["options"] if o["value"] == endpoint)
                return HosterError(f"VDSina: это токен аккаунта другого сайта. Выберите в поле «Сайт аккаунта» "
                                   f"вариант «{label}»", "WRONG_ENDPOINT")
        return error

    def _money(self, value: float) -> str:
        return f"{value:,.2f}".replace(",", " ").replace(".", ",") + (" ₽" if self.currency == "RUB" else " $")

    async def account(self) -> dict:
        acc, balance = await asyncio.gather(self._request("GET", "/account"), self._request("GET", "/account.balance"))
        real = (balance or {}).get("real")
        return {"login": ((acc or {}).get("account") or {}).get("name", ""), "name": "", "status": "",
                "balance": self._money(float(real)) if real is not None else None,
                "limits": f"средств хватит до {acc['forecast']}" if (acc or {}).get("forecast") else ""}

    @staticmethod
    def _specs(data: dict) -> str:
        def part(key: str, unit: str) -> str:
            item = data.get(key) or {}
            value = item.get("total") or item.get("value")
            return f"{value:g} {unit}" if isinstance(value, (int, float)) else ""
        disk = data.get("disk") or {}
        traff = data.get("traff") or {}
        parts = [part("cpu", "vCPU"), part("ram", "GB"),
                 f"{part('disk', 'GB')} {disk.get('title', '')}".strip() if part("disk", "GB") else "",
                 f"{traff['value']:g} {traff.get('for', '')} трафика".strip() if isinstance(traff.get("value"), (int, float)) else ""]
        return " · ".join(p for p in parts if p)

    @staticmethod
    def _dc_label(dc: dict) -> str:
        country = (dc.get("country") or "").upper()
        name = dc.get("name", "")
        if len(country) != 2:
            return name
        return f"{_flag(country)} {COUNTRIES.get(country, country)}, {name}"

    @staticmethod
    def _moscow_iso(value: str) -> str:
        # API timestamps are Europe/Moscow ("2019-07-11 20:05:49")
        return f"{value.replace(' ', 'T')}+03:00" if value and "T" not in value else value

    def _server_view(self, s: dict) -> dict:
        status = s.get("status", "")
        ips = s.get("ip") or []
        return _server(
            id=s.get("id"), name=s.get("name", ""), kind="VDS",
            status=self.status_map.get(status, "unknown"),
            status_label=s.get("status_text") or self.status_labels.get(status, status),
            region=self._dc_label(s.get("datacenter") or {}), plan=(s.get("server-plan") or {}).get("name", ""),
            specs=self._specs(s.get("data") or {}),
            ipv4=[i["ip"] for i in ips if str(i.get("type")) == "4" and i.get("ip")],
            ipv6=[i["ip"] for i in ips if str(i.get("type")) == "6" and i.get("ip")],
            created_at=self._moscow_iso(s.get("created", "")),
        )

    async def servers(self) -> list[dict]:
        try:
            items = await self._request("GET", "/server") or []
        except HosterError as exc:
            if exc.code.startswith("No "):  # "No Server information": the account has none yet
                return []
            raise
        return [self._server_view(s) for s in items]

    def _template_for(self, templates: list[dict], plan_id: int) -> dict | None:
        usable = [t for t in templates if t.get("active") and t.get("ssh-key") and plan_id in (t.get("server-plan") or [])]
        return next((t for want in self.images for t in usable if (t.get("name") or "").startswith(want)), None)

    def _prices(self, plan: dict) -> tuple[float | None, float | None]:
        """(per hour, per month) from the plan's cost per period; VDSina bills by the day."""
        cost, period = plan.get("cost"), plan.get("period")
        if not isinstance(cost, (int, float)):
            return None, None
        per_hour = {"hour": cost, "day": cost / 24, "month": cost / HOURS_PER_MONTH}.get(period)
        per_month = {"hour": cost * HOURS_PER_MONTH, "day": cost * 30, "month": cost}.get(period)
        return (round(per_hour, 4) if per_hour is not None else None,
                round(per_month, 2) if per_month is not None else None)

    async def create_options(self, project: str | None = None) -> dict:
        groups, datacenters, templates, keys = await asyncio.gather(
            self._request("GET", "/server-group"), self._request("GET", "/datacenter"),
            self._request("GET", "/template"), self._request("GET", "/ssh-key"))
        group_plans = await asyncio.gather(*(self._request("GET", f"/server-plan/{g['id']}") for g in groups or []))
        regions = [{"id": str(dc["id"]), "name": self._dc_label(dc)} for dc in datacenters or [] if dc.get("active")]
        plans = []
        for group, items in zip(groups or [], group_plans):
            for plan in items or []:
                # plan builders (has_params) need sizes chosen by hand; plans without Ubuntu cannot carry 3x-ui here
                if not (plan.get("active") and plan.get("enable")) or plan.get("has_params"):
                    continue
                if not self._template_for(templates or [], plan["id"]):
                    continue
                hour, month = self._prices(plan)
                plans.append({"id": str(plan["id"]), "label": f"{plan.get('name', plan['id'])}",
                              "specs": " · ".join(x for x in (group.get("name", ""), self._specs(plan.get("data") or {})) if x),
                              "price_hour": hour, "price_month": month, "price_month_plan": None,
                              "currency": self.currency, "regions": [r["id"] for r in regions]})
        plans.sort(key=lambda p: (p["price_hour"] is None, p["price_hour"] or 0, p["label"]))
        return {"projects": None, "project": None, "ssh_multiple": False,
                "regions": sorted(regions, key=lambda r: r["name"]), "plans": plans,
                "ssh_keys": [{"id": str(k["id"]), "name": k.get("name") or str(k["id"])} for k in keys or []]}

    async def create_server(self, *, name: str, region: str, plan: str, ssh_keys: list[str], user_data: str,
                            project: str | None = None, admin_key: str | None = None) -> str:
        if not admin_key:
            raise HosterError("VDSina: нет SSH-ключа админки для установки 3x-ui")
        template = self._template_for(await self._request("GET", "/template") or [], int(plan))
        if not template:
            raise HosterError(f"VDSina: для тарифа {plan} нет шаблона Ubuntu 24.04 / 22.04")
        key = await self._request("POST", "/ssh-key", {"name": f"vpn-admin {name}", "data": admin_key})
        try:
            server = await self._request("POST", "/server", {
                "datacenter": int(region), "server-plan": int(plan), "template": template["id"],
                "ssh-key": int(key["id"]), "name": name, "autoprolong": 1})
        except HosterError:
            await self.forget_setup_key(name)
            raise
        return str(server["id"])

    async def get_server(self, server_id: str, project: str | None = None) -> dict:
        return self._server_view(await self._request("GET", f"/server/{server_id}") or {})

    async def delete_server(self, server_id: str, project: str | None = None) -> None:
        await self._request("DELETE", f"/server/{server_id}")

    async def public_keys(self, key_ids: list[str]) -> list[str]:
        """Public keys of the account's SSH keys chosen for the server: the admin adds them for root."""
        keys = await asyncio.gather(*(self._request("GET", f"/ssh-key/{k}") for k in key_ids))
        return [k["data"].strip() for k in keys if k and k.get("data")]

    async def forget_setup_key(self, name: str) -> None:
        """Remove the one-time admin key from the account once the server no longer needs it."""
        for key in await self._request("GET", "/ssh-key") or []:
            if key.get("name") == f"vpn-admin {name}":
                await self._request("DELETE", f"/ssh-key/{key['id']}")


CLIENTS = {"digitalocean": DigitalOcean, "ovh": OVHcloud, "vdsina": VDSina}


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
