"""VPN API Hoster: hosting accounts (DigitalOcean, OVHcloud, Scaleway, UpCloud, VDSina, NetGrid) whose APIs
list and create servers for new VPN nodes.

Each provider declares the credential fields it needs (rendered by the UI as a form),
checks the keys by reading the account, and lists the servers of the account in one
normalized shape. Secrets are stored encrypted in the hosters table.
"""

import asyncio
import datetime
import hashlib
import json
import os
import re
import time
from typing import Any

import httpx
from pydantic import BaseModel, Field

from . import db
from .neterrors import describe

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
UPCLOUD_API_URL = os.getenv("UPCLOUD_API_URL", "https://api.upcloud.com/1.3")
SCW_API_URL = os.getenv("SCW_API_URL", "https://api.scaleway.com")
SCW_ZONES = ["fr-par-1", "fr-par-2", "fr-par-3", "nl-ams-1", "nl-ams-2", "nl-ams-3",
             "pl-waw-1", "pl-waw-2", "pl-waw-3", "it-mil-1"]
# VDSina keeps separate accounts on its international and Russian sites, priced in different currencies
VDSINA_ENDPOINTS = {
    "vdsina-com": (os.getenv("VDSINA_COM_API_URL", "https://userapi.vdsina.com/v1"), "USD"),
    "vdsina-ru": (os.getenv("VDSINA_RU_API_URL", "https://userapi.vdsina.ru/v1"), "RUB"),
}
NETGRID_API_URL = os.getenv("NETGRID_API_URL", "https://billing.netgrid.host/api/v1/ext")


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
    "scaleway": {
        "title": "Scaleway",
        "site": "https://www.scaleway.com",
        "fields": [
            {"key": "project_id", "label": "Project ID", "secret": False, "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
            {"key": "secret_key", "label": "Secret Key", "secret": True},
        ],
        "help": "Console → IAM → API keys → Generate API key: Secret Key показывается один раз. У ключа нужны права "
                "на Instances и Block Storage (например, InstancesFullAccess и BlockStorageFullAccess). "
                "Project ID — в Console → Project settings.",
        "help_url": "https://console.scaleway.com/iam/api-keys",
    },
    "upcloud": {
        "title": "UpCloud",
        "site": "https://upcloud.com",
        "fields": [
            {"key": "token", "label": "API-токен", "secret": True, "placeholder": "ucat_…"},
            {"key": "ssh_public_key", "label": "SSH-ключ для входа на новые серверы (необязательно)", "secret": False,
             "optional": True,
             "placeholder": "ssh-ed25519 AAAA… — открытый ключ, как в ~/.ssh/id_ed25519.pub"},
        ],
        "help": "Control Panel → Account → API Tokens → Create token (показывается один раз, срок — до года). "
                "У пользователя токена должен быть доступ к API и правам на серверы. Свой открытый SSH-ключ можно "
                "указать здесь: UpCloud ставит серверы с cloud-init только с входом по ключу.",
        "help_url": "https://hub.upcloud.com/account/api-tokens",
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
    "netgrid": {
        "title": "NetGrid",
        "site": "https://netgrid.host",
        "fields": [
            {"key": "token", "label": "API-ключ", "secret": True},
            {"key": "ssh_public_key", "label": "SSH-ключ для входа на новые серверы (необязательно)", "secret": False,
             "optional": True,
             "placeholder": "ssh-ed25519 AAAA… — открытый ключ, как в ~/.ssh/id_ed25519.pub"},
        ],
        "help": "Личный кабинет NetGrid → API-ключи → создать ключ. Ключ работает только с разрешённых IP: добавьте "
                "в список IP сервера, на котором стоит админка. SSH-ключей в API NetGrid нет, поэтому свой открытый "
                "ключ можно указать здесь: админка добавит его root после установки (root-пароль сервера виден в "
                "кабинете NetGrid).",
        "help_url": "https://billing.netgrid.host/",
    },
}


def _server(*, id: Any, name: str, status: str, status_label: str, region: str, plan: str, ipv4: list[str],
            ipv6: list[str], created_at: str = "", kind: str = "", specs: str = "", price: str = "",
            project: str = "", deletable: bool = True, plan_id: Any = "", region_id: Any = "") -> dict:
    """`project`: what delete_server needs besides the id (OVHcloud's Public Cloud project). `plan_id`,
    `region_id`: the hosting's own ids where they differ from what is shown, for a reinstall (VDSina)."""
    return {"id": str(id), "name": name, "status": status, "status_label": status_label, "region": region,
            "plan": plan, "specs": specs, "price": price, "ipv4": ipv4, "ipv6": ipv6, "created_at": created_at,
            "kind": kind, "project": project, "deletable": deletable,
            "plan_id": str(plan_id or ""), "region_id": str(region_id or "")}


# Systems a new server can get; the install is the same on all of them
OS_LABELS = {"ubuntu-24.04": "Ubuntu 24.04", "ubuntu-22.04": "Ubuntu 22.04", "debian-13": "Debian 13",
             "debian-12": "Debian 12"}
DEFAULT_OS = "ubuntu-24.04"


def _os_options(regions: dict[str, list[str] | None], min_disk: dict[str, int] | None = None) -> list[dict]:
    """The systems a hosting has: {os: regions it is in, None = everywhere}, in OS_LABELS order."""
    return [{"id": os, "label": label, "regions": regions[os], "min_disk_gb": (min_disk or {}).get(os)}
            for os, label in OS_LABELS.items() if os in regions]


def _os_name(names: dict[str, str], os: str) -> str:
    if os not in names:
        raise HosterError(f"Неизвестная система: {os}")
    return names[os]


CURRENCY_SIGNS = {"USD": "$", "EUR": "€", "RUB": "₽", "GBP": "£"}


def _money(value: float, currency: str) -> str:
    """1 234,50 € — the way the account badge shows every hosting's money."""
    return f"{value:,.2f}".replace(",", " ").replace(".", ",") + " " + CURRENCY_SIGNS.get(currency, currency)


def _balance(credit: dict[str, float], spent: dict[str, float] | None = None, due: dict[str, float] | None = None) -> str | None:
    """Badge text for an account billed after the fact: money on the account, this month's spending, debt.
    Each part is {currency: amount}; a part that could not be read is None and is left out."""
    parts = [_money(v, c) for c, v in credit.items() if v > 0.005]
    parts += [f"{_money(v, c)} за месяц" for c, v in (spent or {}).items()]
    parts += [f"долг {_money(v, c)}" for c, v in (due or {}).items() if v > 0.005]
    return " · ".join(parts) or (_money(0, next(iter(credit))) if credit else None)


def _add(total: dict[str, float], currency: str, value: Any) -> None:
    if isinstance(value, (int, float)) and currency:
        total[currency] = total.get(currency, 0.0) + float(value)


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


def _quota_error(data: dict, provider: str) -> HosterError:
    """Scaleway: {"type": "quotas_exceeded", "details": [{"resource": "instances_stardust1_s", "quota": 0, "current": 0}]}"""
    details = []
    for d in data.get("details") or []:  # Scaleway may list the same quota twice
        if isinstance(d, dict) and d not in details:
            details.append(d)
    what = "; ".join(f"{d.get('resource', '?')} — лимит {d.get('quota', '?')}, занято {d.get('current', '?')}"
                     for d in details)
    if any(d.get("quota") == 0 for d in details):
        hint = ("ресурс недоступен организации, пока не подтверждены способ оплаты и личность: в консоли Scaleway "
                "добавьте карту (Billing → Payment methods) и пройдите Verify identity (Organization → Settings), "
                "либо выберите другой тариф")
    else:
        hint = ("удалите ненужные серверы или IP этого типа или выберите другой тариф. У STARDUST1 лимит 1 сервер "
                "на организацию; остальные лимиты — Organization → Quotas, поднять их можно через поддержку Scaleway")
    return HosterError(f"{provider}: исчерпана квота организации{' (' + what + ')' if what else ''}: {hint}", "QUOTA")


def _http_error(resp: httpx.Response, provider: str) -> HosterError:
    try:
        data = resp.json()
        if data.get("type") == "quotas_exceeded":
            return _quota_error(data, provider)
        detail = data.get("message") or data.get("error") or data.get("id") or ""
        for needle, code, hint in OVH_ERROR_HINTS:
            if needle in detail.lower() or data.get("errorCode") == code:
                return HosterError(f"{provider}: {hint or OVH_DISCOVERY_HINT} ({detail})", code)
    except (ValueError, AttributeError):
        detail = resp.text[:200]
    if resp.status_code == 401:
        return HosterError(f"{provider}: ключ не принят (401){': ' + detail if detail else ''}", "HTTP_401")
    if resp.status_code == 403:
        return HosterError(f"{provider}: у ключа нет прав на это действие (403){': ' + detail if detail else ''}",
                           "HTTP_403")
    return HosterError(f"{provider}: HTTP {resp.status_code}{': ' + detail if detail else ''}",
                       "NOT_FOUND" if resp.status_code == 404 else "")


# ---------- where a region is: hosting codes -> flag, country, city ----------

COUNTRIES = {"FR": "Франция", "DE": "Германия", "GB": "Великобритания", "PL": "Польша", "IT": "Италия",
             "NL": "Нидерланды", "CA": "Канада", "US": "США", "SG": "Сингапур", "AU": "Австралия", "IN": "Индия",
             "RU": "Россия", "KZ": "Казахстан", "TR": "Турция", "FI": "Финляндия", "SE": "Швеция", "CH": "Швейцария",
             "ES": "Испания", "LV": "Латвия", "LT": "Литва", "EE": "Эстония", "BG": "Болгария", "MD": "Молдова",
             "RS": "Сербия", "GE": "Грузия", "AM": "Армения", "AE": "ОАЭ", "HK": "Гонконг", "JP": "Япония",
             "DK": "Дания", "NO": "Норвегия", "GR": "Греция", "CZ": "Чехия", "RO": "Румыния", "UA": "Украина"}

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

# UpCloud zones: de-fra1, fi-hel2, us-nyc1…
UPCLOUD_PLACES = [
    ("de-fra", "DE", "Франкфурт"), ("fi-hel", "FI", "Хельсинки"), ("nl-ams", "NL", "Амстердам"),
    ("uk-lon", "GB", "Лондон"), ("pl-waw", "PL", "Варшава"), ("es-mad", "ES", "Мадрид"),
    ("se-sto", "SE", "Стокгольм"), ("dk-cph", "DK", "Копенгаген"), ("no-svg", "NO", "Ставангер"),
    ("us-chi", "US", "Чикаго"), ("us-nyc", "US", "Нью-Йорк"), ("us-sjo", "US", "Сан-Хосе"),
    ("sg-sin", "SG", "Сингапур"), ("au-syd", "AU", "Сидней"),
]

# Scaleway zones: fr-par-1, nl-ams-2…
SCW_PLACES = [("fr-par", "FR", "Париж"), ("nl-ams", "NL", "Амстердам"), ("pl-waw", "PL", "Варшава"),
              ("it-mil", "IT", "Милан")]

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
    os_names = {"ubuntu-24.04": "ubuntu-24-04-x64", "ubuntu-22.04": "ubuntu-22-04-x64", "debian-13": "debian-13-x64",
                "debian-12": "debian-12-x64"}
    rebuild = True  # in place, the IP stays; the droplet runs the user data it was created with again

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
            raise HosterError(f"DigitalOcean недоступен: {describe(exc)}") from exc
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
        except HosterError:
            out["limits"] = " · ".join(x for x in (out["limits"], "баланс не виден: у токена нет billing:read") if x)
            return out
        # account_balance: what was left after the last bill, below zero it is prepaid credit, above zero unpaid;
        # this month's usage is billed at the start of the next one
        left = float(bal.get("account_balance") or 0)
        out["balance"] = _balance({"USD": max(-left, 0.0)}, {"USD": float(bal.get("month_to_date_usage") or 0)},
                                  {"USD": left})
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

    async def _all(self, path: str, key: str, **params) -> list[dict]:
        items, page = [], 1
        while True:
            data = await self._get(path, per_page=200, page=page, **params)
            items += data.get(key) or []
            if not ((data.get("links") or {}).get("pages") or {}).get("next"):
                return items
            page += 1

    async def servers(self) -> list[dict]:
        return [self._droplet(d) for d in await self._all("/droplets", "droplets")]

    async def create_options(self, project: str | None = None) -> dict:
        regions, sizes, keys, images = await asyncio.gather(
            self._all("/regions", "regions"), self._all("/sizes", "sizes"), self._all("/account/keys", "ssh_keys"),
            self._all("/images", "images", type="distribution"))
        plans = sorted((s for s in sizes if s.get("available")), key=lambda s: (s.get("price_monthly") or 0, s["slug"]))
        by_slug = {i.get("slug"): i.get("regions") or [] for i in images}
        return {
            "os": _os_options({os: by_slug[slug] for os, slug in self.os_names.items() if slug in by_slug}),
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
                            project: str | None = None, admin_key: str | None = None, os: str = DEFAULT_OS) -> str:
        data = await self._request("POST", "/droplets", json={
            "name": name, "region": region, "size": plan, "image": _os_name(self.os_names, os), "ipv6": True,
            "monitoring": True,
            "ssh_keys": [int(k) if k.isdigit() else k for k in ssh_keys], "user_data": user_data,
            "tags": ["vpn-admin"],
        })
        return str((data.get("droplet") or {})["id"])

    async def get_server(self, server_id: str, project: str | None = None) -> dict:
        return self._droplet((await self._get(f"/droplets/{server_id}")).get("droplet") or {})

    async def delete_server(self, server_id: str, project: str | None = None) -> None:
        await self._request("DELETE", f"/droplets/{server_id}")

    async def rebuild_server(self, server_id: str, *, plan: str, name: str, project: str | None = None,
                             admin_key: str | None = None, os: str = DEFAULT_OS) -> None:
        """Wipe the disk and install the image again; returns once DigitalOcean reports the rebuild done."""
        action = (await self._request("POST", f"/droplets/{server_id}/actions",
                                      json={"type": "rebuild", "image": _os_name(self.os_names, os)})).get("action") or {}
        for _ in range(60):
            if action.get("status") == "completed":
                return
            if action.get("status") == "errored":
                raise HosterError("DigitalOcean: переустановка дроплета завершилась с ошибкой")
            await asyncio.sleep(10)
            action = (await self._get(f"/actions/{action['id']}")).get("action") or {}
        raise HosterError("DigitalOcean: переустановка дроплета не закончилась за 10 минут")


# when the key may not read /me: the usual subsidiary of each API
OVH_DEFAULT_SUBSIDIARY = {"ovh-eu": "FR", "ovh-ca": "WE", "ovh-us": "US"}
_catalogs: dict[str, tuple[float, dict]] = {}


class OVHcloud:
    """Classic OVH API keys: every call is signed with the application secret and consumer key.
    New servers are Public Cloud instances (hourly billing); classic VPS can only be ordered, not created."""
    title = "OVHcloud"
    os_names = {"ubuntu-24.04": "Ubuntu 24.04", "ubuntu-22.04": "Ubuntu 22.04", "debian-13": "Debian 13",
                "debian-12": "Debian 12"}
    rebuild = True  # in place, the IP stays
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
            raise HosterError(f"OVHcloud недоступен: {describe(exc)}") from exc

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
        login = me.get("nichandle", "")
        return {"login": login, "name": name if me else "без доступа к данным аккаунта (/me)",
                "status": me.get("state", ""), "balance": await self._balance(),
                "limits": " · ".join(x for x in (me.get("email", "") if me.get("email") != login else "",
                                                 me.get("country", ""), "" if me else rights,
                                                 f"ключ до {expires}" if expires else "") if x)}

    async def _balance(self) -> str | None:
        """Prepaid money and vouchers, this month's Public Cloud spending and unpaid bills: OVH bills afterwards,
        so there is no single balance. Whatever cannot be read is left out."""
        async def credit() -> dict[str, float]:
            total: dict[str, float] = {}
            for b in await asyncio.gather(*(self._get(f"/me/credit/balance/{n}")
                                            for n in await self._get("/me/credit/balance"))):
                _add(total, ((b or {}).get("amount") or {}).get("currencyCode", ""), ((b or {}).get("amount") or {}).get("value"))
            return total

        async def spent() -> dict[str, float]:
            total: dict[str, float] = {}
            for u in await asyncio.gather(*(self._get(f"/cloud/project/{p}/usage/current")
                                            for p in await self._get("/cloud/project"))):
                price = (u or {}).get("totalPrice") or {}
                _add(total, price.get("currencyCode", ""), price.get("value"))
            return total

        async def due() -> dict[str, float]:
            price = ((await self._get("/me/debtAccount")) or {}).get("dueAmount") or {}
            total: dict[str, float] = {}
            _add(total, price.get("currencyCode", ""), price.get("value"))
            return total

        parts = await asyncio.gather(credit(), spent(), due(), return_exceptions=True)
        if all(isinstance(p, Exception) for p in parts):
            return None
        credits, spending, debt = (None if isinstance(p, Exception) else p for p in parts)
        if credits is not None and not credits:  # no prepaid account: show zero in the account's currency
            currency = next(iter({**(spending or {}), **(debt or {})}), "")
            credits = {currency: 0.0} if currency else {}
        return _balance(credits or {}, spending, debt)

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
                id=name, name=info.get("displayName") or name, kind="VPS", deletable=False,
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

    def _instance(self, i: dict, project: str = "") -> dict:
        status = i.get("status", "")
        addrs = [a for a in i.get("ipAddresses") or [] if a.get("type") == "public"]
        return _server(
            id=i.get("id"), name=i.get("name", ""), kind="Public Cloud", project=project,
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
            return [self._instance(i, pid) for i in await self._get(f"/cloud/project/{pid}/instance")]

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
        regions, flavors, keys, images = await asyncio.gather(
            self._get(f"/cloud/project/{project}/region"), self._get(f"/cloud/project/{project}/flavor"),
            self._get(f"/cloud/project/{project}/sshkey"), self._get(f"/cloud/project/{project}/image?osType=linux"))
        os_regions: dict[str, list[str] | None] = {}
        for os, wanted in self.os_names.items():
            found = [i.get("region") for i in images or [] if i.get("name") == wanted]
            if found:
                os_regions[os] = found
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
            "projects": projects, "project": project, "ssh_multiple": False, "os": _os_options(os_regions),
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

    def _image_for(self, images: list[dict], os: str, region: str) -> dict:
        wanted = _os_name(self.os_names, os)
        image = next((i for i in images if i.get("name") == wanted), None)
        if not image:
            raise HosterError(f"В регионе {region} нет образа {wanted}")
        return image

    async def create_server(self, *, name: str, region: str, plan: str, ssh_keys: list[str], user_data: str,
                            project: str | None = None, admin_key: str | None = None, os: str = DEFAULT_OS) -> str:
        if not project:
            raise HosterError("Не выбран проект Public Cloud OVHcloud")
        flavors, images = await asyncio.gather(
            self._get(f"/cloud/project/{project}/flavor?region={region}"),
            self._get(f"/cloud/project/{project}/image?osType=linux&region={region}"))
        flavor = next((f for f in flavors if f.get("name") == plan and f.get("region") == region), None)
        if not flavor:
            raise HosterError(f"Тариф {plan} недоступен в регионе {region}")
        image = self._image_for(images, os, region)
        body = {"name": name, "region": region, "flavorId": flavor["id"], "imageId": image["id"],
                "userData": user_data, "monthlyBilling": False}
        if ssh_keys:
            body["sshKeyId"] = ssh_keys[0]  # OVH takes a single key per instance
        return str((await self._request("POST", f"/cloud/project/{project}/instance", body))["id"])

    async def get_server(self, server_id: str, project: str | None = None) -> dict:
        return self._instance(await self._get(f"/cloud/project/{project}/instance/{server_id}"))

    async def delete_server(self, server_id: str, project: str | None = None) -> None:
        await self._request("DELETE", f"/cloud/project/{project}/instance/{server_id}")

    async def rebuild_server(self, server_id: str, *, plan: str, name: str, project: str | None = None,
                             admin_key: str | None = None, os: str = DEFAULT_OS) -> None:
        """Reinstall the instance from a fresh image; OpenStack keeps its IP and creation user data."""
        instance = await self._get(f"/cloud/project/{project}/instance/{server_id}")
        region = instance.get("region", "")
        images = await self._get(f"/cloud/project/{project}/image?osType=linux&region={region}")
        image = self._image_for(images, os, region)
        await self._request("POST", f"/cloud/project/{project}/instance/{server_id}/reinstall", {"imageId": image["id"]})


class VDSina:
    """VDSina user API: token in the Authorization header, answers wrapped in {"status": "ok", "data": ...}.
    VDSina has no cloud-init, so the admin's SSH key is registered in the account and passed with the order."""
    title = "VDSina"
    setup = "ssh"
    rebuild = True
    os_names = {"ubuntu-24.04": "Ubuntu 24.04", "ubuntu-22.04": "Ubuntu 22.04", "debian-13": "Debian 13",
                "debian-12": "Debian 12"}  # template names start with these
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
            raise HosterError(f"VDSina недоступна: {describe(exc)}") from exc
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

    async def account(self) -> dict:
        acc, balance = await asyncio.gather(self._request("GET", "/account"), self._request("GET", "/account.balance"))
        real = (balance or {}).get("real")
        return {"login": ((acc or {}).get("account") or {}).get("name", ""), "name": "", "status": "",
                "balance": _money(float(real), self.currency) if real is not None else None,
                "limits": f"средств хватит до {acc['forecast']}" if (acc or {}).get("forecast") else ""}

    @staticmethod
    def _specs(data: Any) -> str:
        data = VDSina._obj(data)

        def part(key: str, unit: str) -> str:
            item = VDSina._obj(data.get(key))
            value = item.get("total") or item.get("value")
            return f"{value:g} {unit}" if isinstance(value, (int, float)) else ""
        disk = VDSina._obj(data.get("disk"))
        traff = VDSina._obj(data.get("traff"))
        parts = [part("cpu", "vCPU"), part("ram", "GB"),
                 f"{part('disk', 'GB')} {disk.get('title', '')}".strip() if part("disk", "GB") else "",
                 f"{traff['value']:g} {traff.get('for', '')} трафика".strip() if isinstance(traff.get("value"), (int, float)) else ""]
        return " · ".join(p for p in parts if p)

    @staticmethod
    def _obj(value: Any) -> dict:
        """The server list may carry a bare name or ID where the server details have an object."""
        if isinstance(value, dict):
            return value
        return {"name": str(value)} if value not in (None, "", [], False) else {}

    @staticmethod
    def _dc_label(dc: Any) -> str:
        dc = VDSina._obj(dc)
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
        addresses = []  # objects {"ip", "type"} in the details, possibly bare addresses in the list
        for item in ips if isinstance(ips, list) else [ips]:
            address = str(item.get("ip") or "") if isinstance(item, dict) else str(item)
            kind = str(item.get("type") or "") if isinstance(item, dict) else ""
            if address:
                addresses.append((address, kind or ("6" if ":" in address else "4")))
        return _server(
            id=s.get("id"), name=s.get("name", ""), kind="VDS",
            status=self.status_map.get(status, "unknown"),
            status_label=s.get("status_text") or self.status_labels.get(status, status),
            region=self._dc_label(s.get("datacenter")), plan=self._obj(s.get("server-plan")).get("name", ""),
            plan_id=self._obj(s.get("server-plan")).get("id"), region_id=self._obj(s.get("datacenter")).get("id"),
            specs=self._specs(s.get("data")),
            ipv4=[a for a, kind in addresses if kind == "4"],
            ipv6=[a for a, kind in addresses if kind == "6"],
            created_at=self._moscow_iso(str(s.get("created") or "")),
        )

    async def servers(self) -> list[dict]:
        """The list may lack fields (VDSina says to ask each server for the rest), so details are read per
        server; a server whose details fail is shown from the list."""
        try:
            items = await self._request("GET", "/server") or []
        except HosterError as exc:
            if exc.code.startswith("No "):  # "No Server information": the account has none yet
                return []
            raise
        items = [s for s in items if isinstance(s, dict) and s.get("id")]
        details = await asyncio.gather(*(self._request("GET", f"/server/{s['id']}") for s in items),
                                       return_exceptions=True)
        return [self._server_view(d if isinstance(d, dict) else s) for s, d in zip(items, details)]

    def _template_for(self, templates: list[dict], plan_id: int, os: str | None = None) -> dict | None:
        """A template of `os` (or of any supported system) the plan can be installed with."""
        usable = [t for t in templates if t.get("active") and t.get("ssh-key") and plan_id in (t.get("server-plan") or [])]
        wanted = [self.os_names[os]] if os else list(self.os_names.values())
        return next((t for want in wanted for t in usable if (t.get("name") or "").startswith(want)), None)

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
                # plan builders (has_params) need sizes chosen by hand; plans without a supported system are no use
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
        usable = [t for t in templates or [] if t.get("active") and t.get("ssh-key")]
        os_regions = {os: None for os, name in self.os_names.items()
                      if any((t.get("name") or "").startswith(name) for t in usable)}
        return {"projects": None, "project": None, "ssh_multiple": False, "os": _os_options(os_regions),
                "regions": sorted(regions, key=lambda r: r["name"]), "plans": plans,
                "ssh_keys": [{"id": str(k["id"]), "name": k.get("name") or str(k["id"])} for k in keys or []]}

    async def _template(self, plan: str, os: str) -> dict:
        template = self._template_for(await self._request("GET", "/template") or [], int(plan), os)
        if not template:
            raise HosterError(f"VDSina: для тарифа {plan} нет шаблона {_os_name(self.os_names, os)}")
        return template

    async def create_server(self, *, name: str, region: str, plan: str, ssh_keys: list[str], user_data: str,
                            project: str | None = None, admin_key: str | None = None, os: str = DEFAULT_OS) -> str:
        if not admin_key:
            raise HosterError("VDSina: нет SSH-ключа админки для установки 3x-ui")
        template = await self._template(plan, os)
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

    async def check_os(self, os: str, plan: str) -> None:
        """Before anything is changed: the reinstall would fail on a system the plan has no template of."""
        await self._template(plan, os)

    async def rebuild_server(self, server_id: str, *, plan: str, name: str, project: str | None = None,
                             admin_key: str | None = None, os: str = DEFAULT_OS) -> None:
        """Reinstall the OS with root getting the admin's one-time key, like a new server."""
        if not admin_key:
            raise HosterError("VDSina: нет SSH-ключа админки для установки 3x-ui")
        template = await self._template(plan, os)
        key = await self._request("POST", "/ssh-key", {"name": f"vpn-admin {name}", "data": admin_key})
        try:
            await self._request("PUT", f"/server.reinstall/{server_id}",
                                {"template": template["id"], "ssh-key": int(key["id"])})
        except HosterError:
            await self.forget_setup_key(name)
            raise

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


class UpCloud:
    """UpCloud API 1.3 with an API token (Bearer ucat_…). Cloud-init templates only allow SSH-key logins, so a
    server always gets login keys: the admin's one (removed by the install) plus the account's own key when set.
    Prices come in cents per hour; a month is capped at 28 days (672 hours)."""
    title = "UpCloud"
    os_names = {"ubuntu-24.04": "Ubuntu Server 24.04", "ubuntu-22.04": "Ubuntu Server 22.04",
                "debian-13": "Debian GNU/Linux 13", "debian-12": "Debian GNU/Linux 12"}  # template titles start with these
    hours_cap = 672
    state_map = {"started": "running", "maintenance": "pending", "stopped": "stopped", "error": "error"}
    state_labels = {"started": "Работает", "maintenance": "Обслуживание", "stopped": "Выключен", "error": "Ошибка"}

    def __init__(self, credentials: dict[str, str]):
        token = credentials.get("token", "").strip()
        if not token:
            raise HosterError("Укажите API-токен UpCloud")
        self.user_key = credentials.get("ssh_public_key", "").strip()
        self.http = httpx.AsyncClient(base_url=UPCLOUD_API_URL, timeout=TIMEOUT, headers={
            "Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "vpn-admin"})

    async def close(self) -> None:
        await self.http.aclose()

    async def _request(self, method: str, path: str, params: dict | None = None, json: dict | None = None) -> Any:
        try:
            resp = await self.http.request(method, path, params=params, json=json)
        except httpx.HTTPError as exc:
            raise HosterError(f"UpCloud недоступен: {describe(exc)}") from exc
        if resp.status_code < 400:
            return resp.json() if resp.content else None
        try:  # {"error": {"error_code": "SERVER_NOT_FOUND", "error_message": "..."}}
            error = resp.json().get("error") or {}
        except ValueError:
            error = {}
        code = error.get("error_code") or f"HTTP_{resp.status_code}"
        message = error.get("error_message") or resp.text[:200]
        if resp.status_code == 401:
            raise HosterError(f"UpCloud: токен не принят ({message})", "HTTP_401")
        if resp.status_code == 403:
            raise HosterError(f"UpCloud: у токена нет прав на это действие ({message})", "HTTP_403")
        raise HosterError(f"UpCloud: {message} ({code})", "NOT_FOUND" if resp.status_code == 404 else code)

    async def account(self) -> dict:
        account, details = await asyncio.gather(self._request("GET", "/account"),
                                                self._request("GET", "/account/details"), return_exceptions=True)
        if isinstance(account, Exception):
            raise account
        acc = (account or {}).get("account") or {}
        currency = ((details or {}).get("account") or {}).get("currency", "EUR") if isinstance(details, dict) else "EUR"
        credits = acc.get("credits")  # in cents
        return {"login": acc.get("username", ""), "name": "", "status": "",
                "balance": _money(credits / 100, currency) if isinstance(credits, (int, float)) else None,
                "limits": "SSH-ключ для новых серверов задан" if self.user_key else "SSH-ключ для новых серверов не задан"}

    @staticmethod
    def _ips(addresses: list[dict]) -> tuple[list[str], list[str]]:
        public = [a for a in addresses if a.get("access") == "public" and a.get("address")]
        return ([a["address"] for a in public if a.get("family") == "IPv4"],
                [a["address"] for a in public if a.get("family") == "IPv6"])

    def _view(self, s: dict, addresses: list[dict]) -> dict:
        state = s.get("state", "")
        ipv4, ipv6 = self._ips(addresses)
        return _server(
            id=s.get("uuid"), name=s.get("title") or s.get("hostname", ""), kind="Cloud Server",
            status=self.state_map.get(state, "unknown"), status_label=self.state_labels.get(state, state),
            region=region_label(s.get("zone", ""), UPCLOUD_PLACES, with_code=False), plan=s.get("plan", ""),
            specs=f"{s.get('core_number', '?')} vCPU · {round(int(s.get('memory_amount') or 0) / 1024, 1):g} GB",
            ipv4=ipv4, ipv6=ipv6, created_at=(datetime.datetime.fromtimestamp(int(s["created"]), datetime.timezone.utc)
                                              .isoformat() if str(s.get("created", "")).isdigit() else ""),
        )

    async def servers(self) -> list[dict]:
        servers, addresses = await asyncio.gather(self._request("GET", "/server"), self._request("GET", "/ip_address"))
        by_server: dict[str, list[dict]] = {}
        for a in ((addresses or {}).get("ip_addresses") or {}).get("ip_address") or []:
            by_server.setdefault(a.get("server", ""), []).append(a)
        return [self._view(s, by_server.get(s.get("uuid"), []))
                for s in ((servers or {}).get("servers") or {}).get("server") or []]

    async def _templates(self) -> dict[str, list[dict]]:
        """Cloud-init templates of each supported system, newest first."""
        data = await self._request("GET", "/storage/template")
        found = sorted((t for t in ((data or {}).get("storages") or {}).get("storage") or []
                        if t.get("template_type", "cloud-init") == "cloud-init"),
                       key=lambda t: t.get("title") or "", reverse=True)
        out = {os: [t for t in found if (t.get("title") or "").startswith(name)] for os, name in self.os_names.items()}
        return {os: items for os, items in out.items() if items}

    @staticmethod
    def _fitting(templates: list[dict], disk_gb: int) -> dict | None:
        """The disk of a plan cannot be smaller than the template it is cloned from."""
        return next((t for t in templates if (t.get("size") or 0) <= disk_gb), None)

    async def create_options(self, project: str | None = None) -> dict:
        zones, plans, prices, details, templates = await asyncio.gather(
            self._request("GET", "/zone"), self._request("GET", "/plan"), self._request("GET", "/price"),
            self._request("GET", "/account/details"), self._templates(), return_exceptions=True)
        for result in (zones, plans, prices):
            if isinstance(result, Exception):
                raise result
        templates = templates if isinstance(templates, dict) else {}
        # prices come in the account's currency
        currency = ((details or {}).get("account") or {}).get("currency", "EUR") if isinstance(details, dict) else "EUR"
        public = [z for z in ((zones or {}).get("zones") or {}).get("zone") or [] if z.get("public") == "yes"]
        price_by_zone = {p["name"]: p for p in ((prices or {}).get("prices") or {}).get("zone") or []}
        out = []
        for plan in ((plans or {}).get("plans") or {}).get("plan") or []:
            name = plan.get("name", "")
            if "GPU" in name.upper():
                continue
            if templates and not any(self._fitting(t, plan.get("storage_size") or 0) for t in templates.values()):
                continue  # e.g. a 10 GB plan when every image is larger
            key = f"server_plan_{name}"
            regions = [z["id"] for z in public if key in price_by_zone.get(z["id"], {})]
            if not regions:
                continue
            cents = price_by_zone[regions[0]][key].get("price")
            hour = round(cents / 100, 5) if isinstance(cents, (int, float)) else None
            out.append({"id": name, "label": name, "regions": regions, "currency": currency,
                        "specs": f"{plan.get('core_number')} vCPU · {round((plan.get('memory_amount') or 0) / 1024, 1):g} GB"
                                 f" · {plan.get('storage_size')} GB {(plan.get('storage_tier') or '').upper()}",
                        "price_hour": hour, "price_month": round(hour * self.hours_cap, 2) if hour else None,
                        "price_month_plan": None, "disk_gb": plan.get("storage_size")})
        out.sort(key=lambda p: (p["price_hour"] is None, p["price_hour"] or 0, p["id"]))
        return {"projects": None, "project": None, "ssh_multiple": False, "ssh_keys": [],
                "os": _os_options({os: None for os in templates} if templates else {os: None for os in self.os_names},
                                  {os: min(t.get("size") or 0 for t in items) for os, items in templates.items()}),
                "ssh_note": "Войти на сервер можно будет ключом из настроек аккаунта UpCloud в админке."
                            if self.user_key else
                            "В настройках аккаунта UpCloud в админке не задан SSH-ключ: сервер будет работать, но "
                            "войти на него по SSH не получится.",
                "regions": sorted(({"id": z["id"], "name": region_label(z["id"], UPCLOUD_PLACES)} for z in public),
                                  key=lambda r: r["name"]),
                "plans": out}

    async def create_server(self, *, name: str, region: str, plan: str, ssh_keys: list[str], user_data: str,
                            project: str | None = None, admin_key: str | None = None, os: str = DEFAULT_OS) -> str:
        all_templates, plans = await asyncio.gather(self._templates(), self._request("GET", "/plan"))
        wanted = _os_name(self.os_names, os)
        templates = all_templates.get(os) or []
        if not templates:
            raise HosterError(f"UpCloud: нет шаблона {wanted} с cloud-init")
        spec = next((p for p in ((plans or {}).get("plans") or {}).get("plan") or [] if p.get("name") == plan), {})
        disk = spec.get("storage_size") or 25
        template = self._fitting(templates, disk)
        if not template:
            smallest = min(t.get("size") or 0 for t in templates)
            raise HosterError(f"UpCloud: образ {OS_LABELS[os]} занимает {smallest} ГБ, а диск тарифа {plan} — {disk} ГБ. "
                              f"Выберите тариф с диском от {smallest} ГБ или другую систему", "SIZE_INVALID")
        keys = [k for k in (admin_key, self.user_key) if k]
        body = {"server": {
            "zone": region, "title": name, "hostname": name, "plan": plan, "metadata": "yes", "user_data": user_data,
            "labels": {"label": [{"key": "managed-by", "value": "vpn-admin"}]},
            "login_user": {"username": "root", "ssh_keys": {"ssh_key": keys}},
            "storage_devices": {"storage_device": [{
                "action": "clone", "storage": template["uuid"], "title": f"{name}-disk",
                "size": disk, "tier": spec.get("storage_tier") or "maxiops"}]},
            "networking": {"interfaces": {"interface": [
                {"index": 1, "type": "public", "ip_addresses": {"ip_address": [{"family": "IPv4"}]}},
                {"index": 2, "type": "public", "ip_addresses": {"ip_address": [{"family": "IPv6"}]}},
                {"index": 3, "type": "utility", "ip_addresses": {"ip_address": [{"family": "IPv4"}]}},
            ]}},
        }}
        return str((await self._request("POST", "/server", json=body))["server"]["uuid"])

    async def get_server(self, server_id: str, project: str | None = None) -> dict:
        s = (await self._request("GET", f"/server/{server_id}"))["server"]
        return self._view(s, ((s.get("ip_addresses") or {}).get("ip_address")) or [])

    async def delete_server(self, server_id: str, project: str | None = None) -> None:
        """A server must be stopped before it can be deleted; its disks go with it (storages=1)."""
        try:
            state = (await self._request("GET", f"/server/{server_id}"))["server"].get("state")
        except HosterError as exc:
            if exc.code == "NOT_FOUND":
                return
            raise
        if state != "stopped":
            if state == "started":
                await self._request("POST", f"/server/{server_id}/stop",
                                    json={"stop_server": {"stop_type": "hard", "timeout": "60"}})
            for _ in range(60):
                await asyncio.sleep(3)
                if (await self._request("GET", f"/server/{server_id}"))["server"].get("state") == "stopped":
                    break
        await self._request("DELETE", f"/server/{server_id}", params={"storages": 1, "backups": "delete"})


class Scaleway:
    """Scaleway Instance API v1 (zonal): secret key in X-Auth-Token, servers live in a project.
    A server is created stopped with a routed IPv4, gets the cloud-init script and is then powered on;
    the IDs kept by the admin are "zone/uuid". Project SSH keys are added to new servers by Scaleway itself."""
    title = "Scaleway"
    os_names = {"ubuntu-24.04": "ubuntu_noble", "ubuntu-22.04": "ubuntu_jammy", "debian-13": "debian_trixie",
                "debian-12": "debian_bookworm"}  # Marketplace image labels
    state_map = {"running": "running", "starting": "pending", "stopping": "stopped", "stopped": "stopped",
                 "stopped in place": "stopped", "locked": "error"}
    state_labels = {"running": "Работает", "starting": "Запускается", "stopping": "Останавливается",
                    "stopped": "Выключен", "stopped in place": "Выключен", "locked": "Заблокирован"}

    def __init__(self, credentials: dict[str, str]):
        self.project = credentials.get("project_id", "").strip()
        secret = credentials.get("secret_key", "").strip()
        if not (self.project and secret):
            raise HosterError("Укажите Project ID и Secret Key Scaleway")
        self.http = httpx.AsyncClient(base_url=SCW_API_URL, timeout=TIMEOUT,
                                      headers={"X-Auth-Token": secret, "User-Agent": "vpn-admin"})

    async def close(self) -> None:
        await self.http.aclose()

    async def _request(self, method: str, path: str, params: dict | None = None, json: dict | None = None,
                       content: str | None = None) -> Any:
        headers = {"Content-Type": "text/plain"} if content is not None else None
        try:
            resp = await self.http.request(method, path, params=params, json=json, content=content, headers=headers)
        except httpx.HTTPError as exc:
            raise HosterError(f"Scaleway недоступен: {describe(exc)}") from exc
        if resp.status_code == 404:
            raise HosterError("Scaleway: не найдено", "NOT_FOUND")
        if resp.status_code >= 400:
            raise _http_error(resp, self.title)
        return resp.json() if resp.content and "json" in resp.headers.get("content-type", "") else None

    async def account(self) -> dict:
        try:
            project = await self._request("GET", f"/account/v3/projects/{self.project}")
        except HosterError as exc:
            if exc.code == "NOT_FOUND":
                raise HosterError("Scaleway: проект с таким Project ID не найден") from exc
            if exc.code != "HTTP_403":
                raise
            # a key limited to Instances cannot read the project: checking access to servers is enough
            await self._request("GET", f"/instance/v1/zones/{SCW_ZONES[0]}/servers",
                                params={"project": self.project, "per_page": 1})
            project = {}
        org = project.get("organization_id", "")
        try:
            balance = await self._balance(org)
        except HosterError:  # the key has no BillingReadOnly permission set
            balance = None
        return {"login": project.get("name") or self.project, "name": "", "status": "", "balance": balance,
                "limits": " · ".join(x for x in (f"организация {org[:8]}…" if org else "",
                                                 "" if balance else "баланс не виден: у ключа нет BillingReadOnly") if x)}

    async def _balance(self, org: str) -> str | None:
        """Scaleway bills after the month: this month's spending (after discounts) and what is left of
        vouchers and credits. Without the organization ID only this project's spending is counted."""
        owner = {"organization_id": org} if org else {"project_id": self.project}
        spent, total, page = 0.0, None, 1
        currency = "EUR"
        while total is None or (page - 1) * 100 < total:
            data = await self._request("GET", "/billing/v2beta1/consumptions", params={**owner, "page": page, "page_size": 100})
            total = (data or {}).get("total_count") or 0
            for c in (data or {}).get("consumptions") or []:
                value = c.get("value") or {}
                currency = value.get("currency_code") or currency
                spent += float(value.get("units") or 0) + float(value.get("nanos") or 0) / 1e9
            if page == 1:
                spent -= abs(float((data or {}).get("total_discount_untaxed_value") or 0))
            if not (data or {}).get("consumptions"):
                break
            page += 1
        credit = 0.0
        if org:
            try:
                discounts = (await self._request("GET", "/billing/v2beta1/discounts",
                                                 params={"organization_id": org, "page_size": 100}) or {}).get("discounts") or []
            except HosterError:
                discounts = []
            now = datetime.datetime.now(datetime.timezone.utc)

            def active(d: dict) -> bool:
                try:
                    return not d.get("stop_date") or datetime.datetime.fromisoformat(d["stop_date"].replace("Z", "+00:00")) > now
                except ValueError:
                    return True

            credit = sum(float(d.get("value_remaining") or 0) for d in discounts
                         if d.get("mode") in ("discount_mode_value", "discount_mode_splittable") and active(d))
        return _balance({currency: credit}, {currency: max(spent, 0.0)})

    def _view(self, s: dict) -> dict:
        state = s.get("state", "")
        ips = s.get("public_ips") or ([s["public_ip"]] if s.get("public_ip") else [])
        v6 = [i["address"] for i in ips if i.get("family") == "inet6" and i.get("address")]
        if (s.get("ipv6") or {}).get("address"):
            v6.append(s["ipv6"]["address"])
        return _server(
            id=f"{s.get('zone')}/{s.get('id')}", name=s.get("name", ""), kind="Instance",
            status=self.state_map.get(state, "unknown"), status_label=self.state_labels.get(state, state),
            region=region_label(s.get("zone", ""), SCW_PLACES, with_code=False), plan=s.get("commercial_type", ""),
            ipv4=[i["address"] for i in ips if i.get("family", "inet") == "inet" and i.get("address")], ipv6=v6,
            created_at=s.get("creation_date", ""),
        )

    async def servers(self) -> list[dict]:
        async def zone(z: str) -> list[dict]:
            data = await self._request("GET", f"/instance/v1/zones/{z}/servers",
                                       params={"project": self.project, "per_page": 100})
            return [self._view(s) for s in (data or {}).get("servers") or []]

        chunks = await asyncio.gather(*(zone(z) for z in SCW_ZONES), return_exceptions=True)
        if all(isinstance(c, Exception) for c in chunks):
            raise chunks[0]
        return [s for c in chunks if isinstance(c, list) for s in c]

    async def create_options(self, project: str | None = None) -> dict:
        async def zone(z: str):
            products, availability = await asyncio.gather(
                self._request("GET", f"/instance/v1/zones/{z}/products/servers", params={"per_page": 100}),
                self._request("GET", f"/instance/v1/zones/{z}/products/servers/availability", params={"per_page": 100}))
            return z, (products or {}).get("servers") or {}, (availability or {}).get("servers") or {}

        zones = [z for z in await asyncio.gather(*(zone(z) for z in SCW_ZONES), return_exceptions=True)
                 if not isinstance(z, Exception)]
        if not zones:
            raise HosterError("Scaleway: не удалось получить тарифы ни в одной зоне")
        plans: dict[str, dict] = {}
        for z, products, availability in zones:
            for name, t in products.items():
                # no GPU or Windows types, nothing being retired, nothing out of stock in this zone
                if t.get("end_of_service") or t.get("gpu") or "WIN" in name.upper():
                    continue
                if (availability.get(name) or {}).get("availability") == "shortage":
                    continue
                plan = plans.setdefault(name, {
                    "id": name, "label": name, "regions": [], "currency": "EUR",
                    "specs": f"{t.get('ncpus')} vCPU · {round((t.get('ram') or 0) / 1024 ** 3, 1):g} GB"
                             + (f" · {t['arch']}" if t.get("arch") and t["arch"] != "x86_64" else "")
                             + (" · не больше 1 на организацию" if name.startswith("STARDUST") else ""),
                    "single": name.startswith("STARDUST"),
                    "price_hour": t.get("hourly_price"), "price_month": t.get("monthly_price"), "price_month_plan": None})
                plan["regions"].append(z)
        ordered = sorted(plans.values(), key=lambda p: (p["price_hour"] is None, p["price_hour"] or 0, p["id"]))
        return {"projects": None, "project": None, "ssh_multiple": False, "ssh_keys": [],
                "os": _os_options({os: None for os in self.os_names}),  # checked per zone and type when ordering
                "ssh_note": "SSH-ключи проекта Scaleway (Console → IAM → SSH keys) Scaleway сам добавит на сервер.",
                "regions": sorted(({"id": z, "name": region_label(z, SCW_PLACES)} for z, _, _ in zones),
                                  key=lambda r: r["name"]),
                "plans": ordered}

    async def _image(self, zone: str, plan: str, os: str) -> str:
        data = await self._request("GET", "/marketplace/v2/local-images",
                                   params={"image_label": _os_name(self.os_names, os), "zone": zone, "type": "instance_sbs"})
        for image in (data or {}).get("local_images") or []:
            if plan in (image.get("compatible_commercial_types") or []):
                return image["id"]
        raise HosterError(f"Scaleway: в зоне {zone} нет образа {OS_LABELS[os]} для {plan}")

    async def create_server(self, *, name: str, region: str, plan: str, ssh_keys: list[str], user_data: str,
                            project: str | None = None, admin_key: str | None = None, os: str = DEFAULT_OS) -> str:
        zone = region
        image = await self._image(zone, plan, os)
        ip = (await self._request("POST", f"/instance/v1/zones/{zone}/ips",
                                  json={"project": self.project, "type": "routed_ipv4"}))["ip"]
        try:
            server = (await self._request("POST", f"/instance/v1/zones/{zone}/servers", json={
                "name": name, "commercial_type": plan, "image": image, "project": self.project,
                "public_ips": [ip["id"]], "dynamic_ip_required": False, "tags": ["vpn-admin"]}))["server"]
        except HosterError:
            await self._request("DELETE", f"/instance/v1/zones/{zone}/ips/{ip['id']}")
            raise
        # created stopped: the script must be in place before the first boot
        await self._request("PATCH", f"/instance/v1/zones/{zone}/servers/{server['id']}/user_data/cloud-init",
                            content=user_data)
        await self._request("POST", f"/instance/v1/zones/{zone}/servers/{server['id']}/action",
                            json={"action": "poweron"})
        return f"{zone}/{server['id']}"

    async def get_server(self, server_id: str, project: str | None = None) -> dict:
        zone, sid = server_id.split("/", 1)
        return self._view((await self._request("GET", f"/instance/v1/zones/{zone}/servers/{sid}"))["server"])

    async def delete_server(self, server_id: str, project: str | None = None) -> None:
        """terminate removes the server and local disks; its block volume and IP would keep costing, so they go too."""
        zone, sid = server_id.split("/", 1)
        try:
            server = (await self._request("GET", f"/instance/v1/zones/{zone}/servers/{sid}"))["server"]
        except HosterError as exc:
            if exc.code == "NOT_FOUND":
                return
            raise
        volumes = [v["id"] for v in (server.get("volumes") or {}).values() if v.get("volume_type") == "sbs_volume"]
        ips = [i["id"] for i in server.get("public_ips") or [] if i.get("id") and not i.get("dynamic")]
        await self._request("POST", f"/instance/v1/zones/{zone}/servers/{sid}/action", json={"action": "terminate"})
        for _ in range(60):  # until the server is gone and its volume detached
            try:
                await self._request("GET", f"/instance/v1/zones/{zone}/servers/{sid}")
            except HosterError as exc:
                if exc.code == "NOT_FOUND":
                    break
                raise
            await asyncio.sleep(3)
        for volume in volumes:
            for _ in range(20):
                try:
                    await self._request("DELETE", f"/block/v1alpha1/zones/{zone}/volumes/{volume}")
                    break
                except HosterError as exc:
                    if exc.code == "NOT_FOUND":
                        break
                    await asyncio.sleep(3)  # still detaching
        for ip in ips:
            try:
                await self._request("DELETE", f"/instance/v1/zones/{zone}/ips/{ip}")
            except HosterError as exc:
                if exc.code != "NOT_FOUND":
                    raise


REBUILD_START_POLLS, REBUILD_START_EVERY = 18, 10  # up to 3 minutes for NetGrid to show the reinstall


class NetGrid:
    """NetGrid external API (BILLmanager behind it): Bearer key limited to allowed IPs, errors as {"detail": ...}.
    There is no cloud-init and no SSH keys: the order returns a root password, which the admin logs in with
    once to run the install. Servers are paid a month ahead from the balance; the API cannot delete them."""
    title = "NetGrid"
    setup = "password"
    rebuild = True
    os_names = {"ubuntu-24.04": ("ubuntu", "24.04"), "ubuntu-22.04": ("ubuntu", "22.04"),
                "debian-13": ("debian", "13"), "debian-12": ("debian", "12")}
    delete_hint = ("NetGrid не даёт удалять серверы через API: удалите сервер в личном кабинете NetGrid "
                   "(Виртуальные серверы → сервер → Удалить).")
    # BILLmanager service state: 1 — being created, 2 — active (then vm_state tells the machine's own), 3 — suspended
    service_states = {1: "new", 2: "active", 3: "suspended"}
    status_map = {"active": "running", "running": "running", "new": "pending", "creating": "pending",
                  "provisioning": "pending", "pending": "pending", "starting": "pending", "stopping": "pending",
                  "restarting": "pending", "installation": "pending", "reinstalling": "pending",
                  "stopped": "stopped", "suspended": "stopped", "blocked": "stopped", "error": "error",
                  "failed": "error"}
    status_labels = {"active": "Работает", "running": "Работает", "new": "Создаётся", "creating": "Создаётся",
                     "provisioning": "Создаётся", "pending": "Создаётся", "starting": "Запускается",
                     "stopping": "Останавливается", "restarting": "Перезагружается", "installation": "Ставится система",
                     "reinstalling": "Ставится система", "stopped": "Выключен", "suspended": "Заблокирован",
                     "blocked": "Заблокирован", "error": "Ошибка", "failed": "Ошибка"}
    error_hints = {"insufficient_balance": "на балансе NetGrid не хватает денег на месяц тарифа: пополните баланс"}

    def __init__(self, credentials: dict[str, str]):
        token = credentials.get("token", "").strip()
        if not token:
            raise HosterError("Укажите API-ключ NetGrid")
        self.user_key = credentials.get("ssh_public_key", "").strip()
        self.http = httpx.AsyncClient(base_url=NETGRID_API_URL, timeout=TIMEOUT, headers={
            "Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "vpn-admin"})

    async def close(self) -> None:
        await self.http.aclose()

    async def _request(self, method: str, path: str, params: dict | None = None, json: dict | None = None) -> Any:
        try:
            resp = await self.http.request(method, path, params=params, json=json)
        except httpx.HTTPError as exc:
            raise HosterError(f"NetGrid недоступен: {describe(exc)}") from exc
        try:
            data = resp.json() if resp.content else {}
        except ValueError:
            data = {}
        if resp.status_code < 400:
            return data
        detail = data.get("detail") if isinstance(data, dict) else None
        if isinstance(detail, list):  # request validation: [{"loc": [...], "msg": "..."}]
            detail = "; ".join(str(d.get("msg", d)) if isinstance(d, dict) else str(d) for d in detail)
        detail = str(detail or resp.text[:200] or f"HTTP {resp.status_code}")
        detail = self.error_hints.get(detail, detail)
        if resp.status_code == 401:
            raise HosterError(f"NetGrid: ключ не принят ({detail})", "HTTP_401")
        if resp.status_code == 403:
            # the same answer for a wrong key and for an address outside the key's allowlist
            raise HosterError(f"NetGrid: ключ не принят ({detail}). Проверьте ключ и что IP сервера админки есть в "
                              "списке разрешённых IP ключа в кабинете NetGrid", "HTTP_403")
        raise HosterError(f"NetGrid: {detail}", "NOT_FOUND" if resp.status_code == 404 else f"HTTP_{resp.status_code}")

    async def account(self) -> dict:
        me = await self._request("GET", "/whoami") or {}
        return {"login": f"аккаунт {me['account_id']}" if me.get("account_id") else "", "name": "", "status": "",
                "balance": None, "limits": f"ключ «{me['label']}»" if me.get("label") else ""}

    @staticmethod
    def _dc_label(dc: dict) -> str:
        country = str(dc.get("country_code") or dc.get("code") or "").upper()
        city = dc.get("city") or dc.get("name") or str(dc.get("id", ""))
        if len(country) != 2:
            return city
        return f"{_flag(country)} {COUNTRIES.get(country, dc.get('country') or country)}, {city}"

    async def _datacenters(self) -> list[dict]:
        data = await self._request("GET", "/datacenters") or {}
        items = data.get("datacenters") if isinstance(data, dict) else data
        return [dc for dc in items or [] if isinstance(dc, dict) and dc.get("id") is not None
                and dc.get("enabled", True) is not False]

    def _status(self, s: dict) -> str:
        status = s.get("status")
        if isinstance(status, int):
            status = self.service_states.get(status, str(status))
        status = str(status or "").lower()
        if status == "active" and s.get("vm_state"):
            return str(s["vm_state"]).lower()
        return status

    def _view(self, s: dict, regions: dict[str, str]) -> dict:
        status = self._status(s)
        ips = s.get("ips") or s.get("ip") or []
        ips = [str(a.get("ip") or a.get("address") or "") if isinstance(a, dict) else str(a)
               for a in (ips if isinstance(ips, list) else [ips])]
        ipv6 = [a for a in ips + [str(s.get("ipv6") or "")] if ":" in a]
        dc = s.get("datacenter") or s.get("location")
        region = (self._dc_label(dc) if isinstance(dc, dict) else str(dc or "")) or regions.get(str(s.get("dc_id")), "")
        plan = s.get("plan")
        price, period = s.get("price"), s.get("period")
        return _server(
            id=s.get("id"), name=s.get("name") or s.get("hostname") or "", kind="VPS", deletable=False,
            status=self.status_map.get(status, "unknown"), status_label=self.status_labels.get(status, status),
            region=region, plan=(plan.get("name", "") if isinstance(plan, dict) else str(plan or "")),
            plan_id=plan.get("id") if isinstance(plan, dict) else s.get("plan_id"),
            region_id=dc.get("id") if isinstance(dc, dict) else s.get("dc_id"),
            specs=str(s.get("os") or s.get("os_name") or ""),
            price=f"{_money(float(price), 'EUR')}/мес" if isinstance(price, (int, float)) and period in (None, 1) else "",
            ipv4=[a for a in ips if a and ":" not in a], ipv6=ipv6, created_at=str(s.get("created_at") or ""),
        )

    async def servers(self) -> list[dict]:
        """The list carries only the id, name, IP and status, so the rest is read per server; a server whose
        details fail is shown from the list."""
        data, datacenters = await asyncio.gather(self._request("GET", "/vps"), self._datacenters(),
                                                 return_exceptions=True)
        if isinstance(data, Exception):
            raise data
        regions = {} if isinstance(datacenters, Exception) else {str(dc["id"]): self._dc_label(dc) for dc in datacenters}
        listed = (data or {}).get("vps") or {}
        items = [s for s in (listed.get("items") if isinstance(listed, dict) else listed) or []
                 if isinstance(s, dict) and s.get("id") is not None]
        details = await asyncio.gather(*(self._request("GET", f"/vps/{s['id']}") for s in items), return_exceptions=True)
        return [self._view({**s, **d} if isinstance(d, dict) else s, regions) for s, d in zip(items, details)]

    @staticmethod
    def _families(data: Any) -> list[dict]:
        """The families of /os: {"families": [...]} as documented, or the bare list its own cabinet gets; a family
        names itself by "family_slug" (the cabinet's) or "slug" (the docs')."""
        items = data.get("families") if isinstance(data, dict) else data
        return [f for f in items or [] if isinstance(f, dict)]

    @staticmethod
    def _family_slug(family: dict) -> str:
        return str(family.get("family_slug") or family.get("slug") or family.get("family") or "")

    async def _os_items(self) -> dict[str, tuple[str, str]]:
        """{our os: (family slug, image id)} for the systems NetGrid has; its ids look like "ubuntu-24.04"."""
        found: dict[str, tuple[str, str]] = {}
        for family in self._families(await self._request("GET", "/os") or {}):
            slug = self._family_slug(family)
            for os, (want, version) in self.os_names.items():
                if os in found or want not in f"{slug} {family.get('family') or ''}".lower():
                    continue
                pattern = r"(?<![\d.])" + re.escape(version).replace(r"\.", "[.-]?") + r"(?![\d])"
                for item in family.get("items") or []:
                    if not isinstance(item, dict) or item.get("proxmox_supported") is False:
                        continue
                    image = str(item.get("id") or "")
                    text = f"{image} {item.get('name') or ''} {item.get('version') or ''}".lower()
                    if image and (image.lower() == os or re.search(pattern, text)):
                        found[os] = (slug or want, image)
                        break
        return found

    async def create_options(self, project: str | None = None) -> dict:
        data, datacenters, images = await asyncio.gather(self._request("GET", "/plans"), self._datacenters(),
                                                         self._os_items())
        regions = sorted(({"id": str(dc["id"]), "name": self._dc_label(dc)} for dc in datacenters),
                         key=lambda r: r["name"])
        plans = []
        for plan in (data or {}).get("plans") or []:
            if plan.get("id") is None or plan.get("enabled", True) is False:
                continue
            price = plan.get("price")
            month = round(float(price), 2) if isinstance(price, (int, float)) else None
            ram = plan.get("ram")
            ram_gb = f"{ram / 1024:g} GB RAM" if isinstance(ram, (int, float)) and ram >= 128 else f"{ram} GB RAM"
            specs = " · ".join(x for x in (f"{plan['cpu']} vCPU" if plan.get("cpu") else "", ram_gb if ram else "",
                                          f"{plan['disk']} GB NVMe" if plan.get("disk") else "") if x)
            dcs = plan.get("dc_ids") or plan.get("datacenters")
            plans.append({"id": str(plan["id"]), "label": plan.get("name") or str(plan["id"]), "specs": specs,
                          "price_hour": round(month / HOURS_PER_MONTH, 4) if month is not None else None,
                          "price_month": month, "price_month_plan": None,
                          "currency": plan.get("currency") or "EUR",
                          "regions": [str(d.get("id") if isinstance(d, dict) else d) for d in dcs]
                          if isinstance(dcs, list) else [r["id"] for r in regions]})
        plans.sort(key=lambda p: (p["price_month"] is None, p["price_month"] or 0, p["label"]))
        return {"projects": None, "project": None, "ssh_multiple": False, "ssh_keys": [],
                "os": _os_options({os: None for os in images}),
                "ssh_note": "Войти на сервер можно будет ключом из настроек аккаунта NetGrid в админке или "
                            "root-паролем из кабинета NetGrid." if self.user_key else
                            "SSH-ключей в API NetGrid нет: войти на сервер можно root-паролем из кабинета NetGrid "
                            "или ключом, если указать его в настройках аккаунта NetGrid в админке.",
                "regions": regions, "plans": plans}

    async def _image(self, os: str) -> tuple[str, str]:
        images = await self._os_items()
        if os not in images:
            have = ", ".join(OS_LABELS[o] for o in OS_LABELS if o in images)
            raise HosterError(f"NetGrid: нет образа {OS_LABELS.get(os, os)}"
                              + (f" (есть: {have})" if have else ": API не вернул ни одной поддерживаемой системы"))
        return images[os]

    async def check_os(self, os: str, plan: str) -> None:
        """Before anything is changed: the reinstall would fail on a system the hosting does not have."""
        await self._image(os)

    async def create_server(self, *, name: str, region: str, plan: str, ssh_keys: list[str], user_data: str,
                            project: str | None = None, admin_key: str | None = None, os: str = DEFAULT_OS) -> str:
        family, image = await self._image(os)
        data = await self._request("POST", "/vps", json={
            "plan_id": int(plan), "dc_id": int(region), "os_family_slug": family, "os_item_id": image,
            "hostname": name, "period": 1, "autorenew": True})
        return str(data["item_id"])

    async def get_server(self, server_id: str, project: str | None = None) -> dict:
        return self._view(await self._request("GET", f"/vps/{server_id}") or {}, {})

    async def root_password(self, server_id: str) -> str:
        """The current root password: NetGrid shows it in the server's details, also after a reinstall."""
        return str((await self._request("GET", f"/vps/{server_id}") or {}).get("root_password") or "")

    async def rebuild_server(self, server_id: str, *, plan: str, name: str, project: str | None = None,
                             admin_key: str | None = None, os: str = DEFAULT_OS,
                             root_password: str | None = None) -> None:
        """Reinstall the OS with the root password the install logs in with; returns once NetGrid shows the
        server busy with it (or after a while, if its state never says so), so the old system is not taken
        for the new one."""
        _, image = await self._image(os)
        body = {"os_id": image, **({"password": root_password} if root_password else {})}
        await self._request("POST", f"/vps/{server_id}/reinstall", json=body)
        for _ in range(REBUILD_START_POLLS):
            await asyncio.sleep(REBUILD_START_EVERY)
            try:
                if (await self.get_server(server_id))["status"] != "running":
                    return
            except HosterError:
                return  # gone from the API for a moment: busy with the reinstall

    async def delete_server(self, server_id: str, project: str | None = None) -> None:
        raise HosterError(self.delete_hint, "NO_DELETE")

    async def public_keys(self, key_ids: list[str]) -> list[str]:
        """The key from the account's settings in the admin: the API has no SSH keys to choose from."""
        return [self.user_key] if self.user_key else []


CLIENTS = {"digitalocean": DigitalOcean, "ovh": OVHcloud, "vdsina": VDSina, "scaleway": Scaleway, "upcloud": UpCloud,
           "netgrid": NetGrid}


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


async def find_server(hoster: db.Hoster, server_id: str) -> dict | None:
    client = client_for(hoster)
    try:
        return next((s for s in await client.servers() if s["id"] == server_id), None)
    finally:
        await client.close()


async def delete_server(hoster: db.Hoster, server_id: str, project: str | None = None) -> None:
    """Gone already (deleted in the hosting's own panel) counts as deleted."""
    client = client_for(hoster)
    try:
        await client.delete_server(server_id, project)
    except HosterError as exc:
        if exc.code != "NOT_FOUND":
            raise
    finally:
        await client.close()
    invalidate(hoster.id)


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
