"""Decoy website on the domain: a static page served by nginx on the host.

install.sh installs nginx and points it at data/site/ (see nginx.sh). The admin
only writes data/site/index.html, which nginx serves immediately. Five built-in
templates live in site_templates/; a custom page can be pasted instead.
Templates may use {{domain}} and {{year}} placeholders.
"""

import json
import os
import time
from pathlib import Path
from typing import Any

from . import tls
from .config import settings

TEMPLATES_DIR = Path(__file__).resolve().parent / "site_templates"
SITE_DIR = settings.data_dir / "site"
INDEX_FILE = SITE_DIR / "index.html"
STATE_FILE = settings.data_dir / "site.json"
CUSTOM_FILE = settings.data_dir / "site_custom.html"

MAX_CUSTOM_SIZE = 1024 * 1024

TEMPLATES = [
    {"id": "coming-soon", "name": "Скоро открытие", "description": "Тёмная страница «скоро запуск» с формой подписки"},
    {"id": "maintenance", "name": "Техработы", "description": "Сайт на плановом обслуживании"},
    {"id": "studio", "name": "Студия дизайна", "description": "Портфолио фотостудии с работами"},
    {"id": "cafe", "name": "Кофейня", "description": "Кофейня и пекарня: меню, часы работы"},
    {"id": "cloud", "name": "IT-компания", "description": "Лендинг компании по облачной инфраструктуре"},
]
TEMPLATE_IDS = {t["id"] for t in TEMPLATES}


class SiteError(Exception):
    pass


def _state() -> dict[str, Any]:
    try:
        return json.loads(STATE_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_state(**changes: Any) -> None:
    state = {**_state(), **changes}
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2))
    tmp.replace(STATE_FILE)


def domain() -> str:
    return _state().get("domain") or os.getenv("SITE_DOMAIN", "") or tls.load_config().get("domain", "")


def render(html: str) -> str:
    return html.replace("{{domain}}", domain() or "example.com").replace("{{year}}", time.strftime("%Y"))


def template_html(template_id: str) -> str:
    if template_id not in TEMPLATE_IDS:
        raise SiteError("Нет такого шаблона")
    return (TEMPLATES_DIR / f"{template_id}.html").read_text()


def _publish(html: str) -> None:
    SITE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = INDEX_FILE.with_suffix(".tmp")
    tmp.write_text(render(html))
    tmp.chmod(0o644)  # nginx workers read it as an unprivileged user
    tmp.replace(INDEX_FILE)


def apply_template(template_id: str) -> None:
    _publish(template_html(template_id))
    _save_state(template=template_id, updated_at=int(time.time()))


def save_custom(html: str) -> None:
    if not html.strip():
        raise SiteError("Шаблон пустой")
    if len(html.encode()) > MAX_CUSTOM_SIZE:
        raise SiteError("Шаблон больше 1 МБ: вынесите картинки на внешний хостинг или сожмите их")
    CUSTOM_FILE.write_text(html)
    _publish(html)
    _save_state(template="custom", updated_at=int(time.time()))


def status() -> dict[str, Any]:
    state = _state()
    site_domain = domain()
    https = os.getenv("SITE_HTTPS") == "1" and tls.cert_info() is not None
    return {
        "nginx": tls.nginx_mode(),
        "domain": site_domain,
        "https": https,
        "url": f"{'https' if https else 'http'}://{site_domain}" if site_domain else "",
        "current": state.get("template", ""),
        "updated_at": state.get("updated_at"),
        "templates": TEMPLATES,
        "custom_html": CUSTOM_FILE.read_text() if CUSTOM_FILE.exists() else "",
    }
