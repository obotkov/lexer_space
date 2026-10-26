"""HTTPS for the admin itself: Let's Encrypt certificate via certbot.

The HTTP-01 challenge on port 80 is answered in one of two ways:
* nginx mode (install.sh set up nginx for the decoy site): nginx serves
  /.well-known/acme-challenge/ from data/acme, certbot uses --webroot. The same
  certificate is then used by nginx for the site on 443 (see nginx.sh).
* standalone: certbot binds port 80 itself for the few seconds of the check,
  so the port stays free the rest of the time. Needs host networking.
Either way the admin keeps serving on its own port, so port 443 is not needed.

uvicorn cannot swap certificates on the fly: after issuing, renewing or
disabling, the process exits and Docker's restart policy starts it again with
the new settings (see run.py).
"""

import asyncio
import json
import logging
import os
import re
import socket
import time
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509

from .config import settings

log = logging.getLogger("vpn_admin.tls")

CONFIG_FILE = settings.data_dir / "tls.json"
LE_DIR = settings.data_dir / "letsencrypt"
CERT_NAME = "vpn-admin"
CERT_FILE = LE_DIR / "live" / CERT_NAME / "fullchain.pem"
KEY_FILE = LE_DIR / "live" / CERT_NAME / "privkey.pem"
ACME_WEBROOT = settings.data_dir / "acme"
NGINX_MARKER = settings.data_dir / "nginx.enabled"  # written by install.sh when nginx serves port 80
NGINX_RELOAD = settings.data_dir / "nginx.reload"  # picked up by the vpn-admin-nginx.path unit on the host

RENEW_BEFORE_DAYS = 30
RENEW_CHECK_INTERVAL = 12 * 3600
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")

# Overridable for tests against a local ACME server (Pebble)
ACME_SERVER = os.getenv("ACME_SERVER", "")
ACME_INSECURE = os.getenv("ACME_INSECURE", "") == "1"
CHALLENGE_PORT = int(os.getenv("ACME_HTTP_PORT", "80"))


class TLSError(Exception):
    pass


def load_config() -> dict[str, Any]:
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_config(**changes: Any) -> dict[str, Any]:
    config = {**load_config(), **changes}
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(config, ensure_ascii=False, indent=2))
    tmp.replace(CONFIG_FILE)
    return config


def cert_info() -> dict[str, Any] | None:
    if not CERT_FILE.exists() or not KEY_FILE.exists():
        return None
    try:
        cert = x509.load_pem_x509_certificate(CERT_FILE.read_bytes())
    except ValueError:
        return None
    not_after = cert.not_valid_after_utc
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = []
    issuer = (cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
              or cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME))
    return {
        "domains": names,
        "not_after": int(not_after.timestamp()),
        "days_left": int((not_after.timestamp() - time.time()) // 86400),
        "issuer": issuer[0].value if issuer else "",
        "staging": "STAGING" in cert.issuer.rfc4514_string().upper(),
    }


def should_serve_tls() -> bool:
    """Decided at startup by run.py: enabled in config and a readable, unexpired certificate exists."""
    info = cert_info()
    return bool(load_config().get("enabled")) and info is not None and info["days_left"] >= 0


def is_active() -> bool:
    return os.getenv("TLS_ACTIVE") == "1"


def nginx_mode() -> bool:
    return NGINX_MARKER.exists()


def request_nginx_reload() -> None:
    """Asks the host to regenerate the nginx config (e.g. enable 443 with a new certificate) and reload it."""
    if nginx_mode():
        NGINX_RELOAD.write_text(str(int(time.time())))


def caddy_domain() -> str:
    """Set when install.sh put Caddy in front: then Caddy terminates TLS and this module stays off."""
    return os.getenv("DOMAIN", "").strip()


def status() -> dict[str, Any]:
    config = load_config()
    return {
        "enabled": bool(config.get("enabled")),
        "active": is_active(),
        "domain": config.get("domain", ""),
        "email": config.get("email", ""),
        "staging": bool(config.get("staging")),
        "last_error": config.get("last_error"),
        "last_renew_check": config.get("last_renew_check"),
        "certificate": cert_info(),
        "port": int(os.getenv("PORT", "8080")),
        "caddy_domain": caddy_domain(),
        "challenge": "nginx" if nginx_mode() else "standalone",
        "site_domain": os.getenv("SITE_DOMAIN", ""),
    }


async def check_domain(domain: str) -> dict[str, Any]:
    """Does the domain point at this server? Let's Encrypt will fail otherwise."""
    domain = _validate_domain(domain)
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
        resolved = sorted({info[4][0] for info in infos})
    except socket.gaierror:
        resolved = []
    public_ip = None
    try:
        async with httpx.AsyncClient(timeout=5) as http:
            public_ip = (await http.get("https://api.ipify.org")).text.strip()
    except httpx.HTTPError:
        pass
    return {"domain": domain, "resolved": resolved, "server_ip": public_ip,
            "matches": bool(public_ip and public_ip in resolved)}


def _validate_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        raise TLSError("Укажите домен, например admin.example.com. Let's Encrypt не выдаёт сертификаты на IP-адреса")
    return domain


def _certbot_base() -> list[str]:
    args = ["certbot", "--non-interactive", "--config-dir", str(LE_DIR), "--work-dir", str(LE_DIR / "work"),
            "--logs-dir", str(LE_DIR / "logs")]
    if ACME_INSECURE:
        args.append("--no-verify-ssl")
    return args


ERROR_HINTS = [
    ("Could not bind TCP port", "Порт 80 занят другой программой (nginx, Caddy, acme.sh 3x-ui?). "
                                "Освободите его на время выпуска: Let's Encrypt проверяет домен через порт 80"),
    ("Address already in use", "Порт 80 занят другой программой. Освободите его на время выпуска сертификата"),
    ("too many certificates", "Превышен лимит Let's Encrypt на выпуск сертификатов для этого домена. "
                              "Попробуйте позже или включите тестовый режим"),
    ("rateLimited", "Превышен лимит запросов Let's Encrypt. Попробуйте позже"),
    ("DNS problem", "Let's Encrypt не нашёл домен в DNS: проверьте A-запись"),
    ("Timeout during connect", "Let's Encrypt не достучался до сервера по порту 80: откройте порт 80 в файрволе "
                               "и проверьте, что A-запись домена указывает на этот сервер"),
    ("Connection refused", "Let's Encrypt не смог подключиться к порту 80: проверьте файрвол и A-запись домена"),
    ("Invalid response from", "Let's Encrypt получил с порта 80 не тот ответ: проверьте, что A-запись указывает "
                              "на этот сервер и порт 80 обслуживает nginx админки"),
    ("unauthorized", "Let's Encrypt не подтвердил домен: проверьте, что A-запись указывает на этот сервер "
                     "и порт 80 открыт"),
]


async def _run_certbot(args: list[str], timeout: int = 240) -> str:
    proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise TLSError("certbot не уложился в отведённое время")
    output = out.decode(errors="replace")
    if proc.returncode != 0:
        log.warning("certbot failed: %s", output)
        hint = next((h for needle, h in ERROR_HINTS if needle in output), None)
        tail = "\n".join(output.strip().splitlines()[-8:])
        raise TLSError(f"{hint}\n\n{tail}" if hint else f"certbot завершился с ошибкой:\n{tail}")
    return output


_lock = asyncio.Lock()


async def issue(domain: str, email: str, staging: bool) -> dict[str, Any]:
    domain = _validate_domain(domain)
    email = email.strip()
    if caddy_domain():
        raise TLSError(f"HTTPS уже обеспечивает Caddy для домена {caddy_domain()}")
    async with _lock:
        current = cert_info()
        if current and domain not in current["domains"]:
            current = None  # another domain: certbot replaces the names in the same lineage, the old cert stays until then
        if nginx_mode():
            ACME_WEBROOT.mkdir(parents=True, exist_ok=True)
            method = ["--webroot", "-w", str(ACME_WEBROOT)]
        else:
            method = ["--standalone", "--http-01-port", str(CHALLENGE_PORT)]
        args = [*_certbot_base(), "certonly", *method, "--preferred-challenges", "http",
                "--cert-name", CERT_NAME, "-d", domain, "--agree-tos"]
        # same domain, but switching between test and real certificates: certbot would keep the old one
        args.append("--force-renewal" if current and current["staging"] != staging else "--keep-until-expiring")
        args += ["-m", email] if email else ["--register-unsafely-without-email"]
        if staging:
            args.append("--test-cert")
        if ACME_SERVER:
            args += ["--server", ACME_SERVER]
        try:
            output = await _run_certbot(args)
        except TLSError as exc:
            save_config(last_error=str(exc))
            raise
        save_config(enabled=True, domain=domain, email=email, staging=staging, last_error=None,
                    issued_at=int(time.time()))
        request_nginx_reload()
        return {"output": output, "certificate": cert_info()}


async def renew(force: bool = False) -> bool:
    """Returns True when a new certificate was installed (the process should restart)."""
    async with _lock:
        before = cert_info()
        if not before:
            raise TLSError("Сертификат ещё не выпущен")
        # certbot sleeps up to 8 minutes before a non-interactive renewal to spread load on Let's Encrypt;
        # our checks already run at an arbitrary time every 12 hours, and a manual renewal must not hang
        args = [*_certbot_base(), "renew", "--cert-name", CERT_NAME, "--no-random-sleep-on-renew"]
        if force:
            args.append("--force-renewal")
        if ACME_SERVER:
            args += ["--server", ACME_SERVER]
        try:
            await _run_certbot(args)
        except TLSError as exc:
            save_config(last_error=str(exc), last_renew_check=int(time.time()))
            raise
        after = cert_info()
        save_config(last_error=None, last_renew_check=int(time.time()))
        renewed = bool(after and after["not_after"] != before["not_after"])
        if renewed:
            request_nginx_reload()
        return renewed


def disable() -> None:
    save_config(enabled=False)


def restart_soon(delay: float = 1.5) -> None:
    """Exit after the response is sent; Docker (restart: unless-stopped) starts the admin again."""
    log.info("Restarting to apply TLS settings")
    asyncio.get_running_loop().call_later(delay, os._exit, 0)


async def renewal_loop() -> None:
    while True:
        await asyncio.sleep(60)
        config, info = load_config(), cert_info()
        if config.get("enabled") and info and info["days_left"] < RENEW_BEFORE_DAYS:
            log.info("Certificate expires in %s days, renewing", info["days_left"])
            try:
                if await renew():
                    restart_soon()
            except TLSError as exc:
                log.warning("Renewal failed: %s", exc)
        await asyncio.sleep(RENEW_CHECK_INTERVAL)
