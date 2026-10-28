"""New VPN server through a hosting account: order a server, install 3x-ui on it and
attach it as a node of a main 3x-ui v3 panel.

The admin generates everything the node needs up front (panel port, path, login,
password, a self-signed TLS certificate and an SSH key of its own for this server).
The hosting gets only a tiny cloud-init script (VDSina: the key itself) that lets
that key in as root; the admin then logs in over SSH and runs the install: Docker,
the official 3x-ui image, the decoy page on port 80, a Let's Encrypt certificate
for the chosen domain or the server's IP, `x-ui setting`. The install removes the
key again. The admin waits for the panel, checks which certificate it serves,
mints an API token for the main panel and adds the node there: verified by the CA
for a Let's Encrypt certificate, pinned for the self-signed fallback.

Because the cloud-init script runs again whenever the hosting reinstalls the OS,
the admin can always log in afterwards and run the current install from zero.

A reinstall is a new job that takes over an existing one. Where the hosting can
reinstall the OS (DigitalOcean, OVHcloud, VDSina) it does so on the same server
and the IP stays; elsewhere a fresh server is ordered and the old one removed.
Either way the same node of the main panel switches over to the new install.

Steps run in a background task and are saved after each one, so an admin restart
resumes the job where it stopped.
"""

import asyncio
import base64
import contextlib
import datetime
import hashlib
import ipaddress
import logging
import re
import secrets
import shlex
import ssl
import string
import time
from typing import Any
from urllib.parse import urlsplit

import asyncssh
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import BaseModel, Field, field_validator

from . import cdn, connections, db, dns, hosters, nodes, probe, site
from .aggregator import overview_cache, pool
from .xui import XUIClient, XUIError

log = logging.getLogger("vpn-admin.provision")

XUI_IMAGE = "ghcr.io/mhsanaei/3x-ui:latest"
STUB_IMAGE = "nginx:alpine"
SSH_KEY_COMMENT = "vpn-admin-setup"
STEPS = ["create", "boot", "install", "connect", "connections", "retire", "done"]
IN_PLACE_STEPS = ["rebuild", "boot", "install", "connect", "connections", "retire", "done"]
BOOT_TIMEOUT = 10 * 60
INSTALL_TIMEOUT = 25 * 60
SSH_WAIT = 5 * 60  # how long a started server may keep SSH closed before the install gives up
DNS_WAIT = 20 * 60  # how long the script waits for the domain's A record before taking a certificate for the IP
POLL_EVERY = 10
NODE_LOG = "/var/log/vpn-admin-node.log"
INSTALL_FILE = "/root/vpn-admin-install.sh"
INSTALL_PID = "/run/vpn-admin-install.pid"  # the install runs as its own process group, led by this pid

_tasks: dict[int, asyncio.Task] = {}
_background: set[asyncio.Task] = set()  # roll-outs nobody awaits; kept so they are not garbage-collected
_fresh: dict[int, bool] = {}  # jobs whose install the admin asked to run again rather than follow


class ProvisionError(Exception):
    pass


def _site_template(value: str) -> str:
    if value and value not in site.TEMPLATE_IDS | {"custom"}:
        raise ValueError("Нет такого шаблона заглушки")
    return value


class ProvisionIn(BaseModel):
    hoster_id: int
    panel_id: int
    name: str
    region: str = Field(min_length=1)
    plan: str = Field(min_length=1)
    project: str | None = None
    ssh_keys: list[str] = []
    # what the form showed: some hostings use bare IDs for regions and plans
    region_label: str = ""
    plan_label: str = ""
    domain: str = ""  # panel address with a Let's Encrypt certificate; empty = the server's IP
    # the admin keeps the domain's A record in this Cloudflare account and zone; 0 = the user creates it
    dns_account_id: int = 0
    dns_zone_id: str = ""
    site_template: str = ""  # decoy page on port 80: a template of the admin's site, "custom" or "" for none
    connections: bool = True  # create connection templates on the new node
    connection_ids: list[int] | None = None  # which templates; None = every enabled one
    os: str = hosters.DEFAULT_OS  # one of hosters.OS_LABELS

    @field_validator("os")
    @classmethod
    def known_os(cls, value: str) -> str:
        if value not in hosters.OS_LABELS:
            raise ValueError(f"Система: одна из {', '.join(hosters.OS_LABELS.values())}")
        return value

    @field_validator("site_template")
    @classmethod
    def known_template(cls, value: str) -> str:
        return _site_template(value)

    @field_validator("domain")
    @classmethod
    def domain_name(cls, value: str) -> str:
        value = value.strip().lower().rstrip(".")
        if value and not re.fullmatch(r"(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
            raise ValueError("Домен: например vpn1.example.com, без http:// и пути")
        return value

    @field_validator("name")
    @classmethod
    def hostname(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,62}", value):
            raise ValueError("Имя сервера: латинские буквы, цифры, точка и дефис, до 63 символов")
        return value


class ReinstallIn(BaseModel):
    in_place: bool = True  # only where the hosting can reinstall the OS; otherwise a new server
    plan: str = ""  # new server only; empty = the plan of the server being replaced
    plan_label: str = ""
    site_template: str | None = None  # decoy page; None = as before

    @field_validator("site_template")
    @classmethod
    def known_template(cls, value: str | None) -> str | None:
        return value if value is None else _site_template(value)


# ---------- what the new server gets ----------

def _random(length: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def make_certificate() -> tuple[str, str, str]:
    """Self-signed certificate for the node panel: (cert PEM, key PEM, pin).
    The pin is what 3x-ui compares in "pin" TLS mode: base64 of SHA-256 over the DER certificate."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vpn-admin-node")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("vpn-admin-node")]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    return cert_pem, key_pem, base64.b64encode(hashlib.sha256(der).digest()).decode()


def make_ssh_key() -> str:
    """The admin's SSH key for one server, private part in OpenSSH format."""
    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                             serialization.NoEncryption()).decode()


def ssh_public_line(private: str) -> str:
    """authorized_keys line of the admin's key, with the comment the install removes it by."""
    key = serialization.load_ssh_private_key(private.encode(), password=None)
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return f"{public} {SSH_KEY_COMMENT}"


def bootstrap_user_data(p: db.Provision) -> str:
    """cloud-init script: only lets the admin's key in as root, the install comes over SSH. Hostings run it
    again after reinstalling the OS, so the admin can always get back in. Root logs in by key only, which is
    Ubuntu's default; some images forbid root, so it is said explicitly."""
    return f"""#!/bin/bash
# vpn-admin: 3x-ui node "{p.name}", installed by the admin over SSH
mkdir -p /root/.ssh && chmod 700 /root/.ssh
echo {shlex.quote(ssh_public_line(p.secrets["service_key"]))} >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
if [ -d /etc/ssh/sshd_config.d ]; then
  echo "PermitRootLogin prohibit-password" > /etc/ssh/sshd_config.d/00-vpn-admin.conf
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
fi
"""


def _drop_setup_key_script() -> str:
    """Remove the admin's key from root and every user it may have been given to."""
    return (f"for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do "
            f"[ -f \"$f\" ] && sed -i '/ {SSH_KEY_COMMENT}$/d' \"$f\"; done\n")


def _authorized_keys_script(user_keys: list[str]) -> str:
    """Give root the user's keys chosen in the form (hostings without cloud-init), then drop the admin's key."""
    lines = ["mkdir -p /root/.ssh && chmod 700 /root/.ssh && touch /root/.ssh/authorized_keys"]
    for key in user_keys:
        quoted = shlex.quote(key)
        lines.append(f"grep -qxF {quoted} /root/.ssh/authorized_keys || echo {quoted} >> /root/.ssh/authorized_keys")
    return "\n".join(lines) + "\n" + _drop_setup_key_script()


def _stub_html(p: db.Provision) -> str:
    if p.site_template == "custom":
        html = site.CUSTOM_FILE.read_text() if site.CUSTOM_FILE.exists() else ""
    else:
        html = site.template_html(p.site_template) if p.site_template in site.TEMPLATE_IDS else ""
    return html.replace("{{domain}}", p.domain or "example.com").replace("{{year}}", time.strftime("%Y"))


def _stub_script(p: db.Provision) -> str:
    """Decoy page on port 80 (nginx in Docker), like the admin's own site. Port 443 stays for VPN inbounds.
    The same nginx answers Let's Encrypt's checks, so certificates renew without stopping it."""
    html = _stub_html(p) if p.site_template else ""
    if not html.strip():
        return 'ACME_MODE="--standalone --httpport 80"\n'
    return f"""
# decoy page on port 80; Let's Encrypt checks are answered from /opt/vpn-stub/acme
mkdir -p /opt/vpn-stub/html /opt/vpn-stub/acme
cat > /opt/vpn-stub/html/index.html <<'VPN_ADMIN_STUB_HTML'
{html.strip()}
VPN_ADMIN_STUB_HTML
cat > /opt/vpn-stub/default.conf <<'NGINX'
server {{
    listen 80 default_server;
    server_name _;
    server_tokens off;
    location /.well-known/acme-challenge/ {{ root /var/www/acme; }}
    location / {{ root /usr/share/nginx/html; try_files $uri /index.html; }}
}}
NGINX
docker rm -f vpn-stub >/dev/null 2>&1 || true
stage "Запускаю сайт-заглушку на порту 80"
if retry docker pull {STUB_IMAGE}; then
  docker run -d --name vpn-stub --restart unless-stopped --network host \\
    -v /opt/vpn-stub/html:/usr/share/nginx/html:ro -v /opt/vpn-stub/acme:/var/www/acme:ro \\
    -v /opt/vpn-stub/default.conf:/etc/nginx/conf.d/default.conf:ro {STUB_IMAGE}
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow 80/tcp; fi
fi
if docker ps --format '{{{{.Names}}}}' | grep -qx vpn-stub; then
  ACME_MODE="--webroot /opt/vpn-stub/acme"
else
  stage "Сайт-заглушка не запустилась, продолжаю без неё"; ACME_MODE="--standalone --httpport 80"
fi
"""


def _certificate_script(p: db.Provision) -> str:
    """Let's Encrypt for the domain once its A record points here, otherwise for the IP (short-lived,
    renewed by acme.sh's cron); without either the panel keeps the self-signed certificate."""
    return f"""
# TLS for the panel: Let's Encrypt, the self-signed certificate from the admin as the fallback
CERT=/root/cert/panel.crt KEY=/root/cert/panel.key
DOMAIN={shlex.quote(p.domain) if p.domain else "''"}
IP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \\([0-9.]*\\).*/\\1/p')
ACME=/root/.acme.sh/acme.sh
le_issue() {{  # $1: domain or IP, the rest: extra acme.sh options
  local name="$1"; shift
  stage "Получаю сертификат Let's Encrypt на $name"
  if ! "$ACME" --issue -d "$name" $ACME_MODE --server letsencrypt --force "$@"; then
    rm -rf "/root/.acme.sh/$name" "/root/.acme.sh/${{name}}_ecc"; return 1
  fi
  # the reload fails while the panel is not running yet: the installed files are what counts
  "$ACME" --install-cert -d "$name" --key-file /opt/3x-ui/cert/le.key --fullchain-file /opt/3x-ui/cert/le.crt \\
    --reloadcmd "docker restart 3x-ui" || true
  chmod 600 /opt/3x-ui/cert/le.key 2>/dev/null
  [ -s /opt/3x-ui/cert/le.crt ] && [ -s /opt/3x-ui/cert/le.key ] && CERT=/root/cert/le.crt KEY=/root/cert/le.key
}}
dns_points_here() {{
  curl -fsS -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$DOMAIN&type=A" \\
    | grep -q "\\"data\\":\\"$IP\\""
}}
case "$IP" in
  ""|10.*|127.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) PUBLIC=0; stage "Нет публичного IPv4 ($IP): Let's Encrypt пропущен" ;;
  *) PUBLIC=1 ;;
esac
[ "$PUBLIC" = 1 ] && stage "Ставлю socat, cron и acme.sh для Let's Encrypt"
if [ "$PUBLIC" = 1 ] && retry sh -c 'apt-get -o DPkg::Lock::Timeout=300 update -q && apt-get -o DPkg::Lock::Timeout=300 install -y -q socat cron' \\
   && {{ [ -x "$ACME" ] || retry sh -c 'curl -fsSL https://get.acme.sh | sh'; }}; then
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow 80/tcp; fi
  if [ -n "$DOMAIN" ]; then
    stage "Жду A-запись $DOMAIN → $IP (до {DNS_WAIT // 60} минут)"
    for i in $(seq {DNS_WAIT // 20}); do dns_points_here && break; sleep 20; done
    dns_points_here && le_issue "$DOMAIN"
  fi
  [ "$CERT" = /root/cert/panel.crt ] && le_issue "$IP" --certificate-profile shortlived --days 3
fi
case "$CERT" in
  /root/cert/le.crt) stage "Сертификат Let's Encrypt получен" ;;
  *) stage "Let's Encrypt сертификат не выдал: панель будет на самоподписанном" ;;
esac
"""


def _sub_port_script(p: db.Provision) -> str:
    """`x-ui setting` has no flag for the subscription port, so it goes into the panel's database before the
    first start: 2096 is the first port scanners try on a 3x-ui server."""
    if not p.sub_port:
        return ""
    return f"""python3 - <<'PY' || echo "vpn-admin: subscription port not changed"
import sqlite3
db = sqlite3.connect("/opt/3x-ui/db/x-ui.db")
if not db.execute("UPDATE settings SET value = ? WHERE key = 'subPort'", ("{p.sub_port}",)).rowcount:
    db.execute("INSERT INTO settings (key, value) VALUES ('subPort', ?)", ("{p.sub_port}",))
db.commit()
PY
"""


def install_script(p: db.Provision, extra: str = "") -> str:
    """The install the admin starts over SSH: Docker, the decoy page, a certificate and 3x-ui with the generated
    port, path, login and password; `extra` steps at the end. It runs detached on the server and reports its
    stages and exit code into its log, so a dropped SSH connection does not stop it."""
    return f"""#!/bin/bash
# vpn-admin: 3x-ui node "{p.name}"
set -u
umask 022  # nginx reads the decoy page and the Let's Encrypt challenges as its own user
exec > {NODE_LOG} 2>&1
echo $$ > {INSTALL_PID}
trap 'echo "vpn-admin-exit: $?"; rm -f {INSTALL_FILE} {INSTALL_PID}' EXIT
export DEBIAN_FRONTEND=noninteractive HOME=/root

# "vpn-admin-stage:" lines are what the admin shows in the job's log
stage() {{ echo "vpn-admin-stage: $*"; }}
retry() {{ for i in 1 2 3 4 5 6; do "$@" && return 0; echo "retry $i: $*"; stage "Не получилось (попытка $i из 6), повторяю через 20 с"; sleep 20; done; return 1; }}

if command -v cloud-init >/dev/null; then
  stage "Жду, пока система закончит первую настройку (cloud-init)"
  timeout {BOOT_TIMEOUT} cloud-init status --wait >/dev/null 2>&1
fi
# an install stopped halfway may have left dpkg in the middle of something
dpkg --configure -a >/dev/null 2>&1 || true

stage "Готовлю сертификат панели и настройки сети"

mkdir -p /opt/3x-ui/db /opt/3x-ui/cert
cat > /opt/3x-ui/cert/panel.crt <<'CERT'
{p.cert_pem.strip()}
CERT
cat > /opt/3x-ui/cert/panel.key <<'KEY'
{p.secrets["key_pem"].strip()}
KEY
chmod 600 /opt/3x-ui/cert/panel.key

# BBR helps VPN throughput on lossy links
cat > /etc/sysctl.d/90-vpn-admin.conf <<'SYSCTL'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
SYSCTL
sysctl --system >/dev/null || true

# minimal Debian images may lack these
if ! command -v curl >/dev/null || ! command -v python3 >/dev/null; then
  stage "Ставлю curl и python3"
  retry sh -c 'apt-get -o DPkg::Lock::Timeout=300 update -q && apt-get -o DPkg::Lock::Timeout=300 install -y -q curl ca-certificates python3'
fi
if command -v docker >/dev/null; then
  stage "Docker уже установлен"
else
  stage "Устанавливаю Docker (get.docker.com), обычно 1–3 минуты"
  retry sh -c 'curl -fsSL https://get.docker.com | sh' || exit 1
fi
systemctl enable --now docker
stage "Скачиваю образ 3x-ui"
retry docker pull {XUI_IMAGE} || exit 1

docker rm -f 3x-ui >/dev/null 2>&1 || true
{_stub_script(p)}{_certificate_script(p)}
stage "Настраиваю и запускаю 3x-ui"
docker run --rm --entrypoint /app/x-ui -v /opt/3x-ui/db:/etc/x-ui -v /opt/3x-ui/cert:/root/cert {XUI_IMAGE} \\
  setting -port {p.port} -username {p.username} -password {p.secrets["password"]} -webBasePath {p.base_path} \\
  -webCert "$CERT" -webCertKey "$KEY"
{_sub_port_script(p)}docker run -d --name 3x-ui --restart unless-stopped --network host --cap-add NET_ADMIN --cap-add NET_RAW \\
  -e XRAY_VMESS_AEAD_FORCED=false -v /opt/3x-ui/db:/etc/x-ui -v /opt/3x-ui/cert:/root/cert {XUI_IMAGE}

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  stage "Открываю порты в ufw"
  ufw allow {p.port}/tcp{f"; ufw allow {p.sub_port}/tcp" if p.sub_port else ""}{"".join(f"; ufw allow {r}" for r in connections.ufw_rules(p.connections))}
fi
{extra}stage "Установка на сервере закончена"
"""


def _node_host(p: db.Provision) -> str:
    """Where the panel is opened: the chosen domain, also when it got no Let's Encrypt certificate."""
    return p.domain or p.ip


async def _node_address(p: db.Provision) -> str:
    """What the main panel connects to: the domain once it points at the server, otherwise the IP."""
    if p.domain and p.ip in await _addresses(p.domain):
        return p.domain
    if p.domain:
        _log(p, f"{p.domain} пока не указывает на {p.ip}: основная панель подключит узел по IP")
    return p.ip


def _node_url(p: db.Provision, host: str = "") -> str:
    return f"https://{host or _node_host(p)}:{p.port}{p.base_path}"


def _pinned_context(cert_pem: str) -> ssl.SSLContext:
    """Trusts only the certificate generated for this node; its name does not matter."""
    ctx = ssl.create_default_context(cadata=cert_pem)
    ctx.check_hostname = False
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN  # the self-signed leaf is the trust anchor
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    return ctx


# ---------- job ----------

def _log(p: db.Provision, message: str) -> None:
    p.log.append({"t": int(time.time()), "msg": message})
    db.update_provision(p.id, log=p.log[-120:])
    log.info("provision %s: %s", p.id, message)


def _set(p: db.Provision, **fields) -> None:
    for key, value in fields.items():
        setattr(p, key, value)
    db.update_provision(p.id, **fields)


async def _with_client(p: db.Provision, action):
    hoster = db.get_hoster(p.hoster_id)
    if not hoster:
        raise ProvisionError("Аккаунт хостинга удалён из админки")
    client = hosters.client_for(hoster)
    try:
        return await action(client)
    finally:
        await client.close()


async def _step_create(p: db.Provision) -> None:
    _log(p, f"Заказываю сервер {p.labels.get('plan') or p.plan}: {p.labels.get('region') or p.region}, "
            f"{hosters.OS_LABELS.get(p.os, p.os)}")

    # VDSina has no cloud-init and takes the key itself; UpCloud wants a login key for cloud-init servers
    server_id = await _with_client(p, lambda client: client.create_server(
        name=p.name, region=p.region, plan=p.plan, ssh_keys=p.ssh_keys, user_data=bootstrap_user_data(p),
        project=p.project or None, admin_key=ssh_public_line(p.secrets["service_key"]), os=p.os))
    _set(p, server_id=server_id)
    _log(p, f"Сервер создан у хостинга (id {server_id})")


def _steps(p: db.Provision) -> list[str]:
    return IN_PLACE_STEPS if p.in_place else STEPS


async def _panel_answers(p: db.Provision) -> bool:
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as http:  # noqa: S501 - only whether it is up
            return (await http.get(_node_url(p, p.ip))).status_code < 500
    except httpx.HTTPError:
        return False


async def _step_rebuild(p: db.Provision) -> None:
    """The hosting reinstalls the OS on the same server. Its cloud-init script (VDSina: the key passed again)
    lets the admin's key in, and the install runs as for a new server. Servers made before the admin had its
    own key re-run their old cloud-init install instead, so such a job carries the old panel credentials."""
    _log(p, f"Переустанавливаю систему на сервере {p.ip}: IP сохранится")
    admin_key = ssh_public_line(p.secrets["service_key"]) if "service_key" in p.secrets else None
    await _with_client(p, lambda client: client.rebuild_server(
        p.server_id, plan=p.plan, name=p.name, project=p.project or None, admin_key=admin_key, os=p.os))
    _log(p, "Хостинг принял переустановку, жду, пока старая система остановится")
    # the old panel must be gone before the install is awaited, or the admin would talk to the old one
    deadline, misses = time.time() + BOOT_TIMEOUT, 0
    while True:
        server = await _with_client(p, lambda c: c.get_server(p.server_id, p.project or None))
        misses = 0 if await _panel_answers(p) else misses + 1
        if server["status"] != "running" or misses >= 2:
            break
        if time.time() > deadline:
            raise ProvisionError(f"Старая система на сервере работает уже {BOOT_TIMEOUT // 60} минут после "
                                 "запроса переустановки: проверьте сервер в панели хостинга")
        await asyncio.sleep(POLL_EVERY)
    _log(p, "Старая система остановлена, хостинг ставит новую")


async def _step_boot(p: db.Provision) -> None:
    deadline = time.time() + BOOT_TIMEOUT
    while True:
        server = await _with_client(p, lambda c: c.get_server(p.server_id, p.project or None))
        if server["status"] == "error":
            raise ProvisionError(f"Хостинг сообщил об ошибке сервера: {server['status_label']}")
        if server["status"] == "running" and server["ipv4"]:
            _set(p, ip=server["ipv4"][0])
            _log(p, f"Сервер запущен, IP {p.ip}")
            if p.dns_account_id:
                try:
                    record_id = await dns.point(p.dns_account_id, p.dns_zone_id, p.domain, p.ip)
                except dns.DNSError as exc:
                    raise ProvisionError(f"Не удалось создать A-запись {p.domain}: {exc}") from exc
                _set(p, dns_record_id=record_id)
                _log(p, f"Cloudflare: A-запись {p.domain} → {p.ip} (без проксирования)")
                for item in p.connections:  # a reinstall onto a new server: its CDN names follow the node
                    if item.get("cdn_record_id"):
                        try:
                            await dns.point(p.dns_account_id, p.dns_zone_id, item["cdn_domain"], p.ip, proxied=True)
                            _log(p, f"Cloudflare: CDN-запись {item['cdn_domain']} → {p.ip}")
                        except dns.DNSError as exc:
                            _log(p, f"Cloudflare: CDN-запись {item['cdn_domain']} не переведена на {p.ip}: {exc}")
            elif p.domain and not p.in_place:
                _log(p, f"Создайте у регистратора домена A-запись {p.domain} → {p.ip}: установка ждёт её до "
                        f"{DNS_WAIT // 60} минут, иначе возьмёт сертификат Let's Encrypt на IP")
            return
        if time.time() > deadline:
            raise ProvisionError(f"Сервер не запустился за {BOOT_TIMEOUT // 60} минут (статус: {server['status_label']})")
        await asyncio.sleep(POLL_EVERY)


async def _install_over_ssh(p: db.Provision, fresh: bool) -> None:
    """Start the install as root over SSH with the admin's key and follow its log until it ends. The host key
    cannot be known in advance; what matters is checked after: the panel must answer with the certificate
    generated here. The install runs detached on the server, so the SSH connection may drop and be made again.
    `fresh`: the admin asked to run it again, so one still running is stopped; otherwise (an admin restart)
    a running install is followed and a finished one is taken as it is."""

    async def user_keys(client) -> list[str]:  # cloud-init hostings put the chosen keys in place themselves
        if getattr(client, "setup", "") == "ssh" and p.ssh_keys:
            return await client.public_keys(p.ssh_keys)
        return []

    keys_script = _authorized_keys_script(await _with_client(p, user_keys))
    key = asyncssh.import_private_key(p.secrets.get("service_key") or p.secrets["ssh_key"])
    deadline, ssh_deadline = time.time() + _install_timeout(p), time.time() + SSH_WAIT
    started, finished, shown, lost = False, False, 0, False
    _log(p, "Подключаюсь к серверу по SSH")
    while True:
        try:
            async with asyncssh.connect(p.ip, username="root", client_keys=[key], known_hosts=None,
                                        connect_timeout=15, keepalive_interval=15, keepalive_count_max=4) as conn:
                if lost:
                    _log(p, "SSH-подключение восстановлено, установка на сервере шла дальше")
                    lost = False
                if not finished:
                    status = await _remote_install(conn)
                    if not started:
                        started = True
                        if status["running"] and not fresh:
                            _log(p, "Установка на сервере уже идёт, слежу за ней")
                            shown = len(status["stages"])
                        elif status["exit"] == 0 and not fresh:
                            _log(p, "Установка на сервере уже закончена")
                            shown = len(status["stages"])
                        else:
                            if status["running"]:
                                _log(p, "Останавливаю незавершённую установку на сервере")
                            await conn.run(_launch_script(), input=install_script(p), check=True, timeout=60)
                            status = {"running": True, "stages": [], "exit": None}
                            _log(p, "SSH-подключение есть, установка запущена на сервере: Docker, 3x-ui"
                                    + (", сайт-заглушка" if p.site_template else "") + " и сертификат")
                    while True:
                        for stage in status["stages"][shown:]:
                            _log(p, stage)
                        shown = len(status["stages"])
                        if status["exit"] is not None:
                            break
                        if not status["running"]:  # killed, or the server rebooted: no exit code was written
                            raise ProvisionError("Установка на сервере прервалась (процесс остановлен или сервер "
                                                 "перезагрузился). Нажмите «Повторить», чтобы запустить её заново")
                        if time.time() > deadline:
                            raise ProvisionError(f"Установка на сервере не закончилась за {_install_timeout(p) // 60} "
                                                 f"минут. Журнал на сервере: {NODE_LOG}")
                        await asyncio.sleep(POLL_EVERY)
                        status = await _remote_install(conn)
                    if status["exit"] != 0:
                        tail = (await conn.run(f"tail -n 15 {NODE_LOG}", check=False)).stdout
                        raise ProvisionError(f"Установка на сервере завершилась с ошибкой (код {status['exit']}). "
                                             f"Конец журнала {NODE_LOG}: {str(tail).strip()[-1500:]}")
                    finished = True
                # the chosen keys in, the admin's out: from here on SSH does not let the admin in
                await conn.run(f"rm -f {INSTALL_FILE}\n{keys_script}true\n", check=True, timeout=60)
            break
        except (OSError, asyncssh.Error) as exc:  # the OS is still being installed, sshd is not up, the link dropped
            if finished and isinstance(exc, asyncssh.PermissionDenied):
                break  # the keys were swapped before the link dropped
            why = _ssh_reason(exc)
            if not started and time.time() > ssh_deadline:
                raise ProvisionError(f"Сервер {p.ip} не пустил по SSH за {SSH_WAIT // 60} минут ({why}): установка "
                                     "остановлена. Проверьте сервер в панели хостинга и нажмите «Повторить»") from exc
            if time.time() > deadline:
                raise ProvisionError(f"Не удалось выполнить установку по SSH за {_install_timeout(p) // 60} минут: "
                                     f"{why}") from exc
            if started and not lost:
                _log(p, f"SSH-подключение прервалось ({why}), переподключаюсь")
            elif not started and not lost:
                _log(p, f"SSH на сервере пока не отвечает ({why}), жду до {SSH_WAIT // 60} минут")
            lost = True
            await asyncio.sleep(POLL_EVERY)
    # the TLS key is on the server now; the SSH key stays for a later reinstall, but no longer opens the server
    _set(p, secrets={k: v for k, v in p.secrets.items() if k in ("password", "service_key")})
    _log(p, "Установка по SSH завершена, ключ админки удалён с сервера")

    async def forget(client):
        if hasattr(client, "forget_setup_key"):
            await client.forget_setup_key(p.name)

    try:
        await _with_client(p, forget)
    except (hosters.HosterError, ProvisionError) as exc:
        log.warning("provision %s: setup key not removed from the account: %s", p.id, exc)


def _ssh_reason(exc: Exception) -> str:
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return "нет ответа на порту 22"
    if isinstance(exc, ConnectionRefusedError):
        return "порт 22 закрыт"
    if isinstance(exc, asyncssh.PermissionDenied):
        return "ключ админки не принят"
    return str(exc) or type(exc).__name__


def _launch_script() -> str:
    """Stop an install still running, then start the one piped in, detached in its own session."""
    return f"""set -e
PID=$(cat {INSTALL_PID} 2>/dev/null || true)
if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
  kill -TERM -- "-$PID" 2>/dev/null || true
  for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$PID" 2>/dev/null || break; sleep 1; done
  kill -KILL -- "-$PID" 2>/dev/null || true
fi
(umask 077 && cat > {INSTALL_FILE})  # it holds the panel password; the install itself must not inherit this
rm -f {NODE_LOG} {INSTALL_PID}
setsid -f bash {INSTALL_FILE} </dev/null >/dev/null 2>&1
"""


async def _remote_install(conn) -> dict:
    """Whether the install runs on the server, the stages it has reported and its exit code once it ended."""
    result = await conn.run(
        f"PID=$(cat {INSTALL_PID} 2>/dev/null); [ -n \"$PID\" ] && kill -0 \"$PID\" 2>/dev/null && echo running; "
        f"grep -a '^vpn-admin-' {NODE_LOG} 2>/dev/null; true", check=False, timeout=30)
    status = {"running": False, "stages": [], "exit": None}
    for line in str(result.stdout).splitlines():
        if line == "running":
            status["running"] = True
        elif line.startswith("vpn-admin-stage: "):
            status["stages"].append(line.removeprefix("vpn-admin-stage: ").strip())
        elif line.startswith("vpn-admin-exit: "):
            status["exit"] = int(line.removeprefix("vpn-admin-exit: ").strip() or 1)
    if status["exit"] is not None:
        status["running"] = False  # the pid file goes in the same trap, a moment later
    return status


def _install_timeout(p: db.Provision) -> int:
    return INSTALL_TIMEOUT + (DNS_WAIT if p.domain else 0)


async def _served_certificate(host: str, port: int) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # only to see which certificate it is; trust is decided after
    _, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), 15)
    try:
        return writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        writer.close()


async def _ca_verifies(host: str, port: int, name: str) -> bool:
    """A certificate for `name` from a public CA, as browsers and the main panel will check it."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ssl.create_default_context(), server_hostname=name), 15)
    except (OSError, ssl.SSLError, asyncio.TimeoutError):
        return False
    writer.close()
    return True


async def _trust_node(p: db.Provision) -> ssl.SSLContext:
    """Decide by the certificate the panel serves how the node is trusted: the self-signed one generated
    here is pinned, a Let's Encrypt one for the domain or the IP is checked by the CA. The admin itself
    then talks to the node by IP, trusting exactly the certificate it checked."""
    der = await _served_certificate(p.ip, p.port)
    if base64.b64encode(hashlib.sha256(der).digest()).decode() == p.cert_pin:
        mode = "self"
    elif p.domain and await _ca_verifies(p.ip, p.port, p.domain):
        mode = "domain"
    elif await _ca_verifies(p.ip, p.port, p.ip):
        mode = "ip"
    else:
        raise ProvisionError("Панель узла отвечает чужим TLS-сертификатом: это не сертификат админки и не "
                             f"действующий сертификат на {p.domain or p.ip}")
    if mode != p.cert_mode:
        _set(p, cert_mode=mode)
    return _pinned_context(ssl.DER_cert_to_PEM_cert(der))


async def _step_install(p: db.Provision) -> None:
    fresh = _fresh.pop(p.id, False)
    if "service_key" in p.secrets or "ssh_key" in p.secrets:  # ssh_key: VDSina jobs of older versions
        await _install_over_ssh(p, fresh)
        _log(p, "Жду ответа панели 3x-ui")
    else:  # a server made by an older version re-runs its cloud-init install after an OS reinstall
        _log(p, f"Жду установку Docker, 3x-ui и сертификата (обычно 3–7 минут{', плюс ожидание DNS' if p.domain else ''})")
    deadline = time.time() + _install_timeout(p)
    async with httpx.AsyncClient(verify=False, timeout=10) as http:  # noqa: S501 - the certificate is checked next
        while True:
            try:
                resp = await http.get(_node_url(p, p.ip))
                if resp.status_code < 500:
                    break
            except httpx.HTTPError:  # refused / timeout while it installs: keep waiting
                pass
            if time.time() > deadline:
                raise ProvisionError(
                    f"Панель не ответила за {_install_timeout(p) // 60} минут. Журнал установки на сервере: "
                    "/var/log/vpn-admin-node.log")
            await asyncio.sleep(POLL_EVERY)
    await _trust_node(p)
    if p.cert_mode == "domain":
        _log(p, f"Панель 3x-ui отвечает, сертификат Let's Encrypt на {p.domain}")
    elif p.cert_mode == "ip":
        if p.domain:
            _log(p, f"A-запись {p.domain} → {p.ip} не появилась за {DNS_WAIT // 60} минут: взят сертификат на IP")
        _log(p, f"Панель 3x-ui отвечает, сертификат Let's Encrypt на IP {p.ip} (короткий, продлевается сам)")
    else:
        _log(p, "Панель 3x-ui отвечает, но Let's Encrypt сертификат не выдал: панель работает на самоподписанном, "
                "основная панель закрепит его (pin). Причина — в /var/log/vpn-admin-node.log на сервере")


async def _step_connect(p: db.Provision) -> None:
    trusted = await _trust_node(p)
    node = XUIClient(_node_url(p, p.ip), p.username, p.secrets["password"], trusted)
    try:
        token = await node.v3_create_api_token(f"vpn-admin-{int(time.time())}", "node-admin")
    except XUIError as exc:
        raise ProvisionError(f"Не удалось создать API-токен на узле: {exc}") from exc
    finally:
        await node.close()
    body = nodes.NodeIn(
        name=p.name, remark="создан через VPN API Hoster", scheme="https", address=await _node_address(p), port=p.port,
        base_path=p.base_path, api_token=token, tls_verify_mode="pin" if p.cert_mode == "self" else "verify",
        pinned_cert_sha256=p.cert_pin if p.cert_mode == "self" else "",
        allow_private_address=ipaddress.ip_address(p.ip).is_private,
    )
    try:
        current = await nodes.get(p.panel_id, p.node_id) if p.node_id else None
        if current:
            # reinstall: the old server's node switches over; its inbounds and clients stay in the main panel,
            # which pushes them to the fresh panel
            body.name, body.remark, body.enable = current["name"], current["remark"], current["enable"]
            body.inbound_sync_mode, body.inbound_tags = current["inbound_sync_mode"], current["inbound_tags"]
            target = "новую установку 3x-ui" if p.in_place else "новый сервер"
            _log(p, f"API-токен узла создан, переключаю узел «{current['name']}» основной панели на {target}")
            await nodes.update(p.panel_id, p.node_id, body)
            _log(p, f"Узел основной панели переключён на {target}")
            return
        _log(p, "API-токен узла создан, добавляю узел в основную панель")
        created = await nodes.add(p.panel_id, body)
    except nodes.NodeError as exc:
        raise ProvisionError(f"Основная панель не приняла узел: {exc}") from exc
    node_id = created.get("id") if isinstance(created, dict) else None
    _set(p, node_id=node_id)
    _log(p, "Узел добавлен в основную панель")


async def _step_retire(p: db.Provision) -> None:
    """Reinstall: the node already runs on the new server, so the old one goes (it keeps costing money)."""
    old = db.get_provision(p.replaces) if p.replaces else None
    if not old:
        return
    if old.server_id and old.server_id != p.server_id and old.state != "deleted":
        _log(p, f"Удаляю старый сервер {old.ip or old.server_id} у хостинга")
        try:
            await _with_client(old, lambda c: c.delete_server(old.server_id, old.project or None))
        except hosters.HosterError as exc:
            if exc.code != "NOT_FOUND":  # already deleted in the hosting's own panel
                raise
    db.delete_provision(old.id)
    _log(p, "Прежнее задание этого сервера убрано из списка" if p.in_place
         else "Старый сервер удалён, его задание убрано из списка")


def _busy_ports(p: db.Provision) -> set[tuple[int, str]]:
    """Ports of the node no connection may take: the panel, the subscription and the decoy page."""
    return {(p.port, "tcp"), (p.sub_port, "tcp"), (80, "tcp")}


def _target(p: db.Provision) -> connections.Target:
    """The server as its inbounds see it: its name and the certificate the install left. Clients get the node's
    address from the main panel itself."""
    if p.cert_mode in ("domain", "ip"):
        cert, key, pin = "/root/cert/le.crt", "/root/cert/le.key", ""
    elif p.cert_mode == "self":
        cert, key, pin = "/root/cert/panel.crt", "/root/cert/panel.key", connections.pin_hex(p.cert_pin)
    else:
        cert = key = pin = ""
    return connections.Target(server=p.name, tls_name=p.domain if p.cert_mode == "domain" else "",
                              cert_file=cert, key_file=key, pin_hex=pin, stub_html=_stub_html(p) if p.site_template else "",
                              region=p.labels.get("region") or p.region)


async def _cdn_names(p: db.Provision) -> None:
    """A CDN connection gets its CDN before its inbound: a name in the server's Cloudflare zone, a certificate
    and a CDN resource for it at the template's CDN account, with the node's domain as the HTTPS origin."""
    for item in p.connections:
        if item["kind"] != "vless_xhttp_cdn" or item.get("cdn_address") or item.get("inbound_id"):
            continue
        o = item["options"]
        if not p.dns_account_id or not p.domain:  # the reason shows up when its inbound cannot be built
            item["cdn_error"] = "у сервера нет домена Cloudflare: CDN-подключение работает только на таком сервере"
            continue
        try:
            zone = await dns.zone_name(p.dns_account_id, p.dns_zone_id)
            label = connections.fill(o.get("cdn_subdomain") or "cdn-{server}", _target(p).macros).replace(" ", "-")
            name = f"{label}.{zone}".lower()
            if not re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+", name):
                raise cdn.CDNError(f"имя {name} не годится для DNS: в шаблоне только латиница, цифры и дефис")

            async def put_record(kind: str, record: str, content: str) -> str:
                return await dns.put_record(p.dns_account_id, p.dns_zone_id, kind, record, content,
                                            f"vpn-admin: CDN-подключение {p.name}")

            await cdn.set_up(o.get("cdn_account_id") or 0, item, name, f"{p.domain}:{item['port']}", put_record,
                             lambda m: _log(p, m), lambda: _set(p, connections=p.connections))
            item.pop("cdn_error", None)
        except (cdn.CDNError, dns.DNSError) as exc:
            item["cdn_error"] = str(exc)
    _set(p, connections=p.connections)


async def _roll_out(p: db.Provision) -> None:
    await _cdn_names(p)
    _, xui = await nodes.main_panel(p.panel_id)
    try:
        await connections.rollout(xui, p.node_id, p.connections, _target(p), lambda m: _log(p, m),
                                  lambda items: _set(p, connections=items))
    except connections.TemplateError as exc:
        raise ProvisionError(f"Подключения: {exc}") from exc
    finally:
        overview_cache.invalidate()
        probe.kick()  # the new connects get the service client and their first check


async def _step_connections(p: db.Provision) -> None:
    pending = [c for c in p.connections if not c.get("inbound_id") and not c.get("error")]
    if not pending or not p.node_id:
        return  # nothing planned, or a reinstall: the node keeps the inbounds it had
    _log(p, f"Создаю подключения на узле: {len(pending)} шт.")
    await _roll_out(p)


async def apply_connections(provision_id: int) -> dict:
    """Add the enabled templates this node does not have yet; what it has stays untouched."""
    p = db.get_provision(provision_id)
    if not p:
        raise ProvisionError("Задание не найдено")
    if p.state != "done" or not p.node_id:
        raise ProvisionError("Раскатать подключения можно на сервер, который уже работает узлом основной панели")
    try:
        _, xui = await nodes.main_panel(p.panel_id)
        existing = [i for i in await xui.inbounds() if i.get("nodeId") == p.node_id]
    except (nodes.NodeError, XUIError) as exc:
        raise ProvisionError(f"Основная панель: {exc}") from exc
    alive = {i.get("id") for i in existing}
    kept = [c for c in p.connections if c.get("inbound_id") in alive]
    have = {c["template_id"] for c in kept}
    missing = [t for t in connections.snapshot(connections.templates()) if t["template_id"] not in have]
    if not missing:
        raise ProvisionError("На сервере уже есть все включённые подключения")
    taken = _busy_ports(p) | {(i.get("port"), n) for i in existing for n in connections.inbound_nets(i)}
    planned = connections.plan(missing, taken)
    # a CDN connection that did not get its inbound last time keeps what its CDN already has (certificate,
    # resource, records) and the port the resource leads to
    earlier = {c["template_id"]: c for c in p.connections if c not in kept and c.get("cdn_cert_id")}
    for item in planned:
        before = earlier.get(item["template_id"])
        if before:
            item.update({k: v for k, v in before.items() if k.startswith("cdn_")}, port=before["port"])
    _set(p, connections=kept + planned)
    _log(p, f"Раскатываю подключения на узел: {len(missing)} шт.")
    if any(i["kind"] == "vless_xhttp_cdn" for i in planned):
        # a CDN takes up to half an hour (certificate, resource): the button does not wait for it
        _log(p, "CDN-подключение настраивается в фоне, ход — в этом журнале")
        task = asyncio.create_task(_roll_out_logged(p))
        _background.add(task)
        task.add_done_callback(_background.discard)
        return public(db.get_provision(p.id))
    try:
        await _roll_out(p)
    except (ProvisionError, nodes.NodeError) as exc:
        _log(p, f"Ошибка: {exc}")
        raise ProvisionError(str(exc)) from exc
    return public(db.get_provision(p.id))


async def _roll_out_logged(p: db.Provision) -> None:
    try:
        await _roll_out(p)
        _log(p, "Подключения раскатаны")
    except Exception as exc:  # noqa: BLE001 - nobody waits for this task: the job's log is where it ends up
        _log(p, f"Ошибка: {exc}")


STEP_RUNNERS = {"create": _step_create, "rebuild": _step_rebuild, "boot": _step_boot, "install": _step_install,
                "connect": _step_connect, "connections": _step_connections, "retire": _step_retire}


async def run(provision_id: int) -> None:
    p = db.get_provision(provision_id)
    if not p or p.state != "running":
        return
    try:
        while p.step != "done":
            await STEP_RUNNERS[p.step](p)
            steps = _steps(p)
            _set(p, step=steps[steps.index(p.step) + 1])
        _set(p, state="done", error="")
        _log(p, "Готово: сервер работает узлом основной панели")
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - every failure must end up on the job, not in the void
        message = str(exc) or type(exc).__name__
        if not isinstance(exc, (ProvisionError, hosters.HosterError)):
            log.exception("provision %s failed", provision_id)
        _set(p, state="failed", error=message)
        _log(p, f"Ошибка: {message}")
    finally:
        _tasks.pop(provision_id, None)
        hosters.invalidate(p.hoster_id)
        overview_cache.invalidate()


def _spawn(provision_id: int) -> None:
    if provision_id not in _tasks:
        _tasks[provision_id] = asyncio.create_task(run(provision_id))


def resume_all() -> None:
    """After an admin restart: continue every job that was in progress."""
    for p in db.list_provisions():
        if p.state == "running":
            _spawn(p.id)


async def start(body: ProvisionIn) -> dict:
    hoster = db.get_hoster(body.hoster_id)
    if not hoster:
        raise ProvisionError("Аккаунт хостинга не найден")
    try:
        await nodes.main_panel(body.panel_id)  # must be a reachable 3x-ui v3 panel
    except nodes.NodeError as exc:
        raise ProvisionError(f"Основная панель: {exc}") from exc
    if body.dns_account_id:
        await _check_dns_name(body)
    p = _new_job(hoster_id=hoster.id, panel_id=body.panel_id, name=body.name, region=body.region, plan=body.plan,
                 project=body.project or "", ssh_keys=body.ssh_keys, domain=body.domain,
                 site_template=body.site_template, os=body.os,
                 dns_account_id=body.dns_account_id if body.domain else 0, dns_zone_id=body.dns_zone_id,
                 labels={"region": body.region_label.strip()[:100], "plan": body.plan_label.strip()[:100]})
    if body.connections:
        # ports are fixed now: the install opens them in ufw
        chosen = connections.snapshot(connections.templates(), body.connection_ids)
        _set(p, connections=connections.plan(chosen, _busy_ports(p)))
    _log(p, "Задание создано")
    _spawn(p.id)
    return public(p)


async def _check_dns_name(body: ProvisionIn) -> None:
    """The name must belong to the chosen zone and must not already point somewhere else."""
    if not body.domain:
        raise ProvisionError("Укажите имя сервера в домене Cloudflare")
    try:
        zone = await dns.zone_name(body.dns_account_id, body.dns_zone_id)
        if body.domain != zone and not body.domain.endswith("." + zone):
            raise ProvisionError(f"Имя {body.domain} не из домена {zone}")
        taken = await dns.existing_a(body.dns_account_id, body.dns_zone_id, body.domain)
    except dns.DNSError as exc:
        raise ProvisionError(str(exc)) from exc
    if taken:
        raise ProvisionError(f"В Cloudflare уже есть A-запись {body.domain} → {taken}: выберите другое имя")


def _new_job(service_key: str = "", **fields) -> db.Provision:
    """A job with fresh panel credentials and certificate for a server that is yet to be set up; the admin's
    SSH key is new too unless the server already trusts one (an OS reinstall)."""
    lower = string.ascii_lowercase + string.digits
    cert_pem, key_pem, pin = make_certificate()
    port, sub_port = secrets.SystemRandom().sample(range(20000, 60000), 2)  # five digits each, never the same
    return db.create_provision(**{
        "port": port, "sub_port": sub_port, "base_path": f"/{_random(14, lower)}/",
        "username": f"adm_{_random(6, lower)}",
        "secrets": {"password": _random(20), "key_pem": key_pem, "service_key": service_key or make_ssh_key()},
        "cert_pem": cert_pem, "cert_pin": pin, "step": "create", "state": "running", **fields,
    })


async def reinstall(provision_id: int, body: ReinstallIn) -> dict:
    """Start from zero with a freshly installed 3x-ui, the node of the main panel switching over to it.
    In place where the hosting can reinstall the OS (the IP stays), otherwise a new server with the same
    hosting and region (the plan may change) and the old server deleted (the IP changes)."""
    old = db.get_provision(provision_id)
    if not old:
        raise ProvisionError("Задание не найдено")
    if old.state not in ("done", "failed") or not old.server_id:
        raise ProvisionError("Переустановить можно сервер, который уже создан у хостинга")
    for other in db.list_provisions():
        if other.replaces != old.id:
            continue
        if other.state == "failed" and (not other.server_id or other.step == "rebuild"):
            db.delete_provision(other.id)  # an attempt the hosting refused left nothing behind: start over
        else:
            raise ProvisionError("Для этого сервера уже есть задание переустановки: дождитесь его, повторите или "
                                 "удалите его сервер")
    hoster = db.get_hoster(old.hoster_id)
    if not hoster:
        raise ProvisionError("Аккаунт хостинга удалён из админки")
    try:
        await nodes.main_panel(old.panel_id)
    except nodes.NodeError as exc:
        raise ProvisionError(f"Основная панель: {exc}") from exc
    client_class = hosters.CLIENTS[hoster.provider]
    if body.site_template is not None:
        old.site_template = body.site_template  # what the reinstall installs; the old job goes away with it
    if body.in_place and getattr(client_class, "rebuild", False):
        p = _in_place_job(old, ssh_install=getattr(client_class, "setup", "") == "ssh")
        _log(p, f"Переустановка системы на том же сервере {old.ip}: узел основной панели переключится на новую "
                "установку 3x-ui, IP не изменится")
        _spawn(p.id)
        return public(p)
    plan = body.plan.strip() or old.plan
    labels = {**old.labels, "plan": body.plan_label.strip()[:100]} if plan != old.plan else old.labels
    p = _new_job(hoster_id=old.hoster_id, panel_id=old.panel_id, name=old.name, region=old.region, plan=plan,
                 project=old.project, ssh_keys=old.ssh_keys, domain=old.domain, labels=labels,
                 node_id=old.node_id, replaces=old.id, site_template=old.site_template, os=old.os,
                 connections=old.connections, **_dns_fields(old))
    _log(p, f"Переустановка: новый сервер заменит {old.ip or old.server_id}, узел основной панели переключится на "
            "него, старый сервер будет удалён")
    _spawn(p.id)
    return public(p)


def _dns_fields(old: db.Provision) -> dict:
    """A reinstall keeps the domain record: a new server gets it pointed at its IP during boot."""
    return {"dns_account_id": old.dns_account_id, "dns_zone_id": old.dns_zone_id, "dns_record_id": old.dns_record_id}


def _in_place_job(old: db.Provision, ssh_install: bool) -> db.Provision:
    same = dict(hoster_id=old.hoster_id, panel_id=old.panel_id, name=old.name, region=old.region, plan=old.plan,
                project=old.project, ssh_keys=old.ssh_keys, domain=old.domain, labels=old.labels,
                node_id=old.node_id, replaces=old.id, in_place=1, server_id=old.server_id, ip=old.ip,
                site_template=old.site_template, step="rebuild", connections=old.connections, os=old.os,
                **_dns_fields(old))
    if "service_key" in old.secrets:  # its cloud-init lets the same key in again: the usual install from zero
        return _new_job(service_key=old.secrets["service_key"], **same)
    if ssh_install:  # VDSina takes a key with the reinstall
        return _new_job(**same)
    # made by an older version: DigitalOcean and OVHcloud re-run its cloud-init install, panel settings stay
    return db.create_provision(**same, port=old.port, base_path=old.base_path, username=old.username,
                               secrets={"password": old.secrets["password"]}, cert_pem=old.cert_pem,
                               cert_pin=old.cert_pin, state="running")


def retry(provision_id: int) -> dict:
    p = db.get_provision(provision_id)
    if not p:
        raise ProvisionError("Задание не найдено")
    if p.state != "failed":
        raise ProvisionError("Повторить можно только задание с ошибкой")
    _set(p, state="running", error="")
    _log(p, "Повтор с шага, на котором была ошибка")
    if p.step == "install":
        _fresh[p.id] = True
    _spawn(p.id)
    return public(p)


async def restart_install(provision_id: int) -> dict:
    """Run the install again while the job still waits on it, e.g. after it got stuck on the network."""
    p = db.get_provision(provision_id)
    if not p:
        raise ProvisionError("Задание не найдено")
    if p.state != "running" or p.step != "install":
        raise ProvisionError("Перезапустить можно только идущую установку")
    task = _tasks.pop(p.id, None)
    if task:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    _log(p, "Установка перезапущена вручную")
    _fresh[p.id] = True
    _spawn(p.id)
    return public(db.get_provision(p.id))


async def delete_server(provision_id: int) -> dict:
    """Delete the job's server (it costs money) with its connections and node, and close the job."""
    p = db.get_provision(provision_id)
    if not p:
        raise ProvisionError("Задание не найдено")
    if p.state == "running":
        raise ProvisionError("Задание ещё выполняется: дождитесь ошибки или окончания")
    if p.in_place and p.state != "done":
        raise ProvisionError("Это переустановка на том же сервере: повторите её или удалите сервер с карточки "
                             "прежнего задания")
    if any(other.replaces == p.id and other.state == "running" for other in db.list_provisions()):
        raise ProvisionError("Сервер сейчас переустанавливается: старый удалится сам, когда новый заработает")
    hoster = db.get_hoster(p.hoster_id)
    if not hoster:
        raise ProvisionError("Аккаунт хостинга удалён из админки")
    if p.server_id:
        await delete_hosted_server(hoster, p.server_id)
    else:  # nothing was ordered
        _set(p, state="deleted")
    return public(db.get_provision(p.id))


# ---------- deleting a server ----------
# Connections first, then the node, then the server: nothing goes at the hosting while the main panel
# still holds the node, and the main panel cannot drop a node that has inbounds.

async def _addresses(host: str) -> set[str]:
    try:
        return {str(ipaddress.ip_address(host))}
    except ValueError:
        pass
    try:
        infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, None), 5)
    except (OSError, asyncio.TimeoutError):
        return set()
    return {info[4][0] for info in infos}


def _server_jobs(hoster_id: int, server_id: str) -> list[db.Provision]:
    return [p for p in db.list_provisions()
            if p.hoster_id == hoster_id and p.server_id == server_id and p.state != "deleted"]


def _job_node(p: db.Provision) -> tuple[int, int] | None:
    """The node is the job's own once its connect step is through (a reinstall borrows the old one before)."""
    if p.node_id and p.step in _steps(p) and _steps(p).index(p.step) > _steps(p).index("connect"):
        return p.panel_id, p.node_id
    return None


async def delete_plan(hoster: db.Hoster, server_id: str) -> dict:
    """What deleting the server takes: the main panels' nodes that run on it and their inbounds. A server that
    is a main panel itself is not deleted from here."""
    server = await hosters.find_server(hoster, server_id)
    jobs = _server_jobs(hoster.id, server_id)
    if not server and not jobs:
        raise ProvisionError("Сервер не найден у хостинга: обновите список")
    if server and not server["deletable"]:
        raise ProvisionError("Этот сервер через API не удалить: VPS OVHcloud удаляется в панели OVHcloud "
                             "(расторжение подтверждается по почте)")
    if any(p.state == "running" for p in jobs):
        raise ProvisionError("С этим сервером сейчас идёт задание в блоке «Новые серверы»: дождитесь его окончания")
    ips = set(server["ipv4"] + server["ipv6"]) if server else {p.ip for p in jobs if p.ip}
    known = {n for n in map(_job_node, jobs) if n}
    found = []
    for panel in db.list_panels():
        if ips & await _addresses(urlsplit(panel.url).hostname or ""):
            raise ProvisionError(f"На этом сервере основная панель «{panel.name}»: удалите её сначала в разделе "
                                 "«Серверы»")
        xui = await pool.get(panel)
        try:
            await xui.ensure_ready()
            if not xui.is_v3:
                continue  # a legacy panel has no nodes
            panel_nodes, inbounds = await asyncio.gather(xui.v3_nodes(), xui.inbounds())
        except XUIError as exc:
            raise ProvisionError(f"Основная панель «{panel.name}» недоступна, поэтому не проверить, узел ли "
                                 f"этот сервер: {exc}") from exc
        for node in panel_nodes:
            if (panel.id, node["id"]) in known or ips & await _addresses(node.get("address") or ""):
                found.append({
                    "panel_id": panel.id, "panel_name": panel.name, "node_id": node["id"], "name": node.get("name", ""),
                    "inbounds": [{"id": i["id"], "remark": i.get("remark") or i.get("tag") or "",
                                  "protocol": i.get("protocol", ""), "port": i.get("port")}
                                 for i in inbounds if i.get("nodeId") == node["id"]],
                })
    return {"server": server, "nodes": found, "jobs": [p.id for p in jobs]}


async def delete_hosted_server(hoster: db.Hoster, server_id: str) -> dict:
    plan = await delete_plan(hoster, server_id)
    jobs = [db.get_provision(i) for i in plan["jobs"]]
    name = (plan["server"] or {}).get("name") or server_id

    def note(message: str) -> None:
        log.info("delete server %s: %s", name, message)
        for p in jobs:
            _log(p, message)

    for node in plan["nodes"]:
        xui = await pool.get(db.get_panel(node["panel_id"]))
        try:
            for inbound in node["inbounds"]:
                await xui.delete_inbound(inbound["id"])
            if node["inbounds"]:
                note(f"Подключения узла «{node['name']}» удалены из основной панели: {len(node['inbounds'])} шт.")
            await xui.v3_node_delete(node["node_id"])
        except XUIError as exc:
            overview_cache.invalidate()
            raise ProvisionError(f"Узел «{node['name']}» не удалён из основной панели «{node['panel_name']}», "
                                 f"сервер не тронут: {exc}") from exc
        note(f"Узел «{node['name']}» удалён из основной панели")
    overview_cache.invalidate()

    if plan["server"]:
        await hosters.delete_server(hoster, server_id, plan["server"]["project"] or None)
    else:
        hosters.invalidate(hoster.id)
    note(f"Сервер {name} удалён у хостинга")
    for p in jobs:
        _set(p, state="deleted")
        records = [(p.dns_record_id, f"A-запись {p.domain}")] if p.dns_record_id else []
        for c in p.connections:
            if c.get("cdn_resource_id") or c.get("cdn_cert_id"):
                problems = await cdn.tear_down(c)
                _log(p, f"CDN-ресурс {c.get('cdn_domain')} не удалён: {'; '.join(problems)}" if problems
                     else f"CDN-ресурс и сертификат {c.get('cdn_domain')} удалены")
            records += [(r, f"запись CDN-подключения {c.get('cdn_domain')}") for r in c.get("cdn_records") or []]
            if c.get("cdn_record_id"):  # 0.27.0: Cloudflare's own proxy
                records.append((c["cdn_record_id"], f"CDN-запись {c['cdn_domain']}"))
        for record_id, what in records if p.dns_account_id else []:
            try:
                await dns.remove(p.dns_account_id, p.dns_zone_id, record_id)
                _log(p, f"Cloudflare: {what} удалена")
            except dns.DNSError as exc:  # the server is gone already; a stale record is only a leftover
                _log(p, f"Cloudflare: {what} не удалена: {exc}")
    return {"server": name, "nodes": [n["name"] for n in plan["nodes"]],
            "inbounds": sum(len(n["inbounds"]) for n in plan["nodes"])}


def forget(provision_id: int) -> None:
    p = db.get_provision(provision_id)
    if not p:
        raise ProvisionError("Задание не найдено")
    if p.state == "running":
        raise ProvisionError("Задание ещё выполняется")
    db.delete_provision(provision_id)


def public(p: db.Provision) -> dict[str, Any]:
    return {
        "id": p.id, "hoster_id": p.hoster_id, "panel_id": p.panel_id, "name": p.name,
        "region": p.labels.get("region") or p.region, "plan": p.labels.get("plan") or p.plan,
        "server_id": p.server_id, "ip": p.ip, "node_id": p.node_id, "step": p.step,
        "state": p.state, "error": p.error, "log": p.log[-60:], "created_at": p.created_at,
        "updated_at": p.updated_at, "panel_url": _node_url(p) if p.ip else "", "username": p.username,
        "domain": p.domain, "cert_mode": p.cert_mode, "replaces": p.replaces,
        "region_id": p.region, "plan_id": p.plan, "project": p.project, "in_place": bool(p.in_place),
        "dns": "cloudflare" if p.dns_account_id else "",
        "site_template": p.site_template,
        "sub_port": p.sub_port,
        "os": p.os, "os_label": hosters.OS_LABELS.get(p.os, p.os),
        "connections": [connections.item_public(c, connections.macros(p.name, p.labels.get("region") or p.region))
                        for c in p.connections],
        # made before the admin kept its own SSH key: an OS reinstall re-runs the old cloud-init install
        "legacy_install": "service_key" not in p.secrets and p.state == "done",
    }


def list_all() -> list[dict]:
    return [public(p) for p in db.list_provisions()]


def credentials(provision_id: int) -> dict:
    p = db.get_provision(provision_id)
    if not p:
        raise ProvisionError("Задание не найдено")
    return {"panel_url": _node_url(p) if p.ip else "", "username": p.username, "password": p.secrets["password"],
            "cert_pin": p.cert_pin}
