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

import asyncssh
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import BaseModel, Field, field_validator

from . import db, dns, hosters, nodes, site
from .aggregator import overview_cache
from .xui import XUIClient, XUIError

log = logging.getLogger("vpn-admin.provision")

XUI_IMAGE = "ghcr.io/mhsanaei/3x-ui:latest"
STUB_IMAGE = "nginx:alpine"
SSH_KEY_COMMENT = "vpn-admin-setup"
STEPS = ["create", "boot", "install", "connect", "retire", "done"]
IN_PLACE_STEPS = ["rebuild", "boot", "install", "connect", "retire", "done"]
BOOT_TIMEOUT = 10 * 60
INSTALL_TIMEOUT = 25 * 60
DNS_WAIT = 20 * 60  # how long the script waits for the domain's A record before taking a certificate for the IP
POLL_EVERY = 10

_tasks: dict[int, asyncio.Task] = {}


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
if retry docker pull {STUB_IMAGE}; then
  docker run -d --name vpn-stub --restart unless-stopped --network host \\
    -v /opt/vpn-stub/html:/usr/share/nginx/html:ro -v /opt/vpn-stub/acme:/var/www/acme:ro \\
    -v /opt/vpn-stub/default.conf:/etc/nginx/conf.d/default.conf:ro {STUB_IMAGE}
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow 80/tcp; fi
fi
if docker ps --format '{{{{.Names}}}}' | grep -qx vpn-stub; then
  ACME_MODE="--webroot /opt/vpn-stub/acme"
else
  echo "vpn-admin: decoy page not started"; ACME_MODE="--standalone --httpport 80"
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
  ""|10.*|127.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) PUBLIC=0; echo "no public IPv4 ($IP): Let's Encrypt skipped" ;;
  *) PUBLIC=1 ;;
esac
if [ "$PUBLIC" = 1 ] && retry sh -c 'apt-get -o DPkg::Lock::Timeout=300 update -q && apt-get -o DPkg::Lock::Timeout=300 install -y -q socat cron' \\
   && {{ [ -x "$ACME" ] || retry sh -c 'curl -fsSL https://get.acme.sh | sh'; }}; then
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow 80/tcp; fi
  if [ -n "$DOMAIN" ]; then
    echo "waiting for the A record $DOMAIN -> $IP"
    for i in $(seq {DNS_WAIT // 20}); do dns_points_here && break; sleep 20; done
    dns_points_here && le_issue "$DOMAIN"
  fi
  [ "$CERT" = /root/cert/panel.crt ] && le_issue "$IP" --certificate-profile shortlived --days 3
fi
echo "vpn-admin: certificate $CERT"
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
    """The install the admin runs over SSH: Docker, the decoy page, a certificate and 3x-ui with the generated
    port, path, login and password; `extra` steps (keys) at the end."""
    return f"""#!/bin/bash
# vpn-admin: 3x-ui node "{p.name}"
set -u
exec > /var/log/vpn-admin-node.log 2>&1
export DEBIAN_FRONTEND=noninteractive HOME=/root

retry() {{ for i in 1 2 3 4 5 6; do "$@" && return 0; echo "retry $i: $*"; sleep 20; done; return 1; }}

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

command -v docker >/dev/null || retry sh -c 'curl -fsSL https://get.docker.com | sh' || exit 1
systemctl enable --now docker
retry docker pull {XUI_IMAGE} || exit 1

docker rm -f 3x-ui >/dev/null 2>&1 || true
{_stub_script(p)}{_certificate_script(p)}
docker run --rm --entrypoint /app/x-ui -v /opt/3x-ui/db:/etc/x-ui -v /opt/3x-ui/cert:/root/cert {XUI_IMAGE} \\
  setting -port {p.port} -username {p.username} -password {p.secrets["password"]} -webBasePath {p.base_path} \\
  -webCert "$CERT" -webCertKey "$KEY"
{_sub_port_script(p)}docker run -d --name 3x-ui --restart unless-stopped --network host --cap-add NET_ADMIN --cap-add NET_RAW \\
  -e XRAY_VMESS_AEAD_FORCED=false -v /opt/3x-ui/db:/etc/x-ui -v /opt/3x-ui/cert:/root/cert {XUI_IMAGE}

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow {p.port}/tcp{f"; ufw allow {p.sub_port}/tcp" if p.sub_port else ""}
fi
{extra}echo "vpn-admin: done"
"""


def _node_host(p: db.Provision) -> str:
    return p.domain if p.cert_mode == "domain" else p.ip


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
    db.update_provision(p.id, log=p.log[-50:])
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
    _log(p, f"Заказываю сервер {p.labels.get('plan') or p.plan}: {p.labels.get('region') or p.region}")

    # VDSina has no cloud-init and takes the key itself; UpCloud wants a login key for cloud-init servers
    server_id = await _with_client(p, lambda client: client.create_server(
        name=p.name, region=p.region, plan=p.plan, ssh_keys=p.ssh_keys, user_data=bootstrap_user_data(p),
        project=p.project or None, admin_key=ssh_public_line(p.secrets["service_key"])))
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
        p.server_id, plan=p.plan, name=p.name, project=p.project or None, admin_key=admin_key))
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
            elif p.domain and not p.in_place:
                _log(p, f"Создайте у регистратора домена A-запись {p.domain} → {p.ip}: установка ждёт её до "
                        f"{DNS_WAIT // 60} минут, иначе возьмёт сертификат Let's Encrypt на IP")
            return
        if time.time() > deadline:
            raise ProvisionError(f"Сервер не запустился за {BOOT_TIMEOUT // 60} минут (статус: {server['status_label']})")
        await asyncio.sleep(POLL_EVERY)


async def _install_over_ssh(p: db.Provision) -> None:
    """Run the install as root over SSH with the admin's key. The host key cannot be known in advance;
    what matters is checked after: the panel must answer with the certificate generated here."""
    _log(p, "Подключаюсь к серверу по SSH и устанавливаю Docker, 3x-ui"
            + (", сайт-заглушку" if p.site_template else "") + " и сертификат")

    async def user_keys(client) -> list[str]:  # cloud-init hostings put the chosen keys in place themselves
        if getattr(client, "setup", "") == "ssh" and p.ssh_keys:
            return await client.public_keys(p.ssh_keys)
        return []

    script = install_script(p, _authorized_keys_script(await _with_client(p, user_keys)))
    key = asyncssh.import_private_key(p.secrets.get("service_key") or p.secrets["ssh_key"])
    deadline = time.time() + _install_timeout(p)
    while True:
        try:
            async with asyncssh.connect(p.ip, username="root", client_keys=[key], known_hosts=None,
                                        connect_timeout=15) as conn:
                # the hosting's cloud-init may still be running (apt locks, the key itself): let it finish
                await conn.run("command -v cloud-init >/dev/null && cloud-init status --wait >/dev/null 2>&1; true",
                               check=False, timeout=BOOT_TIMEOUT)
                result = await conn.run("bash -s", input=script, check=False, timeout=_install_timeout(p))
                if result.exit_status != 0:
                    tail = (await conn.run("tail -n 15 /var/log/vpn-admin-node.log", check=False)).stdout
                    raise ProvisionError(f"Установка на сервере завершилась с ошибкой (код {result.exit_status}). "
                                         f"Конец журнала /var/log/vpn-admin-node.log: {str(tail).strip()[-1500:]}")
            break
        except (OSError, asyncssh.Error) as exc:  # the OS is still being installed or sshd is not up yet
            if time.time() > deadline:
                raise ProvisionError(f"Не удалось выполнить установку по SSH за {_install_timeout(p) // 60} минут: "
                                     f"{exc}") from exc
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
    if "service_key" in p.secrets or "ssh_key" in p.secrets:  # ssh_key: VDSina jobs of older versions
        await _install_over_ssh(p)
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
        name=p.name, remark="создан через VPN API Hoster", scheme="https", address=_node_host(p), port=p.port,
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


STEP_RUNNERS = {"create": _step_create, "rebuild": _step_rebuild, "boot": _step_boot, "install": _step_install,
                "connect": _step_connect, "retire": _step_retire}


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
                 site_template=body.site_template,
                 dns_account_id=body.dns_account_id if body.domain else 0, dns_zone_id=body.dns_zone_id,
                 labels={"region": body.region_label.strip()[:100], "plan": body.plan_label.strip()[:100]})
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
                 node_id=old.node_id, replaces=old.id, site_template=old.site_template, **_dns_fields(old))
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
                site_template=old.site_template, step="rebuild", **_dns_fields(old))
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
    _spawn(p.id)
    return public(p)


async def delete_server(provision_id: int) -> dict:
    """Destroy the server at the hosting company (it costs money) and close the job. The node it ran as
    leaves the main panel; 3x-ui refuses that while inbounds are attached to it, so such a node is only
    disabled and the user decides what happens to those inbounds and their clients."""
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
    if p.server_id:
        try:
            await _with_client(p, lambda c: c.delete_server(p.server_id, p.project or None))
        except hosters.HosterError as exc:
            if exc.code != "NOT_FOUND":  # already deleted in the hosting's own panel
                raise
        _log(p, f"Сервер {p.ip or p.server_id} удалён у хостинга")
    _set(p, state="deleted")
    hosters.invalidate(p.hoster_id)
    if p.dns_account_id and p.dns_record_id:
        try:
            await dns.remove(p.dns_account_id, p.dns_zone_id, p.dns_record_id)
            _log(p, f"Cloudflare: A-запись {p.domain} удалена")
        except dns.DNSError as exc:  # the server is gone already; a stale record is only a leftover
            _log(p, f"Cloudflare: A-запись {p.domain} не удалена: {exc}")
    # the node is this server's only once the connect step is through (a reinstall borrows the old one before)
    if p.node_id and _steps(p).index(p.step) > _steps(p).index("connect"):
        await _drop_node(p)
    return public(p)


async def _drop_node(p: db.Provision) -> None:
    try:
        node = await nodes.get(p.panel_id, p.node_id)
        if not node:
            return
        if node["inbounds"]:
            await nodes.set_enable(p.panel_id, p.node_id, False)
            _log(p, f"Узел «{node['name']}» выключен в основной панели: к нему привязано инбаундов — "
                    f"{node['inbounds']}. Удалите или перенесите их, затем удалите узел на странице «Узлы»")
        else:
            await nodes.delete(p.panel_id, p.node_id)
            _log(p, f"Узел «{node['name']}» удалён из основной панели")
    except nodes.NodeError as exc:  # the server is gone already; the node is a cosmetic leftover
        _log(p, f"Узел в основной панели не изменён: {exc}")


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
        "state": p.state, "error": p.error, "log": p.log[-15:], "created_at": p.created_at,
        "updated_at": p.updated_at, "panel_url": _node_url(p) if p.ip else "", "username": p.username,
        "domain": p.domain, "cert_mode": p.cert_mode, "replaces": p.replaces,
        "region_id": p.region, "plan_id": p.plan, "project": p.project, "in_place": bool(p.in_place),
        "dns": "cloudflare" if p.dns_account_id else "",
        "site_template": p.site_template,
        "sub_port": p.sub_port,
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
