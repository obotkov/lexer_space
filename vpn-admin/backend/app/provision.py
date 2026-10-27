"""New VPN server through a hosting account: order a server, install 3x-ui on it and
attach it as a node of a main 3x-ui v3 panel.

The admin generates everything the node needs up front (panel port, path, login,
password and a self-signed TLS certificate) and passes it to the server as
cloud-init user data. The script installs Docker and the official 3x-ui image and
configures the panel with `x-ui setting`. The admin then waits for the panel to
answer with exactly that certificate, logs in, mints an API token for the main
panel and adds the node there with the certificate pinned.

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

from . import db, hosters, nodes
from .aggregator import overview_cache
from .xui import XUIClient, XUIError

log = logging.getLogger("vpn-admin.provision")

XUI_IMAGE = "ghcr.io/mhsanaei/3x-ui:latest"
SSH_KEY_COMMENT = "vpn-admin-setup"
STEPS = ["create", "boot", "install", "connect", "done"]
BOOT_TIMEOUT = 10 * 60
INSTALL_TIMEOUT = 25 * 60
POLL_EVERY = 10

_tasks: dict[int, asyncio.Task] = {}


class ProvisionError(Exception):
    pass


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

    @field_validator("name")
    @classmethod
    def hostname(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,62}", value):
            raise ValueError("Имя сервера: латинские буквы, цифры, точка и дефис, до 63 символов")
        return value


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


def make_ssh_key() -> tuple[str, str]:
    """One-time key for hostings without cloud-init: (private key in OpenSSH format, public key line)."""
    key = ed25519.Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return private, f"{public} {SSH_KEY_COMMENT}"


def _drop_setup_key_script() -> str:
    """Remove the admin's one-time key from root and every user it may have been given to."""
    return (f"for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do "
            f"[ -f \"$f\" ] && sed -i '/ {SSH_KEY_COMMENT}$/d' \"$f\"; done\n")


def _authorized_keys_script(user_keys: list[str]) -> str:
    """Give root the user's keys chosen in the form, then drop the admin's one-time key."""
    lines = ["mkdir -p /root/.ssh && chmod 700 /root/.ssh && touch /root/.ssh/authorized_keys"]
    for key in user_keys:
        quoted = shlex.quote(key)
        lines.append(f"grep -qxF {quoted} /root/.ssh/authorized_keys || echo {quoted} >> /root/.ssh/authorized_keys")
    return "\n".join(lines) + "\n" + _drop_setup_key_script()


def user_data(p: db.Provision, extra: str = "") -> str:
    """cloud-init script: Docker + 3x-ui with the generated port, path, login and certificate.
    Hostings without cloud-init get the same script over SSH, with `extra` steps at the end."""
    return f"""#!/bin/bash
# vpn-admin: 3x-ui node "{p.name}"
set -u
exec > /var/log/vpn-admin-node.log 2>&1
export DEBIAN_FRONTEND=noninteractive

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
docker run --rm --entrypoint /app/x-ui -v /opt/3x-ui/db:/etc/x-ui -v /opt/3x-ui/cert:/root/cert {XUI_IMAGE} \\
  setting -port {p.port} -username {p.username} -password {p.secrets["password"]} -webBasePath {p.base_path} \\
  -webCert /root/cert/panel.crt -webCertKey /root/cert/panel.key
docker run -d --name 3x-ui --restart unless-stopped --network host --cap-add NET_ADMIN --cap-add NET_RAW \\
  -e XRAY_VMESS_AEAD_FORCED=false -v /opt/3x-ui/db:/etc/x-ui -v /opt/3x-ui/cert:/root/cert {XUI_IMAGE}

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then ufw allow {p.port}/tcp; fi
{extra}echo "vpn-admin: done"
"""


def _node_url(p: db.Provision) -> str:
    return f"https://{p.ip}:{p.port}{p.base_path}"


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

    def order(client):
        admin_key, script = None, user_data(p)
        if getattr(client, "setup", "") == "ssh":  # no cloud-init: the admin will log in and install itself
            private, admin_key = make_ssh_key()
            _set(p, secrets={**p.secrets, "ssh_key": private})
        elif getattr(client, "login_key_required", False):
            # the hosting refuses servers without a login key: give a throwaway one, the script deletes it
            _, admin_key = make_ssh_key()
            script = user_data(p, _drop_setup_key_script())
        return client.create_server(name=p.name, region=p.region, plan=p.plan, ssh_keys=p.ssh_keys,
                                    user_data=script, project=p.project or None, admin_key=admin_key)

    server_id = await _with_client(p, order)
    if "ssh_key" in p.secrets:  # the TLS key goes to the server over SSH later
        _set(p, server_id=server_id)
    else:  # the key reached the server; the admin trusts the node by the certificate alone
        _set(p, server_id=server_id, secrets={"password": p.secrets["password"]})
    _log(p, f"Сервер создан у хостинга (id {server_id})")


async def _step_boot(p: db.Provision) -> None:
    deadline = time.time() + BOOT_TIMEOUT
    while True:
        server = await _with_client(p, lambda c: c.get_server(p.server_id, p.project or None))
        if server["status"] == "error":
            raise ProvisionError(f"Хостинг сообщил об ошибке сервера: {server['status_label']}")
        if server["status"] == "running" and server["ipv4"]:
            _set(p, ip=server["ipv4"][0])
            _log(p, f"Сервер запущен, IP {p.ip}")
            return
        if time.time() > deadline:
            raise ProvisionError(f"Сервер не запустился за {BOOT_TIMEOUT // 60} минут (статус: {server['status_label']})")
        await asyncio.sleep(POLL_EVERY)


async def _install_over_ssh(p: db.Provision) -> None:
    """Run the setup script as root over SSH with the one-time key. The host key cannot be known in
    advance; what matters is checked after: the panel must answer with the certificate generated here."""
    _log(p, "У хостинга нет cloud-init: подключаюсь к серверу по SSH и устанавливаю Docker и 3x-ui")
    user_keys = await _with_client(p, lambda c: c.public_keys(p.ssh_keys)) if p.ssh_keys else []
    script = user_data(p, _authorized_keys_script(user_keys))
    key = asyncssh.import_private_key(p.secrets["ssh_key"])
    deadline = time.time() + INSTALL_TIMEOUT
    while True:
        try:
            async with asyncssh.connect(p.ip, username="root", client_keys=[key], known_hosts=None,
                                        connect_timeout=15) as conn:
                result = await conn.run("bash -s", input=script, check=False, timeout=INSTALL_TIMEOUT)
                if result.exit_status != 0:
                    tail = (await conn.run("tail -n 15 /var/log/vpn-admin-node.log", check=False)).stdout
                    raise ProvisionError(f"Установка на сервере завершилась с ошибкой (код {result.exit_status}). "
                                         f"Конец журнала /var/log/vpn-admin-node.log: {str(tail).strip()[-1500:]}")
            break
        except (OSError, asyncssh.Error) as exc:  # the OS is still being installed or sshd is not up yet
            if time.time() > deadline:
                raise ProvisionError(f"Не удалось выполнить установку по SSH за {INSTALL_TIMEOUT // 60} минут: "
                                     f"{exc}") from exc
            await asyncio.sleep(POLL_EVERY)
    _set(p, secrets={"password": p.secrets["password"]})
    _log(p, "Установка по SSH завершена, одноразовый ключ админки удалён с сервера")
    try:
        await _with_client(p, lambda c: c.forget_setup_key(p.name))
    except (hosters.HosterError, ProvisionError) as exc:
        log.warning("provision %s: setup key not removed from the account: %s", p.id, exc)


async def _step_install(p: db.Provision) -> None:
    if "ssh_key" in p.secrets:
        await _install_over_ssh(p)
        _log(p, "Жду ответа панели 3x-ui")
    else:
        _log(p, "Жду установку Docker и 3x-ui (обычно 3–7 минут)")
    deadline = time.time() + INSTALL_TIMEOUT
    async with httpx.AsyncClient(verify=_pinned_context(p.cert_pem), timeout=10) as http:
        while True:
            try:
                resp = await http.get(_node_url(p))
                if resp.status_code < 500:
                    _log(p, "Панель 3x-ui на сервере отвечает")
                    return
            except httpx.HTTPError as exc:  # refused / timeout while it installs: keep waiting
                if "CERTIFICATE_VERIFY_FAILED" in str(exc):
                    raise ProvisionError(f"Сервер ответил с чужим TLS-сертификатом: {exc}") from exc
            if time.time() > deadline:
                raise ProvisionError(
                    f"Панель не ответила за {INSTALL_TIMEOUT // 60} минут. Журнал установки на сервере: "
                    "/var/log/vpn-admin-node.log")
            await asyncio.sleep(POLL_EVERY)


async def _step_connect(p: db.Provision) -> None:
    node = XUIClient(_node_url(p), p.username, p.secrets["password"], _pinned_context(p.cert_pem))
    try:
        token = await node.v3_create_api_token(f"vpn-admin-{int(time.time())}", "node-admin")
    except XUIError as exc:
        raise ProvisionError(f"Не удалось создать API-токен на узле: {exc}") from exc
    finally:
        await node.close()
    _log(p, "API-токен узла создан, добавляю узел в основную панель")
    body = nodes.NodeIn(
        name=p.name, remark="создан через VPN API Hoster", scheme="https", address=p.ip, port=p.port,
        base_path=p.base_path, api_token=token, tls_verify_mode="pin", pinned_cert_sha256=p.cert_pin,
        allow_private_address=ipaddress.ip_address(p.ip).is_private,
    )
    try:
        created = await nodes.add(p.panel_id, body)
    except nodes.NodeError as exc:
        raise ProvisionError(f"Основная панель не приняла узел: {exc}") from exc
    node_id = created.get("id") if isinstance(created, dict) else None
    _set(p, node_id=node_id)
    _log(p, "Узел добавлен в основную панель")


STEP_RUNNERS = {"create": _step_create, "boot": _step_boot, "install": _step_install, "connect": _step_connect}


async def run(provision_id: int) -> None:
    p = db.get_provision(provision_id)
    if not p or p.state != "running":
        return
    try:
        while p.step != "done":
            await STEP_RUNNERS[p.step](p)
            _set(p, step=STEPS[STEPS.index(p.step) + 1])
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
    cert_pem, key_pem, pin = make_certificate()
    p = db.create_provision(
        hoster_id=hoster.id, panel_id=body.panel_id, name=body.name, region=body.region, plan=body.plan,
        project=body.project or "", ssh_keys=body.ssh_keys, port=secrets.randbelow(40000) + 20000,
        base_path=f"/{_random(14, string.ascii_lowercase + string.digits)}/", username=f"adm_{_random(6, string.ascii_lowercase + string.digits)}",
        secrets={"password": _random(20), "key_pem": key_pem}, cert_pem=cert_pem, cert_pin=pin,
        step="create", state="running",
        labels={"region": body.region_label.strip()[:100], "plan": body.plan_label.strip()[:100]},
    )
    _log(p, "Задание создано")
    _spawn(p.id)
    return public(p)


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
    """Destroy the server at the hosting company (it costs money) and close the job."""
    p = db.get_provision(provision_id)
    if not p:
        raise ProvisionError("Задание не найдено")
    if p.state == "running":
        raise ProvisionError("Задание ещё выполняется: дождитесь ошибки или окончания")
    if p.server_id:
        await _with_client(p, lambda c: c.delete_server(p.server_id, p.project or None))
        _log(p, f"Сервер {p.server_id} удалён у хостинга")
    _set(p, state="deleted")
    hosters.invalidate(p.hoster_id)
    return public(p)


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
    }


def list_all() -> list[dict]:
    return [public(p) for p in db.list_provisions()]


def credentials(provision_id: int) -> dict:
    p = db.get_provision(provision_id)
    if not p:
        raise ProvisionError("Задание не найдено")
    return {"panel_url": _node_url(p) if p.ip else "", "username": p.username, "password": p.secrets["password"],
            "cert_pin": p.cert_pin}
