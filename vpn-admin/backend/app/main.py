import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import clients, connections, db, dns, hosters, netload, nodes, ping, provision, site, system, tls
from .aggregator import overview_cache, pool
from .config import settings
from .security import (SESSION_COOKIE, check_credentials, login_throttle, make_session, read_session,
                       require_admin)
from .xui import XUIClient, XUIError, normalize_url, parse_json_field

log = logging.getLogger("vpn_admin")


def seed_panel_from_env() -> None:
    has_auth = settings.xui_api_token or settings.xui_username
    if settings.xui_url and has_auth and db.count_panels() == 0:
        db.create_panel("Основной сервер", normalize_url(settings.xui_url), settings.xui_username,
                        settings.xui_password, settings.xui_verify_tls, "", settings.xui_api_token)
        log.info("Added 3x-ui panel from env: %s", settings.xui_url)


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.init_db()
    seed_panel_from_env()
    renewal = asyncio.create_task(tls.renewal_loop())
    sampler = asyncio.create_task(netload.loop())
    provision.resume_all()
    yield
    renewal.cancel()
    sampler.cancel()
    await pool.close_all()


app = FastAPI(title="VPN Admin", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


# ---------- auth ----------

class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
async def login(body: LoginIn, request: Request, response: Response):
    ip = request.client.host if request.client else "?"
    if login_throttle.is_blocked(ip):
        raise HTTPException(429, "Слишком много попыток. Подождите 5 минут")
    if not check_credentials(body.username, body.password):
        login_throttle.fail(ip)
        raise HTTPException(401, "Неверный логин или пароль")
    login_throttle.reset(ip)
    response.set_cookie(SESSION_COOKIE, make_session(body.username), max_age=settings.session_hours * 3600,
                        httponly=True, samesite="strict", secure=settings.cookie_secure or tls.is_active())
    return {"username": body.username}


@app.post("/api/auth/logout")
async def logout(response: Response):
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/auth/me")
async def me(request: Request):
    user = read_session(request.cookies.get(SESSION_COOKIE))
    if not user:
        raise HTTPException(401, "Не авторизован")
    return {"username": user}


# ---------- 3x-ui panels ----------

class PanelIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=1)
    auth_mode: Literal["password", "token"] = "password"
    username: str = ""
    password: str = ""
    api_token: str = ""
    verify_tls: bool = True
    sub_base_url: str = ""


class PanelTestIn(BaseModel):
    url: str
    auth_mode: Literal["password", "token"] = "password"
    username: str = ""
    password: str = ""
    api_token: str = ""
    verify_tls: bool = True
    panel_id: int | None = None  # when editing: use the stored secret if none given


def _resolve_secrets(body: PanelIn | PanelTestIn, stored: db.Panel | None) -> tuple[str, str]:
    """(password, api_token) for a connection: empty fields fall back to what is stored."""
    if body.auth_mode == "token":
        token = body.api_token.strip() or (stored.api_token if stored else "")
        if not token:
            raise HTTPException(422, "Укажите API-токен 3x-ui")
        return "", token
    if not body.username.strip():
        raise HTTPException(422, "Укажите логин 3x-ui")
    password = body.password or (stored.password if stored else "")
    if not password:
        raise HTTPException(422, "Укажите пароль от 3x-ui")
    return password, ""


async def _test_connection(url: str, username: str, password: str, verify_tls: bool, api_token: str) -> dict:
    client = XUIClient(url, username, password, verify_tls, api_token)
    try:
        inbounds = await client.inbounds()
        if client.is_v3:
            client_count = len(await client.v3_clients())
        else:
            client_count = sum(len(parse_json_field(i.get("settings")).get("clients") or []) for i in inbounds)
        try:
            status = await client.server_status()
        except XUIError:
            status = {}
    except XUIError as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        await client.close()
    return {"ok": True, "nodes": len(inbounds), "clients": client_count, "api_version": client.api_version,
            "xray_version": (status.get("xray") or {}).get("version")}


@app.get("/api/panels", dependencies=[Depends(require_admin)])
async def panels_list():
    return [p.public() for p in db.list_panels()]


@app.post("/api/panels", dependencies=[Depends(require_admin)])
async def panels_create(body: PanelIn):
    password, token = _resolve_secrets(body, None)
    panel = db.create_panel(body.name.strip(), normalize_url(body.url), body.username.strip(), password,
                            body.verify_tls, body.sub_base_url.strip(), token)
    overview_cache.invalidate()
    return panel.public()


@app.put("/api/panels/{panel_id}", dependencies=[Depends(require_admin)])
async def panels_update(panel_id: int, body: PanelIn):
    stored = db.get_panel(panel_id)
    if not stored:
        raise HTTPException(404, "Сервер не найден")
    password, token = _resolve_secrets(body, stored)
    # switching to password auth drops the token; the stored password stays as a fallback
    panel = db.update_panel(panel_id, body.name.strip(), normalize_url(body.url), body.username.strip(),
                            body.password or None, body.verify_tls, body.sub_base_url.strip(), token)
    await pool.drop(panel_id)
    overview_cache.invalidate()
    return panel.public()


@app.delete("/api/panels/{panel_id}", dependencies=[Depends(require_admin)])
async def panels_delete(panel_id: int):
    if not db.delete_panel(panel_id):
        raise HTTPException(404, "Сервер не найден")
    await pool.drop(panel_id)
    overview_cache.invalidate()
    return {"ok": True}


@app.post("/api/panels/test", dependencies=[Depends(require_admin)])
async def panels_test(body: PanelTestIn):
    stored = db.get_panel(body.panel_id) if body.panel_id else None
    password, token = _resolve_secrets(body, stored)
    return await _test_connection(body.url, body.username.strip(), password, body.verify_tls, token)


# ---------- clients ----------

class RefsIn(BaseModel):
    refs: list[clients.ClientRef] = Field(min_length=1)


class UpdateIn(RefsIn):
    changes: clients.ClientChanges


class ExtendIn(RefsIn):
    days: int = Field(ge=1, le=3650)


@app.post("/api/clients", dependencies=[Depends(require_admin)])
async def clients_create(body: clients.ClientCreate):
    return await clients.create_clients(body)


@app.post("/api/clients/update", dependencies=[Depends(require_admin)])
async def clients_update(body: UpdateIn):
    return {"results": await clients.update_clients(body.refs, body.changes)}


@app.post("/api/clients/extend", dependencies=[Depends(require_admin)])
async def clients_extend(body: ExtendIn):
    return {"results": await clients.extend_clients(body.refs, body.days)}


@app.post("/api/clients/reset-traffic", dependencies=[Depends(require_admin)])
async def clients_reset(body: RefsIn):
    return {"results": await clients.reset_traffic(body.refs)}


@app.post("/api/clients/delete", dependencies=[Depends(require_admin)])
async def clients_delete(body: RefsIn):
    return {"results": await clients.delete_clients(body.refs)}


# ---------- connects (inbounds) ----------

class InboundEnableIn(BaseModel):
    panel_id: int
    inbound_id: int
    enable: bool


@app.post("/api/inbounds/enable", dependencies=[Depends(require_admin)])
async def inbounds_enable(body: InboundEnableIn):
    """Switch a connect on or off; a node's connect is switched through its main panel."""
    panel = db.get_panel(body.panel_id)
    if not panel:
        raise HTTPException(404, "Сервер не найден")
    try:
        await (await pool.get(panel)).set_inbound_enable(body.inbound_id, body.enable)
    except XUIError as exc:
        raise HTTPException(409, str(exc)) from exc
    overview_cache.invalidate()
    return {"ok": True}


# ---------- nodes (remote 3x-ui servers of a main v3 panel) ----------

class NodeCreateIn(nodes.NodeIn):
    panel_id: int


class NodeCheckIn(nodes.NodeIn):
    panel_id: int
    node_id: int = 0  # editing an existing node: an empty token means the stored one


class NodeEnableIn(BaseModel):
    enable: bool


async def _nodes_call(coro):
    try:
        return await coro
    except nodes.NodeError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.get("/api/nodes", dependencies=[Depends(require_admin)])
async def nodes_list():
    return await nodes.list_all()


@app.post("/api/nodes", dependencies=[Depends(require_admin)])
async def nodes_add(body: NodeCreateIn):
    return await _nodes_call(nodes.add(body.panel_id, body))


@app.put("/api/nodes/{panel_id}/{node_id}", dependencies=[Depends(require_admin)])
async def nodes_update(panel_id: int, node_id: int, body: nodes.NodeIn):
    await _nodes_call(nodes.update(panel_id, node_id, body))
    return {"ok": True}


@app.delete("/api/nodes/{panel_id}/{node_id}", dependencies=[Depends(require_admin)])
async def nodes_delete(panel_id: int, node_id: int):
    await _nodes_call(nodes.delete(panel_id, node_id))
    return {"ok": True}


@app.post("/api/nodes/{panel_id}/{node_id}/enable", dependencies=[Depends(require_admin)])
async def nodes_enable(panel_id: int, node_id: int, body: NodeEnableIn):
    await _nodes_call(nodes.set_enable(panel_id, node_id, body.enable))
    return {"ok": True}


@app.post("/api/nodes/{panel_id}/{node_id}/probe", dependencies=[Depends(require_admin)])
async def nodes_probe(panel_id: int, node_id: int):
    return await _nodes_call(nodes.probe(panel_id, node_id))


@app.post("/api/nodes/test", dependencies=[Depends(require_admin)])
async def nodes_test(body: NodeCheckIn):
    return await _nodes_call(nodes.test(body.panel_id, body, body.node_id))


@app.post("/api/nodes/inbound-options", dependencies=[Depends(require_admin)])
async def nodes_inbound_options(body: NodeCheckIn):
    return await _nodes_call(nodes.inbound_options(body.panel_id, body, body.node_id))


# ---------- VPN API Hoster: hosting accounts (DigitalOcean, OVHcloud) ----------

def _hoster_credentials(body: hosters.HosterIn, stored: db.Hoster | None) -> dict[str, str]:
    try:
        return hosters.merge_credentials(body.provider, body.credentials,
                                         stored.credentials if stored and stored.provider == body.provider else None)
    except hosters.HosterError as exc:
        raise HTTPException(422, str(exc)) from exc


async def _hoster_check(provider: str, credentials: dict[str, str]) -> dict:
    try:
        return await hosters.check(provider, credentials)
    except hosters.HosterError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/hosters/providers", dependencies=[Depends(require_admin)])
async def hosters_providers():
    # rebuild: the hosting reinstalls the OS of a server in place, keeping its IP
    return {key: {**info, "rebuild": getattr(hosters.CLIENTS[key], "rebuild", False)}
            for key, info in hosters.PROVIDERS.items()}


@app.get("/api/hosters", dependencies=[Depends(require_admin)])
async def hosters_list(refresh: bool = False):
    return await hosters.list_all(refresh)


@app.post("/api/hosters/test", dependencies=[Depends(require_admin)])
async def hosters_test(body: hosters.HosterTestIn):
    stored = db.get_hoster(body.hoster_id) if body.hoster_id else None
    return await _hoster_check(body.provider, _hoster_credentials(body, stored))


@app.post("/api/hosters", dependencies=[Depends(require_admin)])
async def hosters_create(body: hosters.HosterIn):
    credentials = _hoster_credentials(body, None)
    await _hoster_check(body.provider, credentials)  # never store keys the provider rejects
    return hosters.public(db.create_hoster(body.provider, body.name.strip(), credentials))


@app.put("/api/hosters/{hoster_id}", dependencies=[Depends(require_admin)])
async def hosters_update(hoster_id: int, body: hosters.HosterIn):
    stored = db.get_hoster(hoster_id)
    if not stored:
        raise HTTPException(404, "Аккаунт не найден")
    if body.provider != stored.provider:
        raise HTTPException(422, "Хостинг аккаунта менять нельзя: добавьте новый аккаунт")
    credentials = _hoster_credentials(body, stored)
    if credentials != stored.credentials:
        await _hoster_check(body.provider, credentials)
    hosters.invalidate(hoster_id)
    return hosters.public(db.update_hoster(hoster_id, body.name.strip(), credentials))


@app.get("/api/hosters/{hoster_id}/options", dependencies=[Depends(require_admin)])
async def hosters_options(hoster_id: int, project: str | None = None):
    hoster = db.get_hoster(hoster_id)
    if not hoster:
        raise HTTPException(404, "Аккаунт не найден")
    try:
        return await hosters.create_options(hoster, project)
    except hosters.HosterError as exc:
        raise HTTPException(400, str(exc)) from exc


class HosterServerIn(BaseModel):
    server_id: str


def _stored_hoster(hoster_id: int) -> db.Hoster:
    hoster = db.get_hoster(hoster_id)
    if not hoster:
        raise HTTPException(404, "Аккаунт не найден")
    return hoster


@app.post("/api/hosters/{hoster_id}/servers/delete-plan", dependencies=[Depends(require_admin)])
async def hosters_server_delete_plan(hoster_id: int, body: HosterServerIn):
    try:
        return await provision.delete_plan(_stored_hoster(hoster_id), body.server_id)
    except (provision.ProvisionError, hosters.HosterError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/hosters/{hoster_id}/servers/delete", dependencies=[Depends(require_admin)])
async def hosters_server_delete(hoster_id: int, body: HosterServerIn):
    """The server's connections (its node's inbounds), then the node, then the server at the hosting."""
    try:
        return await provision.delete_hosted_server(_stored_hoster(hoster_id), body.server_id)
    except (provision.ProvisionError, hosters.HosterError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.delete("/api/hosters/{hoster_id}", dependencies=[Depends(require_admin)])
async def hosters_delete(hoster_id: int):
    if not db.delete_hoster(hoster_id):
        raise HTTPException(404, "Аккаунт не найден")
    hosters.invalidate(hoster_id)
    return {"ok": True}


# ---------- DNS accounts (Cloudflare) ----------

@app.get("/api/dns-accounts", dependencies=[Depends(require_admin)])
async def dns_accounts_list():
    return {"accounts": await dns.list_all(), "help": dns.TOKEN_HELP, "help_url": dns.TOKEN_HELP_URL}


@app.post("/api/dns-accounts", dependencies=[Depends(require_admin)])
async def dns_accounts_create(body: dns.DnsAccountIn):
    try:
        await dns.check(body.token)  # never store a token Cloudflare rejects
    except dns.DNSError as exc:
        raise HTTPException(400, str(exc)) from exc
    return dns.public(db.create_dns_account("cloudflare", body.name.strip(), {"token": body.token.strip()}))


@app.put("/api/dns-accounts/{account_id}", dependencies=[Depends(require_admin)])
async def dns_accounts_update(account_id: int, body: dns.DnsAccountIn):
    stored = db.get_dns_account(account_id)
    if not stored:
        raise HTTPException(404, "Аккаунт не найден")
    token = body.token.strip() or stored.credentials.get("token", "")
    if token != stored.credentials.get("token"):
        try:
            await dns.check(token)
        except dns.DNSError as exc:
            raise HTTPException(400, str(exc)) from exc
    return dns.public(db.update_dns_account(account_id, body.name.strip(), {"token": token}))


@app.delete("/api/dns-accounts/{account_id}", dependencies=[Depends(require_admin)])
async def dns_accounts_delete(account_id: int):
    if not db.delete_dns_account(account_id):
        raise HTTPException(404, "Аккаунт не найден")
    return {"ok": True}


# ---------- connection templates for new servers ----------

async def _panel_emails() -> list[str]:
    """Users of the v3 panels, to choose who gets the new servers' connections."""
    async def one(panel: db.Panel) -> list[str]:
        try:
            xui = await pool.get(panel)
            await xui.ensure_ready()
            return [c["email"] for c in await xui.v3_clients() if c.get("email")] if xui.is_v3 else []
        except XUIError:
            return []
    return sorted({e for chunk in await asyncio.gather(*(one(p) for p in db.list_panels())) for e in chunk})


@app.get("/api/connections", dependencies=[Depends(require_admin)])
async def connections_list():
    return {"templates": [connections.public(t) for t in connections.templates()], "kinds": connections.kinds_public(),
            "users": connections.users(), "emails": await _panel_emails()}


def _template_fields(body: connections.TemplateIn) -> dict:
    try:
        options = body.cleaned()
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"kind": body.kind, "remark": body.remark, "enabled": body.enabled, "port": body.port, "options": options}


@app.post("/api/connections", dependencies=[Depends(require_admin)])
async def connections_create(body: connections.TemplateIn):
    return connections.public(db.create_connection_template(**_template_fields(body)))


@app.put("/api/connections/{template_id}", dependencies=[Depends(require_admin)])
async def connections_update(template_id: int, body: connections.TemplateIn):
    if not db.get_connection_template(template_id):
        raise HTTPException(404, "Подключение не найдено")
    return connections.public(db.update_connection_template(template_id, **_template_fields(body)))


class EnabledIn(BaseModel):
    enabled: bool


@app.post("/api/connections/{template_id}/enabled", dependencies=[Depends(require_admin)])
async def connections_set_enabled(template_id: int, body: EnabledIn):
    if not db.get_connection_template(template_id):
        raise HTTPException(404, "Подключение не найдено")
    return connections.public(db.update_connection_template(template_id, enabled=body.enabled))


@app.post("/api/connections-enabled", dependencies=[Depends(require_admin)])
async def connections_set_all_enabled(body: EnabledIn):
    for t in db.list_connection_templates():
        if t.enabled != body.enabled:
            db.update_connection_template(t.id, enabled=body.enabled)
    return {"ok": True}


class OrderIn(BaseModel):
    ids: list[int]


@app.post("/api/connections/order", dependencies=[Depends(require_admin)])
async def connections_order(body: OrderIn):
    for position, template_id in enumerate(body.ids):
        db.update_connection_template(template_id, position=position)
    return {"ok": True}


@app.delete("/api/connections/{template_id}", dependencies=[Depends(require_admin)])
async def connections_delete(template_id: int):
    if not db.delete_connection_template(template_id):
        raise HTTPException(404, "Подключение не найдено")
    return {"ok": True}


@app.put("/api/connections-users", dependencies=[Depends(require_admin)])
async def connections_users(body: connections.UsersIn):
    connections.set_users(body)
    return connections.users()


class SniIn(BaseModel):
    host: str = Field(min_length=1, max_length=253)


@app.post("/api/connections/check-sni", dependencies=[Depends(require_admin)])
async def connections_check_sni(body: SniIn):
    results = {}
    for host in [h.strip() for h in body.host.replace(";", ",").split(",") if h.strip()][:10]:
        results[host] = await asyncio.to_thread(connections.check_sni, host)
    return {"results": results}


# ---------- version & self-update ----------

@app.get("/api/system/version", dependencies=[Depends(require_admin)])
async def system_version():
    return system.current_version()


@app.get("/api/system/check-update", dependencies=[Depends(require_admin)])
async def system_check_update(force: bool = False):
    return await system.checker.check(force=force)


@app.get("/api/system/update", dependencies=[Depends(require_admin)])
async def system_update_status():
    return system.read_status()


@app.post("/api/system/update")
async def system_update(user: str = Depends(require_admin)):
    try:
        return system.request_update(user)
    except system.UpdateError as exc:
        raise HTTPException(409, str(exc)) from exc


# ---------- HTTPS for the admin (Let's Encrypt) ----------

class TLSIssueIn(BaseModel):
    domain: str
    email: str = ""
    staging: bool = False
    accept_tos: bool = False


@app.get("/api/tls", dependencies=[Depends(require_admin)])
async def tls_status():
    return tls.status()


@app.get("/api/tls/check-domain", dependencies=[Depends(require_admin)])
async def tls_check_domain(domain: str):
    try:
        return await tls.check_domain(domain)
    except tls.TLSError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/api/tls/issue", dependencies=[Depends(require_admin)])
async def tls_issue(body: TLSIssueIn):
    if not body.accept_tos:
        raise HTTPException(422, "Нужно принять условия использования Let's Encrypt")
    try:
        result = await tls.issue(body.domain, body.email, body.staging)
    except tls.TLSError as exc:
        raise HTTPException(409, str(exc)) from exc
    tls.restart_soon()
    return {**result, "restarting": True, "url": f"https://{tls.load_config()['domain']}:{tls.status()['port']}"}


@app.post("/api/tls/renew", dependencies=[Depends(require_admin)])
async def tls_renew():
    try:
        renewed = await tls.renew(force=True)
    except tls.TLSError as exc:
        raise HTTPException(409, str(exc)) from exc
    if renewed and tls.is_active():
        tls.restart_soon()
    return {"renewed": renewed, "restarting": renewed and tls.is_active(), "certificate": tls.cert_info()}


@app.post("/api/tls/disable", dependencies=[Depends(require_admin)])
async def tls_disable():
    tls.disable()
    restarting = tls.is_active()
    if restarting:
        tls.restart_soon()
    return {"restarting": restarting}


# ---------- decoy website (nginx on the host) ----------

class SiteApplyIn(BaseModel):
    template: str


class SiteCustomIn(BaseModel):
    html: str


@app.get("/api/site", dependencies=[Depends(require_admin)])
async def site_status():
    return site.status()


@app.get("/api/site/templates/{template_id}", dependencies=[Depends(require_admin)])
async def site_template(template_id: str):
    try:
        return {"id": template_id, "html": site.render(site.template_html(template_id))}
    except site.SiteError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.post("/api/site/apply", dependencies=[Depends(require_admin)])
async def site_apply(body: SiteApplyIn):
    try:
        site.apply_template(body.template)
    except site.SiteError as exc:
        raise HTTPException(422, str(exc)) from exc
    return site.status()


@app.post("/api/site/custom", dependencies=[Depends(require_admin)])
async def site_custom(body: SiteCustomIn):
    try:
        site.save_custom(body.html)
    except site.SiteError as exc:
        raise HTTPException(422, str(exc)) from exc
    return site.status()


# ---------- aggregated data ----------

@app.get("/api/overview", dependencies=[Depends(require_admin)])
async def overview(refresh: bool = False):
    return await overview_cache.get(force=refresh)


@app.get("/api/netload", dependencies=[Depends(require_admin)])
async def network_load():
    """Download + upload speed of each server over the last 5 minutes, sampled every 5 seconds."""
    return netload.snapshot()


@app.get("/api/ping", dependencies=[Depends(require_admin)])
async def ping_servers(refresh: bool = False):
    """Ping from the admin's server to each main panel and node."""
    return await ping.ping_all(force=refresh)


@app.get("/api/health")
async def health():
    return {"ok": True}

# ---------- new servers: order at a hosting account, install 3x-ui, attach as a node ----------

def _provision_call(action):
    try:
        return action()
    except provision.ProvisionError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/provisions", dependencies=[Depends(require_admin)])
async def provisions_list():
    return provision.list_all()


@app.post("/api/provisions", dependencies=[Depends(require_admin)])
async def provisions_start(body: provision.ProvisionIn):
    try:
        return await provision.start(body)
    except provision.ProvisionError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/provisions/{provision_id}/retry", dependencies=[Depends(require_admin)])
async def provisions_retry(provision_id: int):
    return _provision_call(lambda: provision.retry(provision_id))


@app.post("/api/provisions/{provision_id}/restart-install", dependencies=[Depends(require_admin)])
async def provisions_restart_install(provision_id: int):
    try:
        return await provision.restart_install(provision_id)
    except provision.ProvisionError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/provisions/{provision_id}/reinstall", dependencies=[Depends(require_admin)])
async def provisions_reinstall(provision_id: int, body: provision.ReinstallIn):
    try:
        return await provision.reinstall(provision_id, body)
    except provision.ProvisionError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/provisions/{provision_id}/connections", dependencies=[Depends(require_admin)])
async def provisions_connections(provision_id: int):
    try:
        return await provision.apply_connections(provision_id)
    except provision.ProvisionError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/provisions/{provision_id}/delete-server", dependencies=[Depends(require_admin)])
async def provisions_delete_server(provision_id: int):
    try:
        return await provision.delete_server(provision_id)
    except (provision.ProvisionError, hosters.HosterError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/provisions/{provision_id}/credentials", dependencies=[Depends(require_admin)])
async def provisions_credentials(provision_id: int):
    return _provision_call(lambda: provision.credentials(provision_id))


@app.delete("/api/provisions/{provision_id}", dependencies=[Depends(require_admin)])
async def provisions_forget(provision_id: int):
    _provision_call(lambda: provision.forget(provision_id))
    return {"ok": True}


# ---------- frontend (built SPA) ----------
if (settings.static_dir / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=settings.static_dir / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(404)
        file = (settings.static_dir / path).resolve()
        if path and file.is_file() and settings.static_dir.resolve() in file.parents:
            return FileResponse(file)
        # assets have hashed names, but index.html must be re-fetched after an update
        return FileResponse(settings.static_dir / "index.html", headers={"Cache-Control": "no-cache"})

