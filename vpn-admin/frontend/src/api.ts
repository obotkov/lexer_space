export type ClientStatus = "active" | "disabled" | "expired" | "depleted";

export interface PanelStatus {
  cpu: number | null;
  mem_current: number | null;
  mem_total: number | null;
  uptime: number | null;
  xray_state: string | null;
  xray_version: string | null;
}

export type AuthMode = "password" | "token";

export interface Panel {
  id: number;
  name: string;
  url: string;
  username: string;
  verify_tls: boolean;
  sub_base_url: string;
  created_at: number;
  auth_mode: AuthMode;
}

export interface PanelInfo extends Panel {
  ok: boolean;
  error: string | null;
  /** "v3" — 3x-ui 3.x (clients shared between inbounds), "legacy" — 2.x; null when unreachable */
  api_version: "v3" | "legacy" | null;
  status: PanelStatus | null;
  nodes: number;
  clients: number;
  online: number;
  sub_base: string;
}

export interface Node {
  panel_id: number;
  panel_name: string;
  id: number;
  remark: string;
  protocol: string;
  port: number;
  listen: string;
  network: string;
  security: string;
  enable: boolean;
  up: number;
  down: number;
  total: number;
  expiry_time: number;
  clients: number;
  online: number;
}

export interface Client {
  panel_id: number;
  panel_name: string;
  api: "v3" | "legacy";
  inbound_id: number;
  inbound_ids: number[];
  inbound_remarks: string[];
  inbound_remark: string;
  protocol: string;
  email: string;
  secret: string;
  sub_id: string;
  sub_url: string;
  enable: boolean;
  up: number;
  down: number;
  total: number;
  expiry_time: number;
  limit_ip: number;
  tg_id: string | number;
  comment: string;
  online: boolean;
  last_online: number;
  status: ClientStatus;
}

export interface Subscription {
  sub_id: string;
  urls: { panel: string; url: string }[];
  emails: string[];
  panels: string[];
  nodes: string[];
  up: number;
  down: number;
  online: boolean;
  expiry_time: number;
  comment: string;
  tg_id: string | number;
  status: ClientStatus;
}

export interface Totals {
  panels: number;
  panels_ok: number;
  nodes: number;
  nodes_enabled: number;
  clients: number;
  users: number;
  users_active: number;
  users_online: number;
  users_expired: number;
  users_disabled: number;
  subscriptions: number;
  traffic_up: number;
  traffic_down: number;
}

export interface Overview {
  generated_at: number;
  totals: Totals;
  panels: PanelInfo[];
  nodes: Node[];
  clients: Client[];
  subscriptions: Subscription[];
}

export interface PanelForm {
  name: string;
  url: string;
  auth_mode: AuthMode;
  username: string;
  password: string;
  api_token: string;
  verify_tls: boolean;
  sub_base_url: string;
}

export interface TestResult {
  ok: boolean;
  error?: string;
  nodes?: number;
  clients?: number;
  xray_version?: string | null;
  api_version?: "v3" | "legacy";
}

export interface VersionInfo {
  version: string;
  tree: string;
  commit: string;
  commit_date: string;
  built_at: string;
  repo: string;
  branch: string;
  path: string;
  /** systemd watcher installed on the host: updates can be started from the admin */
  updater: boolean;
}

export interface UpdateCheck {
  checked_at: number;
  current: VersionInfo;
  error: string | null;
  latest_version: string | null;
  latest_tree: string | null;
  update_available: boolean;
  commits: { sha: string; date: string; url: string; message: string }[];
}

export type UpdateState = "idle" | "queued" | "running" | "done" | "failed" | "stale" | "unknown";

export interface UpdateStatus {
  state: UpdateState;
  message?: string;
  started_at?: number;
  finished_at?: number | null;
  requested_at?: number;
  log: string;
}

export interface ClientRef {
  panel_id: number;
  inbound_id: number;
  email: string;
}

/** Only set fields are changed. total — bytes (0 = ∞); expiry_time — ms (0 = never, negative = days after first use). */
export interface ClientChanges {
  enable?: boolean;
  total?: number;
  expiry_time?: number;
  limit_ip?: number;
  comment?: string;
  tg_id?: string;
}

export interface OpResult extends ClientRef {
  ok: boolean;
  error: string | null;
  note?: string;
}

export interface ClientCreateForm {
  targets: { panel_id: number; inbound_id: number }[];
  email: string;
  sub_id: string;
  enable: boolean;
  total: number;
  expiry_time: number;
  limit_ip: number;
  comment: string;
  tg_id: string;
}

export const SUPPORTED_PROTOCOLS = ["vless", "vmess", "trojan", "shadowsocks"];

export const refOf = (c: Client): ClientRef => ({ panel_id: c.panel_id, inbound_id: c.inbound_id, email: c.email });

export interface CertInfo {
  domains: string[];
  not_after: number;
  days_left: number;
  issuer: string;
  staging: boolean;
}

export interface TlsStatus {
  /** HTTPS switched on in settings */
  enabled: boolean;
  /** the running process actually serves HTTPS */
  active: boolean;
  domain: string;
  email: string;
  staging: boolean;
  last_error: string | null;
  last_renew_check: number | null;
  certificate: CertInfo | null;
  port: number;
  /** HTTPS is provided by Caddy on 443 (install-time DOMAIN): in-app certificates are off */
  caddy_domain: string;
}

export interface DomainCheck {
  domain: string;
  resolved: string[];
  server_ip: string | null;
  matches: boolean;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(method: string, url: string, body?: unknown): Promise<T> {
  const resp = await fetch(url, {
    method,
    credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!resp.ok) {
    let message = `HTTP ${resp.status}`;
    try {
      const data = await resp.json();
      if (typeof data.detail === "string") message = data.detail;
      else if (Array.isArray(data.detail)) message = data.detail.map((d: { msg: string }) => d.msg).join("; ");
    } catch {
      /* not json */
    }
    if (resp.status === 401) window.dispatchEvent(new Event("unauthorized"));
    throw new ApiError(resp.status, message);
  }
  return resp.json();
}

export const api = {
  me: () => request<{ username: string }>("GET", "/api/auth/me"),
  login: (username: string, password: string) =>
    request<{ username: string }>("POST", "/api/auth/login", { username, password }),
  logout: () => request("POST", "/api/auth/logout"),
  overview: (refresh = false) => request<Overview>("GET", `/api/overview${refresh ? "?refresh=true" : ""}`),
  panels: () => request<Panel[]>("GET", "/api/panels"),
  createPanel: (form: PanelForm) => request<Panel>("POST", "/api/panels", form),
  updatePanel: (id: number, form: PanelForm) => request<Panel>("PUT", `/api/panels/${id}`, form),
  deletePanel: (id: number) => request("DELETE", `/api/panels/${id}`),
  testPanel: (form: PanelForm, panelId?: number) =>
    request<TestResult>("POST", "/api/panels/test", { ...form, panel_id: panelId ?? null }),
  createClients: (form: ClientCreateForm) =>
    request<{ sub_id: string; results: OpResult[] }>("POST", "/api/clients", form),
  updateClients: (refs: ClientRef[], changes: ClientChanges) =>
    request<{ results: OpResult[] }>("POST", "/api/clients/update", { refs, changes }),
  extendClients: (refs: ClientRef[], days: number) =>
    request<{ results: OpResult[] }>("POST", "/api/clients/extend", { refs, days }),
  resetTraffic: (refs: ClientRef[]) => request<{ results: OpResult[] }>("POST", "/api/clients/reset-traffic", { refs }),
  deleteClients: (refs: ClientRef[]) => request<{ results: OpResult[] }>("POST", "/api/clients/delete", { refs }),
  version: () => request<VersionInfo>("GET", "/api/system/version"),
  checkUpdate: (force = false) => request<UpdateCheck>("GET", `/api/system/check-update${force ? "?force=true" : ""}`),
  updateStatus: () => request<UpdateStatus>("GET", "/api/system/update"),
  startUpdate: () => request<UpdateStatus>("POST", "/api/system/update"),
  health: () => request<{ ok: boolean }>("GET", "/api/health"),
  tls: () => request<TlsStatus>("GET", "/api/tls"),
  tlsCheckDomain: (domain: string) => request<DomainCheck>("GET", `/api/tls/check-domain?domain=${encodeURIComponent(domain)}`),
  tlsIssue: (domain: string, email: string, staging: boolean) =>
    request<{ restarting: boolean; url: string; certificate: CertInfo }>("POST", "/api/tls/issue", { domain, email, staging, accept_tos: true }),
  tlsRenew: () => request<{ renewed: boolean; restarting: boolean; certificate: CertInfo }>("POST", "/api/tls/renew"),
  tlsDisable: () => request<{ restarting: boolean }>("POST", "/api/tls/disable"),
};
