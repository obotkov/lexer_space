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
  /** traffic of all inbounds of the panel, its nodes' included */
  up: number;
  down: number;
  clients: number;
  online: number;
  sub_base: string;
  /** child servers (nodes) of a 3x-ui v3 main panel */
  children: ChildNode[];
}

/** A node as shown on the overview: heartbeat stats plus traffic summed over the inbounds it hosts. */
export interface ChildNode extends XNode {
  up: number;
  down: number;
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
  /** how Let's Encrypt reaches port 80: host nginx (webroot) or certbot itself */
  challenge: "nginx" | "standalone";
  site_domain: string;
}

export interface SiteTemplate {
  id: string;
  name: string;
  description: string;
}

export interface SiteStatus {
  /** nginx for the decoy site is installed on the host */
  nginx: boolean;
  domain: string;
  https: boolean;
  url: string;
  /** template id, "custom" or "" */
  current: string;
  updated_at: number | null;
  templates: SiteTemplate[];
  custom_html: string;
}

export interface DomainCheck {
  domain: string;
  resolved: string[];
  server_ip: string | null;
  matches: boolean;
}

export type TlsVerifyMode = "verify" | "skip" | "pin";

/** A remote 3x-ui server attached to a main v3 panel (3x-ui "Nodes" page) */
export interface XNode {
  id: number;
  name: string;
  remark: string;
  scheme: "http" | "https";
  address: string;
  port: number;
  base_path: string;
  enable: boolean;
  /** "online" | "offline" | "unknown" … as reported by the main panel's heartbeat */
  status: string;
  last_error: string;
  last_heartbeat: number;
  latency_ms: number | null;
  cpu: number | null;
  mem: number | null;
  uptime: number | null;
  xray_version: string;
  xray_state: string;
  xray_error: string;
  panel_version: string;
  update_available: boolean;
  /** current throughput, bytes/sec */
  net_up: number;
  net_down: number;
  inbounds: number;
  clients: number;
  online: number;
  allow_private_address: boolean;
  tls_verify_mode: TlsVerifyMode;
  pinned_cert_sha256: string;
  has_api_token: boolean;
  inbound_sync_mode: "all" | "selected";
  inbound_tags: string[];
  transitive: boolean;
}

export interface NodesPanel {
  panel_id: number;
  panel_name: string;
  ok: boolean;
  /** false for 3x-ui 2.x: no nodes there */
  supported: boolean;
  error: string | null;
  nodes: XNode[];
}

export interface NodesData {
  panels: NodesPanel[];
  latest_panel_version: string | null;
  totals: { nodes: number; online: number; offline: number; disabled: number; avg_latency_ms: number | null; clients: number; online_clients: number };
}

export interface NodeForm {
  name: string;
  remark: string;
  scheme: "http" | "https";
  address: string;
  port: number;
  base_path: string;
  enable: boolean;
  allow_private_address: boolean;
  tls_verify_mode: TlsVerifyMode;
  pinned_cert_sha256: string;
  api_token: string;
  inbound_sync_mode: "all" | "selected";
  inbound_tags: string[];
}

export interface NodeHeartbeat {
  status: string;
  error?: string;
  latencyMs?: number;
  cpuPct?: number;
  memPct?: number;
  panelVersion?: string;
  xrayVersion?: string;
  uptimeSecs?: number;
}

export interface HosterField {
  key: string;
  label: string;
  secret?: boolean;
  /** may be left empty */
  optional?: boolean;
  placeholder?: string;
  options?: { value: string; label: string }[];
  default?: string;
}

export interface HosterProvider {
  title: string;
  site: string;
  fields: HosterField[];
  help: string;
  help_url: string;
  /** per value of the "endpoint" field, when the key page depends on it */
  help_urls?: Record<string, string>;
  /** the hosting reinstalls a server's OS in place, keeping its IP */
  rebuild?: boolean;
}

export interface HosterServer {
  id: string;
  name: string;
  status: "running" | "stopped" | "pending" | "error" | "unknown";
  status_label: string;
  region: string;
  plan: string;
  specs: string;
  price: string;
  ipv4: string[];
  ipv6: string[];
  created_at: string;
  /** Droplet, VPS, Public Cloud… */
  kind: string;
}

export interface Hoster {
  id: number;
  provider: string;
  name: string;
  created_at: number;
  /** non-secret credential fields */
  credentials: Record<string, string>;
  /** keys of secret fields that are stored */
  secrets_set: string[];
}

export interface HosterAccount {
  login: string;
  name: string;
  status: string;
  balance: string | null;
  limits: string;
}

export interface HosterInfo extends Hoster {
  ok: boolean;
  error: string | null;
  account: HosterAccount | null;
  servers: HosterServer[];
  servers_error: string | null;
}

export interface HosterForm {
  provider: string;
  name: string;
  credentials: Record<string, string>;
}

export interface HostingPlan {
  id: string;
  label: string;
  specs: string;
  /** null when the provider's price list did not have the plan */
  price_hour: number | null;
  /** what a month costs with the billing the server is created with (hourly) */
  price_month: number | null;
  /** OVHcloud: price of the same plan with monthly billing, for comparison */
  price_month_plan: number | null;
  currency: string;
  regions: string[];
  /** the hosting allows one server of this plan per organisation (Scaleway STARDUST1) */
  single?: boolean;
}

export interface CreateOptions {
  /** OVHcloud: Public Cloud projects; null when the provider has none */
  /** discovery: a new OVHcloud project that cannot create servers until it is activated */
  projects: { id: string; name: string; discovery?: boolean }[] | null;
  project: string | null;
  /** false: the provider takes a single SSH key per server */
  ssh_multiple: boolean;
  regions: { id: string; name: string }[];
  plans: HostingPlan[];
  ssh_keys: { id: string; name: string }[];
  /** shown instead of the key list when the hosting adds SSH keys by itself */
  ssh_note?: string;
}

export interface ProvisionForm {
  hoster_id: number;
  panel_id: number;
  name: string;
  region: string;
  plan: string;
  project: string | null;
  ssh_keys: string[];
  /** what the form showed, kept on the job: some hostings use bare IDs for regions and plans */
  region_label: string;
  plan_label: string;
  /** panel address with a Let's Encrypt certificate; empty = the server's IP */
  domain: string;
  /** the admin creates the domain's A record in this Cloudflare account and zone; 0 = the user does */
  dns_account_id: number;
  dns_zone_id: string;
  /** decoy page on port 80 of the node: a site template id, "custom" or "" for none */
  site_template: string;
}

export interface DnsZone {
  id: string;
  name: string;
}

export interface DnsAccount {
  id: number;
  provider: "cloudflare";
  name: string;
  created_at: number;
  ok: boolean;
  error: string;
  zones: DnsZone[];
}

export interface DnsAccounts {
  accounts: DnsAccount[];
  /** how to make a token, and where */
  help: string;
  help_url: string;
}

export type ProvisionStep = "create" | "rebuild" | "boot" | "install" | "connect" | "retire" | "done";

export interface Provision {
  id: number;
  hoster_id: number;
  panel_id: number;
  name: string;
  region: string;
  plan: string;
  server_id: string;
  ip: string;
  node_id: number | null;
  /** the step being run, or the one that failed */
  step: ProvisionStep;
  state: "running" | "done" | "failed" | "deleted";
  error: string;
  log: { t: number; msg: string }[];
  created_at: number;
  updated_at: number;
  panel_url: string;
  username: string;
  domain: string;
  /** certificate the node panel ended up with; "" until the panel answered */
  cert_mode: "" | "domain" | "ip" | "self";
  /** reinstall: id of the job whose server this one replaces */
  replaces: number;
  /** the hosting's own IDs; region and plan above are what the form showed */
  region_id: string;
  plan_id: string;
  project: string;
  /** reinstall on the same server by the hosting (the IP stays) */
  in_place: boolean;
  /** "cloudflare" when the admin keeps the domain's A record */
  dns: "" | "cloudflare";
  site_template: string;
  /** subscription port of the node panel; 0 = 3x-ui's default (servers made before 0.18.0) */
  sub_port: number;
  /** made before the admin kept its own SSH key: an OS reinstall re-runs the old cloud-init install */
  legacy_install: boolean;
}

export interface ProvisionCredentials {
  panel_url: string;
  username: string;
  password: string;
  cert_pin: string;
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
  nodes: () => request<NodesData>("GET", "/api/nodes"),
  hosterProviders: () => request<Record<string, HosterProvider>>("GET", "/api/hosters/providers"),
  hosters: (refresh = false) => request<HosterInfo[]>("GET", `/api/hosters${refresh ? "?refresh=true" : ""}`),
  createHoster: (form: HosterForm) => request<Hoster>("POST", "/api/hosters", form),
  updateHoster: (id: number, form: HosterForm) => request<Hoster>("PUT", `/api/hosters/${id}`, form),
  deleteHoster: (id: number) => request("DELETE", `/api/hosters/${id}`),
  dnsAccounts: () => request<DnsAccounts>("GET", "/api/dns-accounts"),
  createDnsAccount: (body: { name: string; token: string }) => request("POST", "/api/dns-accounts", body),
  updateDnsAccount: (id: number, body: { name: string; token: string }) => request("PUT", `/api/dns-accounts/${id}`, body),
  deleteDnsAccount: (id: number) => request("DELETE", `/api/dns-accounts/${id}`),
  hosterOptions: (id: number, project?: string | null) =>
    request<CreateOptions>("GET", `/api/hosters/${id}/options${project ? `?project=${encodeURIComponent(project)}` : ""}`),
  provisions: () => request<Provision[]>("GET", "/api/provisions"),
  startProvision: (form: ProvisionForm) => request<Provision>("POST", "/api/provisions", form),
  retryProvision: (id: number) => request<Provision>("POST", `/api/provisions/${id}/retry`),
  reinstallProvision: (id: number, body: { in_place: boolean; plan: string; plan_label: string; site_template: string }) =>
    request<Provision>("POST", `/api/provisions/${id}/reinstall`, body),
  deleteProvisionServer: (id: number) => request<Provision>("POST", `/api/provisions/${id}/delete-server`),
  provisionCredentials: (id: number) => request<ProvisionCredentials>("GET", `/api/provisions/${id}/credentials`),
  forgetProvision: (id: number) => request("DELETE", `/api/provisions/${id}`),
  testHoster: (form: HosterForm, hosterId?: number) => request<HosterAccount>("POST", "/api/hosters/test", { ...form, hoster_id: hosterId ?? null }),
  addNode: (panelId: number, form: NodeForm) => request<unknown>("POST", "/api/nodes", { ...form, panel_id: panelId }),
  updateNode: (panelId: number, id: number, form: NodeForm) => request("PUT", `/api/nodes/${panelId}/${id}`, form),
  deleteNode: (panelId: number, id: number) => request("DELETE", `/api/nodes/${panelId}/${id}`),
  enableNode: (panelId: number, id: number, enable: boolean) => request("POST", `/api/nodes/${panelId}/${id}/enable`, { enable }),
  probeNode: (panelId: number, id: number) => request<NodeHeartbeat>("POST", `/api/nodes/${panelId}/${id}/probe`),
  testNode: (panelId: number, form: NodeForm, nodeId = 0) => request<NodeHeartbeat>("POST", "/api/nodes/test", { ...form, panel_id: panelId, node_id: nodeId }),
  nodeInboundOptions: (panelId: number, form: NodeForm, nodeId = 0) =>
    request<{ tag: string; remark: string; protocol: string; port: number }[]>("POST", "/api/nodes/inbound-options", { ...form, panel_id: panelId, node_id: nodeId }),
  site: () => request<SiteStatus>("GET", "/api/site"),
  siteTemplate: (id: string) => request<{ id: string; html: string }>("GET", `/api/site/templates/${id}`),
  siteApply: (template: string) => request<SiteStatus>("POST", "/api/site/apply", { template }),
  siteCustom: (html: string) => request<SiteStatus>("POST", "/api/site/custom", { html }),
  tls: () => request<TlsStatus>("GET", "/api/tls"),
  tlsCheckDomain: (domain: string) => request<DomainCheck>("GET", `/api/tls/check-domain?domain=${encodeURIComponent(domain)}`),
  tlsIssue: (domain: string, email: string, staging: boolean) =>
    request<{ restarting: boolean; url: string; certificate: CertInfo }>("POST", "/api/tls/issue", { domain, email, staging, accept_tos: true }),
  tlsRenew: () => request<{ renewed: boolean; restarting: boolean; certificate: CertInfo }>("POST", "/api/tls/renew"),
  tlsDisable: () => request<{ restarting: boolean }>("POST", "/api/tls/disable"),
};
