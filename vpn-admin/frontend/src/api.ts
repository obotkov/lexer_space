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

/** Download + upload speed (bytes/sec) of each server, sampled every `interval` seconds over `window`. */
export interface NetLoad {
  interval: number;
  window: number;
  series: { key: string; name: string; panel: string; kind: "main" | "node" }[];
  /** null: the server did not answer at that moment */
  points: { t: number; values: Record<string, number | null> }[];
}

/** Ping from the admin's own server to a main panel or a node. */
export interface PingTarget {
  kind: "main" | "node";
  panel: string;
  name: string;
  host: string;
  ip: string;
  port: number;
  enable: boolean;
  /** icmp, or tcp (connect time to the panel port) where ICMP is not allowed or dropped */
  method: "icmp" | "tcp" | "";
  avg_ms: number | null;
  min_ms: number | null;
  max_ms: number | null;
  /** percent of lost probes */
  loss: number | null;
  /** latency the main panel itself measures to this node (its heartbeat) */
  panel_ms: number | null;
  error: string;
}

/** One connect checked through Xray-core with the admin's service client. */
export interface ProbeItem {
  key: string;
  inbound_id: number | null;
  remark: string;
  protocol: string;
  network?: string;
  security?: string;
  port?: number;
  /** the main panel's name or its node's */
  server: string;
  server_kind: "main" | "node";
  enable?: boolean;
  address?: string;
  /** ok: works; fail: no traffic through it; skip: cannot be checked (MTProto, WireGuard…); off: disabled */
  status: "ok" | "fail" | "skip" | "off";
  /** answer through the open tunnel */
  ms: number | null;
  /** tunnel set up plus the first answer */
  connect_ms?: number;
  error: string;
  detail?: string;
  history: { t: number; ms: number | null }[];
}

export interface ProbePanel {
  panel_id: number;
  panel: string;
  error: string | null;
  items: ProbeItem[];
}

export interface ProbeResult {
  checked_at: number;
  duration: number;
  error: string | null;
  panels: ProbePanel[];
  running: boolean;
  interval: number;
  url: string;
  xray: boolean;
}

export interface PingResult {
  checked_at: number;
  targets: PingTarget[];
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
  /** …and the admin gets in after that also on a server it did not create */
  adopt?: boolean;
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
  /** false: the hosting's API cannot delete it (an OVHcloud VPS, NetGrid) */
  deletable: boolean;  /** the hosting's own region id where it differs from what is shown (VDSina, NetGrid) */
  region_id?: string;
}

/** A main panel's node that runs on a hosting's server, with its inbounds. */
export interface ServerNode {
  panel_id: number;
  panel_name: string;
  node_id: number;
  name: string;
  address: string;
  inbounds: {
    id: number;
    remark: string;
    protocol: string;
    port: number;
    /** certificate files of the inbound's TLS that the install does not make (adopt plan only) */
    foreign_certs?: string[];
  }[];
}

/** What deleting a hosting's server takes: the nodes of main panels that run on it, with their inbounds. */
export interface ServerDeletePlan {
  server: HosterServer | null;
  nodes: ServerNode[];
  jobs: number[];
  /** the hosting cannot delete it through its API: only the nodes go, this says why the server stays */
  kept: string;
}

/** From zero on a server the admin did not create: the node it already runs, if any, switches over. */
export interface AdoptPlan {
  server: HosterServer;
  node: ServerNode | null;
  /** job name made of the server's name */
  name: string;
  /** the node's address when it is a domain */
  domain: string;
}

export interface AdoptForm {
  server_id: string;
  /** in the admin and of the new node; the server keeps its name at the hosting */
  name: string;
  ssh_keys: string[];
  /** a server that already is a node: drop that node with its inbounds and join anew */
  fresh_node: boolean;
  panel_id: number;
  os: string;
  domain: string;
  /** Cloudflare account and zone the admin points the domain's A record in; 0 = the user does */
  dns_account_id: number;
  dns_zone_id: string;
  site_template: string;
  connections: boolean;
  connection_ids: number[];
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
  /** UpCloud: disk size, which must hold the system image */
  disk_gb?: number | null;
}

export interface HostingOs {
  /** e.g. "ubuntu-24.04" */
  id: string;
  label: string;
  /** regions that have the image; null = all of them */
  regions: string[] | null;
  /** UpCloud: size of the image, the plan's disk cannot be smaller */
  min_disk_gb: number | null;
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
  /** systems the hosting can install */
  os: HostingOs[];
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
  /** create the enabled connection templates on the new node */
  connections: boolean;
  /** templates picked in the form; omitted = every enabled one */
  connection_ids?: number[];
  os: string;
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

/** A CDN account (Yandex Cloud CDN): connections for whitelisted networks go through its CDN. */
export interface CdnAccount {
  id: number;
  provider: string;
  provider_title: string;
  name: string;
  folder_id: string;
  created_at: number;
}

export interface CdnAccountChecked extends CdnAccount {
  ok: boolean;
  error: string;
  resources: number;
}

export interface CdnProvider {
  title: string;
  available: boolean;
  help?: string;
  help_url?: string;
}

export interface CdnAccounts {
  accounts: CdnAccountChecked[];
  providers: Record<string, CdnProvider>;
}

export interface DnsAccounts {
  accounts: DnsAccount[];
  /** how to make a token, and where */
  help: string;
  help_url: string;
}

export type ProvisionStep = "create" | "rebuild" | "boot" | "install" | "connect" | "connections" | "retire" | "done";

export type ConnectionNet = "tcp" | "udp" | "both";

/** one connection planned for or created on a server */
export interface ProvisionConnection {
  template_id: number;
  kind: string;
  title: string;
  remark: string;
  port: number;
  net: ConnectionNet;
  /** inbound of the main panel bound to the node; null until created */
  inbound_id: number | null;
  error: string;
  /** a connection through a CDN: its name (SNI and Host) and the CDN's address the links lead to */
  cdn_domain: string;
  cdn_address: string;
}

export type ConnectionOptionValue = string | number | boolean;

/** Sections of an inbound in 3x-ui as a template builds them */
export type ConnectionSections = Record<"settings" | "streamSettings" | "sniffing", Record<string, unknown>>;
/** A template's own JSON: what differs from the form's build; null removes a key, "{auto}" keeps the server's value */
export type ConnectionCustom = Partial<ConnectionSections>;

export interface ConnectionKind {
  kind: string;
  title: string;
  protocol: string;
  net: ConnectionNet;
  /** needs the server's certificate */
  tls: boolean;
  /** suggested port; 0 = random */
  port: number;
  remark: string;
  note: string;
  options: Record<string, { default: ConnectionOptionValue; choices: ConnectionOptionValue[] | null }>;
}

export interface ConnectionTemplate {
  id: number;
  kind: string;
  kind_title: string;
  protocol: string;
  net: ConnectionNet;
  tls: boolean;
  remark: string;
  enabled: boolean;
  /** 0 = a random free port on every server */
  port: number;
  options: Record<string, ConnectionOptionValue>;
  custom: ConnectionCustom | null;
  position: number;
}

export interface ConnectionUsers {
  mode: "all" | "selected" | "none";
  emails: string[];
}

export interface ConnectionsData {
  templates: ConnectionTemplate[];
  kinds: ConnectionKind[];
  users: ConnectionUsers;
  /** users of the v3 panels */
  emails: string[];
  /** what a CDN connection can go through */
  cdn_accounts: CdnAccount[];
}

export interface ConnectionTemplateForm {
  kind: string;
  remark: string;
  enabled: boolean;
  port: number;
  options: Record<string, ConnectionOptionValue>;
  custom: ConnectionCustom | null;
}

/** A template made of a foreign inbound */
export interface ConnectionImport {
  kind: string;
  port: number;
  remark: string;
  options: Record<string, ConnectionOptionValue>;
  custom: ConnectionCustom | null;
  notes: string[];
}

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
  /** from zero on a server the admin did not create */
  adopted: boolean;
  connections: ProvisionConnection[];
  /** system installed on the server; a reinstall keeps it */
  os: string;
  os_label: string;
}

export interface ProvisionCredentials {
  panel_url: string;
  username: string;
  password: string;
  cert_pin: string;
}

export interface BackupSection {
  key: string;
  title: string;
  /** sections it is restored together with (created servers refer to the panels and hostings) */
  needs: string[];
}

export interface BackupFile {
  format: string;
  version: number;
  app_version: string;
  created_at: number;
  /** what the file holds and how many of each, readable without the password */
  sections: Record<string, number>;
  kdf: Record<string, unknown>;
  payload: string;
}

export interface BackupPreview {
  app_version: string;
  created_at: number;
  sections: (BackupSection & { items: string[]; current: number })[];
}

export interface BackupRestored {
  restored: { key: string; title: string; count: number }[];
  /** copy of the database before the import, next to it in the data folder */
  snapshot: string;
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
  setInboundEnable: (panelId: number, inboundId: number, enable: boolean) =>
    request<{ ok: boolean }>("POST", "/api/inbounds/enable", { panel_id: panelId, inbound_id: inboundId, enable }),
  netload: () => request<NetLoad>("GET", "/api/netload"),
  probe: () => request<ProbeResult>("GET", "/api/probe"),
  probeRun: () => request<ProbeResult>("POST", "/api/probe/run"),
  ping: (refresh = false) => request<PingResult>("GET", `/api/ping${refresh ? "?refresh=true" : ""}`),
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
  cdnAccounts: () => request<CdnAccounts>("GET", "/api/cdn-accounts"),
  createCdnAccount: (body: { provider: string; name: string; folder_id: string; key: string }) => request("POST", "/api/cdn-accounts", body),
  updateCdnAccount: (id: number, body: { provider: string; name: string; folder_id: string; key: string }) =>
    request("PUT", `/api/cdn-accounts/${id}`, body),
  deleteCdnAccount: (id: number) => request("DELETE", `/api/cdn-accounts/${id}`),
  dnsAccounts: () => request<DnsAccounts>("GET", "/api/dns-accounts"),
  createDnsAccount: (body: { name: string; token: string }) => request("POST", "/api/dns-accounts", body),
  updateDnsAccount: (id: number, body: { name: string; token: string }) => request("PUT", `/api/dns-accounts/${id}`, body),
  deleteDnsAccount: (id: number) => request("DELETE", `/api/dns-accounts/${id}`),
  serverDeletePlan: (hosterId: number, serverId: string) =>
    request<ServerDeletePlan>("POST", `/api/hosters/${hosterId}/servers/delete-plan`, { server_id: serverId }),
  deleteHostedServer: (hosterId: number, serverId: string) =>
    request<{ server: string; nodes: string[]; inbounds: number; kept: string }>("POST", `/api/hosters/${hosterId}/servers/delete`, { server_id: serverId }),
  serverAdoptPlan: (hosterId: number, serverId: string) =>
    request<AdoptPlan>("POST", `/api/hosters/${hosterId}/servers/adopt-plan`, { server_id: serverId }),
  adoptServer: (hosterId: number, form: AdoptForm) => request<Provision>("POST", `/api/hosters/${hosterId}/servers/adopt`, form),
  hosterOptions: (id: number, project?: string | null) =>
    request<CreateOptions>("GET", `/api/hosters/${id}/options${project ? `?project=${encodeURIComponent(project)}` : ""}`),
  provisions: () => request<Provision[]>("GET", "/api/provisions"),
  startProvision: (form: ProvisionForm) => request<Provision>("POST", "/api/provisions", form),
  retryProvision: (id: number) => request<Provision>("POST", `/api/provisions/${id}/retry`),
  restartProvisionInstall: (id: number) => request<Provision>("POST", `/api/provisions/${id}/restart-install`),
  reinstallProvision: (id: number, body: { in_place: boolean; plan: string; plan_label: string; site_template: string }) =>
    request<Provision>("POST", `/api/provisions/${id}/reinstall`, body),
  deleteProvisionServer: (id: number) => request<Provision>("POST", `/api/provisions/${id}/delete-server`),
  applyProvisionConnections: (id: number) => request<Provision>("POST", `/api/provisions/${id}/connections`),
  connections: () => request<ConnectionsData>("GET", "/api/connections"),
  createConnection: (form: ConnectionTemplateForm) => request<ConnectionTemplate>("POST", "/api/connections", form),
  updateConnection: (id: number, form: ConnectionTemplateForm) => request<ConnectionTemplate>("PUT", `/api/connections/${id}`, form),
  enableConnection: (id: number, enabled: boolean) => request<ConnectionTemplate>("POST", `/api/connections/${id}/enabled`, { enabled }),
  enableAllConnections: (enabled: boolean) => request("POST", "/api/connections-enabled", { enabled }),
  orderConnections: (ids: number[]) => request("POST", "/api/connections/order", { ids }),
  deleteConnection: (id: number) => request("DELETE", `/api/connections/${id}`),
  setConnectionUsers: (users: ConnectionUsers) => request<ConnectionUsers>("PUT", "/api/connections-users", users),
  connectionPreview: (kind: string, options: Record<string, ConnectionOptionValue>, custom: ConnectionCustom | null) =>
    request<{ json: ConnectionSections }>("POST", "/api/connections/preview", { kind, options, custom }),
  connectionCustom: (kind: string, options: Record<string, ConnectionOptionValue>, json: unknown) =>
    request<{ custom: ConnectionCustom | null }>("POST", "/api/connections/json", { kind, options, json }),
  importConnection: (text: string, keepSecrets: boolean) =>
    request<ConnectionImport>("POST", "/api/connections/import", { text, keep_secrets: keepSecrets }),
  checkSni: (host: string) => request<{ results: Record<string, string> }>("POST", "/api/connections/check-sni", { host }),
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
  backupSections: () => request<BackupSection[]>("GET", "/api/backup/sections"),
  backupExport: (password: string, sections: string[]) => request<BackupFile>("POST", "/api/backup/export", { password, sections }),
  backupPreview: (backup: BackupFile, password: string) => request<BackupPreview>("POST", "/api/backup/preview", { backup, password }),
  backupImport: (backup: BackupFile, password: string, sections: string[]) =>
    request<BackupRestored>("POST", "/api/backup/import", { backup, password, sections }),
  tls: () => request<TlsStatus>("GET", "/api/tls"),
  tlsCheckDomain: (domain: string) => request<DomainCheck>("GET", `/api/tls/check-domain?domain=${encodeURIComponent(domain)}`),
  tlsIssue: (domain: string, email: string, staging: boolean) =>
    request<{ restarting: boolean; url: string; certificate: CertInfo }>("POST", "/api/tls/issue", { domain, email, staging, accept_tos: true }),
  tlsRenew: () => request<{ renewed: boolean; restarting: boolean; certificate: CertInfo }>("POST", "/api/tls/renew"),
  tlsDisable: () => request<{ restarting: boolean }>("POST", "/api/tls/disable"),
};
