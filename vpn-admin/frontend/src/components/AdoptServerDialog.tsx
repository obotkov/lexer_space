import { useEffect, useState, type FormEvent } from "react";
import { api, type AdoptPlan, type ConnectionTemplate, type CreateOptions, type DnsAccount, type HostingOs, type HosterInfo, type HosterServer, type PanelInfo } from "../api";
import { fillRemark, randomName, SshKeyField } from "./CreateServerDialog";
import { StubTemplateSelect } from "./StubTemplateSelect";

const DEFAULT_OS: HostingOs = { id: "ubuntu-24.04", label: "Ubuntu 24.04", regions: null, min_disk_gb: null };

type Address = "ip" | "domain" | "cloudflare";

/** Where the panel address starts: the node's domain as it is (in a Cloudflare zone of the admin, or the
 * user's own), otherwise a Cloudflare name following the server name like for a new server, or the IP.
 * `label` null: the Cloudflare name follows the server name. */
function startAddress(plan: AdoptPlan, dnsAccounts: DnsAccount[]): { address: Address; zoneKey: string; label: string | null; domain: string } {
  const first = dnsAccounts[0] ? `${dnsAccounts[0].id}:${dnsAccounts[0].zones[0].id}` : "";
  if (plan.domain) {
    for (const a of dnsAccounts)
      for (const z of a.zones)
        if (plan.domain === z.name || plan.domain.endsWith(`.${z.name}`))
          return { address: "cloudflare", zoneKey: `${a.id}:${z.id}`, label: plan.domain.slice(0, -z.name.length).replace(/\.$/, ""), domain: "" };
    return { address: "domain", zoneKey: first, label: null, domain: plan.domain };
  }
  return { address: dnsAccounts.length ? "cloudflare" : "ip", zoneKey: first, label: null, domain: "" };
}

/** From zero on a server the admin did not create, with everything a new server is set up with but the plan
 * and region: the hosting reinstalls its OS (the IP stays), the admin installs 3x-ui as on a new server, and
 * the node it already runs switches over or is replaced by a new one. */
export function AdoptServerDialog({
  hoster,
  server,
  providerTitle,
  panels,
  dnsAccounts,
  onClose,
  onStarted,
}: {
  hoster: HosterInfo;
  server: HosterServer;
  providerTitle: string;
  panels: PanelInfo[];
  /** Cloudflare accounts with zones: the admin can point a name of theirs at the server */
  dnsAccounts: DnsAccount[];
  onClose: () => void;
  onStarted: () => void;
}) {
  const mainPanels = panels.filter((p) => p.ok && p.api_version === "v3");
  const [plan, setPlan] = useState<AdoptPlan | null>(null);
  const [options, setOptions] = useState<CreateOptions | null>(null);
  const [name, setName] = useState("");
  const [os, setOs] = useState(DEFAULT_OS.id);
  const [sshKeys, setSshKeys] = useState<string[]>([]);
  // panel address: the server's IP, a domain whose A record the user keeps, or a Cloudflare name the admin points
  const [address, setAddress] = useState<Address>("ip");
  const [domain, setDomain] = useState("");
  const [zoneKey, setZoneKey] = useState("");
  const [label, setLabel] = useState<string | null>(null);
  const [siteTemplate, setSiteTemplate] = useState<string | null>(null);
  // a server that already is a node: keep that node (switched over) or join anew like a new server
  const [freshNode, setFreshNode] = useState(false);
  const [panelId, setPanelId] = useState(mainPanels[0]?.id ?? 0);
  const [templates, setTemplates] = useState<ConnectionTemplate[] | null>(null);
  const [picked, setPicked] = useState<Set<number>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    api.serverAdoptPlan(hoster.id, server.id).then(
      (p) => {
        if (!alive) return;
        setPlan(p);
        setName(p.name);
        const start = startAddress(p, dnsAccounts);
        setAddress(start.address);
        setZoneKey(start.zoneKey);
        setLabel(start.label);
        setDomain(start.domain);
        if (p.node) setPanelId(p.node.panel_id);
      },
      (e) => alive && setError((e as Error).message),
    );
    // systems and SSH keys of the account; without them the default system is offered
    api.hosterOptions(hoster.id).then(
      (o) => {
        if (!alive) return;
        setOptions(o);
        setSshKeys(o.ssh_multiple ? o.ssh_keys.map((k) => k.id) : o.ssh_keys.slice(0, 1).map((k) => k.id));
      },
      () => alive && setOptions(null),
    );
    api.connections().then(
      (d) => {
        if (!alive) return;
        const enabled = d.templates.filter((t) => t.enabled);
        setTemplates(enabled);
        setPicked(new Set(enabled.map((t) => t.id)));
      },
      () => alive && setTemplates([]),
    );
    return () => {
      alive = false;
    };
    // dnsAccounts are read once the plan comes: a refresh of them in the parent must not reset the form
  }, [hoster.id, server.id]);

  const node = plan?.node ?? null;
  const keepNode = !!node && !freshNode;
  const systems = options?.os.filter((x) => !x.regions || !server.region_id || x.regions.includes(server.region_id)) ?? [];
  // without the account's options the default system is offered; with them, only what the hosting has
  const osList = options ? systems : [DEFAULT_OS];
  const osId = osList.some((o) => o.id === os) ? os : osList[0]?.id ?? "";
  const osLabel = osList.find((o) => o.id === osId)?.label ?? osId;
  const ip = server.ipv4[0] ?? "";
  const foreign = keepNode ? node.inbounds.filter((i) => i.foreign_certs?.length) : [];
  const [dnsAccountId, zoneId] = zoneKey.split(":");
  const zone = dnsAccounts.find((a) => String(a.id) === dnsAccountId)?.zones.find((z) => z.id === zoneId);
  const sub = (label ?? name).trim().toLowerCase();
  const cloudflareName = zone ? (sub ? `${sub}.${zone.name}` : zone.name) : "";
  const panelDomain = address === "domain" ? domain.trim() : address === "cloudflare" ? cloudflareName : "";
  const pick = (id: number, on: boolean) =>
    setPicked((all) => {
      const next = new Set(all);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!plan) return;
    const dropping = node && freshNode ? ` Узел «${node.name}» и его подключения (${node.inbounds.length} шт.) удалятся из основной панели.` : "";
    if (!confirm(`Переустановить систему на сервере «${server.name}» (${ip})? Диск будет стёрт, всё, что на нём сейчас, пропадёт.${dropping}`)) return;
    setBusy(true);
    setError("");
    try {
      await api.adoptServer(hoster.id, {
        server_id: server.id,
        name: name.trim(),
        ssh_keys: sshKeys,
        fresh_node: !!node && freshNode,
        panel_id: keepNode ? node.panel_id : panelId,
        os: osId,
        domain: panelDomain,
        dns_account_id: address === "cloudflare" ? Number(dnsAccountId) : 0,
        dns_zone_id: address === "cloudflare" ? zoneId : "",
        site_template: siteTemplate ?? "",
        connections: !keepNode && picked.size > 0,
        connection_ids: [...picked],
      });
      onStarted();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <form className="modal modal-wide" onSubmit={submit}>
        <div className="modal-head">
          <h2>Установить «{server.name}» с нуля</h2>
          <button type="button" className="btn btn-small" onClick={onClose} disabled={busy}>
            ✕
          </button>
        </div>

        {!plan && !error && <div className="muted small">Проверяю, подключён ли этот сервер узлом к основной панели…</div>}

        {plan && (
          <>
            <div className="field-row">
              <label className="field">
                <span>Имя сервера</span>
                <div className="input-with-button">
                  <input className="input mono" required pattern="[a-zA-Z0-9][a-zA-Z0-9.\-]{0,62}" value={name} onChange={(e) => setName(e.target.value)} />
                  <button type="button" className="btn btn-small" title="Другое случайное имя" onClick={() => setName(randomName())}>
                    ↻
                  </button>
                </div>
              </label>
              <label className="field">
                <span>Регион</span>
                <input className="input" value={server.region || "—"} disabled readOnly />
              </label>
              <label className="field">
                <span>Система</span>
                <select className="input" value={osId} onChange={(e) => setOs(e.target.value)} disabled={osList.length === 0}>
                  {osList.map((o) => (
                    <option key={o.id} value={o.id}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            {osList.length === 0 && (
              <div className="notice notice-bad small">{providerTitle} не вернул ни одной системы из поддерживаемых (Ubuntu 22.04/24.04, Debian 12/13): установить не на что.</div>
            )}
            <small className="muted">
              Тариф и регион не меняются: это тот же сервер{[server.plan, server.specs, server.price].filter(Boolean).length > 0 ? ` (${[server.plan, server.specs, server.price].filter(Boolean).join(" · ")})` : ""}.
              Имя — для админки, узла и подключений; у хостинга сервер остаётся под своим именем.
            </small>

            {options && <SshKeyField options={options} value={sshKeys} onChange={setSshKeys} />}

            <div className="field">
              <span>Адрес панели узла и сертификат</span>
              <div className="segmented">
                {(
                  [
                    ["ip", "IP-адрес сервера"],
                    ...(dnsAccounts.length ? [["cloudflare", "Домен Cloudflare"]] : []),
                    ["domain", "Свой домен"],
                  ] as [Address, string][]
                ).map(([id, title]) => (
                  <button key={id} type="button" className={address === id ? "active" : ""} aria-pressed={address === id} onClick={() => setAddress(id)}>
                    {title}
                  </button>
                ))}
              </div>
              {address === "domain" && (
                <input
                  className="input mono"
                  required
                  placeholder="vpn1.example.com"
                  pattern="([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                />
              )}
              {address === "cloudflare" && (
                <div className="domain-row">
                  <input
                    className="input mono"
                    aria-label="Имя в домене"
                    pattern="([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
                    value={label ?? name}
                    onChange={(e) => setLabel(e.target.value)}
                  />
                  <span className="muted">.</span>
                  <select className="input" aria-label="Домен Cloudflare" value={zoneKey} onChange={(e) => setZoneKey(e.target.value)}>
                    {dnsAccounts.map((a) =>
                      a.zones.map((z) => (
                        <option key={`${a.id}:${z.id}`} value={`${a.id}:${z.id}`}>
                          {dnsAccounts.length > 1 ? `${z.name} (${a.name})` : z.name}
                        </option>
                      )),
                    )}
                  </select>
                </div>
              )}
              <small className="muted">
                {address === "cloudflare"
                  ? `Админка создаст в Cloudflare A-запись ${cloudflareName} → ${ip} (без проксирования, иначе VPN не заработает) или оставит её, если она уже указывает на этот сервер, а сервер выпустит на этот домен сертификат Let's Encrypt. При удалении сервера из админки запись удалится.`
                  : address === "domain"
                    ? `A-запись ${domain.trim() || "домена"} должна указывать на ${ip}: тогда сервер выпустит сертификат Let's Encrypt на домен. Если записи нет, установка ждёт её до 20 минут, затем берёт сертификат на IP.`
                    : "Сертификат Let's Encrypt на IP: короткий (около 6 дней), сервер продлевает его сам."}
                {plan.domain && panelDomain === plan.domain ? " Домен взят из адреса узла." : ""}{" "}
                Если Let's Encrypt откажет, панель останется на самоподписанном сертификате, закреплённом в основной панели.
              </small>
            </div>

            <StubTemplateSelect value={siteTemplate} onChange={setSiteTemplate} />

            {node && (
              <div className="field">
                <span>Узел основной панели</span>
                <div className="segmented">
                  <button type="button" className={freshNode ? "" : "active"} aria-pressed={!freshNode} onClick={() => setFreshNode(false)}>
                    Оставить узел «{node.name}»
                  </button>
                  <button type="button" className={freshNode ? "active" : ""} aria-pressed={freshNode} onClick={() => setFreshNode(true)}>
                    Подключить заново
                  </button>
                </div>
                <small className="muted">
                  {freshNode
                    ? `Узел «${node.name}» и его подключения (${node.inbounds.length} шт.) удалятся из основной панели «${node.panel_name}», клиенты останутся. Сервер подключится новым узлом с подключениями, выбранными ниже, как новый сервер: у клиентов появятся новые ссылки.`
                    : `Узел «${node.name}» основной панели «${node.panel_name}» переключится на новую установку: его подключения (${node.inbounds.length} шт.) и клиенты сохранятся, ссылки не изменятся, порты подключений откроются как раньше. Недостающие подключения из шаблонов потом добавит «Раскатать подключения».`}
                </small>
              </div>
            )}

            {foreign.length > 0 && (
              <div className="notice notice-warn small">
                У {foreign.length === 1 ? "подключения" : "подключений"} {foreign.map((i) => `«${i.remark || i.protocol} :${i.port}»`).join(", ")} TLS-сертификат
                лежит в файлах старой системы ({[...new Set(foreign.flatMap((i) => i.foreign_certs ?? []))].join(", ")}): после переустановки их
                не будет. Поправьте сертификат в настройках этих подключений в основной панели: у новой установки он лежит в /root/cert/le.crt и
                /root/cert/le.key.
              </div>
            )}

            {!keepNode && (
              <>
                <label className="field">
                  <span>Подключить узлом к основной панели</span>
                  <select className="input" value={panelId} onChange={(e) => setPanelId(Number(e.target.value))} disabled={mainPanels.length === 0}>
                    {mainPanels.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                      </option>
                    ))}
                  </select>
                  {mainPanels.length === 0 && <small className="error-text">Нет доступной основной панели 3x-ui v3: добавьте её в разделе «Серверы».</small>}
                </label>

                {templates && (
                  <div className="field">
                    <span>Подключения на сервере</span>
                    {templates.length > 0 ? (
                      <>
                        <div className="conn-pick">
                          {templates.map((t) => (
                            <label key={t.id} className="checkbox">
                              <input type="checkbox" checked={picked.has(t.id)} onChange={(e) => pick(t.id, e.target.checked)} />
                              <span>
                                {fillRemark(t.remark, name, server.region)}
                                <span className="muted small">
                                  {" "}
                                  · {t.kind_title} · порт {t.port || "случайный"}
                                </span>
                              </span>
                            </label>
                          ))}
                        </div>
                        <small className="muted">
                          Включённые подключения из раздела «Подключения». Выбрано {picked.size} из {templates.length}:{" "}
                          <button type="button" className="link-button" onClick={() => setPicked(new Set(templates.map((t) => t.id)))}>
                            все
                          </button>{" "}
                          ·{" "}
                          <button type="button" className="link-button" onClick={() => setPicked(new Set())}>
                            ни одного
                          </button>
                        </small>
                        {address !== "cloudflare" && templates.some((t) => t.kind === "vless_xhttp_cdn" && picked.has(t.id)) && (
                          <small className="error-text">
                            Подключение через CDN создаётся только на сервере с доменом Cloudflare: выберите адрес «Домен Cloudflare» выше или снимите
                            его галочку.
                          </small>
                        )}
                      </>
                    ) : (
                      <small className="muted">В разделе «Подключения» ни одно не включено: инбаунды узлу можно добавить потом в основной панели.</small>
                    )}
                  </div>
                )}
              </>
            )}

            <div className="notice notice-info small">
              {providerTitle} переустановит {osLabel} на этом же сервере: <b>диск будет стёрт</b>, IP {ip} и тариф останутся прежними, новый сервер
              не заказывается. Затем админка поставит Docker, 3x-ui с новыми логином и паролем, сайт-заглушку и сертификат, как на новый сервер,
              и сервер появится в блоке «Новые серверы»: дальше его можно переустанавливать с нуля и удалять оттуда. Обычно всё занимает 5–10
              минут, VPN на сервере в это время не работает.
            </div>
          </>
        )}

        {error && <div className="notice notice-bad small">{error}</div>}

        <div className="modal-actions">
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
            Отмена
          </button>
          <button type="submit" className="btn btn-danger" disabled={!plan || busy || !osId || (!keepNode && mainPanels.length === 0)}>
            {busy ? "Запускаю…" : "Установить с нуля"}
          </button>
        </div>
      </form>
    </div>
  );
}
