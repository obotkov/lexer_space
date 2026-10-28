import { useEffect, useState, type FormEvent } from "react";
import { api, type AdoptPlan, type ConnectionTemplate, type DnsAccount, type HostingOs, type HosterInfo, type HosterServer, type PanelInfo } from "../api";
import { fillRemark } from "./CreateServerDialog";
import { StubTemplateSelect } from "./StubTemplateSelect";

const DEFAULT_OS: HostingOs = { id: "ubuntu-24.04", label: "Ubuntu 24.04", regions: null, min_disk_gb: null };

type Address = "ip" | "domain" | "cloudflare";

/** Where the panel address starts: the node's domain as it is (in a Cloudflare zone of the admin, or the
 * user's own), otherwise a Cloudflare name like for a new server, or the IP. */
function startAddress(plan: AdoptPlan, dnsAccounts: DnsAccount[]): { address: Address; zoneKey: string; label: string; domain: string } {
  const first = dnsAccounts[0] ? `${dnsAccounts[0].id}:${dnsAccounts[0].zones[0].id}` : "";
  if (plan.domain) {
    for (const a of dnsAccounts)
      for (const z of a.zones)
        if (plan.domain === z.name || plan.domain.endsWith(`.${z.name}`))
          return { address: "cloudflare", zoneKey: `${a.id}:${z.id}`, label: plan.domain.slice(0, -z.name.length).replace(/\.$/, ""), domain: "" };
    return { address: "domain", zoneKey: first, label: plan.name, domain: plan.domain };
  }
  return { address: dnsAccounts.length ? "cloudflare" : "ip", zoneKey: first, label: plan.name, domain: "" };
}

/** From zero on a server the admin did not create: the hosting reinstalls its OS (the IP stays), the admin
 * installs 3x-ui as on a new server, and the node it already runs switches over, or a new node joins. */
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
  const [systems, setSystems] = useState<HostingOs[] | null>(null);
  const [os, setOs] = useState(DEFAULT_OS.id);
  // panel address: the server's IP, a domain whose A record the user keeps, or a Cloudflare name the admin points
  const [address, setAddress] = useState<Address>("ip");
  const [domain, setDomain] = useState("");
  const [zoneKey, setZoneKey] = useState("");
  const [label, setLabel] = useState("");
  const [siteTemplate, setSiteTemplate] = useState<string | null>(null);
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
        const start = startAddress(p, dnsAccounts);
        setAddress(start.address);
        setZoneKey(start.zoneKey);
        setLabel(start.label);
        setDomain(start.domain);
      },
      (e) => alive && setError((e as Error).message),
    );
    // the systems the hosting has; without them the default one is offered
    api.hosterOptions(hoster.id).then(
      (o) => alive && setSystems(o.os.filter((x) => !x.regions || !server.region_id || x.regions.includes(server.region_id))),
      () => alive && setSystems([DEFAULT_OS]),
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
  }, [hoster.id, server.id, server.region_id]);

  const node = plan?.node ?? null;
  const osList = systems && systems.length > 0 ? systems : [DEFAULT_OS];
  const osId = osList.some((o) => o.id === os) ? os : osList[0].id;
  const osLabel = osList.find((o) => o.id === osId)?.label ?? osId;
  const ip = server.ipv4[0] ?? "";
  const foreign = node?.inbounds.filter((i) => i.foreign_certs?.length) ?? [];
  const [dnsAccountId, zoneId] = zoneKey.split(":");
  const zone = dnsAccounts.find((a) => String(a.id) === dnsAccountId)?.zones.find((z) => z.id === zoneId);
  const name = label.trim().toLowerCase();
  const cloudflareName = zone ? (name ? `${name}.${zone.name}` : zone.name) : "";
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
    if (!confirm(`Переустановить систему на сервере «${server.name}» (${ip})? Диск будет стёрт, всё, что на нём сейчас, пропадёт.`)) return;
    setBusy(true);
    setError("");
    try {
      await api.adoptServer(hoster.id, {
        server_id: server.id,
        panel_id: node ? node.panel_id : panelId,
        os: osId,
        domain: panelDomain,
        dns_account_id: address === "cloudflare" ? Number(dnsAccountId) : 0,
        dns_zone_id: address === "cloudflare" ? zoneId : "",
        site_template: siteTemplate ?? "",
        connections: !node && picked.size > 0,
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
            <ol className="delete-steps small">
              <li>
                {providerTitle} переустановит ОС ({osLabel}) на этом же сервере: <b>диск будет стёрт</b>, IP {ip} и тариф останутся прежними,
                новый сервер не заказывается.
              </li>
              <li>
                Админка выполнит штатную установку, как у нового сервера: Docker, 3x-ui с новыми логином и паролем, сайт-заглушка и сертификат
                Let's Encrypt.
              </li>
              <li>
                {node ? (
                  <>
                    Узел «{node.name}» основной панели «{node.panel_name}» переключится на новую установку: его подключения
                    {node.inbounds.length > 0 ? ` (${node.inbounds.length} шт.)` : ""} и клиенты сохранятся, порты подключений откроются как
                    раньше.
                  </>
                ) : (
                  <>Сервер подключится новым узлом к основной панели, которую вы выберете ниже.</>
                )}
              </li>
              <li>Сервер появится в блоке «Новые серверы»: дальше его можно переустанавливать с нуля и удалять оттуда, как созданные в админке.</li>
            </ol>
            <div className="muted small">Пока идёт установка (обычно 5–10 минут), VPN на этом сервере не работает.</div>

            {foreign.length > 0 && (
              <div className="notice notice-warn small">
                У {foreign.length === 1 ? "подключения" : "подключений"} {foreign.map((i) => `«${i.remark || i.protocol} :${i.port}»`).join(", ")} TLS-сертификат
                лежит в файлах старой системы ({[...new Set(foreign.flatMap((i) => i.foreign_certs ?? []))].join(", ")}): после переустановки их
                не будет. Поправьте сертификат в настройках этих подключений в основной панели: у новой установки он лежит в /root/cert/le.crt и
                /root/cert/le.key.
              </div>
            )}

            <label className="field">
              <span>Система</span>
              <select className="input" value={osId} onChange={(e) => setOs(e.target.value)} disabled={!systems}>
                {osList.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>

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
                    value={label}
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

            {!node && (
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
                                {fillRemark(t.remark, plan.name, server.region)}
                                <span className="muted small">
                                  {" "}
                                  · {t.kind_title} · порт {t.port || "случайный"}
                                </span>
                              </span>
                            </label>
                          ))}
                        </div>
                        {address !== "cloudflare" && templates.some((t) => t.kind === "vless_xhttp_cdn" && picked.has(t.id)) && (
                          <small className="error-text">
                            Подключение через CDN создаётся только на сервере с доменом Cloudflare: выберите адрес «Домен Cloudflare» выше или снимите
                            его галочку.
                          </small>
                        )}
                      </>
                    ) : (
                      <small className="muted">В разделе «Подключения» ни одно не включено: инбаунды узлу можно добавить потом.</small>
                    )}
                  </div>
                )}
              </>
            )}
          </>
        )}

        {error && <div className="notice notice-bad small">{error}</div>}

        <div className="modal-actions">
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
            Отмена
          </button>
          <button type="submit" className="btn btn-danger" disabled={!plan || busy || (!node && mainPanels.length === 0)}>
            {busy ? "Запускаю…" : "Установить с нуля"}
          </button>
        </div>
      </form>
    </div>
  );
}
