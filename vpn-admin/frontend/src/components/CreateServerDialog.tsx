import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, type ConnectionTemplate, type CreateOptions, type DnsAccount, type HosterInfo, type HostingPlan, type PanelInfo } from "../api";
import { formatPrice } from "../format";
import { StubTemplateSelect } from "./StubTemplateSelect";

const randomSuffix = () => Math.random().toString(36).slice(2, 6);


/** Order a server at a hosting account; the admin installs 3x-ui on it and attaches it as a node. */
export function CreateServerDialog({
  hoster,
  dnsAccounts,
  providerTitle,
  panels,
  onClose,
  onStarted,
}: {
  hoster: HosterInfo;
  /** Cloudflare accounts with zones: their domains can be given to the server automatically */
  dnsAccounts: DnsAccount[];
  providerTitle: string;
  panels: PanelInfo[];
  onClose: () => void;
  onStarted: () => void;
}) {
  const mainPanels = panels.filter((p) => p.ok && p.api_version === "v3");
  // project the options are loaded for (OVHcloud); null = the provider's default
  const [project, setProject] = useState<string | null>(null);
  const [options, setOptions] = useState<CreateOptions | null>(null);
  const [name, setName] = useState(`vpn-node-${randomSuffix()}`);
  const [region, setRegion] = useState("");
  const [plan, setPlan] = useState("");
  const [sshKeys, setSshKeys] = useState<string[]>([]);
  const [panelId, setPanelId] = useState(mainPanels[0]?.id ?? 0);
  // panel address: the server's IP, a domain whose A record the user makes, or a Cloudflare name the admin makes
  const [address, setAddress] = useState<"ip" | "domain" | "cloudflare">(dnsAccounts.length ? "cloudflare" : "ip");
  const [domain, setDomain] = useState("");
  const [zoneKey, setZoneKey] = useState(dnsAccounts[0] ? `${dnsAccounts[0].id}:${dnsAccounts[0].zones[0].id}` : "");
  const [subdomain, setSubdomain] = useState<string | null>(null); // null = follow the server name
  const [siteTemplate, setSiteTemplate] = useState<string | null>(null);
  const [withConnections, setWithConnections] = useState(true);
  // enabled connection templates: what the new node gets right after it joins the main panel
  const [templates, setTemplates] = useState<ConnectionTemplate[] | null>(null);
  useEffect(() => {
    api.connections().then(
      (d) => setTemplates(d.templates.filter((t) => t.enabled)),
      () => setTemplates([]),
    );
  }, []);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError("");
    api.hosterOptions(hoster.id, project).then(
      (o) => {
        if (!alive) return;
        setOptions(o);
        const usable = o.regions.filter((x) => o.plans.some((p) => p.regions.includes(x.id)));
        setRegion((r) => (usable.some((x) => x.id === r) ? r : usable[0]?.id ?? ""));
        setSshKeys(o.ssh_multiple ? o.ssh_keys.map((k) => k.id) : o.ssh_keys.slice(0, 1).map((k) => k.id));
        setLoading(false);
      },
      (e) => {
        if (!alive) return;
        setError((e as Error).message);
        setLoading(false);
      },
    );
    return () => {
      alive = false;
    };
  }, [hoster.id, project]);

  // regions without a single plan are of no use here
  const regions = options?.regions.filter((r) => options.plans.some((p) => p.regions.includes(r.id))) ?? [];
  const plans = options?.plans.filter((p) => p.regions.includes(region)) ?? [];
  // the chosen plan if the region has it, otherwise the cheapest one there
  const planId = plans.some((p) => p.id === plan) ? plan : plans[0]?.id ?? "";

  const chosen = plans.find((p) => p.id === planId);

  const [dnsAccountId, zoneId] = zoneKey.split(":");
  const zone = dnsAccounts.find((a) => String(a.id) === dnsAccountId)?.zones.find((z) => z.id === zoneId);
  const label = (subdomain ?? name).trim().toLowerCase();
  const cloudflareName = zone ? (label ? `${label}.${zone.name}` : zone.name) : "";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.startProvision({
        hoster_id: hoster.id,
        panel_id: panelId,
        name,
        region,
        plan: planId,
        project: options?.project ?? null,
        ssh_keys: sshKeys,
        region_label: regions.find((r) => r.id === region)?.name ?? region,
        plan_label: chosen?.label ?? planId,
        domain: address === "domain" ? domain.trim() : address === "cloudflare" ? cloudflareName : "",
        dns_account_id: address === "cloudflare" ? Number(dnsAccountId) : 0,
        dns_zone_id: address === "cloudflare" ? zoneId : "",
        site_template: siteTemplate ?? "",
        connections: withConnections && !!templates?.length,
      });
      onStarted();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  const discovery = !!options?.projects?.find((p) => p.id === options.project)?.discovery;

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <form className="modal modal-wide" onSubmit={submit}>
        <div className="modal-head">
          <h2>Новый сервер — {hoster.name}</h2>
          <button type="button" className="btn btn-small" onClick={onClose} disabled={busy}>
            ✕
          </button>
        </div>

        {mainPanels.length === 0 && (
          <div className="notice notice-bad small">
            Нет основной панели 3x-ui v3 на связи: новый сервер подключается к ней узлом. Добавьте её в «Серверы 3x-ui».
          </div>
        )}

        {options?.projects && (
          <label className="field">
            <span>Проект Public Cloud</span>
            <select className="input" value={options.project ?? ""} onChange={(e) => setProject(e.target.value)} disabled={loading}>
              {options.projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.discovery ? `${p.name} — Discovery, не активирован` : p.name}
                </option>
              ))}
            </select>
            {discovery && (
              <div className="notice notice-bad small">
                Проект в режиме Discovery: это пробный проект без способа оплаты, OVHcloud не даст создать в нём сервер. Активируйте его в панели
                OVHcloud: Public Cloud → этот проект → «Activate project» (понадобится способ оплаты), затем откройте эту форму снова.
              </div>
            )}
          </label>
        )}

        {loading && !options ? (
          <div className="muted small">Загружаю регионы и тарифы {providerTitle}…</div>
        ) : options ? (
          <>
            <div className="field-row">
              <label className="field">
                <span>Имя сервера</span>
                <input className="input mono" required pattern="[a-zA-Z0-9][a-zA-Z0-9.\-]{0,62}" value={name} onChange={(e) => setName(e.target.value)} />
              </label>
              <label className="field">
                <span>Регион</span>
                <select className="input" required value={region} onChange={(e) => setRegion(e.target.value)}>
                  {regions.map((r) => (
                    <option key={r.id} value={r.id}>
                      {r.name}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <div className="field">
              <span id="plan-label">Тариф</span>
              {plans.length === 0 ? (
                <small className="muted">В этом регионе нет доступных тарифов</small>
              ) : (
                <PlanList plans={plans} value={planId} onChange={setPlan} />
              )}
              {chosen && <PlanNote plan={chosen} provider={hoster.provider} />}
              {chosen?.single && (
                <div className="notice notice-warn small">
                  {providerTitle} разрешает только один сервер {chosen.label} на организацию. На таком сервере не получится «Переустановить с
                  нуля» на тот же тариф: новый сервер заказывается до удаления старого. При переустановке можно будет выбрать другой тариф.
                </div>
              )}
            </div>

            <div className="field">
              <span>SSH-ключ для входа на сервер</span>
              {options.ssh_note ? (
                <small className="muted">{options.ssh_note}</small>
              ) : options.ssh_keys.length === 0 ? (
                <small className="muted">В аккаунте нет SSH-ключей: сервер будет работать, но войти на него по SSH не получится. Ключ можно добавить в панели хостинга.</small>
              ) : options.ssh_multiple ? (
                <div className="node-picker">
                  {options.ssh_keys.map((k) => (
                    <label key={k.id} className="checkbox">
                      <input
                        type="checkbox"
                        checked={sshKeys.includes(k.id)}
                        onChange={() => setSshKeys((s) => (s.includes(k.id) ? s.filter((x) => x !== k.id) : [...s, k.id]))}
                      />
                      <span>{k.name}</span>
                    </label>
                  ))}
                </div>
              ) : (
                <select className="input" value={sshKeys[0] ?? ""} onChange={(e) => setSshKeys(e.target.value ? [e.target.value] : [])}>
                  <option value="">Без ключа</option>
                  {options.ssh_keys.map((k) => (
                    <option key={k.id} value={k.id}>
                      {k.name}
                    </option>
                  ))}
                </select>
              )}
            </div>

            <div className="field">
              <span>Адрес панели узла и сертификат</span>
              <div className="segmented">
                {(
                  [
                    ["ip", "IP-адрес сервера"],
                    ...(dnsAccounts.length ? [["cloudflare", "Домен Cloudflare"]] : []),
                    ["domain", "Свой домен"],
                  ] as ["ip" | "domain" | "cloudflare", string][]
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
                    value={subdomain ?? name}
                    onChange={(e) => setSubdomain(e.target.value)}
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
                  ? `Как только сервер получит IP, админка создаст в Cloudflare A-запись ${cloudflareName} на него (без проксирования, иначе VPN не заработает), а сервер выпустит на этот домен сертификат Let's Encrypt. При переустановке запись переедет на новый IP, при удалении сервера — удалится.`
                  : address === "domain"
                    ? "IP сервера станет известен после заказа: он появится в журнале задания, тогда создайте A-запись домена на него. Установка ждёт её до 20 минут и выпускает сертификат Let's Encrypt на домен; если запись не появится — на IP."
                    : "Сертификат Let's Encrypt на IP: короткий (около 6 дней), сервер продлевает его сам."}{" "}
                Если Let's Encrypt откажет, панель останется на самоподписанном сертификате, закреплённом в основной панели.
              </small>
            </div>

            <StubTemplateSelect value={siteTemplate} onChange={setSiteTemplate} />

            <label className="field">
              <span>Подключить узлом к основной панели</span>
              <select className="input" value={panelId} onChange={(e) => setPanelId(Number(e.target.value))} disabled={mainPanels.length === 0}>
                {mainPanels.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </select>
            </label>

            {templates && (
              <div className="field">
                {templates.length > 0 ? (
                  <>
                    <label className="checkbox">
                      <input type="checkbox" checked={withConnections} onChange={(e) => setWithConnections(e.target.checked)} />
                      Создать подключения из раздела «Подключения»: {templates.length} шт.
                    </label>
                    <small className="muted">{templates.map((t) => t.remark.replace("{server}", name).trim()).join(", ")}</small>
                  </>
                ) : (
                  <small className="muted">
                    Подключения на новом сервере не создаются: в разделе «Подключения» ни одно не включено. Инбаунды узлу можно добавить потом в
                    основной панели.
                  </small>
                )}
              </div>
            )}

            <div className="notice notice-info small">
              На сервер встанут Ubuntu 24.04, Docker, 3x-ui последней версии и сайт-заглушка. Админка зайдёт на сервер по SSH своим ключом и
              установит всё сама: порт, путь, логин и пароль панели задаст сама, сертификат выпустит Let's Encrypt. В конце установки ключ админки
              удаляется с сервера. Обычно всё занимает 5–10 минут. Хостинг начнёт брать плату за сервер сразу после создания.
            </div>
          </>
        ) : null}

        {error && <div className="notice notice-bad small">{error}</div>}

        <div className="modal-actions">
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
            Отмена
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy || loading || !options || !planId || !region || mainPanels.length === 0 || discovery}>
            {busy ? "Создаю…" : "Создать сервер"}
          </button>
        </div>
      </form>
    </div>
  );
}

/** Plans as radio rows: name and resources on the left, price per month and per hour on the right. */
export function PlanList({ plans, value, onChange }: { plans: HostingPlan[]; value: string; onChange: (id: string) => void }) {
  const selected = useRef<HTMLLabelElement>(null);

  // keep the chosen plan in sight when the list changes (another region or project)
  useEffect(() => {
    selected.current?.scrollIntoView({ block: "nearest" });
  }, [plans]);

  return (
    <div className="plan-list" role="radiogroup" aria-labelledby="plan-label">
      {plans.map((p) => (
        <label key={p.id} ref={p.id === value ? selected : undefined} className={`plan-row ${p.id === value ? "selected" : ""}`}>
          <input type="radio" name="plan" value={p.id} checked={p.id === value} onChange={() => onChange(p.id)} />
          <span className="plan-info">
            <span className="strong">{p.label}</span>
            <span className="muted small">{p.specs}</span>
          </span>
          <span className="plan-price">
            {p.price_month != null ? <span className="strong">≈ {formatPrice(p.price_month, p.currency)}/мес</span> : <span className="muted">цена неизвестна</span>}
            {p.price_hour != null && <span className="muted small">{formatPrice(p.price_hour, p.currency)}/ч</span>}
          </span>
        </label>
      ))}
    </div>
  );
}

/** How each hosting bills; OVHcloud's note depends on the plan and is built in PlanNote. */
const BILLING_NOTES: Record<string, string> = {
  digitalocean: "Оплата почасовая, но за месяц не больше месячной цены тарифа. Платёж идёт, пока сервер существует, даже выключенный. Цены без налогов.",
  scaleway:
    "Почасовая оплата, месяц — по прайсу Scaleway. Публичный IPv4 и диск сервера оплачиваются отдельно, обычно это ещё несколько евро в месяц. Цены без НДС.",
  upcloud:
    "Почасовая оплата, но за месяц не больше 28 дней (672 часа). Сервер оплачивается, пока существует, даже выключенный. Диск по тарифу включён, дополнительные IP и диски — отдельно.",
  vdsina:
    "Оплата посуточная с баланса аккаунта VDSina, месяц — 30 дней; цена в час — суточная, делённая на 24. Для заказа на балансе должно хватать средств на тариф.",
};

export function PlanNote({ plan, provider }: { plan: HostingPlan; provider: string }) {
  if (plan.price_hour == null && plan.price_month == null)
    return <small className="muted">Цена тарифа {plan.label} не найдена в прайс-листе хостинга: посмотрите её в панели хостинга.</small>;
  return (
    <small className="muted">
      {BILLING_NOTES[provider] ??
        `Почасовая оплата, месяц — 730 часов. ${
          plan.price_month_plan != null
            ? `С помесячной оплатой ${plan.label} стоит ${formatPrice(plan.price_month_plan, plan.currency)} в месяц: её можно включить для сервера в панели OVHcloud. `
            : ""
        }Цены без налогов.`}
    </small>
  );
}
