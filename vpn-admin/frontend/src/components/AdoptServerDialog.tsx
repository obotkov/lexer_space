import { useEffect, useState, type FormEvent } from "react";
import { api, type AdoptPlan, type ConnectionTemplate, type HostingOs, type HosterInfo, type HosterServer, type PanelInfo } from "../api";
import { fillRemark } from "./CreateServerDialog";
import { StubTemplateSelect } from "./StubTemplateSelect";

const DEFAULT_OS: HostingOs = { id: "ubuntu-24.04", label: "Ubuntu 24.04", regions: null, min_disk_gb: null };

/** From zero on a server the admin did not create: the hosting reinstalls its OS (the IP stays), the admin
 * installs 3x-ui as on a new server, and the node it already runs switches over, or a new node joins. */
export function AdoptServerDialog({
  hoster,
  server,
  providerTitle,
  panels,
  onClose,
  onStarted,
}: {
  hoster: HosterInfo;
  server: HosterServer;
  providerTitle: string;
  panels: PanelInfo[];
  onClose: () => void;
  onStarted: () => void;
}) {
  const mainPanels = panels.filter((p) => p.ok && p.api_version === "v3");
  const [plan, setPlan] = useState<AdoptPlan | null>(null);
  const [systems, setSystems] = useState<HostingOs[] | null>(null);
  const [os, setOs] = useState(DEFAULT_OS.id);
  const [domain, setDomain] = useState("");
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
        setDomain(p.domain);
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
  }, [hoster.id, server.id, server.region_id]);

  const node = plan?.node ?? null;
  const osList = systems && systems.length > 0 ? systems : [DEFAULT_OS];
  const osId = osList.some((o) => o.id === os) ? os : osList[0].id;
  const osLabel = osList.find((o) => o.id === osId)?.label ?? osId;
  const ip = server.ipv4[0] ?? "";
  const foreign = node?.inbounds.filter((i) => i.foreign_certs?.length) ?? [];
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
        domain: domain.trim(),
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

            <label className="field">
              <span>Домен панели узла (необязательно)</span>
              <input
                className="input mono"
                placeholder="vpn1.example.com"
                pattern="([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
              />
              <small className="muted">
                {domain.trim()
                  ? `A-запись ${domain.trim()} должна указывать на ${ip}: тогда сервер выпустит сертификат Let's Encrypt на домен. Если записи нет, установка ждёт её до 20 минут, затем берёт сертификат на IP.`
                  : "Без домена сервер выпустит сертификат Let's Encrypt на IP: короткий, сервер продлевает его сам."}
                {plan.domain && domain.trim() === plan.domain ? " Домен взят из адреса узла." : ""}
              </small>
            </label>

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
                        {templates.some((t) => t.kind === "vless_xhttp_cdn" && picked.has(t.id)) && (
                          <small className="error-text">
                            Подключение через CDN создаётся только на сервере с доменом Cloudflare, а здесь домен ваш: снимите его галочку.
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
