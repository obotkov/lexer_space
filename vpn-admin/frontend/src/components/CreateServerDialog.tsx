import { useEffect, useState, type FormEvent } from "react";
import { api, type CreateOptions, type HosterInfo, type PanelInfo } from "../api";

const randomSuffix = () => Math.random().toString(36).slice(2, 6);

/** Order a server at a hosting account; the admin installs 3x-ui on it and attaches it as a node. */
export function CreateServerDialog({
  hoster,
  providerTitle,
  panels,
  onClose,
  onStarted,
}: {
  hoster: HosterInfo;
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

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.startProvision({ hoster_id: hoster.id, panel_id: panelId, name, region, plan: planId, project: options?.project ?? null, ssh_keys: sshKeys });
      onStarted();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  const chosen = plans.find((p) => p.id === planId);

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
                  {p.name}
                </option>
              ))}
            </select>
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

            <label className="field">
              <span>Тариф</span>
              <select className="input" required value={planId} onChange={(e) => setPlan(e.target.value)}>
                {plans.length === 0 && <option value="">В этом регионе нет доступных тарифов</option>}
                {plans.map((p) => (
                  <option key={p.id} value={p.id}>
                    {[p.label, p.specs, p.price].filter(Boolean).join(" — ")}
                  </option>
                ))}
              </select>
              {chosen && <small className="muted">{[chosen.specs, chosen.price].filter(Boolean).join(" · ")}</small>}
            </label>

            <div className="field">
              <span>SSH-ключ для входа на сервер</span>
              {options.ssh_keys.length === 0 ? (
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

            <div className="notice notice-info small">
              На сервер встанут Ubuntu 24.04, Docker и 3x-ui последней версии. Порт, путь, логин и пароль панели админка задаст сама и выпустит для неё
              TLS-сертификат, который основная панель закрепит (pin). Обычно всё занимает 5–10 минут. Хостинг начнёт брать плату за сервер сразу после
              создания.
            </div>
          </>
        ) : null}

        {error && <div className="notice notice-bad small">{error}</div>}

        <div className="modal-actions">
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
            Отмена
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy || loading || !options || !planId || !region || mainPanels.length === 0}>
            {busy ? "Создаю…" : "Создать сервер"}
          </button>
        </div>
      </form>
    </div>
  );
}
