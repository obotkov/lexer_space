import { useEffect, useState, type FormEvent } from "react";
import { api, type CreateOptions, type Provision } from "../api";
import { PlanList, PlanNote } from "./CreateServerDialog";

/** Reinstall from zero: a new server in the same region, the plan may change; the node switches over. */
export function ReinstallDialog({
  job,
  provider,
  providerTitle,
  onClose,
  onStarted,
}: {
  job: Provision;
  provider: string;
  providerTitle: string;
  onClose: () => void;
  onStarted: () => void;
}) {
  const [options, setOptions] = useState<CreateOptions | null>(null);
  const [plan, setPlan] = useState(job.plan_id);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    api.hosterOptions(job.hoster_id, job.project || null).then(
      (o) => alive && setOptions(o),
      (e) => alive && setError((e as Error).message),
    );
    return () => {
      alive = false;
    };
  }, [job.hoster_id, job.project]);

  const plans = options?.plans.filter((p) => p.regions.includes(job.region_id)) ?? [];
  // the current plan if the region still has it, otherwise the cheapest one
  const planId = plans.some((p) => p.id === plan) ? plan : plans[0]?.id ?? "";
  const chosen = plans.find((p) => p.id === planId);
  // the new server is ordered before the old one goes: a one-per-organisation plan cannot replace itself
  const blocked = !!chosen?.single && chosen.id === job.plan_id;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.reinstallProvision(job.id, { plan: planId, plan_label: chosen?.label ?? planId });
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
          <h2>Переустановить «{job.name}» с нуля</h2>
          <button type="button" className="btn btn-small" onClick={onClose} disabled={busy}>
            ✕
          </button>
        </div>

        <div className="notice notice-info small">
          Админка закажет у {providerTitle} новый сервер в том же регионе ({job.region}), поставит 3x-ui заново и переключит на него узел
          основной панели: инбаунды и клиенты сохранятся. Старый сервер {job.ip} будет удалён, когда новый заработает. IP изменится
          {job.domain ? ` — A-запись ${job.domain} нужно будет направить на новый IP` : ""}.
        </div>

        <div className="field">
          <span id="plan-label">Тариф нового сервера</span>
          {!options && !error ? (
            <small className="muted">Загружаю тарифы {providerTitle}…</small>
          ) : options && plans.length === 0 ? (
            <small className="muted">В регионе {job.region} сейчас нет доступных тарифов</small>
          ) : (
            options && <PlanList plans={plans} value={planId} onChange={setPlan} />
          )}
          {chosen && <PlanNote plan={chosen} provider={provider} />}
        </div>

        {blocked ? (
          <div className="notice notice-bad small">
            {providerTitle} разрешает только один сервер {chosen.label} на организацию, а старый сервер удаляется только после того, как
            заработает новый. Выберите другой тариф.
          </div>
        ) : (
          chosen?.single && (
            <div className="notice notice-warn small">
              {providerTitle} разрешает только один сервер {chosen.label} на организацию: если такой сервер в организации уже есть, заказ не
              пройдёт.
            </div>
          )
        )}

        {error && <div className="notice notice-bad small">{error}</div>}

        <div className="modal-actions">
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
            Отмена
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy || !chosen || blocked}>
            {busy ? "Запускаю…" : "Переустановить"}
          </button>
        </div>
      </form>
    </div>
  );
}
