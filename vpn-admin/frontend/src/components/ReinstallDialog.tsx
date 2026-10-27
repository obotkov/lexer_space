import { useEffect, useState, type FormEvent } from "react";
import { api, type CreateOptions, type Provision } from "../api";
import { PlanList, PlanNote } from "./CreateServerDialog";
import { StubTemplateSelect } from "./StubTemplateSelect";

/** Reinstall from zero: on the same server where the hosting can do it (the IP stays), or a new server in
 * the same region with a plan of choice; either way the node of the main panel switches over. */
export function ReinstallDialog({
  job,
  provider,
  providerTitle,
  rebuild,
  onClose,
  onStarted,
}: {
  job: Provision;
  provider: string;
  providerTitle: string;
  /** the hosting can reinstall the OS in place */
  rebuild: boolean;
  onClose: () => void;
  onStarted: () => void;
}) {
  const [inPlace, setInPlace] = useState(rebuild);
  // older servers had no decoy page: offer the admin's current one
  const [siteTemplate, setSiteTemplate] = useState<string | null>(job.legacy_install ? null : job.site_template);
  // servers made by an older version re-run their old cloud-init install after an OS reinstall (VDSina excepted)
  const legacy = inPlace && job.legacy_install && provider !== "vdsina";
  const [options, setOptions] = useState<CreateOptions | null>(null);
  const [plan, setPlan] = useState(job.plan_id);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (inPlace) return; // the same server keeps its plan: no price list needed
    let alive = true;
    api.hosterOptions(job.hoster_id, job.project || null).then(
      (o) => alive && setOptions(o),
      (e) => alive && setError((e as Error).message),
    );
    return () => {
      alive = false;
    };
  }, [job.hoster_id, job.project, inPlace]);

  const plans = options?.plans.filter((p) => p.regions.includes(job.region_id)) ?? [];
  // the current plan if the region still has it, otherwise the cheapest one
  const planId = plans.some((p) => p.id === plan) ? plan : plans[0]?.id ?? "";
  const chosen = plans.find((p) => p.id === planId);
  // the new server is ordered before the old one goes: a one-per-organisation plan cannot replace itself
  const blocked = !inPlace && !!chosen?.single && chosen.id === job.plan_id;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.reinstallProvision(job.id, {
        in_place: inPlace,
        plan: planId,
        plan_label: chosen?.label ?? planId,
        site_template: siteTemplate ?? "",
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
          <h2>Переустановить «{job.name}» с нуля</h2>
          <button type="button" className="btn btn-small" onClick={onClose} disabled={busy}>
            ✕
          </button>
        </div>

        {rebuild && (
          <div className="segmented">
            <button type="button" className={inPlace ? "active" : ""} aria-pressed={inPlace} onClick={() => setInPlace(true)}>
              Этот же сервер
            </button>
            <button type="button" className={inPlace ? "" : "active"} aria-pressed={!inPlace} onClick={() => setInPlace(false)}>
              Новый сервер
            </button>
          </div>
        )}

        {inPlace ? (
          legacy ? (
            <div className="notice notice-warn small">
              Этот сервер создан прежней версией админки. После переустановки ОС {providerTitle} запустит тот скрипт, с которым сервер
              создавался: 3x-ui встанет с прежними логином и паролем, но без сайта-заглушки. Чтобы получить штатную установку целиком, выберите
              «Новый сервер».
            </div>
          ) : (
            <div className="notice notice-info small">
              1. {providerTitle} переустановит ОС ({job.os_label}) на этом же сервере: диск будет стёрт, IP {job.ip} и тариф останутся прежними.
              <br />
              2. Админка выполнит штатную установку, как у нового сервера: Docker, 3x-ui с новыми логином и паролем, сайт-заглушка и сертификат
              Let's Encrypt, — и переключит на неё узел основной панели: инбаунды и клиенты сохранятся.
              <br />
              Пока идёт переустановка (обычно 5–10 минут), VPN на этом сервере не работает.
            </div>
          )
        ) : (
          <>
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
          </>
        )}

        {!legacy && <StubTemplateSelect value={siteTemplate} onChange={setSiteTemplate} />}

        {error && <div className="notice notice-bad small">{error}</div>}

        <div className="modal-actions">
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
            Отмена
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy || (!inPlace && (!chosen || blocked))}>
            {busy ? "Запускаю…" : "Переустановить"}
          </button>
        </div>
      </form>
    </div>
  );
}
