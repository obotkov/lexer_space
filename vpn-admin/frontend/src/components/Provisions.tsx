import { useState } from "react";
import { api, type HosterInfo, type Provision, type ProvisionCredentials, type ProvisionStep } from "../api";

const STEPS: { id: ProvisionStep; title: string }[] = [
  { id: "create", title: "Заказ сервера" },
  { id: "boot", title: "Запуск" },
  { id: "install", title: "Установка 3x-ui" },
  { id: "connect", title: "Подключение узлом" },
];

const STATE_BADGE: Record<Provision["state"], [string, string]> = {
  running: ["badge-depleted", "Выполняется"],
  done: ["badge-active", "Готово"],
  failed: ["badge-expired", "Ошибка"],
  deleted: ["badge-disabled", "Сервер удалён"],
};

const time = (ts: number) => new Date(ts * 1000).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" });

/** Jobs that order a server, install 3x-ui and attach it as a node; newest first. */
export function Provisions({
  items,
  accounts,
  onChanged,
}: {
  items: Provision[];
  accounts: HosterInfo[];
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [creds, setCreds] = useState<Record<number, ProvisionCredentials>>({});
  const [openLog, setOpenLog] = useState<number | null>(null);

  const act = async (id: number, action: () => Promise<unknown>) => {
    setBusy(id);
    setError("");
    try {
      await action();
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const toggleCreds = async (id: number) => {
    if (creds[id]) {
      setCreds((all) => {
        const next = { ...all };
        delete next[id];
        return next;
      });
      return;
    }
    try {
      const c = await api.provisionCredentials(id);
      setCreds((all) => ({ ...all, [id]: c }));
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <>
      <h2 className="section-title">Новые серверы</h2>
      {error && <div className="notice notice-bad small">{error}</div>}
      <div className="provisions">
        {items.map((p) => {
          const account = accounts.find((a) => a.id === p.hoster_id);
          const current = STEPS.findIndex((s) => s.id === p.step);
          const [badgeClass, badgeText] = STATE_BADGE[p.state];
          const c = creds[p.id];
          return (
            <section key={p.id} className="card provision">
              <div className="card-head">
                <div>
                  <div className="strong">{p.name}</div>
                  <div className="muted small">
                    {[account?.name ?? "аккаунт удалён", p.region, p.plan, p.ip].filter(Boolean).join(" · ")}
                  </div>
                </div>
                <span className={`badge ${badgeClass}`}>{badgeText}</span>
              </div>

              <ol className="steps">
                {STEPS.map((s, i) => {
                  const state =
                    p.step === "done" || i < current ? "done" : i === current ? (p.state === "failed" ? "failed" : p.state === "running" ? "active" : "") : "";
                  return (
                    <li key={s.id} className={`step step-${state || "pending"}`}>
                      <span className="step-mark">{state === "done" ? "✓" : state === "failed" ? "!" : i + 1}</span>
                      {s.title}
                    </li>
                  );
                })}
              </ol>

              {p.error && <div className="error-text small provision-error">{p.error}</div>}
              {p.state === "running" && p.log.length > 0 && <div className="muted small">{p.log[p.log.length - 1].msg}…</div>}

              {p.state === "done" && p.panel_url && (
                <dl className="kv small">
                  <dt>Панель узла</dt>
                  <dd>
                    <a href={p.panel_url} target="_blank" rel="noreferrer" className="mono">
                      {p.panel_url}
                    </a>
                  </dd>
                  <dt>Логин</dt>
                  <dd className="mono">{p.username}</dd>
                  <dt>Пароль</dt>
                  <dd className="mono">
                    {c ? c.password : "••••••••"}{" "}
                    <button className="link-button" onClick={() => toggleCreds(p.id)}>
                      {c ? "скрыть" : "показать"}
                    </button>
                  </dd>
                </dl>
              )}
              {p.state === "done" && (
                <div className="muted small">Сертификат панели узла самоподписанный: браузер предупредит о нём при входе, это ожидаемо.</div>
              )}

              {openLog === p.id && (
                <ul className="log provision-log">
                  {p.log.map((l, i) => (
                    <li key={i}>
                      <span className="muted">{time(l.t)}</span> {l.msg}
                    </li>
                  ))}
                </ul>
              )}

              <div className="card-actions">
                <button className="btn btn-small" onClick={() => setOpenLog(openLog === p.id ? null : p.id)}>
                  {openLog === p.id ? "Скрыть журнал" : "Журнал"}
                </button>
                {p.state === "failed" && (
                  <button className="btn btn-small btn-primary" disabled={busy === p.id} onClick={() => act(p.id, () => api.retryProvision(p.id))}>
                    Повторить
                  </button>
                )}
                {p.state === "failed" && p.server_id && (
                  <button
                    className="btn btn-small btn-danger"
                    disabled={busy === p.id}
                    onClick={() =>
                      confirm(`Удалить сервер «${p.name}» у хостинга? Он будет уничтожен вместе с данными, плата за него прекратится.`) &&
                      act(p.id, () => api.deleteProvisionServer(p.id))
                    }
                  >
                    Удалить сервер у хостинга
                  </button>
                )}
                {p.state !== "running" && (
                  <button
                    className="btn btn-small"
                    disabled={busy === p.id}
                    onClick={() =>
                      confirm(
                        p.state === "done"
                          ? "Убрать задание из списка? Сервер и узел останутся, но сохранённые логин и пароль панели узла будут удалены из админки."
                          : "Убрать задание из списка?",
                      ) && act(p.id, () => api.forgetProvision(p.id))
                    }
                  >
                    Убрать из списка
                  </button>
                )}
              </div>
            </section>
          );
        })}
      </div>
    </>
  );
}
