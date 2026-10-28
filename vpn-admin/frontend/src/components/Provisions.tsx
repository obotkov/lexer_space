import { useState } from "react";
import { ReinstallDialog } from "./ReinstallDialog";
import { api, type HosterInfo, type HosterProvider, type Provision, type ProvisionCredentials, type ProvisionStep } from "../api";

const STEPS: { id: ProvisionStep; title: string }[] = [
  { id: "create", title: "Заказ сервера" },
  { id: "rebuild", title: "Переустановка системы" }, // only an in-place reinstall has it
  { id: "boot", title: "Запуск" },
  { id: "install", title: "Установка 3x-ui" },
  { id: "connect", title: "Подключение узлом" },
  { id: "connections", title: "Подключения" }, // only when templates were planned for the server
  { id: "retire", title: "Удаление старого сервера" }, // only a reinstall has it
];

const CERT_NOTES: Record<Provision["cert_mode"], (p: Provision) => string> = {
  domain: (p) => `Сертификат Let's Encrypt на ${p.domain}, продлевается на сервере автоматически.`,
  ip: (p) => `Сертификат Let's Encrypt на IP ${p.ip}: короткий, сервер продлевает его сам.`,
  self: () => "Сертификат панели узла самоподписанный: браузер предупредит о нём при входе, это ожидаемо.",
  "": () => "Сертификат панели узла самоподписанный: браузер предупредит о нём при входе, это ожидаемо.",
};

const STATE_BADGE: Record<Provision["state"], [string, string]> = {
  running: ["badge-depleted", "Выполняется"],
  done: ["badge-active", "Готово"],
  failed: ["badge-expired", "Ошибка"],
  deleted: ["badge-disabled", "Сервер удалён"],
};

/** Keeps the log scrolled to its newest line unless it was scrolled up to read older ones; passed as a new
 * function on each render, so React calls it after every update. */
const followLog = (el: HTMLUListElement | null) => {
  if (el && (!el.dataset.seen || el.scrollHeight - el.scrollTop - el.clientHeight < 120)) {
    el.scrollTop = el.scrollHeight;
    el.dataset.seen = "1";
  }
};

const time = (ts: number) => new Date(ts * 1000).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" });

/** Jobs that order a server, install 3x-ui and attach it as a node; newest first. */
export function Provisions({
  items,
  accounts,
  providers,
  onChanged,
}: {
  items: Provision[];
  accounts: HosterInfo[];
  providers: Record<string, HosterProvider>;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [creds, setCreds] = useState<Record<number, ProvisionCredentials>>({});
  const [openLog, setOpenLog] = useState<number | null>(null);
  const [reinstalling, setReinstalling] = useState<Provision | null>(null);
  const reinstallAccount = reinstalling && accounts.find((a) => a.id === reinstalling.hoster_id);

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
          // in place nothing is ordered and nothing is removed; a new server has no rebuild
          const steps = STEPS.filter(
            (s) =>
              (p.in_place ? s.id !== "create" && s.id !== "retire" : s.id !== "rebuild" && (p.replaces > 0 || s.id !== "retire")) &&
              (s.id !== "connections" || (!p.replaces && p.connections.length > 0)),
          );
          const found = steps.findIndex((s) => s.id === p.step);
          const current = found < 0 ? steps.length : found; // a step without a chip runs after all of them
          // a refused attempt (no server ordered) does not hold the old server: a new reinstall replaces it
          const replacedBy = items.find(
            (x) => x.replaces === p.id && (x.state === "running" || (x.state === "failed" && !!x.server_id && !(x.in_place && x.step === "rebuild"))),
          );
          const canReinstall = !replacedBy && !!p.server_id && (p.state === "done" || (p.state === "failed" && !p.replaces));
          const [badgeClass, badgeText] = STATE_BADGE[p.state];
          // NetGrid and OVHcloud VPS: the API cannot delete the server, only take it out of the admin
          const kept = account?.servers.find((s) => s.id === p.server_id)?.deletable === false;
          const c = creds[p.id];
          return (
            <section key={p.id} className="card provision">
              <div className="card-head">
                <div>
                  <div className="strong">
                    {p.title || p.name}
                    {p.replaces > 0 && <span className="muted small"> · переустановка</span>}
                    {p.adopted && <span className="muted small"> · с нуля на существующем сервере</span>}
                  </div>
                  <div className="provision-source small">
                    {account ? (
                      <>
                        <span className={`provider-badge provider-badge-small provider-${account.provider}`}>
                          {providers[account.provider]?.title ?? account.provider}
                        </span>
                        <span>{account.name}</span>
                      </>
                    ) : (
                      <span className="muted">аккаунт удалён</span>
                    )}
                  </div>
                  <div className="muted small">{[p.region, p.plan, p.os_label, p.ip, p.domain && (p.dns ? `${p.domain} (Cloudflare)` : p.domain)].filter(Boolean).join(" · ")}</div>
                </div>
                <span className={`badge ${badgeClass}`}>{badgeText}</span>
              </div>

              <ol className="steps">
                {steps.map((s, i) => {
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
              {p.replaces > 0 && p.state === "failed" && !p.server_id && (
                <div className="muted small">
                  Новый сервер не заказан, старый работает как прежде. Чтобы выбрать другой тариф, нажмите «Переустановить с нуля» на карточке
                  старого сервера — это задание заменится новым.
                </div>
              )}
              {p.in_place && p.state === "failed" && (
                <div className="muted small">
                  {p.step === "rebuild"
                    ? p.adopted
                      ? "Нажмите «Повторить». Чтобы выбрать другую систему, уберите задание из списка и снова нажмите «0» у сервера в аккаунте хостинга."
                      : "Нажмите «Повторить» или «Переустановить с нуля» на карточке прежнего задания: там можно выбрать и новый сервер вместо переустановки на месте."
                    : "Система на сервере уже переустановлена: нажмите «Повторить», чтобы продолжить с этого шага."}
                </div>
              )}
              {replacedBy && (
                <div className="notice notice-info small">
                  {replacedBy.state === "running"
                    ? replacedBy.in_place
                      ? `Система на сервере переустанавливается в задании «${replacedBy.name} · переустановка», IP сохранится. После этого эта карточка заменится новой.`
                      : `Сервер переустанавливается: новый заказан в задании «${replacedBy.name} · переустановка», после переключения узла этот будет удалён.`
                    : replacedBy.in_place
                      ? `Переустановка системы остановилась с ошибкой: повторите задание «${replacedBy.name} · переустановка». Пока она не закончится, VPN на сервере не работает.`
                      : `Переустановка остановилась с ошибкой: повторите задание «${replacedBy.name} · переустановка» или удалите его сервер. Этот сервер пока работает.`}
                </div>
              )}
              {p.state === "running" && p.log.length > 0 && <div className="muted small">{p.log[p.log.length - 1].msg}…</div>}

              {p.state === "done" && p.panel_url && (
                <dl className="kv small">
                  <dt>Панель узла</dt>
                  <dd>
                    <a href={p.panel_url} target="_blank" rel="noreferrer" className="mono">
                      {p.panel_url}
                    </a>
                  </dd>
                  {p.sub_port > 0 && (
                    <>
                      <dt>Порт подписки</dt>
                      <dd className="mono">{p.sub_port}</dd>
                    </>
                  )}
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
              {p.state === "done" && <div className="muted small">{CERT_NOTES[p.cert_mode ?? ""](p)}</div>}

              {p.connections.length > 0 && (p.state === "done" || p.step === "connections") && (
                <div className="provision-connections">
                  {p.connections.map((c, i) => (
                    <span
                      key={i}
                      className={`badge ${c.inbound_id ? "badge-active" : c.error ? "badge-expired" : "badge-disabled"}`}
                      title={c.error || `${c.title}${c.cdn_domain ? `, через CDN ${c.cdn_domain}${c.cdn_address ? ` (${c.cdn_address})` : ""}` : ""}, порт ${c.port}${c.net === "tcp" ? "" : `/${c.net === "both" ? "tcp+udp" : c.net}`}`}
                    >
                      {c.remark || c.title} :{c.port}
                      {c.net === "udp" ? "/udp" : ""}
                    </span>
                  ))}
                </div>
              )}

              {openLog === p.id && (
                <ul className="log provision-log" ref={(el) => followLog(el)}>
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
                {p.state === "running" && p.step === "install" && (
                  <button
                    className="btn btn-small"
                    disabled={busy === p.id}
                    title="Если установка застряла, например из-за сетевой ошибки: незавершённая установка на сервере остановится и начнётся заново"
                    onClick={() =>
                      confirm("Перезапустить установку? Незавершённая установка на сервере остановится и начнётся с начала.") &&
                      act(p.id, () => api.restartProvisionInstall(p.id))
                    }
                  >
                    Перезапустить установку
                  </button>
                )}
                {p.state === "done" && p.node_id && (
                  <button
                    className="btn btn-small"
                    disabled={busy === p.id}
                    title="Добавить на этот сервер включённые подключения из раздела «Подключения», которых на нём ещё нет"
                    onClick={() => act(p.id, () => api.applyProvisionConnections(p.id))}
                  >
                    {busy === p.id ? "Раскатываю…" : "Раскатать подключения"}
                  </button>
                )}
                {canReinstall && (
                  <button className="btn btn-small" disabled={busy === p.id} onClick={() => setReinstalling(p)}>
                    Переустановить с нуля
                  </button>
                )}
                {(p.state === "done" || (p.state === "failed" && (!p.in_place || p.adopted))) && p.server_id && replacedBy?.state !== "running" && (
                  <button
                    className="btn btn-small btn-danger"
                    disabled={busy === p.id}
                    onClick={() =>
                      confirm(
                        kept
                          ? `Убрать сервер «${p.title || p.name}»${p.ip ? ` (${p.ip})` : ""} из админки? Из основной панели удалятся подключения (инбаунды) этого узла и сам узел, задание уйдёт из списка. Клиенты останутся в панели.\n\nСам сервер ${providers[account?.provider ?? ""]?.title ?? ""} через API не удалить: удалите его в панели хостинга, иначе он продолжит стоить денег.`
                          : `Удалить сервер «${p.title || p.name}»${p.ip ? ` (${p.ip})` : ""} у хостинга? Он будет уничтожен вместе с данными, плата за него прекратится.` +
                          (p.state === "done"
                            ? "\n\nVPN на этом сервере перестанет работать. Сначала из основной панели удалятся подключения (инбаунды) этого узла и сам узел, затем сервер. Клиенты останутся в панели."
                            : ""),
                      ) && act(p.id, () => api.deleteProvisionServer(p.id))
                    }
                  >
                    {kept ? "Убрать из админки" : p.state === "done" ? "Удалить сервер" : "Удалить сервер у хостинга"}
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
      {reinstalling && reinstallAccount && (
        <ReinstallDialog
          job={reinstalling}
          provider={reinstallAccount.provider}
          providerTitle={providers[reinstallAccount.provider]?.title ?? reinstallAccount.provider}
          rebuild={!!providers[reinstallAccount.provider]?.rebuild}
          onClose={() => setReinstalling(null)}
          onStarted={() => {
            setReinstalling(null);
            onChanged();
          }}
        />
      )}
    </>
  );
}
