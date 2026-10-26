import { useMemo, useState } from "react";
import type { ClientStatus, Overview, Subscription } from "../api";
import { ClientDialog } from "../components/ClientDialog";
import { CreateClientDialog } from "../components/CreateClientDialog";
import { CopyButton, Empty, OnlineDot, StatusBadge } from "../components/ui";
import { formatBytes, formatExpiry, STATUS_LABELS } from "../format";

export function Subscriptions({ data, onChanged }: { data: Overview; onChanged: () => void }) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<ClientStatus | "">("");
  const [managing, setManaging] = useState<Subscription | null>(null);
  const [creating, setCreating] = useState(false);

  const subs = useMemo(() => {
    const q = query.trim().toLowerCase();
    return data.subscriptions.filter(
      (s) =>
        (!status || s.status === status) &&
        (!q || [s.sub_id, s.comment, String(s.tg_id), ...s.emails].some((v) => v.toLowerCase().includes(q))),
    );
  }, [data.subscriptions, query, status]);

  const withoutSub = data.clients.filter((c) => !c.sub_id).length;

  return (
    <>
      <div className="toolbar">
        <button className="btn btn-primary" onClick={() => setCreating(true)}>
          + Новый клиент
        </button>
        <input className="input" placeholder="Поиск: subId, email, комментарий, Telegram ID" value={query} onChange={(e) => setQuery(e.target.value)} />
        <select className="input" value={status} onChange={(e) => setStatus(e.target.value as ClientStatus | "")}>
          <option value="">Все статусы</option>
          {Object.entries(STATUS_LABELS).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
        <span className="muted">{subs.length} шт.</span>
      </div>
      {withoutSub > 0 && <p className="muted small">Клиентов без subId: {withoutSub} — они не входят ни в одну подписку.</p>}
      {subs.length === 0 ? (
        <Empty>Подписки не найдены</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th></th>
                <th>Подписка</th>
                <th>Клиенты</th>
                <th>Узлы</th>
                <th className="num">Трафик</th>
                <th>Срок</th>
                <th>Статус</th>
                <th>Ссылка</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {subs.map((s) => (
                <tr key={s.sub_id}>
                  <td>
                    <OnlineDot online={s.online} />
                  </td>
                  <td>
                    <div className="mono strong">{s.sub_id}</div>
                    {s.comment && <div className="muted small">{s.comment}</div>}
                    {s.tg_id ? <div className="muted small">TG: {s.tg_id}</div> : null}
                  </td>
                  <td className="small">{s.emails.join(", ")}</td>
                  <td className="small">
                    {s.nodes.map((n) => (
                      <div key={n}>{n}</div>
                    ))}
                  </td>
                  <td className="num">{formatBytes(s.up + s.down)}</td>
                  <td className="small">{formatExpiry(s.expiry_time)}</td>
                  <td>
                    <StatusBadge status={s.status} />
                  </td>
                  <td>
                    {s.urls.length === 0 ? (
                      <span className="muted small" title="Включите подписки в настройках 3x-ui или задайте URL подписки для сервера">
                        нет URL
                      </span>
                    ) : (
                      s.urls.map((u) => (
                        <div key={u.url} className="link-row">
                          <CopyButton text={u.url} label={s.urls.length > 1 ? u.panel : "Копировать"} />
                          <a href={u.url} target="_blank" rel="noreferrer" className="small">
                            открыть
                          </a>
                        </div>
                      ))
                    )}
                  </td>
                  <td>
                    <button className="btn btn-small" onClick={() => setManaging(s)}>
                      Управлять
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {managing && (
        <ClientDialog
          clients={data.clients.filter((c) => c.sub_id === managing.sub_id)}
          title={`Подписка ${managing.sub_id}`}
          onClose={() => setManaging(null)}
          onChanged={onChanged}
        />
      )}
      {creating && <CreateClientDialog nodes={data.nodes} panels={data.panels} onClose={() => setCreating(false)} onChanged={onChanged} />}
    </>
  );
}
