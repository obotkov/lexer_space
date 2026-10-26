import { useMemo, useState } from "react";
import type { Client, ClientStatus, Overview } from "../api";
import { ClientDialog } from "../components/ClientDialog";
import { CreateClientDialog } from "../components/CreateClientDialog";
import { CopyButton, Empty, OnlineDot, PanelFilter, StatusBadge, TrafficBar } from "../components/ui";
import { formatBytes, formatDateTime, formatExpiry, formatLimit, STATUS_LABELS } from "../format";

type SortKey = "email" | "traffic" | "expiry";

const keyOf = (c: Client) => `${c.panel_id}-${c.inbound_id}-${c.email}`;

export function Users({ data, onChanged }: { data: Overview; onChanged: () => void }) {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<ClientStatus | "">("");
  const [panelId, setPanelId] = useState(0);
  const [onlineOnly, setOnlineOnly] = useState(false);
  const [sort, setSort] = useState<SortKey>("email");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<Set<string> | null>(null);
  const [creating, setCreating] = useState(false);

  const clients = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = data.clients.filter(
      (c) =>
        (!status || c.status === status) &&
        (!panelId || c.panel_id === panelId) &&
        (!onlineOnly || c.online) &&
        (!q || [c.email, c.sub_id, c.comment, String(c.tg_id), c.inbound_remark, c.secret].some((v) => v.toLowerCase().includes(q))),
    );
    const cmp: Record<SortKey, (a: Client, b: Client) => number> = {
      email: (a, b) => a.email.localeCompare(b.email),
      traffic: (a, b) => b.up + b.down - (a.up + a.down),
      expiry: (a, b) => (a.expiry_time || Infinity) - (b.expiry_time || Infinity),
    };
    return list.sort(cmp[sort]);
  }, [data.clients, query, status, panelId, onlineOnly, sort]);

  // selection survives refreshes, but only for clients that still exist
  const selectedClients = data.clients.filter((c) => selected.has(keyOf(c)));
  const allVisibleSelected = clients.length > 0 && clients.every((c) => selected.has(keyOf(c)));

  const toggle = (c: Client) =>
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(keyOf(c))) next.delete(keyOf(c));
      else next.add(keyOf(c));
      return next;
    });
  const toggleAll = () => setSelected(allVisibleSelected ? new Set() : new Set(clients.map(keyOf)));

  return (
    <>
      <div className="toolbar">
        <button className="btn btn-primary" onClick={() => setCreating(true)}>
          + Новый клиент
        </button>
        <input className="input" placeholder="Поиск: email, subId, UUID, комментарий" value={query} onChange={(e) => setQuery(e.target.value)} />
        <select className="input" value={status} onChange={(e) => setStatus(e.target.value as ClientStatus | "")}>
          <option value="">Все статусы</option>
          {Object.entries(STATUS_LABELS).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
        <PanelFilter panels={data.panels} value={panelId} onChange={setPanelId} />
        <select className="input" value={sort} onChange={(e) => setSort(e.target.value as SortKey)}>
          <option value="email">По имени</option>
          <option value="traffic">По трафику</option>
          <option value="expiry">По сроку</option>
        </select>
        <label className="checkbox">
          <input type="checkbox" checked={onlineOnly} onChange={(e) => setOnlineOnly(e.target.checked)} /> Только онлайн
        </label>
        <span className="muted">{clients.length} шт.</span>
      </div>

      {selectedClients.length > 0 && (
        <div className="selection-bar">
          <span>Выбрано: {selectedClients.length}</span>
          <button className="btn btn-primary btn-small" onClick={() => setEditing(new Set(selectedClients.map(keyOf)))}>
            Действия с выбранными
          </button>
          <button className="btn btn-small" onClick={() => setSelected(new Set())}>
            Снять выделение
          </button>
        </div>
      )}

      {clients.length === 0 ? (
        <Empty>Пользователи не найдены</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>
                  <input type="checkbox" checked={allVisibleSelected} onChange={toggleAll} title="Выбрать все" />
                </th>
                <th></th>
                <th>Email</th>
                <th>Коннект</th>
                <th>Подписка</th>
                <th>Трафик</th>
                <th>Срок</th>
                <th className="num">IP</th>
                <th>Статус</th>
                <th>Был онлайн</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {clients.map((c) => (
                <tr key={keyOf(c)} className={selected.has(keyOf(c)) ? "row-selected" : ""}>
                  <td>
                    <input type="checkbox" checked={selected.has(keyOf(c))} onChange={() => toggle(c)} />
                  </td>
                  <td>
                    <OnlineDot online={c.online} />
                  </td>
                  <td>
                    <div className="strong">{c.email}</div>
                    {c.comment && <div className="muted small">{c.comment}</div>}
                  </td>
                  <td className="small">
                    {c.inbound_remark}
                    <div className="muted">
                      {c.panel_name} · {c.protocol}
                    </div>
                  </td>
                  <td>
                    {c.sub_id ? (
                      <>
                        <div className="mono small">{c.sub_id}</div>
                        {c.sub_url && <CopyButton text={c.sub_url} label="Ссылка" />}
                      </>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td>
                    {formatBytes(c.up + c.down)} / {formatLimit(c.total)}
                    <TrafficBar used={c.up + c.down} total={c.total} />
                  </td>
                  <td className="small">{formatExpiry(c.expiry_time)}</td>
                  <td className="num">{c.limit_ip || "∞"}</td>
                  <td>
                    <StatusBadge status={c.status} />
                  </td>
                  <td className="small">{c.online ? "сейчас" : formatDateTime(c.last_online)}</td>
                  <td>
                    <button className="btn btn-small" onClick={() => setEditing(new Set([keyOf(c)]))}>
                      Изменить
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {editing && <ClientDialog clients={data.clients.filter((c) => editing.has(keyOf(c)))} onClose={() => setEditing(null)} onChanged={onChanged} />}
      {creating && <CreateClientDialog nodes={data.nodes} panels={data.panels} onClose={() => setCreating(false)} onChanged={onChanged} />}
    </>
  );
}
