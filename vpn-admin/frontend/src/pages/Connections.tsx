import { useMemo, useState } from "react";
import { api, SUPPORTED_PROTOCOLS, type Node, type Overview } from "../api";
import { CreateClientDialog } from "../components/CreateClientDialog";
import { Switch } from "../components/NodeDialog";
import { Empty, PanelFilter, TrafficBar } from "../components/ui";
import { formatBytes, formatExpiry, formatLimit } from "../format";

export function Connections({ data, onChanged }: { data: Overview; onChanged: () => void }) {
  const [panelId, setPanelId] = useState(0);
  const [addingTo, setAddingTo] = useState<Node | null>(null);
  const [query, setQuery] = useState("");
  // switched here but not yet back in the overview data: key -> the new state
  const [pending, setPending] = useState<Record<string, boolean>>({});
  const [error, setError] = useState("");

  const toggle = async (n: Node, enable: boolean) => {
    const key = `${n.panel_id}-${n.id}`;
    setPending((p) => ({ ...p, [key]: enable }));
    setError("");
    try {
      await api.setInboundEnable(n.panel_id, n.id, enable);
      await onChanged();
    } catch (e) {
      setError(`«${n.remark || `#${n.id}`}»: ${(e as Error).message}`);
    } finally {
      setPending((p) => {
        const next = { ...p };
        delete next[key];
        return next;
      });
    }
  };

  const nodes = useMemo(() => {
    const q = query.trim().toLowerCase();
    return data.nodes.filter(
      (n) =>
        (!panelId || n.panel_id === panelId) &&
        (!q || [n.remark, n.protocol, String(n.port), n.network].some((v) => v.toLowerCase().includes(q))),
    );
  }, [data.nodes, panelId, query]);

  return (
    <>
      <div className="toolbar">
        <input className="input" placeholder="Поиск: название, протокол, порт" value={query} onChange={(e) => setQuery(e.target.value)} />
        <PanelFilter panels={data.panels} value={panelId} onChange={setPanelId} />
        <span className="muted">{nodes.length} шт.</span>
      </div>
      {error && <div className="notice notice-bad small">{error}</div>}
      {nodes.length === 0 ? (
        <Empty>Коннекты не найдены</Empty>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Коннект</th>
                <th>Сервер</th>
                <th>Протокол</th>
                <th className="num">Порт</th>
                <th>Транспорт</th>
                <th className="num">Клиенты</th>
                <th className="num">Онлайн</th>
                <th>Трафик</th>
                <th>Срок</th>
                <th>Статус</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {nodes.map((n) => {
                const key = `${n.panel_id}-${n.id}`;
                const enabled = pending[key] ?? n.enable;
                return (
                <tr key={key} className={enabled ? "" : "row-muted"}>
                  <td className="strong">{n.remark || `#${n.id}`}</td>
                  <td>{n.panel_name}</td>
                  <td>
                    <span className="tag">{n.protocol}</span>
                  </td>
                  <td className="num mono">{n.port}</td>
                  <td>
                    {n.network || "—"}
                    {n.security && n.security !== "none" && <span className="tag tag-soft">{n.security}</span>}
                  </td>
                  <td className="num">{n.clients}</td>
                  <td className="num">{n.online}</td>
                  <td>
                    {formatBytes(n.up + n.down)} / {formatLimit(n.total)}
                    <TrafficBar used={n.up + n.down} total={n.total} />
                  </td>
                  <td className="small">{formatExpiry(n.expiry_time)}</td>
                  <td>
                    <span className="inbound-switch">
                      <Switch
                        checked={enabled}
                        disabled={key in pending}
                        onChange={(v) => toggle(n, v)}
                        title={enabled ? "Выключить коннект: клиенты не смогут через него подключаться" : "Включить коннект"}
                      />
                      <span className={enabled ? "good-text small" : "muted small"}>{enabled ? "Включён" : "Выключен"}</span>
                    </span>
                  </td>
                  <td>
                    {SUPPORTED_PROTOCOLS.includes(n.protocol) && (
                      <button className="btn btn-small" onClick={() => setAddingTo(n)}>
                        + Клиент
                      </button>
                    )}
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {addingTo && (
        <CreateClientDialog nodes={data.nodes} panels={data.panels} preselected={[addingTo]} onClose={() => setAddingTo(null)} onChanged={onChanged} />
      )}
    </>
  );
}
