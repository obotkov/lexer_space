import { useMemo, useState } from "react";
import { api, SUPPORTED_PROTOCOLS, type Node, type Overview } from "../api";
import { CreateClientDialog } from "../components/CreateClientDialog";
import { Switch } from "../components/NodeDialog";
import { Empty, TrafficBar } from "../components/ui";
import { formatBytes, formatExpiry, formatLimit } from "../format";

export function Connections({ data, onChanged }: { data: Overview; onChanged: () => void }) {
  // "" or "<panel_id>:<node_id>": a panel's own server or one of its v3 nodes
  const [server, setServer] = useState("");
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

  const serverKey = (n: Node) => `${n.panel_id}:${n.node_id}`;
  const servers = useMemo(() => {
    const seen = new Map<string, string>();
    for (const n of data.nodes) if (!seen.has(serverKey(n))) seen.set(serverKey(n), n.node_id ? `${n.server} (${n.panel_name})` : n.server);
    return [...seen].sort((a, b) => a[1].localeCompare(b[1]));
  }, [data.nodes]);

  const nodes = useMemo(() => {
    const q = query.trim().toLowerCase();
    return data.nodes.filter(
      (n) =>
        (!server || serverKey(n) === server) &&
        (!q || [n.remark, n.server, n.protocol, String(n.port), n.network].some((v) => v.toLowerCase().includes(q))),
    );
  }, [data.nodes, server, query]);

  return (
    <>
      <div className="toolbar">
        <input className="input" placeholder="Поиск: название, сервер, протокол, порт" value={query} onChange={(e) => setQuery(e.target.value)} />
        {servers.length > 1 && (
          <select className="input" value={server} onChange={(e) => setServer(e.target.value)}>
            <option value="">Все серверы</option>
            {servers.map(([key, name]) => (
              <option key={key} value={key}>
                {name}
              </option>
            ))}
          </select>
        )}
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
                <th aria-label="Включён"></th>
                <th>Коннект</th>
                <th>Сервер</th>
                <th>Протокол</th>
                <th className="num">Порт</th>
                <th>Транспорт</th>
                <th className="num">Клиенты</th>
                <th className="num">Онлайн</th>
                <th>Трафик</th>
                <th>Срок</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {nodes.map((n) => {
                const key = `${n.panel_id}-${n.id}`;
                const enabled = pending[key] ?? n.enable;
                return (
                <tr key={key} className={enabled ? "" : "row-muted"}>
                  <td className="inbound-switch">
                    <Switch
                      checked={enabled}
                      disabled={key in pending}
                      onChange={(v) => toggle(n, v)}
                      title={enabled ? "Выключить коннект: клиенты не смогут через него подключаться" : "Включить коннект"}
                    />
                  </td>
                  <td className="strong">{n.remark || `#${n.id}`}</td>
                  <td>
                    {n.server}
                    {n.node_id > 0 && <div className="muted small">узел панели {n.panel_name}</div>}
                  </td>
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
