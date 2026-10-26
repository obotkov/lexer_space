import { useCallback, useEffect, useState } from "react";
import { api, type NodesData, type NodesPanel, type PanelInfo, type XNode } from "../api";
import { NodeDialog, Switch } from "../components/NodeDialog";
import { Empty, StatCard } from "../components/ui";
import { formatDateTime, formatSpeed, formatUptime } from "../format";

const REFRESH_MS = 30_000;

const STATUS_LABELS: Record<string, string> = { online: "В сети", offline: "Не в сети", unknown: "Нет данных" };

const nodeUrl = (n: XNode) => `${n.scheme}://${n.address}:${n.port}${n.base_path && n.base_path !== "/" ? n.base_path : ""}`;

/** Remote 3x-ui servers attached to the main panel(s), with the heartbeat stats the main panel collects. */
export function Nodes({ panels, onChanged }: { panels: PanelInfo[]; onChanged: () => void }) {
  const [data, setData] = useState<NodesData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showAddress, setShowAddress] = useState(false);
  const [editing, setEditing] = useState<{ panelId: number; node: XNode | null } | null>(null);
  const [rowBusy, setRowBusy] = useState<string | null>(null);
  const [message, setMessage] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setData(await api.nodes());
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => clearInterval(timer);
  }, [load]);

  const rowAction = async (key: string, action: () => Promise<unknown>, done?: string) => {
    setRowBusy(key);
    setMessage("");
    setError("");
    try {
      await action();
      if (done) setMessage(done);
      await load();
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRowBusy(null);
    }
  };

  if (!data) return error ? <div className="notice notice-bad">{error}</div> : <div className="center muted">Загрузка узлов…</div>;

  const mainPanels = data.panels.filter((p) => p.supported && p.ok);
  const t = data.totals;

  if (panels.length === 0) return <Empty>Сначала подключите главную панель 3x-ui в разделе «Серверы 3x-ui».</Empty>;

  return (
    <>
      <div className="stats">
        <StatCard label="Всего узлов" value={t.nodes} hint={t.disabled ? `выключено: ${t.disabled}` : undefined} />
        <StatCard label="В сети" value={t.online} tone="good" />
        <StatCard label="Не в сети" value={t.offline} tone={t.offline ? "bad" : undefined} />
        <StatCard label="Средняя задержка" value={t.avg_latency_ms != null ? `${t.avg_latency_ms} ms` : "—"} />
        <StatCard label="Клиентов онлайн" value={t.online_clients} hint={`всего на узлах: ${t.clients}`} />
      </div>

      <div className="toolbar section-title">
        <button className="btn btn-primary" disabled={mainPanels.length === 0} onClick={() => setEditing({ panelId: mainPanels[0].panel_id, node: null })}>
          + Добавить узел
        </button>
        <button className="btn" onClick={load} disabled={loading}>
          {loading ? "Обновляю…" : "Обновить"}
        </button>
        {data.latest_panel_version && <span className="muted small">Последняя версия 3x-ui: {data.latest_panel_version}</span>}
      </div>

      {message && <div className="notice notice-ok small">{message}</div>}
      {error && <div className="notice notice-bad small">{error}</div>}

      {data.panels.map((p) => (
        <PanelNodes
          key={p.panel_id}
          panel={p}
          showTitle={data.panels.length > 1}
          showAddress={showAddress}
          onToggleAddress={() => setShowAddress((v) => !v)}
          rowBusy={rowBusy}
          onEdit={(node) => setEditing({ panelId: p.panel_id, node })}
          onToggle={(node) =>
            rowAction(`${p.panel_id}-${node.id}`, () => api.enableNode(p.panel_id, node.id, !node.enable), `Узел «${node.name}» ${node.enable ? "выключен" : "включён"}`)
          }
          onProbe={(node) =>
            rowAction(`${p.panel_id}-${node.id}`, async () => {
              const hb = await api.probeNode(p.panel_id, node.id);
              setMessage(hb.status === "online" ? `«${node.name}» отвечает: ${hb.latencyMs} мс` : `«${node.name}» не отвечает: ${hb.error || hb.status}`);
            })
          }
          onDelete={(node) => {
            if (!confirm(`Отключить узел «${node.name}» от главной панели? Сам сервер и его 3x-ui не пострадают, но его коннекты и клиенты перестанут синхронизироваться.`)) return;
            rowAction(`${p.panel_id}-${node.id}`, () => api.deleteNode(p.panel_id, node.id), `Узел «${node.name}» удалён`);
          }}
        />
      ))}

      {editing && (
        <NodeDialog
          mainPanels={mainPanels}
          panelId={editing.panelId}
          node={editing.node}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setMessage(editing.node ? `Узел «${editing.node.name}» сохранён` : "Узел добавлен");
            setEditing(null);
            load();
            onChanged();
          }}
        />
      )}
    </>
  );
}

function PanelNodes({
  panel,
  showTitle,
  showAddress,
  onToggleAddress,
  rowBusy,
  onEdit,
  onToggle,
  onProbe,
  onDelete,
}: {
  panel: NodesPanel;
  showTitle: boolean;
  showAddress: boolean;
  onToggleAddress: () => void;
  rowBusy: string | null;
  onEdit: (n: XNode) => void;
  onToggle: (n: XNode) => void;
  onProbe: (n: XNode) => void;
  onDelete: (n: XNode) => void;
}) {
  const title = showTitle && <h2 className="section-title">Главная панель: {panel.panel_name}</h2>;
  if (!panel.supported)
    return showTitle ? (
      <>
        {title}
        <div className="notice notice-info small">Это 3x-ui 2.x: узлов в ней нет, они появились в 3x-ui v3.</div>
      </>
    ) : (
      <Empty>Подключённая панель — 3x-ui 2.x. Узлы (управление другими серверами из одной панели) есть только в 3x-ui v3.</Empty>
    );
  if (!panel.ok)
    return (
      <>
        {title}
        <div className="notice notice-bad small">Не удалось получить узлы: {panel.error}</div>
      </>
    );

  return (
    <>
      {title}
      {panel.nodes.length === 0 ? (
        <Empty>К главной панели пока не подключено ни одного узла. Нажмите «Добавить узел».</Empty>
      ) : (
        <div className="table-wrap">
          <table className="nodes-table">
            <thead>
              <tr>
                <th>Вкл.</th>
                <th>Имя</th>
                <th>
                  <button className="link-button" onClick={onToggleAddress} title={showAddress ? "Скрыть адреса" : "Показать адреса"}>
                    Адрес {showAddress ? "🙈" : "👁"}
                  </button>
                </th>
                <th>Статус</th>
                <th className="num">CPU</th>
                <th className="num">Память</th>
                <th>Xray</th>
                <th>Панель</th>
                <th className="num">Аптайм</th>
                <th className="num">Задержка</th>
                <th className="num">Онлайн</th>
                <th className="num">Скорость</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {panel.nodes.map((n) => {
                const busy = rowBusy === `${panel.panel_id}-${n.id}`;
                const online = n.status === "online";
                return (
                  <tr key={n.id} className={n.enable ? "" : "row-muted"}>
                    <td>
                      <Switch checked={n.enable} disabled={busy} onChange={() => onToggle(n)} title={n.enable ? "Выключить синхронизацию" : "Включить"} />
                    </td>
                    <td>
                      <div className="strong">{n.name}</div>
                      {n.remark && <div className="muted small">{n.remark}</div>}
                    </td>
                    <td className={`mono small node-addr ${showAddress ? "" : "blurred"}`} title={showAddress ? nodeUrl(n) : ""}>
                      {nodeUrl(n)}
                    </td>
                    <td>
                      <span className={`status ${online ? "status-on" : "status-off"}`} title={n.last_error || (n.last_heartbeat ? `проверен ${formatDateTime(n.last_heartbeat * 1000)}` : "")}>
                        <span className={`dot ${online ? "dot-on" : "dot-off"}`} /> {STATUS_LABELS[n.status] ?? n.status}
                      </span>
                      {!online && n.last_error && <div className="error-text small node-error">{n.last_error}</div>}
                      {online && n.xray_state && n.xray_state !== "running" && <div className="error-text small">Xray: {n.xray_error || n.xray_state}</div>}
                    </td>
                    <td className="num">{n.cpu != null && online ? `${n.cpu.toFixed(1)}%` : "—"}</td>
                    <td className="num">{n.mem != null && online ? `${n.mem.toFixed(1)}%` : "—"}</td>
                    <td>{n.xray_version || "—"}</td>
                    <td>
                      {n.panel_version || "—"}
                      {n.update_available && <div className="badge badge-depleted">Доступно обновление</div>}
                    </td>
                    <td className="num">{online ? formatUptime(n.uptime) : "—"}</td>
                    <td className="num">{online && n.latency_ms ? `${n.latency_ms} ms` : "—"}</td>
                    <td className="num">
                      {n.online} / {n.clients}
                    </td>
                    <td className="num small">
                      {online ? (
                        <>
                          ↓ {formatSpeed(n.net_down)}
                          <div className="muted">↑ {formatSpeed(n.net_up)}</div>
                        </>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>
                      <div className="row-actions">
                        <button className="icon-btn" title="Проверить связь" disabled={busy} onClick={() => onProbe(n)}>
                          ⚡
                        </button>
                        <button className="icon-btn" title="Изменить" disabled={busy} onClick={() => onEdit(n)}>
                          ✎
                        </button>
                        <button className="icon-btn danger" title="Удалить" disabled={busy} onClick={() => onDelete(n)}>
                          🗑
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
