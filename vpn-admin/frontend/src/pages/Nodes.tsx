import { useCallback, useEffect, useState } from "react";
import { api, type NodesData, type NodesPanel, type PanelInfo, type XNode } from "../api";
import { NodeDialog, Switch } from "../components/NodeDialog";
import { Empty, StatCard } from "../components/ui";
import { formatDateTime, formatSpeed, formatUptime } from "../format";

const REFRESH_MS = 30_000;
// a node's self-update: download, restart, then its new version comes with a heartbeat
const UPDATE_CHECKS_MS = [20_000, 45_000, 90_000, 150_000];
const UPDATE_WAIT_MS = 4 * 60_000;

/** Started self-updates: the version a node had and when, by "panel-node". */
type Updating = Record<string, { from: string; at: number }>;

/** A node the button can update: 3x-ui outside Docker, enabled and online (the main panel skips the rest). */
const updatable = (n: XNode) => n.update_available && !n.docker && n.enable && n.status === "online";

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
  const [updating, setUpdating] = useState<Updating>({});

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

  // a node that came back with a new version is done
  useEffect(() => {
    if (!data) return;
    setUpdating((all) => {
      const next = { ...all };
      for (const p of data.panels)
        for (const n of p.nodes) {
          const u = next[`${p.panel_id}-${n.id}`];
          if (u && n.panel_version && n.panel_version !== u.from) delete next[`${p.panel_id}-${n.id}`];
        }
      return Object.keys(next).length === Object.keys(all).length ? all : next;
    });
  }, [data]);

  /** Start the self-update on these nodes of one main panel; the list is re-read while they restart. */
  const updatePanels = async (panelId: number, list: XNode[]) => {
    const results = (await api.updateNodePanels(panelId, list.map((n) => n.id))).results;
    const started = results.filter((r) => r.ok);
    const at = Date.now();
    setUpdating((all) => ({
      ...all,
      ...Object.fromEntries(
        started.map((r) => [`${panelId}-${r.id}`, { from: list.find((n) => n.id === r.id)?.panel_version ?? "", at }]),
      ),
    }));
    for (const ms of UPDATE_CHECKS_MS) setTimeout(load, ms);
    const failed = results.filter((r) => !r.ok).map((r) => `«${r.name || r.id}»: ${r.error || "не запустилось"}`);
    if (failed.length) setError(`Обновление не запущено — ${failed.join("; ")}`);
    return started.length;
  };

  if (!data) return error ? <div className="notice notice-bad">{error}</div> : <div className="center muted">Загрузка узлов…</div>;

  const mainPanels = data.panels.filter((p) => p.supported && p.ok);
  const t = data.totals;
  const toUpdate = data.panels.map((p) => ({ panel: p, nodes: p.nodes.filter((n) => updatable(n) && !updating[`${p.panel_id}-${n.id}`]) }));
  const toUpdateCount = toUpdate.reduce((sum, x) => sum + x.nodes.length, 0);

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
        {toUpdateCount > 1 && (
          <button
            className="btn"
            disabled={rowBusy === "all"}
            onClick={() => {
              if (!confirm(`Обновить 3x-ui до ${data.latest_panel_version} на ${toUpdateCount} узлах? Каждый узел перезапустит панель и Xray: VPN на нём прервётся примерно на полминуты.`)) return;
              rowAction("all", async () => {
                let started = 0;
                for (const x of toUpdate) if (x.nodes.length) started += await updatePanels(x.panel.panel_id, x.nodes);
                setMessage(`Обновление запущено на узлах: ${started}. Новая версия появится, когда узлы перезапустятся (обычно 1–2 минуты).`);
              });
            }}
          >
            Обновить все узлы ({toUpdateCount})
          </button>
        )}
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
          latest={data.latest_panel_version}
          updating={updating}
          onUpdate={(node) => {
            if (!confirm(`Обновить 3x-ui на узле «${node.name}» с ${node.panel_version} до ${data.latest_panel_version}? Узел перезапустит панель и Xray: VPN на нём прервётся примерно на полминуты.`)) return;
            rowAction(`${p.panel_id}-${node.id}`, async () => {
              if (await updatePanels(p.panel_id, [node]))
                setMessage(`Обновление «${node.name}» запущено: новая версия появится, когда узел перезапустится (обычно 1–2 минуты).`);
            });
          }}
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
  latest,
  updating,
  onUpdate,
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
  latest: string | null;
  updating: Updating;
  onUpdate: (n: XNode) => void;
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
                <th className="col-panel">Панель</th>
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
                    <td className="col-panel">
                      {n.panel_version || "—"}
                      <PanelUpdate node={n} latest={latest} started={updating[`${panel.panel_id}-${n.id}`]} busy={busy} onUpdate={() => onUpdate(n)} />
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

/** What the Panel column offers when 3x-ui on the node is behind: the update button, its progress, or why not. */
function PanelUpdate({
  node: n,
  latest,
  started,
  busy,
  onUpdate,
}: {
  node: XNode;
  latest: string | null;
  started?: { from: string; at: number };
  busy: boolean;
  onUpdate: () => void;
}) {
  if (started) {
    if (Date.now() - started.at < UPDATE_WAIT_MS) return <div className="badge badge-depleted">Обновляется…</div>;
    return (
      <div className="error-text small node-update-note">
        Не обновился за {UPDATE_WAIT_MS / 60_000} минуты: обновление 3x-ui на узле не прошло, причина — в журнале 3x-ui на нём.
      </div>
    );
  }
  if (!n.update_available) return null;
  if (n.docker)
    return (
      <>
        <div className="badge badge-depleted">Доступно обновление</div>
        <div className="muted small node-update-note">
          3x-ui в Docker не обновляет сам себя: обновите узел кнопкой «Переустановить с нуля» в блоке «Новые серверы»
        </div>
      </>
    );
  const why = !n.enable ? "Узел выключен: включите его, чтобы обновить" : n.status !== "online" ? "Узел не в сети" : "";
  return (
    <div>
      <button className="btn btn-small btn-update" disabled={busy || !!why} title={why || `Обновить 3x-ui на узле до ${latest}`} onClick={onUpdate}>
        Обновить{latest ? ` до ${latest}` : ""}
      </button>
    </div>
  );
}
