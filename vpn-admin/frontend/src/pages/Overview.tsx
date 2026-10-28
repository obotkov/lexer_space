import { useState, type MouseEvent } from "react";
import type { ChildNode, Overview as OverviewData, PanelInfo } from "../api";
import { NetLoadWidget } from "../components/NetLoadWidget";
import { PingWidget } from "../components/PingWidget";
import { ProbeWidget } from "../components/ProbeWidget";
import { Empty, StatCard } from "../components/ui";
import { formatBytes, formatUptime } from "../format";

const NODE_STATUS: Record<string, string> = { online: "В сети", offline: "Не в сети", unknown: "Нет данных" };

export function Overview({ data, onGoServers }: { data: OverviewData; onGoServers: () => void }) {
  const t = data.totals;

  if (t.panels === 0) {
    return (
      <Empty>
        <p>Ещё не подключён ни один сервер 3x-ui.</p>
        <button className="btn btn-primary" onClick={onGoServers}>
          Добавить сервер
        </button>
      </Empty>
    );
  }

  const topUsers = [...data.subscriptions].sort((a, b) => b.up + b.down - (a.up + a.down)).slice(0, 8);
  const children = data.panels.flatMap((p) => p.children.map((node) => ({ node, panel: p })));

  return (
    <>
      <div className="stats">
        <StatCard label="Пользователей" value={t.users} hint={`${t.clients} клиентов во всех коннектах`} />
        <StatCard label="Активных" value={t.users_active} tone="good" hint={`онлайн сейчас: ${t.users_online}`} />
        <StatCard label="Истекших / отключённых" value={`${t.users_expired} / ${t.users_disabled}`} tone={t.users_expired ? "warn" : undefined} />
        <StatCard label="Подписок" value={t.subscriptions} />
        <StatCard label="Коннектов" value={t.nodes} hint={`включено: ${t.nodes_enabled}`} />
        <StatCard
          label="Серверов"
          value={`${t.panels_ok} / ${t.panels}`}
          tone={t.panels_ok < t.panels ? "bad" : "good"}
          hint={t.panels_ok < t.panels ? "есть недоступные" : children.length ? `+ узлов: ${children.length}` : "все на связи"}
        />
        <StatCard label="Трафик всего" value={formatBytes(t.traffic_up + t.traffic_down)} hint={`↑ ${formatBytes(t.traffic_up)} · ↓ ${formatBytes(t.traffic_down)}`} />
      </div>

      <h2 className="section-title">Серверы</h2>
      <div className="table-wrap">
        <table className="servers-table">
          <thead>
            <tr>
              <th>Сервер</th>
              <th>Состояние</th>
              <th>Xray</th>
              <th>CPU</th>
              <th>RAM</th>
              <th>Аптайм</th>
              <th className="num">Коннектов</th>
              <th className="num">Клиентов</th>
              <th className="num">Онлайн</th>
              <th className="num">Трафик</th>
            </tr>
          </thead>
          <tbody>
            {data.panels.map((p) => (
              <ServerRows key={p.id} panel={p} />
            ))}
          </tbody>
        </table>
      </div>

      <h2 className="section-title">Сетевая нагрузка</h2>
      <NetLoadWidget multiPanel={data.panels.length > 1} />

      <h2 className="section-title">Проверка коннектов</h2>
      <ProbeWidget multiPanel={data.panels.length > 1} />

      <div className="overview-widgets">
        <section className="overview-widget">
          <h2 className="section-title">Пинг до серверов</h2>
          <PingWidget multiPanel={data.panels.length > 1} />
        </section>

        {children.length > 0 && (
          <section className="overview-widget">
            <h2 className="section-title">Трафик узлов</h2>
            <NodeTrafficChart items={children.map(({ node, panel }) => ({ node, label: data.panels.length > 1 ? `${panel.name} › ${node.name}` : node.name }))} />
          </section>
        )}

        {topUsers.length > 0 && (
          <section className="overview-widget">
            <h2 className="section-title">Топ по трафику</h2>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Подписка</th>
                    <th>Клиенты</th>
                    <th className="num">Трафик</th>
                  </tr>
                </thead>
                <tbody>
                  {topUsers.map((s) => (
                    <tr key={s.sub_id}>
                      <td className="mono">{s.sub_id}</td>
                      <td className="overview-top-emails">{s.emails.join(", ")}</td>
                      <td className="num">{formatBytes(s.up + s.down)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}
      </div>
    </>
  );
}

/** The main panel row, then its nodes indented under it. */
function ServerRows({ panel: p }: { panel: PanelInfo }) {
  const childTraffic = p.children.reduce((sum, n) => sum + n.up + n.down, 0);
  const ownTraffic = p.up + p.down - childTraffic; // inbounds hosted on the main server itself

  return (
    <>
      <tr className="server-main">
        <td>
          <div className="server-name">
            <span className="strong">{p.name}</span>
            <span className="badge badge-main">{p.children.length ? "Основной" : "Сервер"}</span>
          </div>
          <div className="muted small">{p.url}</div>
        </td>
        <td>
          {p.ok ? (
            <span className="badge badge-active">На связи</span>
          ) : (
            <span className="badge badge-expired" title={p.error ?? ""}>
              Ошибка
            </span>
          )}
          {!p.ok && <div className="error-text small">{p.error}</div>}
        </td>
        <td>
          {p.status?.xray_version ?? "—"}
          {p.status?.xray_state && p.status.xray_state !== "running" && <div className="error-text small">{p.status.xray_state}</div>}
        </td>
        <td>{p.status?.cpu != null ? `${p.status.cpu.toFixed(1)}%` : "—"}</td>
        <td>{p.status?.mem_total ? `${formatBytes(p.status.mem_current ?? 0)} / ${formatBytes(p.status.mem_total)}` : "—"}</td>
        <td>{formatUptime(p.status?.uptime ?? null)}</td>
        <td className="num">{p.nodes}</td>
        <td className="num">{p.clients}</td>
        <td className="num">{p.online}</td>
        <td className="num" title={p.children.length ? `вместе с узлами: ${formatBytes(p.up + p.down)}` : ""}>
          {formatBytes(ownTraffic)}
        </td>
      </tr>
      {p.children.map((n, i) => (
        <ChildRow key={n.id} node={n} last={i === p.children.length - 1} />
      ))}
    </>
  );
}

function ChildRow({ node: n, last }: { node: ChildNode; last: boolean }) {
  const online = n.status === "online";
  return (
    <tr className={`server-child ${n.enable ? "" : "row-muted"}`}>
      <td>
        <div className="server-name child-name">
          <span className={`tree-line ${last ? "tree-last" : ""}`} aria-hidden />
          <div>
            <div>
              <span className="strong">{n.name}</span> <span className="badge badge-node">узел</span>
            </div>
            {n.remark && <div className="muted small">{n.remark}</div>}
          </div>
        </div>
      </td>
      <td>
        {!n.enable ? (
          <span className="badge badge-disabled">Выключен</span>
        ) : (
          <span className={`status ${online ? "status-on" : "status-off"}`}>
            <span className={`dot ${online ? "dot-on" : "dot-off"}`} /> {NODE_STATUS[n.status] ?? n.status}
          </span>
        )}
        {n.enable && !online && n.last_error && <div className="error-text small node-error">{n.last_error}</div>}
      </td>
      <td>
        {n.xray_version || "—"}
        {online && n.xray_state && n.xray_state !== "running" && <div className="error-text small">{n.xray_error || n.xray_state}</div>}
      </td>
      <td>{online && n.cpu != null ? `${n.cpu.toFixed(1)}%` : "—"}</td>
      <td>{online && n.mem != null ? `${n.mem.toFixed(1)}%` : "—"}</td>
      <td>{online ? formatUptime(n.uptime) : "—"}</td>
      <td className="num">{n.inbounds}</td>
      <td className="num">{n.clients}</td>
      <td className="num">{n.online}</td>
      <td className="num">{formatBytes(n.up + n.down)}</td>
    </tr>
  );
}

/** Horizontal bars: total traffic of each node's inbounds, largest first. Hover shows the split. */
function NodeTrafficChart({ items }: { items: { node: ChildNode; label: string }[] }) {
  const [hover, setHover] = useState<{ index: number; x: number; y: number } | null>(null);
  const rows = [...items].sort((a, b) => b.node.up + b.node.down - (a.node.up + a.node.down));
  const max = Math.max(...rows.map((r) => r.node.up + r.node.down), 1);
  const sum = rows.reduce((s, r) => s + r.node.up + r.node.down, 0);

  const move = (index: number) => (e: MouseEvent<HTMLDivElement>) => {
    const box = e.currentTarget.parentElement!.getBoundingClientRect();
    setHover({ index, x: e.clientX - box.left, y: e.clientY - box.top });
  };

  const active = hover && rows[hover.index];

  return (
    <div className="card traffic-chart">
      <div className="muted small traffic-chart-note">
        Сумма трафика коннектов каждого узла (↑ + ↓) с последнего сброса счётчиков. Всего по узлам: {formatBytes(sum)}
      </div>
      <div className="traffic-bars" onMouseLeave={() => setHover(null)}>
        {rows.map(({ node, label }, i) => {
          const total = node.up + node.down;
          return (
            <div key={`${label}-${node.id}`} className={`traffic-row ${hover && hover.index !== i ? "dimmed" : ""}`} onMouseMove={move(i)}>
              <div className="traffic-label" title={label}>
                {label}
              </div>
              <div className="traffic-track">
                {total > 0 && <div className="traffic-bar" style={{ width: `${Math.max((total / max) * 100, 0.5)}%` }} />}
              </div>
              <div className="traffic-value">{formatBytes(total)}</div>
            </div>
          );
        })}
        {active && hover && (
          <div className="chart-tooltip" style={{ left: hover.x, top: hover.y }}>
            <div className="strong">{active.label}</div>
            <div>
              Всего: {formatBytes(active.node.up + active.node.down)}
              {sum > 0 && <span className="muted"> · {(((active.node.up + active.node.down) / sum) * 100).toFixed(1)}%</span>}
            </div>
            <div className="muted">
              ↓ {formatBytes(active.node.down)} · ↑ {formatBytes(active.node.up)}
            </div>
            <div className="muted">
              коннектов: {active.node.inbounds}, клиентов: {active.node.clients}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
