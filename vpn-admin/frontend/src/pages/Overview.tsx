import type { Overview as OverviewData } from "../api";
import { Empty, StatCard } from "../components/ui";
import { formatBytes, formatUptime } from "../format";

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

  return (
    <>
      <div className="stats">
        <StatCard label="Пользователей" value={t.users} hint={`${t.clients} клиентов во всех узлах`} />
        <StatCard label="Активных" value={t.users_active} tone="good" hint={`онлайн сейчас: ${t.users_online}`} />
        <StatCard label="Истекших / отключённых" value={`${t.users_expired} / ${t.users_disabled}`} tone={t.users_expired ? "warn" : undefined} />
        <StatCard label="Подписок" value={t.subscriptions} />
        <StatCard label="Узлов" value={t.nodes} hint={`включено: ${t.nodes_enabled}`} />
        <StatCard
          label="Серверов"
          value={`${t.panels_ok} / ${t.panels}`}
          tone={t.panels_ok < t.panels ? "bad" : "good"}
          hint={t.panels_ok < t.panels ? "есть недоступные" : "все на связи"}
        />
        <StatCard label="Трафик всего" value={formatBytes(t.traffic_up + t.traffic_down)} hint={`↑ ${formatBytes(t.traffic_up)} · ↓ ${formatBytes(t.traffic_down)}`} />
      </div>

      <h2 className="section-title">Серверы</h2>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Сервер</th>
              <th>Состояние</th>
              <th>Xray</th>
              <th>CPU</th>
              <th>RAM</th>
              <th>Аптайм</th>
              <th className="num">Узлов</th>
              <th className="num">Клиентов</th>
              <th className="num">Онлайн</th>
            </tr>
          </thead>
          <tbody>
            {data.panels.map((p) => (
              <tr key={p.id}>
                <td>
                  <div className="strong">{p.name}</div>
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
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {topUsers.length > 0 && (
        <>
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
                    <td>{s.emails.join(", ")}</td>
                    <td className="num">{formatBytes(s.up + s.down)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}
