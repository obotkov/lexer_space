import { useEffect, useMemo, useState, type MouseEvent } from "react";
import { api, type ServerReplacement } from "../api";
import { Empty, StatCard } from "../components/ui";
import { DAY_MS, formatDateTime, plural } from "../format";

const CHART_DAYS = 30;

const dayStart = (ts: number) => new Date(ts).setHours(0, 0, 0, 0);
const shortDate = (ts: number) => new Date(ts).toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit" });
const days = (n: number) => `${n} ${plural(n, "день", "дня", "дней")}`;

/** Whole days the old server worked; null when that is not known. */
const workedDays = (r: ServerReplacement) => (r.started_at ? Math.floor((r.replaced_at - r.started_at) / 86400) : null);

/** Servers created through the admin and deleted later, from what it recorded when each one went. */
export function Replacements() {
  const [items, setItems] = useState<ServerReplacement[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.replacements().then((r) => setItems(r.items), (e) => setError(e.message));
  }, []);

  if (error) return <div className="notice notice-bad">{error}</div>;
  if (!items) return <div className="center muted">Загрузка…</div>;
  if (items.length === 0) {
    return (
      <Empty>
        <p>Замен пока нет.</p>
        <p className="muted small">Здесь появится каждый сервер, созданный через админку и затем удалённый.</p>
      </Empty>
    );
  }
  return <Stats items={items} />;
}

function Stats({ items }: { items: ServerReplacement[] }) {
  const weekAgo = dayStart(Date.now()) - 6 * DAY_MS;
  const lastWeek = items.filter((r) => r.replaced_at * 1000 >= weekAgo).length;
  const known = items.map(workedDays).filter((d): d is number => d !== null);
  const average = known.length ? Math.round(known.reduce((a, b) => a + b, 0) / known.length) : null;

  return (
    <>
      <div className="stats">
        <StatCard label="Всего замен" value={items.length} hint={`с ${new Date(items[items.length - 1].replaced_at * 1000).toLocaleDateString("ru-RU")}`} />
        <StatCard label="За последние 7 дней" value={lastWeek} />
        <StatCard
          label="В среднем проработал"
          value={average === null ? "—" : days(average)}
          hint={known.length < items.length ? `по ${known.length} из ${items.length}: у старых замен срок не сохранился` : undefined}
        />
      </div>

      <div className="overview-widgets">
        <section className="overview-widget">
          <h2 className="section-title">Замены по дням</h2>
          <DaysChart items={items} />
        </section>
        <section className="overview-widget">
          <h2 className="section-title">Замены по хостерам</h2>
          <HostersChart items={items} />
        </section>
      </div>

      <h2 className="section-title">Заменённые серверы</h2>
      <ReplacedServers items={items} />
    </>
  );
}

function DaysChart({ items }: { items: ServerReplacement[] }) {
  const [hover, setHover] = useState<{ index: number; x: number; y: number } | null>(null);
  const today = dayStart(Date.now());
  const bars = useMemo(() => {
    // by calendar date, not by adding 24 hours: a clock change makes a day shorter or longer
    const list = Array.from({ length: CHART_DAYS }, (_, i) => {
      const day = new Date(today);
      day.setDate(day.getDate() - (CHART_DAYS - 1 - i));
      return { day: day.getTime(), servers: [] as ServerReplacement[] };
    });
    const byDay = new Map(list.map((b) => [b.day, b]));
    for (const r of items) byDay.get(dayStart(r.replaced_at * 1000))?.servers.push(r);
    return list;
  }, [items, today]);
  const max = Math.max(...bars.map((b) => b.servers.length), 1);
  const inPeriod = bars.reduce((sum, b) => sum + b.servers.length, 0);

  const move = (index: number) => (e: MouseEvent<HTMLDivElement>) => {
    const box = e.currentTarget.parentElement!.getBoundingClientRect();
    setHover({ index, x: e.clientX - box.left, y: e.clientY - box.top });
  };
  const active = hover && bars[hover.index];

  return (
    <div className="card">
      <div className="muted small">
        За {CHART_DAYS} дней: {inPeriod}
      </div>
      <div className="days-chart" onMouseLeave={() => setHover(null)} role="img" aria-label={`Замены серверов за ${CHART_DAYS} дней: ${inPeriod}`}>
        {bars.map((b, i) => (
          <div key={b.day} className={`days-column ${hover && hover.index !== i ? "dimmed" : ""}`} onMouseMove={move(i)}>
            {b.servers.length > 0 && <div className="days-count">{b.servers.length}</div>}
            {b.servers.length > 0 && <div className="days-bar" style={{ height: `${(b.servers.length / max) * 100}%` }} />}
          </div>
        ))}
        {active && hover && (
          <div className={`chart-tooltip ${hover.index > CHART_DAYS * 0.6 ? "days-tooltip-left" : ""}`} style={{ left: hover.x, top: hover.y }}>
            <div className="strong">
              {shortDate(active.day)}: {active.servers.length} {plural(active.servers.length, "замена", "замены", "замен")}
            </div>
            {active.servers.map((r) => (
              <div key={r.id} className="muted">
                {r.name}
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="days-axis muted small">
        <span>{shortDate(bars[0].day)}</span>
        <span>{shortDate(bars[Math.floor(CHART_DAYS / 2)].day)}</span>
        <span>сегодня</span>
      </div>
    </div>
  );
}

function hostersOf(items: ServerReplacement[]) {
  const groups = new Map<number, { id: number; name: string; provider: string; title: string; rows: ServerReplacement[] }>();
  for (const r of items) {
    const group = groups.get(r.hoster_id) ?? { id: r.hoster_id, name: r.hoster_name, provider: r.provider, title: r.provider_title, rows: [] };
    group.rows.push(r);
    groups.set(r.hoster_id, group);
  }
  return [...groups.values()].sort((a, b) => b.rows.length - a.rows.length);
}

function HostersChart({ items }: { items: ServerReplacement[] }) {
  const groups = hostersOf(items);
  const max = Math.max(...groups.map((g) => g.rows.length));
  return (
    <div className="card traffic-chart">
      <div className="traffic-bars">
        {groups.map((g) => {
          const label = `${g.title} · ${g.name}`;
          return (
            <div key={g.id} className="traffic-row" title={`${label}: ${Math.round((g.rows.length / items.length) * 100)}% замен`}>
              <div className="traffic-label">{label}</div>
              <div className="traffic-track">
                <div className="traffic-bar" style={{ width: `${(g.rows.length / max) * 100}%` }} />
              </div>
              <div className="traffic-value">{g.rows.length}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/** Every IP a server has had, oldest first. */
function ipChains(items: ServerReplacement[]) {
  const chains = new Map<string, string[]>();
  for (const r of [...items].reverse()) {
    const key = `${r.hoster_id}:${r.name}`;
    const chain = chains.get(key) ?? [];
    for (const ip of [r.old_ip, r.new_ip]) if (ip && !chain.includes(ip)) chain.push(ip);
    chains.set(key, chain);
  }
  return chains;
}

function ReplacedServers({ items }: { items: ServerReplacement[] }) {
  const chains = useMemo(() => ipChains(items), [items]);
  return (
    <>
      {hostersOf(items).map((g) => (
        <section key={g.id} className="replaced-group">
          <div className="replaced-head">
            <span className={`provider-badge provider-${g.provider}`}>{g.title}</span>
            <span className="strong">{g.name}</span>
            <span className="muted small">
              {g.rows.length} {plural(g.rows.length, "замена", "замены", "замен")}
            </span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Сервер</th>
                  <th>Удалён</th>
                  <th className="num">Проработал</th>
                  <th>Заведённые IP</th>
                </tr>
              </thead>
              <tbody>
                {g.rows.map((r) => {
                  const worked = workedDays(r);
                  const chain = chains.get(`${r.hoster_id}:${r.name}`) ?? [];
                  return (
                    <tr key={r.id}>
                      <td>
                        <div className="strong">{r.name}</div>
                        {r.region && <div className="muted small">{r.region}</div>}
                      </td>
                      <td className="small">{formatDateTime(r.replaced_at * 1000)}</td>
                      <td className="num">
                        {worked === null ? <span className="muted" title="Сервер заменён до того, как админка начала хранить срок работы">нет данных</span> : worked === 0 ? "меньше дня" : days(worked)}
                      </td>
                      <td className="mono small ip-chain">
                        {chain.length === 0 && "—"}
                        {chain.map((ip, i) => (
                          <span key={ip}>
                            {i > 0 && <span className="muted"> → </span>}
                            <span className={ip === r.old_ip ? "ip-replaced" : "muted"} title={ip === r.old_ip ? "IP удалённого сервера" : undefined}>
                              {ip}
                            </span>
                          </span>
                        ))}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </>
  );
}
