import { useEffect, useMemo, useState, type MouseEvent } from "react";
import { api, type TrafficDaily } from "../api";
import { formatBytes } from "../format";

const DAYS = 30;
const REFRESH_MS = 5 * 60_000;

const dayStart = (ts: number) => new Date(ts).setHours(0, 0, 0, 0);
const shortDate = (ts: number) => new Date(ts).toLocaleDateString("ru-RU", { day: "2-digit", month: "2-digit" });
const longDate = (ts: number) => new Date(ts).toLocaleDateString("ru-RU", { day: "numeric", month: "long", weekday: "short" });

interface Day {
  day: number;
  up: number;
  down: number;
  servers: Map<string, number>;
}

/** Traffic of all connects by day (↓ + ↑), from the hourly growth of the panels' counters that the admin records. */
export function TrafficDaysWidget() {
  const [data, setData] = useState<TrafficDaily | null>(null);
  const [error, setError] = useState("");
  const [hover, setHover] = useState<{ index: number; x: number; y: number } | null>(null);

  useEffect(() => {
    const load = () => api.trafficDaily(DAYS).then(setData, (e) => setError((e as Error).message));
    load();
    const timer = setInterval(() => document.visibilityState === "visible" && load(), REFRESH_MS);
    return () => clearInterval(timer);
  }, []);

  const today = dayStart(Date.now());
  const days = useMemo(() => {
    // by calendar date, not by adding 24 hours: a clock change makes a day shorter or longer
    const list: Day[] = Array.from({ length: DAYS }, (_, i) => {
      const day = new Date(today);
      day.setDate(day.getDate() - (DAYS - 1 - i));
      return { day: day.getTime(), up: 0, down: 0, servers: new Map() };
    });
    const byDay = new Map(list.map((d) => [d.day, d]));
    for (const h of data?.hours ?? []) {
      const d = byDay.get(dayStart(h.t * 1000));
      if (!d) continue;
      d.up += h.up;
      d.down += h.down;
      d.servers.set(h.server, (d.servers.get(h.server) ?? 0) + h.up + h.down);
    }
    return list;
  }, [data, today]);

  if (error) return <div className="card error-text small">{error}</div>;
  if (!data) return <div className="card muted small">Загрузка…</div>;

  const total = (d: Day) => d.up + d.down;
  const max = Math.max(...days.map(total), 1);
  const sum = days.reduce((s, d) => s + total(d), 0);
  const started = data.started_at ? dayStart(data.started_at * 1000) : today;
  // whole days only: the one counting began on and today are partial
  const full = days.filter((d) => d.day >= data.started_at * 1000 && d.day < today);

  const move = (index: number) => (e: MouseEvent<HTMLDivElement>) => {
    const box = e.currentTarget.parentElement!.getBoundingClientRect();
    setHover({ index, x: e.clientX - box.left, y: e.clientY - box.top });
  };
  const active = hover && days[hover.index];

  return (
    <div className="card traffic-days">
      <div className="traffic-days-head">
        <div>
          <div className="netload-total">{formatBytes(total(days[DAYS - 1]))}</div>
          <div className="muted small">сегодня, все коннекты: скачивание + отдача</div>
        </div>
        <div className="muted small traffic-days-sum">
          За {DAYS} дней: <span className="strong">{formatBytes(sum)}</span>
          {full.length > 0 && <> · в среднем {formatBytes(full.reduce((s, d) => s + total(d), 0) / full.length)} в день</>}
        </div>
      </div>
      {!data.started_at || sum === 0 ? (
        <div className="muted small">
          Админка считает трафик по счётчикам коннектов раз в {Math.round(data.interval / 60)} минут
          {data.started_at ? ` с ${new Date(data.started_at * 1000).toLocaleString("ru-RU")}` : ""}: первые данные появятся после следующего замера.
        </div>
      ) : (
        <>
          <div className="days-chart" onMouseLeave={() => setHover(null)} role="img" aria-label={`Трафик за ${DAYS} дней: ${formatBytes(sum)}`}>
            {days.map((d, i) => (
              <div key={d.day} className={`days-column ${hover && hover.index !== i ? "dimmed" : ""}`} onMouseMove={move(i)}>
                {total(d) > 0 && <div className="days-bar" style={{ height: `${(total(d) / max) * 100}%` }} />}
              </div>
            ))}
            <div className="days-max muted small">макс. {formatBytes(max)}</div>
            {active && hover && (
              <div className={`chart-tooltip ${hover.index > DAYS * 0.6 ? "days-tooltip-left" : ""}`} style={{ left: hover.x, top: hover.y }}>
                <div className="strong">
                  {longDate(active.day)}: {active.day < started ? "ещё не считался" : formatBytes(total(active))}
                </div>
                {total(active) > 0 && (
                  <>
                    <div className="muted">
                      ↓ {formatBytes(active.down)} · ↑ {formatBytes(active.up)}
                    </div>
                    {[...active.servers]
                      .sort((a, b) => b[1] - a[1])
                      .slice(0, 8)
                      .map(([name, bytes]) => (
                        <div key={name}>
                          {name} <span className="muted">{formatBytes(bytes)}</span>
                        </div>
                      ))}
                  </>
                )}
              </div>
            )}
          </div>
          <div className="days-axis muted small">
            <span>{shortDate(days[0].day)}</span>
            <span>{shortDate(days[Math.floor(DAYS / 2)].day)}</span>
            <span>сегодня</span>
          </div>
          {data.started_at * 1000 > days[0].day && (
            <div className="muted small">Считается с {new Date(data.started_at * 1000).toLocaleString("ru-RU")}: раньше админка трафик по дням не записывала.</div>
          )}
        </>
      )}
    </div>
  );
}
