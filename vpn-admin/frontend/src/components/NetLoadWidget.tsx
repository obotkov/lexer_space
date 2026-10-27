import { useCallback, useEffect, useLayoutEffect, useRef, useState, type PointerEvent } from "react";
import { api, type NetLoad } from "../api";

const REFRESH_MS = 5_000;
const HEIGHT = 220;
const PAD = { top: 26, right: 12, bottom: 24, left: 52 };
// eight categorical slots (--series-1…8); a ninth server and beyond fold into "Остальные"
const SLOTS = 8;

type Line = { key: string; label: string; color: string; values: (number | null)[] };

/** bytes/sec -> a readable bit rate */
export function formatRate(bytesPerSec: number): string {
  const bits = bytesPerSec * 8;
  if (bits >= 1e9) return `${(bits / 1e9).toFixed(2)} Гбит/с`;
  if (bits >= 1e6) return `${(bits / 1e6).toFixed(bits >= 1e8 ? 0 : 1)} Мбит/с`;
  return `${Math.round(bits / 1e3)} Кбит/с`;
}

/** Grid step of 1, 2, 2.5 or 5 × 10^n giving about four lines up to the peak, so they land on round Mbit/s */
function niceScale(maxMbit: number): { step: number; max: number } {
  const raw = Math.max(maxMbit, 1) / 4; // at least 1 Mbit/s: idle servers stay flat instead of filling the chart with noise
  const power = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * power).find((v) => v >= raw)!;
  return { step, max: Math.max(step, Math.ceil(maxMbit / step - 1e-9) * step) };
}

function useWidth() {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    const el = ref.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    observer.observe(el);
    setWidth(el.clientWidth);
    return () => observer.disconnect();
  }, []);
  return [ref, width] as const;
}

/** Download + upload speed of every server over the last 5 minutes, one line each. */
export function NetLoadWidget({ multiPanel }: { multiPanel: boolean }) {
  const [data, setData] = useState<NetLoad | null>(null);
  const [error, setError] = useState("");
  const [hover, setHover] = useState<number | null>(null);
  const [ref, width] = useWidth();

  const load = useCallback(async () => {
    try {
      setData(await api.netload());
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(() => document.visibilityState === "visible" && load(), REFRESH_MS);
    return () => clearInterval(timer);
  }, [load]);

  const points = data?.points ?? [];
  // the color follows the server (its place in the list), never its current speed
  const named = (data?.series ?? []).map((s) => ({ ...s, label: s.kind === "node" && multiPanel ? `${s.panel} › ${s.name}` : s.name }));
  const lines: Line[] = named.slice(0, named.length > SLOTS ? SLOTS - 1 : SLOTS).map((s, i) => ({
    key: s.key,
    label: s.label,
    color: `var(--series-${i + 1})`,
    values: points.map((p) => p.values[s.key] ?? null),
  }));
  if (named.length > SLOTS) {
    const rest = named.slice(SLOTS - 1);
    lines.push({
      key: "other",
      label: `Остальные (${rest.length})`,
      color: "var(--series-other)",
      values: points.map((p) => {
        const got = rest.map((s) => p.values[s.key]).filter((v): v is number => v != null);
        return got.length ? got.reduce((a, b) => a + b, 0) : null;
      }),
    });
  }

  const latest = (l: Line) => [...l.values].reverse().find((v) => v != null) ?? null;
  const total = lines.reduce((sum, l) => sum + (latest(l) ?? 0), 0);

  const plotW = Math.max(width - PAD.left - PAD.right, 10);
  const plotH = HEIGHT - PAD.top - PAD.bottom;
  const toMbit = (v: number) => (v * 8) / 1e6;
  const scale = niceScale(Math.max(0, ...lines.flatMap((l) => l.values.map((v) => (v == null ? 0 : toMbit(v))))));
  const yMax = scale.max;
  const now = points.length ? points[points.length - 1].t : 0;
  const windowSec = data?.window ?? 300;
  const x = (t: number) => PAD.left + plotW * (1 - (now - t) / windowSec);
  const y = (v: number) => PAD.top + plotH * (1 - toMbit(v) / yMax);

  const path = (values: (number | null)[]) => {
    let d = "";
    let pen = false;
    values.forEach((v, i) => {
      if (v == null) {
        pen = false; // a server that did not answer leaves a gap, not a drop to zero
        return;
      }
      d += `${pen ? "L" : "M"}${x(points[i].t).toFixed(1)},${y(v).toFixed(1)}`;
      pen = true;
    });
    return d;
  };

  const onMove = (e: PointerEvent<SVGRectElement>) => {
    if (!points.length) return;
    const box = e.currentTarget.getBoundingClientRect();
    const px = e.clientX - box.left + PAD.left;
    let best = 0;
    points.forEach((p, i) => {
      if (Math.abs(x(p.t) - px) < Math.abs(x(points[best].t) - px)) best = i;
    });
    setHover(best);
  };

  const ticks = Array.from({ length: Math.round(yMax / scale.step) + 1 }, (_, i) => i * scale.step);
  const minutes = [5, 4, 3, 2, 1, 0];
  const hoverPoint = hover != null ? points[hover] : null;
  const hoverRows = hoverPoint
    ? lines
        .map((l) => ({ line: l, value: l.values[hover!] }))
        .sort((a, b) => (b.value ?? -1) - (a.value ?? -1))
    : [];
  const tooltipLeft = hoverPoint ? x(hoverPoint.t) : 0;

  return (
    <div className="card netload-card">
      <div className="netload-head">
        <div>
          <div className="netload-total">{formatRate(total)}</div>
          <div className="muted small">
            сейчас по всем серверам: скачивание + отдача. График — последние 5 минут, точка каждые {data?.interval ?? 5} секунд
          </div>
        </div>
      </div>
      {error && <div className="error-text small">{error}</div>}
      {lines.length > 0 && (
        <ul className="netload-legend">
          {lines.map((l) => {
            const v = latest(l);
            return (
              <li key={l.key}>
                <span className="netload-key" style={{ background: l.color }} aria-hidden />
                <span className="netload-name">{l.label}</span>
                <span className="netload-now">{v == null ? "нет данных" : formatRate(v)}</span>
              </li>
            );
          })}
        </ul>
      )}
      <div className="netload-plot" ref={ref}>
        {points.length < 2 ? (
          <div className="muted small netload-empty">{data ? "Собираю данные: первые точки появятся через несколько секунд…" : "Загрузка…"}</div>
        ) : (
          width > 0 && (
            <svg width={width} height={HEIGHT} role="img" aria-label={`Сетевая нагрузка серверов за 5 минут, сейчас всего ${formatRate(total)}`}>
              {ticks.map((t) => (
                <g key={t}>
                  <line className="netload-grid" x1={PAD.left} x2={PAD.left + plotW} y1={PAD.top + plotH * (1 - t / yMax)} y2={PAD.top + plotH * (1 - t / yMax)} />
                  <text className="netload-axis" x={PAD.left - 8} y={PAD.top + plotH * (1 - t / yMax)} textAnchor="end" dominantBaseline="middle">
                    {t === 0 ? "0" : `${+t.toFixed(2)}`}
                  </text>
                </g>
              ))}
              <text className="netload-axis" x={PAD.left - 8} y={10} textAnchor="end">
                Мбит/с
              </text>
              {minutes.map((m) => (
                <text key={m} className="netload-axis" x={x(now - m * 60)} y={HEIGHT - 6} textAnchor={m === 5 ? "start" : m === 0 ? "end" : "middle"}>
                  {m === 0 ? "сейчас" : `−${m} мин`}
                </text>
              ))}
              {lines.map((l) => (
                <path key={l.key} d={path(l.values)} fill="none" stroke={l.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
              ))}
              {hoverPoint && (
                <>
                  <line className="netload-crosshair" x1={x(hoverPoint.t)} x2={x(hoverPoint.t)} y1={PAD.top} y2={PAD.top + plotH} />
                  {lines.map((l) => {
                    const v = l.values[hover!];
                    return v == null ? null : (
                      <circle key={l.key} cx={x(hoverPoint.t)} cy={y(v)} r={4} fill={l.color} className="netload-dot" />
                    );
                  })}
                </>
              )}
              <rect
                x={PAD.left}
                y={PAD.top}
                width={plotW}
                height={plotH}
                fill="transparent"
                onPointerMove={onMove}
                onPointerLeave={() => setHover(null)}
              />
            </svg>
          )
        )}
        {hoverPoint && (
          <div className={`chart-tooltip netload-tooltip ${tooltipLeft > width / 2 ? "netload-tooltip-left" : ""}`} style={{ left: tooltipLeft, top: PAD.top }}>
            <div className="muted">{new Date(hoverPoint.t * 1000).toLocaleTimeString("ru-RU")}</div>
            {hoverRows.map(({ line, value }) => (
              <div key={line.key} className="netload-tip-row">
                <span className="netload-key" style={{ background: line.color }} aria-hidden />
                <span className="strong">{value == null ? "—" : formatRate(value)}</span>
                <span className="muted">{line.label}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
