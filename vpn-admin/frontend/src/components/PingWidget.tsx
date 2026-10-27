import { useCallback, useEffect, useState } from "react";
import { api, type PingResult, type PingTarget } from "../api";

const REFRESH_MS = 30_000;

const tone = (ms: number) => (ms < 80 ? "good" : ms < 200 ? "warn" : "bad");

/** Ping from the admin's own server to each main panel and its nodes, refreshed while the page is open. */
export function PingWidget({ multiPanel }: { multiPanel: boolean }) {
  const [data, setData] = useState<PingResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async (refresh = false) => {
    setBusy(true);
    try {
      setData(await api.ping(refresh));
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(() => document.visibilityState === "visible" && load(), REFRESH_MS);
    return () => clearInterval(timer);
  }, [load]);

  const targets = data?.targets ?? [];
  // the bar scale: the slowest answer, at least 100 ms so a few ms do not look like a lot
  const scale = Math.max(100, ...targets.map((t) => t.max_ms ?? 0));
  const tcp = targets.some((t) => t.method === "tcp");

  return (
    <div className="card ping-card">
      <div className="ping-head">
        <div className="muted small">
          С сервера админки, {tcp ? "ICMP или время TCP-подключения к порту панели" : "ICMP"}, 4 запроса; обновляется каждые 30 секунд.
          {data && ` Проверено в ${new Date(data.checked_at * 1000).toLocaleTimeString("ru-RU")}.`}
        </div>
        <button className="btn btn-small" onClick={() => load(true)} disabled={busy}>
          {busy ? "Пингую…" : "Обновить"}
        </button>
      </div>
      {error && <div className="error-text small">{error}</div>}
      {!data && !error && <div className="muted small">Пингую серверы…</div>}
      {data && targets.length === 0 && <div className="muted small">Нет серверов с адресом для проверки.</div>}
      <div className="ping-rows">
        {targets.map((t, i) => (
          <PingRow key={`${t.panel}-${t.kind}-${t.name}-${i}`} target={t} scale={scale} multiPanel={multiPanel} />
        ))}
      </div>
    </div>
  );
}

function PingRow({ target: t, scale, multiPanel }: { target: PingTarget; scale: number; multiPanel: boolean }) {
  const label = t.kind === "node" && multiPanel ? `${t.panel} › ${t.name}` : t.name;
  return (
    <div className={`ping-row ${t.enable ? "" : "row-muted"}`}>
      <div className="ping-label">
        <div className="ping-name" title={label}>
          <span className="strong">{label}</span>{" "}
          <span className={`badge ${t.kind === "main" ? "badge-main" : "badge-node"}`}>{t.kind === "main" ? "основной" : "узел"}</span>
        </div>
        <div className="muted small mono ping-host" title={t.ip && t.ip !== t.host ? `${t.host} → ${t.ip}` : t.host}>
          {t.host}
        </div>
      </div>
      <div className="ping-track" title={t.min_ms != null ? `мин ${t.min_ms} · макс ${t.max_ms} мс` : ""}>
        {t.avg_ms != null && (
          <>
            <div className="ping-range" style={{ left: `${(t.min_ms! / scale) * 100}%`, width: `${Math.max(((t.max_ms! - t.min_ms!) / scale) * 100, 0.5)}%` }} />
            <div className={`ping-bar ping-${tone(t.avg_ms)}`} style={{ width: `${Math.max((t.avg_ms / scale) * 100, 1)}%` }} />
          </>
        )}
      </div>
      <div className="ping-value">
        {t.avg_ms != null ? (
          <>
            <span className={`ping-ms ping-text-${tone(t.avg_ms)}`}>{t.avg_ms} мс</span>
            <div className="muted small">
              {[
                t.loss ? `потери ${t.loss}%` : "",
                t.method === "tcp" ? "TCP" : "",
                t.panel_ms != null ? `от основной ${t.panel_ms} мс` : "",
              ]
                .filter(Boolean)
                .join(" · ")}
            </div>
          </>
        ) : (
          <span className="error-text small">{t.error || "нет ответа"}</span>
        )}
      </div>
    </div>
  );
}
