import { useCallback, useEffect, useState } from "react";
import { api, type ProbeItem, type ProbeResult } from "../api";

const REFRESH_MS = 30_000;
const SPARK_W = 120;
const SPARK_H = 22;

// the delay through an open tunnel: two hops and the test site's answer, so higher than a plain ping
const tone = (ms: number) => (ms < 300 ? "good" : ms < 700 ? "warn" : "bad");

const PROTOCOLS: Record<string, string> = {
  vless: "VLESS", vmess: "VMess", trojan: "Trojan", shadowsocks: "Shadowsocks", hysteria: "Hysteria2",
  mtproto: "MTProto", wireguard: "WireGuard", amneziawg: "AmneziaWG", tuic: "TUIC",
};
const SECURITY: Record<string, string> = { reality: "Reality", tls: "TLS" };

function kindLabel(i: ProbeItem): string {
  const parts = [PROTOCOLS[i.protocol] ?? i.protocol];
  if (i.network && !["tcp", "hysteria", "udp", ""].includes(i.network)) parts.push(i.network.toUpperCase());
  if (i.security && SECURITY[i.security] && i.protocol !== "hysteria") parts.push(SECURITY[i.security]);
  return parts.join(" · ") + (i.port ? ` · ${i.port}` : "");
}

/** Every connect of the main panels, checked through Xray-core with a service client, refreshed while open. */
export function ProbeWidget() {
  const [data, setData] = useState<ProbeResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async (run = false) => {
    if (run) setBusy(true);
    try {
      setData(run ? await api.probeRun() : await api.probe());
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      if (run) setBusy(false);
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(() => document.visibilityState === "visible" && load(), REFRESH_MS);
    return () => clearInterval(timer);
  }, [load]);

  const panels = data?.panels ?? [];
  const checked = panels.flatMap((p) => p.items.filter((i) => i.status === "ok" || i.status === "fail"));
  const working = checked.filter((i) => i.status === "ok").length;
  const running = busy || data?.running;

  return (
    <div className="card probe-card">
      <div className="probe-head">
        <div>
          {checked.length > 0 && (
            <div className={`probe-total ${working < checked.length ? "probe-total-bad" : ""}`}>
              Работают {working} из {checked.length}
            </div>
          )}
          <div className="muted small">
            Через Xray-core с сервера админки служебным клиентом vpn-admin-probe, каждые {Math.round((data?.interval ?? 180) / 60)} мин.
            Задержка — ответ {data ? new URL(data.url).host : "тестового сайта"} через уже открытое соединение.
            {data?.checked_at ? ` Проверено в ${new Date(data.checked_at * 1000).toLocaleTimeString("ru-RU")}.` : ""}
          </div>
        </div>
        <button className="btn btn-small" onClick={() => load(true)} disabled={!!running}>
          {running ? "Проверяю…" : "Проверить сейчас"}
        </button>
      </div>
      {error && <div className="error-text small">{error}</div>}
      {data?.error && <div className="notice notice-warn small">{data.error}</div>}
      {!data && !error && <div className="muted small">Загрузка…</div>}
      {data && !data.error && data.checked_at === 0 && <div className="muted small">Первая проверка начнётся через несколько секунд после запуска админки…</div>}
      {panels.map((p) => (
        <ProbePanelBlock key={p.panel_id} name={p.panel} error={p.error} items={p.items} />
      ))}
    </div>
  );
}

function ProbePanelBlock({ name, error, items }: { name: string; error: string | null; items: ProbeItem[] }) {
  const groups: { server: string; kind: string; ip: string; hoster: ProbeItem["hoster"]; items: ProbeItem[] }[] = [];
  for (const item of items) {
    const last = groups[groups.length - 1];
    if (last && last.server === item.server) {
      last.items.push(item);
      last.ip ||= item.server_ip ?? "";
      last.hoster ||= item.hoster;
    } else groups.push({ server: item.server, kind: item.server_kind, ip: item.server_ip ?? "", hoster: item.hoster, items: [item] });
  }
  return (
    <div className="probe-panel">
      {error && (
        <div className="error-text small">
          {name}: {error}
        </div>
      )}
      {groups.map((g) => {
        const checked = g.items.filter((i) => i.status === "ok" || i.status === "fail");
        const rest = g.items.filter((i) => i.status === "skip" || i.status === "off");
        return (
          <section key={g.server} className="probe-group">
            <div className="probe-group-head">
              {g.kind === "node" && (
                <>
                  <span className="strong">{name}</span>
                  <span className="probe-sep">›</span>
                </>
              )}
              {g.hoster && (
                <>
                  <span className={`provider-badge provider-${g.hoster.provider}`} title={`Хостинг: ${g.hoster.name}`}>
                    {g.hoster.title}
                  </span>
                  <span className="probe-sep">›</span>
                </>
              )}
              <span className="strong">{g.server}</span>
              {g.kind === "main" && <span className="badge badge-main">основной</span>}
              {g.ip && g.ip !== g.server && (
                <>
                  <span className="probe-sep">›</span>
                  <span className="probe-ip">{g.ip}</span>
                </>
              )}
            </div>
            {checked.map((i) => (
              <ProbeRow key={i.key} item={i} />
            ))}
            {rest.length > 0 && (
              <div className="muted small probe-rest">
                {rest.map((i) => `${i.remark} — ${i.status === "off" ? "выключен" : "не проверяется"}`).join(" · ")}
              </div>
            )}
          </section>
        );
      })}
    </div>
  );
}

function ProbeRow({ item: i }: { item: ProbeItem }) {
  const ok = i.status === "ok" && i.ms != null;
  return (
    <div className="probe-row">
      <div className="probe-label">
        <div className="probe-name">
          <span className={`dot ${ok ? "dot-on" : "dot-off"}`} aria-hidden />
          <span className="strong" title={i.remark}>
            {i.remark}
          </span>
        </div>
        <div className="muted small">{kindLabel(i)}</div>
        {!ok && (
          <div className="error-text small probe-error" title={i.detail || i.error}>
            {i.error}
          </div>
        )}
      </div>
      <Sparkline history={i.history} />
      <div className="ping-value">
        {ok ? (
          <>
            <span className={`ping-ms ping-text-${tone(i.ms!)}`}>{i.ms} мс</span>
            {i.connect_ms != null && <div className="muted small">подключение {i.connect_ms} мс</div>}
          </>
        ) : (
          <span className="error-text strong small">не работает</span>
        )}
      </div>
    </div>
  );
}

/** The last hour: a bar per check, its height the delay; a failed check is a full-height bar in the "bad" color. */
function Sparkline({ history }: { history: ProbeItem["history"] }) {
  if (history.length === 0) return <div />;
  const scale = Math.max(300, ...history.map((h) => h.ms ?? 0));
  const slots = Math.max(history.length, 20);
  const step = SPARK_W / slots;
  const offset = (slots - history.length) * step; // the newest check sits at the right edge
  const failed = history.filter((h) => h.ms == null).length;
  return (
    <svg className="probe-spark" width={SPARK_W} height={SPARK_H} role="img" aria-label={`За час: ${history.length} проверок, неудачных ${failed}`}>
      {history.map((h, n) => {
        const height = h.ms == null ? SPARK_H : Math.max(2, (h.ms / scale) * SPARK_H);
        const time = new Date(h.t * 1000).toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit" });
        return (
          <rect
            key={h.t}
            className={h.ms == null ? "probe-spark-fail" : "probe-spark-ok"}
            x={offset + n * step + 0.5}
            y={SPARK_H - height}
            width={Math.max(step - 1.5, 1.5)}
            height={height}
            rx={1}
          >
            <title>{`${time} — ${h.ms == null ? "не работал" : `${h.ms} мс`}`}</title>
          </rect>
        );
      })}
    </svg>
  );
}
