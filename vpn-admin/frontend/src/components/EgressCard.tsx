import { useEffect, useState } from "react";
import { api, type EgressCheck, type EgressRoute } from "../api";

const value = (r: { panel_id: number; inbound_id: number }) => `${r.panel_id}:${r.inbound_id}`;

/** Requests to Cloudflare and NetGrid through one of the connects, for a server that cannot reach them directly. */
export function EgressCard() {
  const [route, setRoute] = useState<EgressRoute | null>(null);
  const [checks, setChecks] = useState<EgressCheck[] | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    api.egress().then(setRoute, (e) => setError(e.message));
  }, []);

  const check = async () => {
    setBusy("check");
    setError("");
    setChecks(null);
    try {
      setChecks((await api.checkEgress()).results);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  };

  const choose = async (key: string) => {
    const [panelId, inboundId] = key ? key.split(":").map(Number) : [0, 0];
    setBusy("save");
    setError("");
    setChecks(null);
    try {
      setRoute(await api.setEgress(panelId, inboundId));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  };

  const selected = route?.selected ? value(route.selected) : "";
  const known = route?.options.some((o) => value(o) === selected);

  return (
    <div className="card">
      <div className="card-head">
        <div className="strong">Исходящий маршрут</div>
        {route && <span className={`badge ${route.running ? "badge-active" : route.selected ? "badge-expired" : "badge-disabled"}`}>{route.running ? "Работает" : route.selected ? "Не работает" : "Напрямую"}</span>}
      </div>
      <div className="muted small">
        Запросы к Cloudflare и NetGrid через выбранный коннект. Нужно, если сервер админки не достаёт их напрямую. Остальные запросы идут как обычно. Выбирайте коннект на сервере за пределами сети с блокировкой.
      </div>
      {route && (
        <label className="field">
          <span>Коннект</span>
          <select className="input" value={selected} disabled={!!busy} onChange={(e) => choose(e.target.value)}>
            <option value="">Напрямую, без маршрута</option>
            {selected && !known && <option value={selected}>{route.remark || "Выбранный коннект"}</option>}
            {route.options.map((o) => (
              <option key={value(o)} value={value(o)}>
                {o.server} › {o.remark} · {o.status === "ok" ? `${o.ms} мс` : "ошибка проверки"}
              </option>
            ))}
          </select>
        </label>
      )}
      {route?.error && <div className="error-text small">{route.error}</div>}
      {route && route.options.length === 0 && <div className="muted small">Коннектов пока нет: они появятся после проверки коннектов на обзоре.</div>}
      {checks?.map((c) => (
        <div key={c.name} className="small">
          <span className={c.ok ? "" : "error-text"}>
            {c.name}: {c.ok ? `отвечает, HTTP ${c.status}, ${c.ms} мс` : c.error}
          </span>
        </div>
      ))}
      <div className="card-actions">
        <button className="btn" onClick={check} disabled={!!busy}>
          {busy === "check" ? "Проверяю…" : "Проверить доступ"}
        </button>
      </div>
      {error && <div className="error-text small">{error}</div>}
    </div>
  );
}
