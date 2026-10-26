import { useEffect, useState, type FormEvent } from "react";
import { api, refOf, type Client, type ClientChanges, type OpResult } from "../api";
import { bytesToGb, DAY_MS, dateInputToMs, formatBytes, formatExpiry, formatLimit, gbToBytes, msToDateInput, plural } from "../format";
import { CopyButton, StatusBadge } from "./ui";

type ExpiryMode = "keep" | "never" | "date" | "delayed";

interface FormState {
  limitGb: string;
  expiryMode: ExpiryMode;
  expiryDate: string;
  delayedDays: string;
  limitIp: string;
  comment: string;
  tgId: string;
}

function initialState(clients: Client[]): FormState {
  if (clients.length !== 1) {
    return { limitGb: "", expiryMode: "keep", expiryDate: msToDateInput(Date.now() + 30 * DAY_MS), delayedDays: "30", limitIp: "", comment: "", tgId: "" };
  }
  const c = clients[0];
  return {
    limitGb: bytesToGb(c.total),
    expiryMode: c.expiry_time === 0 ? "never" : c.expiry_time < 0 ? "delayed" : "date",
    expiryDate: msToDateInput(c.expiry_time > 0 ? c.expiry_time : Date.now() + 30 * DAY_MS),
    delayedDays: c.expiry_time < 0 ? String(Math.round(-c.expiry_time / DAY_MS)) : "30",
    limitIp: String(c.limit_ip),
    comment: c.comment,
    tgId: c.tg_id ? String(c.tg_id) : "",
  };
}

/** Builds the change set: only fields the admin actually touched. Throws on invalid input. */
function buildChanges(initial: FormState, form: FormState, bulk: boolean): ClientChanges {
  const changes: ClientChanges = {};
  if (form.limitGb.trim() !== "" && form.limitGb !== initial.limitGb) {
    const total = gbToBytes(form.limitGb);
    if (Number.isNaN(total)) throw new Error("Лимит трафика должен быть числом");
    changes.total = total;
  }
  const expiryChanged =
    form.expiryMode !== initial.expiryMode ||
    (form.expiryMode === "date" && form.expiryDate !== initial.expiryDate) ||
    (form.expiryMode === "delayed" && form.delayedDays !== initial.delayedDays);
  if (form.expiryMode !== "keep" && expiryChanged) {
    if (form.expiryMode === "never") changes.expiry_time = 0;
    if (form.expiryMode === "date") {
      if (!form.expiryDate) throw new Error("Укажите дату окончания");
      changes.expiry_time = dateInputToMs(form.expiryDate);
    }
    if (form.expiryMode === "delayed") {
      const days = parseInt(form.delayedDays, 10);
      if (!(days > 0)) throw new Error("Укажите число дней больше нуля");
      changes.expiry_time = -days * DAY_MS;
    }
  }
  if (form.limitIp.trim() !== "" && form.limitIp !== initial.limitIp) {
    const limit = parseInt(form.limitIp, 10);
    if (!(limit >= 0)) throw new Error("Лимит IP должен быть целым числом");
    changes.limit_ip = limit;
  }
  // in bulk mode an empty text field means "don't change"; for one client clearing it is a change
  if (form.comment !== initial.comment && (!bulk || form.comment !== "")) changes.comment = form.comment;
  if (form.tgId !== initial.tgId && (!bulk || form.tgId !== "")) changes.tg_id = form.tgId.trim();
  return changes;
}

export function ClientDialog({ clients, title, onClose, onChanged }: { clients: Client[]; title?: string; onClose: () => void; onChanged: () => void }) {
  const single = clients.length === 1 ? clients[0] : null;
  const refs = clients.map(refOf);
  const [initial, setInitial] = useState(() => initialState(clients));
  const [form, setForm] = useState(initial);

  // after an action (or someone else's edit) the client's values change: show the fresh ones
  useEffect(() => {
    if (!single) return;
    const fresh = initialState([single]);
    setInitial(fresh);
    setForm(fresh);
  }, [single?.total, single?.expiry_time, single?.limit_ip, single?.comment, single?.tg_id]);
  const [extendDays, setExtendDays] = useState("30");
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<{ action: string; items: OpResult[] } | null>(null);
  const [error, setError] = useState("");

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) => setForm((f) => ({ ...f, [key]: value }));

  const run = async (action: string, call: () => Promise<{ results: OpResult[] }>, closeOnSuccess = false) => {
    setBusy(true);
    setError("");
    setResults(null);
    try {
      const { results } = await call();
      onChanged();
      if (closeOnSuccess && results.every((r) => r.ok)) return onClose();
      setResults({ action, items: results });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const count = `${clients.length} ${plural(clients.length, "клиента", "клиентов", "клиентов")}`;

  const extend = () => {
    const days = parseInt(extendDays, 10);
    if (!(days > 0)) return setError("Укажите число дней больше нуля");
    run(`Продление на ${days} дн.`, () => api.extendClients(refs, days));
  };
  const reset = () => {
    if (!confirm(`Обнулить счётчик трафика у ${single ? single.email : count}?`)) return;
    run("Сброс трафика", () => api.resetTraffic(refs));
  };
  const setEnable = (enable: boolean) => run(enable ? "Включение" : "Отключение", () => api.updateClients(refs, { enable }));
  const remove = () => {
    if (!confirm(`Удалить ${single ? `клиента ${single.email}` : count} из 3x-ui? Это необратимо.`)) return;
    run("Удаление", () => api.deleteClients(refs), true);
  };
  const save = (e: FormEvent) => {
    e.preventDefault();
    let changes: ClientChanges;
    try {
      changes = buildChanges(initial, form, !single);
    } catch (err) {
      return setError((err as Error).message);
    }
    if (Object.keys(changes).length === 0) return setError("Нет изменений");
    run("Сохранение", () => api.updateClients(refs, changes));
  };

  const failed = results?.items.filter((r) => !r.ok) ?? [];
  const notes = results?.items.filter((r) => r.ok && r.note) ?? [];

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <form className="modal modal-wide" onSubmit={save}>
        <div className="modal-head">
          <h2>{title ?? (single ? single.email : `Изменить ${count}`)}</h2>
          <button type="button" className="btn btn-small" onClick={onClose} disabled={busy}>
            ✕
          </button>
        </div>

        {single ? (
          <div className="client-summary">
            <StatusBadge status={single.status} />
            <span className="muted">
              {single.panel_name} · {single.inbound_remark} · {single.protocol}
            </span>
            <span>
              Трафик: {formatBytes(single.up + single.down)} / {formatLimit(single.total)}
            </span>
            <span>Срок: {formatExpiry(single.expiry_time)}</span>
            {single.sub_url && <CopyButton text={single.sub_url} label="Ссылка подписки" />}
          </div>
        ) : (
          <div className="muted small">
            {clients.slice(0, 8).map((c) => c.email).join(", ")}
            {clients.length > 8 && ` и ещё ${clients.length - 8}`}
          </div>
        )}

        <section className="modal-section">
          <h3>Действия</h3>
          <div className="action-row">
            <span>Продлить на</span>
            <input className="input input-num" type="number" min={1} value={extendDays} onChange={(e) => setExtendDays(e.target.value)} />
            <span>дн.</span>
            {[30, 90, 365].map((d) => (
              <button key={d} type="button" className="btn btn-small" onClick={() => setExtendDays(String(d))}>
                {d}
              </button>
            ))}
            <button type="button" className="btn btn-primary" onClick={extend} disabled={busy}>
              Продлить
            </button>
          </div>
          <div className="muted small">От текущей даты окончания, а если срок уже истёк — от сегодня. Бессрочных клиентов продление не затрагивает.</div>
          <div className="action-row">
            <button type="button" className="btn" onClick={reset} disabled={busy}>
              Сбросить трафик
            </button>
            {(!single || !single.enable) && (
              <button type="button" className="btn" onClick={() => setEnable(true)} disabled={busy}>
                Включить
              </button>
            )}
            {(!single || single.enable) && (
              <button type="button" className="btn" onClick={() => setEnable(false)} disabled={busy}>
                Выключить
              </button>
            )}
            <span className="spacer" />
            <button type="button" className="btn btn-danger" onClick={remove} disabled={busy}>
              Удалить
            </button>
          </div>
        </section>

        <section className="modal-section">
          <h3>Параметры</h3>
          {!single && <div className="muted small">Пустые поля не меняются.</div>}
          <div className="field-row">
            <label className="field">
              <span>Лимит трафика, ГБ (0 — без лимита)</span>
              <input className="input" type="number" min={0} step="any" value={form.limitGb} placeholder="не менять" onChange={(e) => set("limitGb", e.target.value)} />
            </label>
            <label className="field">
              <span>Лимит IP (0 — без лимита)</span>
              <input className="input" type="number" min={0} value={form.limitIp} placeholder="не менять" onChange={(e) => set("limitIp", e.target.value)} />
            </label>
          </div>
          <div className="field">
            <span>Срок действия</span>
            <div className="action-row">
              <select className="input" value={form.expiryMode} onChange={(e) => set("expiryMode", e.target.value as ExpiryMode)}>
                {!single && <option value="keep">Не менять</option>}
                <option value="never">Бессрочно</option>
                <option value="date">До даты</option>
                <option value="delayed">N дней с первого подключения</option>
              </select>
              {form.expiryMode === "date" && <input className="input" type="date" value={form.expiryDate} onChange={(e) => set("expiryDate", e.target.value)} />}
              {form.expiryMode === "delayed" && (
                <>
                  <input className="input input-num" type="number" min={1} value={form.delayedDays} onChange={(e) => set("delayedDays", e.target.value)} />
                  <span>дн.</span>
                </>
              )}
            </div>
          </div>
          <div className="field-row">
            <label className="field">
              <span>Комментарий</span>
              <input className="input" value={form.comment} placeholder={single ? "" : "не менять"} onChange={(e) => set("comment", e.target.value)} />
            </label>
            <label className="field">
              <span>Telegram ID</span>
              <input className="input" value={form.tgId} placeholder={single ? "" : "не менять"} onChange={(e) => set("tgId", e.target.value)} />
            </label>
          </div>
          <div className="action-row">
            <span className="spacer" />
            <button type="submit" className="btn btn-primary" disabled={busy}>
              Сохранить
            </button>
          </div>
        </section>

        {busy && <div className="muted">Выполняется…</div>}
        {error && <div className="notice notice-bad">{error}</div>}
        {results && <ResultsNotice action={results.action} total={results.items.length} failed={failed} notes={notes} />}
      </form>
    </div>
  );
}

export function ResultsNotice({ action, total, failed, notes }: { action: string; total: number; failed: OpResult[]; notes: OpResult[] }) {
  return (
    <div className={`notice ${failed.length ? "notice-bad" : "notice-ok"}`}>
      <div>
        {action}: успешно {total - failed.length} из {total}
      </div>
      {notes.map((r) => (
        <div key={`n-${r.panel_id}-${r.inbound_id}-${r.email}`} className="small muted">
          {r.email}: {r.note}
        </div>
      ))}
      {failed.map((r) => (
        <div key={`f-${r.panel_id}-${r.inbound_id}-${r.email}`} className="small">
          {r.email}: {r.error}
        </div>
      ))}
    </div>
  );
}
