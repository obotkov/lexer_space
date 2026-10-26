import { useState, type FormEvent } from "react";
import { api, SUPPORTED_PROTOCOLS, type Node, type OpResult, type PanelInfo } from "../api";
import { DAY_MS, gbToBytes } from "../format";
import { ResultsNotice } from "./ClientDialog";

const nodeKey = (n: Node) => `${n.panel_id}:${n.id}`;

export function CreateClientDialog({
  nodes,
  panels,
  preselected = [],
  onClose,
  onChanged,
}: {
  nodes: Node[];
  panels: PanelInfo[];
  preselected?: Node[];
  onClose: () => void;
  onChanged: () => void;
}) {
  const available = nodes.filter((n) => SUPPORTED_PROTOCOLS.includes(n.protocol));
  const [selected, setSelected] = useState<Set<string>>(() => new Set((preselected.length ? preselected : available.length === 1 ? available : []).map(nodeKey)));
  const [email, setEmail] = useState("");
  const [subId, setSubId] = useState("");
  const [limitGb, setLimitGb] = useState("0");
  const [days, setDays] = useState("30");
  const [delayed, setDelayed] = useState(false);
  const [limitIp, setLimitIp] = useState("0");
  const [comment, setComment] = useState("");
  const [tgId, setTgId] = useState("");
  const [enable, setEnable] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [failed, setFailed] = useState<OpResult[] | null>(null);
  const [total, setTotal] = useState(0);

  const toggle = (key: string) =>
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");
    const targets = available.filter((n) => selected.has(nodeKey(n))).map((n) => ({ panel_id: n.panel_id, inbound_id: n.id }));
    if (!targets.length) return setError("Выберите хотя бы один коннект");
    const totalBytes = gbToBytes(limitGb || "0");
    const dayCount = parseInt(days || "0", 10);
    if (Number.isNaN(totalBytes) || !(dayCount >= 0)) return setError("Проверьте лимит трафика и срок");
    const expiry = dayCount === 0 ? 0 : delayed ? -dayCount * DAY_MS : Date.now() + dayCount * DAY_MS;

    setBusy(true);
    try {
      const res = await api.createClients({
        targets,
        email: email.trim(),
        sub_id: subId.trim(),
        enable,
        total: totalBytes,
        expiry_time: expiry,
        limit_ip: parseInt(limitIp || "0", 10) || 0,
        comment,
        tg_id: tgId.trim(),
      });
      onChanged();
      const bad = res.results.filter((r) => !r.ok);
      if (!bad.length) return onClose();
      setTotal(res.results.length);
      setFailed(bad);
      setSubId(res.sub_id);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const multiPanel = panels.length > 1;

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <form className="modal modal-wide" onSubmit={submit}>
        <div className="modal-head">
          <h2>Новый клиент</h2>
          <button type="button" className="btn btn-small" onClick={onClose} disabled={busy}>
            ✕
          </button>
        </div>

        <label className="field">
          <span>Email / имя</span>
          <input className="input" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} placeholder="ivan" />
          <small className="muted">
            В 3x-ui v3 создаётся один клиент на все выбранные коннекты сервера. В 3x-ui 2.x email должен быть уникальным на весь сервер, поэтому на втором и следующих коннектах к
            имени добавится -2, -3 и т. д.
          </small>
        </label>

        <div className="field">
          <span>Коннекты</span>
          {available.length === 0 ? (
            <div className="muted">Нет коннектов с поддерживаемыми протоколами (VLESS, VMess, Trojan, Shadowsocks)</div>
          ) : (
            <div className="node-picker">
              {available.map((n) => (
                <label key={nodeKey(n)} className={`checkbox node-option ${n.enable ? "" : "row-muted"}`}>
                  <input type="checkbox" checked={selected.has(nodeKey(n))} onChange={() => toggle(nodeKey(n))} />
                  <span>
                    {multiPanel && <span className="muted">{n.panel_name} · </span>}
                    {n.remark || `#${n.id}`} <span className="tag">{n.protocol}</span>
                    <span className="muted small">:{n.port}</span>
                    {!n.enable && <span className="muted small"> (выключен)</span>}
                  </span>
                </label>
              ))}
            </div>
          )}
        </div>

        <div className="field-row">
          <label className="field">
            <span>Лимит трафика, ГБ (0 — без лимита)</span>
            <input className="input" type="number" min={0} step="any" value={limitGb} onChange={(e) => setLimitGb(e.target.value)} />
          </label>
          <label className="field">
            <span>Срок, дней (0 — бессрочно)</span>
            <input className="input" type="number" min={0} value={days} onChange={(e) => setDays(e.target.value)} />
          </label>
          <label className="field">
            <span>Лимит IP (0 — без лимита)</span>
            <input className="input" type="number" min={0} value={limitIp} onChange={(e) => setLimitIp(e.target.value)} />
          </label>
        </div>
        <label className="checkbox">
          <input type="checkbox" checked={delayed} onChange={(e) => setDelayed(e.target.checked)} />
          Отсчитывать срок с первого подключения
        </label>

        <label className="field">
          <span>Подписка (subId)</span>
          <input className="input mono" value={subId} onChange={(e) => setSubId(e.target.value)} placeholder="пусто — создать новую" />
          <small className="muted">Укажите существующий subId, чтобы добавить клиента в уже выданную подписку.</small>
        </label>
        <div className="field-row">
          <label className="field">
            <span>Комментарий</span>
            <input className="input" value={comment} onChange={(e) => setComment(e.target.value)} />
          </label>
          <label className="field">
            <span>Telegram ID</span>
            <input className="input" value={tgId} onChange={(e) => setTgId(e.target.value)} />
          </label>
        </div>
        <label className="checkbox">
          <input type="checkbox" checked={enable} onChange={(e) => setEnable(e.target.checked)} />
          Включён
        </label>

        {error && <div className="notice notice-bad">{error}</div>}
        {failed && (
          <>
            <ResultsNotice action="Создание" total={total} failed={failed} notes={[]} />
            <div className="muted small">
              Успешно созданные клиенты уже в 3x-ui, подписка <span className="mono">{subId}</span>. Можно исправить ошибки и создать клиента на оставшихся коннектах с этим же subId.
            </div>
          </>
        )}

        <div className="modal-actions">
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
            Отмена
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? "Создание…" : "Создать"}
          </button>
        </div>
      </form>
    </div>
  );
}
