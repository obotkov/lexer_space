import { useState, type FormEvent } from "react";
import { api, type NodeForm, type NodeHeartbeat, type NodesPanel, type XNode } from "../api";
import { formatUptime } from "../format";

const EMPTY: NodeForm = {
  name: "",
  remark: "",
  scheme: "https",
  address: "",
  port: 2053,
  base_path: "/",
  enable: true,
  allow_private_address: false,
  tls_verify_mode: "verify",
  pinned_cert_sha256: "",
  api_token: "",
  inbound_sync_mode: "all",
  inbound_tags: [],
};

const fromNode = (n: XNode): NodeForm => ({
  name: n.name,
  remark: n.remark,
  scheme: n.scheme,
  address: n.address,
  port: n.port,
  base_path: n.base_path || "/",
  enable: n.enable,
  allow_private_address: n.allow_private_address,
  tls_verify_mode: n.tls_verify_mode,
  pinned_cert_sha256: n.pinned_cert_sha256,
  api_token: "",
  inbound_sync_mode: n.inbound_sync_mode,
  inbound_tags: n.inbound_tags,
});

/** Add or edit a node of a main 3x-ui v3 panel: same fields as the 3x-ui "Add node" form. */
export function NodeDialog({
  mainPanels,
  panelId: initialPanelId,
  node,
  onClose,
  onSaved,
}: {
  mainPanels: NodesPanel[];
  panelId: number;
  node: XNode | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [panelId, setPanelId] = useState(initialPanelId);
  const [form, setForm] = useState<NodeForm>(node ? fromNode(node) : EMPTY);
  const [showToken, setShowToken] = useState(false);
  const [test, setTest] = useState<NodeHeartbeat | null>(null);
  const [inboundOptions, setInboundOptions] = useState<{ tag: string; remark: string; protocol: string; port: number }[] | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  const set = <K extends keyof NodeForm>(key: K, value: NodeForm[K]) => {
    setForm((f) => ({ ...f, [key]: value }));
    setTest(null);
  };

  const run = async (label: string, action: () => Promise<void>) => {
    setBusy(label);
    setError("");
    try {
      await action();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  };

  const runTest = () => run("Проверяю соединение…", async () => setTest(await api.testNode(panelId, form, node?.id)));

  const loadInbounds = () => run("Загружаю коннекты узла…", async () => setInboundOptions(await api.nodeInboundOptions(panelId, form, node?.id)));

  const toggleTag = (tag: string) =>
    set("inbound_tags", form.inbound_tags.includes(tag) ? form.inbound_tags.filter((t) => t !== tag) : [...form.inbound_tags, tag]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    run(node ? "Сохраняю…" : "Подключаю узел: главная панель проверяет связь…", async () => {
      if (node) await api.updateNode(panelId, node.id, form);
      else await api.addNode(panelId, form);
      onSaved();
    });
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <form className="modal modal-wide" onSubmit={submit}>
        <div className="modal-head">
          <h2>{node ? `Узел «${node.name}»` : "Добавить узел"}</h2>
          <button type="button" className="btn btn-small" onClick={onClose} disabled={!!busy}>
            ✕
          </button>
        </div>

        {!node && mainPanels.length > 1 && (
          <label className="field">
            <span>Главная панель</span>
            <select className="input" value={panelId} onChange={(e) => setPanelId(Number(e.target.value))}>
              {mainPanels.map((p) => (
                <option key={p.panel_id} value={p.panel_id}>
                  {p.panel_name}
                </option>
              ))}
            </select>
          </label>
        )}

        <div className="field-row">
          <label className="field">
            <span>Имя</span>
            <input className="input" required value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="напр. de-frankfurt-1" />
          </label>
          <label className="field">
            <span>Примечание</span>
            <input className="input" value={form.remark} onChange={(e) => set("remark", e.target.value)} />
          </label>
        </div>

        <div className="field-row">
          <label className="field field-narrow">
            <span>Схема</span>
            <select className="input" value={form.scheme} onChange={(e) => set("scheme", e.target.value as NodeForm["scheme"])}>
              <option value="https">https</option>
              <option value="http">http</option>
            </select>
          </label>
          <label className="field">
            <span>Адрес</span>
            <input className="input" required value={form.address} onChange={(e) => set("address", e.target.value)} placeholder="panel.example.com или 1.2.3.4" />
          </label>
          <label className="field field-narrow">
            <span>Порт</span>
            <input className="input" type="number" min={1} max={65535} required value={form.port} onChange={(e) => set("port", Number(e.target.value))} />
          </label>
        </div>

        <div className="field-row">
          <label className="field">
            <span>Базовый путь (webBasePath узла)</span>
            <input className="input" value={form.base_path} onChange={(e) => set("base_path", e.target.value)} placeholder="/" />
          </label>
          <label className="field field-narrow">
            <span>Включён</span>
            <Switch checked={form.enable} onChange={(v) => set("enable", v)} />
          </label>
        </div>

        <label className="field">
          <span>API-токен узла</span>
          <div className="input-with-button">
            <input
              className="input mono"
              type={showToken ? "text" : "password"}
              required={!node}
              value={form.api_token}
              onChange={(e) => set("api_token", e.target.value)}
              placeholder={node?.has_api_token ? "не менять" : "Токен со страницы настроек удалённой панели"}
              autoComplete="off"
            />
            <button type="button" className="btn btn-small" onClick={() => setShowToken((v) => !v)}>
              {showToken ? "Скрыть" : "Показать"}
            </button>
          </div>
          <small className="muted">В 3x-ui на самом узле: Настройки → Безопасность → API Token.</small>
        </label>

        <div className="field-row">
          <label className="field">
            <span>Проверка TLS</span>
            <select className="input" value={form.tls_verify_mode} onChange={(e) => set("tls_verify_mode", e.target.value as NodeForm["tls_verify_mode"])}>
              <option value="verify">Проверять (стандартный CA)</option>
              <option value="pin">Закрепить сертификат (SHA-256)</option>
              <option value="skip">Не проверять (самоподписанный)</option>
            </select>
          </label>
          <label className="field field-narrow">
            <span>Частный адрес</span>
            <Switch checked={form.allow_private_address} onChange={(v) => set("allow_private_address", v)} />
          </label>
        </div>
        {form.tls_verify_mode === "pin" && (
          <label className="field">
            <span>SHA-256 сертификата узла</span>
            <input className="input mono" required value={form.pinned_cert_sha256} onChange={(e) => set("pinned_cert_sha256", e.target.value)} placeholder="AB:CD:…" />
          </label>
        )}
        <small className="muted">«Частный адрес» разрешает 10.x, 192.168.x и т. п.: нужно, если узел в одной сети с главной панелью.</small>

        <div className="field">
          <span>Импорт коннектов</span>
          <select className="input" value={form.inbound_sync_mode} onChange={(e) => set("inbound_sync_mode", e.target.value as NodeForm["inbound_sync_mode"])}>
            <option value="all">Все коннекты узла</option>
            <option value="selected">Только выбранные</option>
          </select>
          {form.inbound_sync_mode === "selected" && (
            <div className="node-picker">
              {inboundOptions === null ? (
                <button type="button" className="btn btn-small" onClick={loadInbounds} disabled={!!busy || !form.address}>
                  Загрузить список коннектов узла
                </button>
              ) : inboundOptions.length === 0 ? (
                <span className="muted small">На узле нет коннектов</span>
              ) : (
                inboundOptions.map((o) => (
                  <label key={o.tag} className="checkbox node-option">
                    <input type="checkbox" checked={form.inbound_tags.includes(o.tag)} onChange={() => toggleTag(o.tag)} />
                    <span>
                      {o.remark || o.tag} <span className="tag">{o.protocol}</span>
                      <span className="muted small">:{o.port}</span>
                    </span>
                  </label>
                ))
              )}
              {inboundOptions === null && form.inbound_tags.length > 0 && <span className="muted small">Выбрано: {form.inbound_tags.join(", ")}</span>}
            </div>
          )}
        </div>

        {test && (
          <div className={`notice small ${test.status === "online" ? "notice-ok" : "notice-bad"}`}>
            {test.status === "online"
              ? `Узел отвечает: задержка ${test.latencyMs} мс, панель ${test.panelVersion || "?"}, Xray ${test.xrayVersion || "?"}, аптайм ${formatUptime(test.uptimeSecs ?? null)}`
              : `Нет связи: ${test.error || test.status}`}
          </div>
        )}
        {busy && <div className="notice notice-info small">{busy}</div>}
        {error && <div className="notice notice-bad small">{error}</div>}

        <div className="modal-actions">
          <button type="button" className="btn" onClick={runTest} disabled={!!busy || !form.address || (!node && !form.api_token)}>
            Проверить соединение
          </button>
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose} disabled={!!busy}>
            Отмена
          </button>
          <button type="submit" className="btn btn-primary" disabled={!!busy}>
            Сохранить
          </button>
        </div>
      </form>
    </div>
  );
}

export function Switch({ checked, onChange, disabled, title }: { checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; title?: string }) {
  return (
    <button type="button" role="switch" aria-checked={checked} title={title} className={`switch ${checked ? "on" : ""}`} disabled={disabled} onClick={() => onChange(!checked)}>
      <span />
    </button>
  );
}
