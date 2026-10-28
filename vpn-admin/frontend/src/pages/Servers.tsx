import { useState, type FormEvent } from "react";
import { api, type PanelForm, type PanelInfo, type TestResult } from "../api";
import { Empty } from "../components/ui";

const EMPTY_FORM: PanelForm = { name: "", url: "", auth_mode: "token", username: "", password: "", api_token: "", verify_tls: true, sub_base_url: "" };

const API_LABELS = { v3: "3x-ui v3", legacy: "3x-ui 2.x" } as const;

export function Servers({ panels, onChanged }: { panels: PanelInfo[]; onChanged: () => void }) {
  const [editing, setEditing] = useState<PanelInfo | "new" | null>(null);

  const remove = async (p: PanelInfo) => {
    if (!confirm(`Отключить сервер «${p.name}» от админки? На самом сервере 3x-ui ничего не удалится.`)) return;
    await api.deletePanel(p.id);
    onChanged();
  };

  return (
    <>
      <div className="toolbar">
        <button className="btn btn-primary" onClick={() => setEditing("new")}>
          + Добавить сервер 3x-ui
        </button>
      </div>

      {panels.length === 0 ? (
        <Empty>Добавьте первый сервер: нужен адрес панели 3x-ui (вместе с секретным путём), логин и пароль.</Empty>
      ) : (
        <div className="cards">
          {panels.map((p) => (
            <div key={p.id} className="card">
              <div className="card-head">
                <div>
                  <div className="strong">{p.name}</div>
                  <div className="muted small mono card-url" title={p.url}>
                    {p.url}
                  </div>
                </div>
                {p.ok ? <span className="badge badge-active">На связи</span> : <span className="badge badge-expired">Ошибка</span>}
              </div>
              {!p.ok && <div className="error-text small">{p.error}</div>}
              <dl className="kv">
                <dt>Вход</dt>
                <dd>{p.auth_mode === "token" ? "API-токен" : `логин ${p.username}`}</dd>
                <dt>Версия API</dt>
                <dd>{p.api_version ? API_LABELS[p.api_version] : "—"}</dd>
                <dt>Коннектов / клиентов</dt>
                <dd>
                  {p.nodes} / {p.clients}
                </dd>
                <dt>Xray</dt>
                <dd>{p.status?.xray_version ?? "—"}</dd>
                <dt>URL подписок</dt>
                <dd className="mono small">{p.sub_base || <span className="muted">не найден</span>}</dd>
                <dt>Проверка TLS</dt>
                <dd>{p.verify_tls ? "да" : "нет"}</dd>
              </dl>
              <div className="card-actions">
                <button className="btn" onClick={() => setEditing(p)}>
                  Изменить
                </button>
                <button className="btn btn-danger" onClick={() => remove(p)}>
                  Отключить
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {editing && (
        <ServerDialog
          panel={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            onChanged();
          }}
        />
      )}
    </>
  );
}

function ServerDialog({ panel, onClose, onSaved }: { panel: PanelInfo | null; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState<PanelForm>(
    panel
      ? { name: panel.name, url: panel.url, auth_mode: panel.auth_mode, username: panel.username, password: "", api_token: "", verify_tls: panel.verify_tls, sub_base_url: panel.sub_base_url }
      : EMPTY_FORM,
  );
  const [test, setTest] = useState<TestResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const set = <K extends keyof PanelForm>(key: K, value: PanelForm[K]) => {
    setForm((f) => ({ ...f, [key]: value }));
    setTest(null);
  };

  const runTest = async () => {
    setBusy(true);
    setError("");
    try {
      setTest(await api.testPanel(form, panel?.id));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (panel) await api.updatePanel(panel.id, form);
      else await api.createPanel(form);
      onSaved();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <form className="modal" onSubmit={submit}>
        <h2>{panel ? "Изменить сервер" : "Новый сервер 3x-ui"}</h2>

        <label className="field">
          <span>Название</span>
          <input className="input" required value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="Германия #1" />
        </label>
        <label className="field">
          <span>Адрес панели</span>
          <input className="input" required value={form.url} onChange={(e) => set("url", e.target.value)} placeholder="https://1.2.3.4:2053/секретный-путь" />
          <small className="muted">Как в адресной строке браузера, вместе с webBasePath.</small>
        </label>
        <div className="field">
          <span>Способ входа</span>
          <div className="segmented">
            <button type="button" className={form.auth_mode === "token" ? "active" : ""} onClick={() => set("auth_mode", "token")}>
              API-токен
            </button>
            <button type="button" className={form.auth_mode === "password" ? "active" : ""} onClick={() => set("auth_mode", "password")}>
              Логин и пароль
            </button>
          </div>
        </div>
        {form.auth_mode === "token" ? (
          <label className="field">
            <span>API-токен</span>
            <input
              className="input mono"
              type="password"
              required={!(panel && panel.auth_mode === "token")}
              value={form.api_token}
              onChange={(e) => set("api_token", e.target.value)}
              placeholder={panel && panel.auth_mode === "token" ? "не менять" : ""}
              autoComplete="off"
            />
            <small className="muted">
              3x-ui v3.0.2 и новее: Настройки → Безопасность → API Token. Нужна область <b>Admin</b>: остальные не дают управлять клиентами. С токеном не нужны CSRF и
              двухфакторная авторизация.
            </small>
          </label>
        ) : (
          <div className="field-row">
            <label className="field">
              <span>Логин</span>
              <input className="input" required value={form.username} onChange={(e) => set("username", e.target.value)} autoComplete="off" />
            </label>
            <label className="field">
              <span>Пароль</span>
              <input
                className="input"
                type="password"
                required={!panel}
                value={form.password}
                onChange={(e) => set("password", e.target.value)}
                placeholder={panel ? "не менять" : ""}
                autoComplete="new-password"
              />
            </label>
          </div>
        )}
        <label className="field">
          <span>URL подписок (необязательно)</span>
          <input className="input" value={form.sub_base_url} onChange={(e) => set("sub_base_url", e.target.value)} placeholder="https://sub.example.com/sub/" />
          <small className="muted">Если пусто — берётся из настроек подписки в 3x-ui.</small>
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={form.verify_tls} onChange={(e) => set("verify_tls", e.target.checked)} />
          Проверять TLS-сертификат (снимите для самоподписанного)
        </label>

        {test && (
          <div className={`notice ${test.ok ? "notice-ok" : "notice-bad"}`}>
            {test.ok
              ? `Подключено (${test.api_version ? API_LABELS[test.api_version] : "3x-ui"}): коннектов ${test.nodes}, клиентов ${test.clients}${test.xray_version ? `, Xray ${test.xray_version}` : ""}`
              : test.error}
          </div>
        )}
        {error && <div className="notice notice-bad">{error}</div>}

        <div className="modal-actions">
          <button type="button" className="btn" onClick={runTest} disabled={busy || !form.url}>
            Проверить подключение
          </button>
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            Сохранить
          </button>
        </div>
      </form>
    </div>
  );
}
