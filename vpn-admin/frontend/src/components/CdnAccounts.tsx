import { useState, type FormEvent } from "react";
import { api, type CdnAccountChecked, type CdnAccountForm, type CdnAccounts as CdnAccountsData, type CdnResource } from "../api";

const BUTTONS: Record<string, string> = { yandex: "Yandex Cloud", vk: "VK Cloud", beget: "Beget" };
// accounts that sign in with a login and password rather than a key
const PASSWORD = ["vk", "beget"];

/** CDN accounts (Yandex Cloud CDN, VK Cloud CDN): a connection for whitelisted networks gets its CDN resource there. */
export function CdnAccounts({ data, onChanged }: { data: CdnAccountsData; onChanged: () => void }) {
  const [editing, setEditing] = useState<{ provider: string; account: CdnAccountChecked | null } | null>(null);
  const [error, setError] = useState("");

  const remove = async (a: CdnAccountChecked) => {
    const secret = PASSWORD.includes(a.provider) ? "Пароль будет стёрт" : "Ключ будет стёрт";
    if (!confirm(`Удалить CDN-аккаунт «${a.name}» из админки? ${secret}, CDN-ресурсы в облаке останутся.`)) return;
    try {
      await api.deleteCdnAccount(a.id);
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const available = Object.entries(data.providers).filter(([, p]) => p.available);
  const soon = Object.values(data.providers)
    .filter((p) => !p.available)
    .map((p) => p.title);
  const provider = editing ? data.providers[editing.provider] : null;

  return (
    <>
      <div className="toolbar section-title">
        <h2>CDN для белых списков</h2>
        <div className="toolbar-actions">
          {available.map(([key, p]) => (
            <button key={key} className="btn btn-small" onClick={() => setEditing({ provider: key, account: null })}>
              + Подключить {BUTTONS[key] ?? p.title}
            </button>
          ))}
        </div>
      </div>
      {error && <div className="notice notice-bad small">{error}</div>}

      {data.accounts.length === 0 ? (
        <div className="muted small dns-empty">
          Подключите CDN, чьи адреса операторы пускают в режиме белых списков, и включите в «Подключениях» шаблон «VLESS XHTTP через CDN»:
          админка сама выпустит сертификат, создаст CDN-ресурс и пропишет его адрес в ссылки. {soon.length > 0 && `Скоро: ${soon.join(", ")}.`}
        </div>
      ) : (
        data.accounts.map((a) => (
          <section key={a.id} className="card hoster-card">
            <div className="card-head">
              <div className="hoster-title">
                <span className={`provider-badge provider-${a.provider}`}>{a.provider_title}</span>
                <div>
                  <div className="strong">{a.name}</div>
                  <div className="muted small">
                    {a.provider === "vk" ? (
                      <>
                        проект <span className="mono">{a.project_id}</span> · {a.username}
                      </>
                    ) : a.provider === "beget" ? (
                      <>логин {a.username}</>
                    ) : (
                      <>
                        каталог <span className="mono">{a.folder_id}</span>
                      </>
                    )}
                    {a.ok ? ` · CDN-ресурсов: ${a.resources}` : ""}
                  </div>
                </div>
              </div>
              <div className="hoster-actions">
                {a.ok ? (
                  <span className="badge badge-active">{PASSWORD.includes(a.provider) ? "Доступ работает" : "Ключ работает"}</span>
                ) : (
                  <span className="badge badge-expired">Ошибка</span>
                )}
                <button className="btn btn-small" onClick={() => setEditing({ provider: a.provider, account: a })}>
                  Изменить
                </button>
                <button className="btn btn-small btn-danger" onClick={() => remove(a)}>
                  Удалить
                </button>
              </div>
            </div>
            {!a.ok && <div className="error-text small hoster-error">{a.error}</div>}
            {a.ok && a.items.length === 0 && <div className="muted small">CDN-ресурсов пока нет.</div>}
            {a.items.length > 0 && <CdnResources items={a.items} />}
          </section>
        ))
      )}

      {editing && (
        <CdnAccountDialog
          provider={editing.provider}
          title={provider?.title ?? editing.provider}
          account={editing.account}
          help={provider?.help ?? ""}
          helpUrl={provider?.help_url ?? ""}
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

const RESOURCE_DOT: Record<string, string> = { active: "dot-on", processed: "dot-warn", off: "dot-off", suspended: "dot-off" };

function CdnResources({ items }: { items: CdnResource[] }) {
  return (
    <div className="table-wrap">
      <table className="cdn-resources">
        <thead>
          <tr>
            <th>Домен</th>
            <th>Адрес CDN</th>
            <th>Источник</th>
            <th>Статус</th>
            <th>HTTPS</th>
            <th>Сервер админки</th>
          </tr>
        </thead>
        <tbody>
          {items.map((r) => (
            <tr key={r.id}>
              <td>
                <div className="strong mono">{r.domain || "—"}</div>
                {r.name && <div className="muted small">{r.name}</div>}
                {r.domains.length > 0 && <div className="muted small mono">{r.domains.join(", ")}</div>}
              </td>
              <td className="mono small">{r.address || "—"}</td>
              <td className="mono small">{r.origin || "—"}</td>
              <td>
                <span className="status">
                  <span className={`dot ${RESOURCE_DOT[r.status] ?? "dot-off"}`} /> {r.status_label || "—"}
                </span>
              </td>
              <td className="small">
                {r.https === null ? "—" : r.https ? "есть" : <span className="muted">нет</span>}
                {r.https_note && <div className="muted small">{r.https_note}</div>}
              </td>
              <td>{r.owner ? <span className="badge badge-main">{r.owner.server}</span> : <span className="muted small">создан не админкой</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function CdnAccountDialog({
  provider,
  title,
  account,
  help,
  helpUrl,
  onClose,
  onSaved,
}: {
  provider: string;
  title: string;
  account: CdnAccountChecked | null;
  help: string;
  helpUrl: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const vk = provider === "vk";
  const beget = provider === "beget";
  const [name, setName] = useState(account?.name ?? "");
  const [folderId, setFolderId] = useState(account?.folder_id ?? "");
  const [key, setKey] = useState("");
  const [projectId, setProjectId] = useState(account?.project_id ?? "");
  const [username, setUsername] = useState(account?.username ?? "");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    const body: CdnAccountForm = vk
      ? { provider, name, project_id: projectId, username, password }
      : beget
        ? { provider, name, username, password }
        : { provider, name, folder_id: folderId, key };
    try {
      if (account) await api.updateCdnAccount(account.id, body);
      else await api.createCdnAccount(body);
      onSaved();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <form className="modal" onSubmit={submit}>
        <div className="modal-head">
          <h2>{account ? `${title} «${account.name}»` : `Подключить ${title}`}</h2>
          <button type="button" className="btn btn-small" onClick={onClose} disabled={busy}>
            ✕
          </button>
        </div>

        <label className="field">
          <span>Название в админке</span>
          <input className="input" required value={name} onChange={(e) => setName(e.target.value)} placeholder={`${title}`} />
        </label>

        {vk || beget ? (
          <>
            {vk && (
            <label className="field">
              <span>Project ID</span>
              <input
                className="input mono"
                required
                value={projectId}
                onChange={(e) => setProjectId(e.target.value)}
                placeholder="вкладка «Доступ по API» в настройках проекта"
                autoComplete="off"
              />
            </label>
            )}
            <label className="field">
              <span>{vk ? "Логин VK Cloud (email)" : "Логин Beget"}</span>
              <input
                className="input"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={vk ? "user@example.com" : "логин аккаунта Beget"}
                autoComplete="off"
              />
            </label>
            <label className="field">
              <span>Пароль</span>
              <input
                className="input"
                type="password"
                required={!account}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={account ? "сохранён, оставьте пустым чтобы не менять" : ""}
                autoComplete="new-password"
              />
            </label>
          </>
        ) : (
          <>
            <label className="field">
              <span>ID каталога</span>
              <input className="input mono" required value={folderId} onChange={(e) => setFolderId(e.target.value)} placeholder="b1g…" autoComplete="off" />
            </label>

            <label className="field">
              <span>Авторизованный ключ сервисного аккаунта (JSON)</span>
              <textarea
                className="input mono cdn-key"
                required={!account}
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder={account ? "сохранён, оставьте пустым чтобы не менять" : '{"id": "…", "service_account_id": "…", "private_key": "…"}'}
                spellCheck={false}
                autoComplete="off"
              />
            </label>
          </>
        )}

        <div className="notice notice-info small">
          {help}{" "}
          {helpUrl && (
            <a href={helpUrl} target="_blank" rel="noreferrer">
              {vk ? "Как включить доступ по API →" : beget ? "Доступ к API в панели Beget →" : "Как создать ключ →"}
            </a>
          )}
        </div>

        {busy && <div className="notice notice-info small">{vk ? "Вхожу в VK Cloud и проверяю доступ к CDN…" : beget ? "Вхожу в Beget и проверяю доступ к CDN…" : "Проверяю ключ и права в каталоге…"}</div>}
        {error && <div className="notice notice-bad small">{error}</div>}

        <div className="modal-actions">
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
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
