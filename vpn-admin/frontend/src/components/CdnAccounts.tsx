import { useState, type FormEvent } from "react";
import { api, type CdnAccountChecked, type CdnAccounts as CdnAccountsData } from "../api";

/** CDN accounts (Yandex Cloud CDN): a connection for whitelisted networks gets its CDN resource there. */
export function CdnAccounts({ data, onChanged }: { data: CdnAccountsData; onChanged: () => void }) {
  const [editing, setEditing] = useState<CdnAccountChecked | "new" | null>(null);
  const [error, setError] = useState("");

  const remove = async (a: CdnAccountChecked) => {
    if (!confirm(`Удалить CDN-аккаунт «${a.name}» из админки? Ключ будет стёрт, CDN-ресурсы в облаке останутся.`)) return;
    try {
      await api.deleteCdnAccount(a.id);
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const soon = Object.values(data.providers)
    .filter((p) => !p.available)
    .map((p) => p.title);

  return (
    <>
      <div className="toolbar section-title">
        <h2>CDN для белых списков</h2>
        <button className="btn btn-small" onClick={() => setEditing("new")}>
          + Подключить Yandex Cloud
        </button>
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
                    каталог <span className="mono">{a.folder_id}</span>
                    {a.ok ? ` · CDN-ресурсов: ${a.resources}` : ""}
                  </div>
                </div>
              </div>
              <div className="hoster-actions">
                {a.ok ? <span className="badge badge-active">Ключ работает</span> : <span className="badge badge-expired">Ошибка</span>}
                <button className="btn btn-small" onClick={() => setEditing(a)}>
                  Изменить
                </button>
                <button className="btn btn-small btn-danger" onClick={() => remove(a)}>
                  Удалить
                </button>
              </div>
            </div>
            {!a.ok && <div className="error-text small hoster-error">{a.error}</div>}
          </section>
        ))
      )}

      {editing && (
        <CdnAccountDialog
          account={editing === "new" ? null : editing}
          help={data.providers.yandex?.help ?? ""}
          helpUrl={data.providers.yandex?.help_url ?? ""}
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

function CdnAccountDialog({
  account,
  help,
  helpUrl,
  onClose,
  onSaved,
}: {
  account: CdnAccountChecked | null;
  help: string;
  helpUrl: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(account?.name ?? "");
  const [folderId, setFolderId] = useState(account?.folder_id ?? "");
  const [key, setKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    const body = { provider: "yandex", name, folder_id: folderId, key };
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
          <h2>{account ? `Yandex Cloud «${account.name}»` : "Подключить Yandex Cloud CDN"}</h2>
          <button type="button" className="btn btn-small" onClick={onClose} disabled={busy}>
            ✕
          </button>
        </div>

        <label className="field">
          <span>Название в админке</span>
          <input className="input" required value={name} onChange={(e) => setName(e.target.value)} placeholder="Yandex Cloud — CDN" />
        </label>

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

        <div className="notice notice-info small">
          {help}{" "}
          {helpUrl && (
            <a href={helpUrl} target="_blank" rel="noreferrer">
              Как создать ключ →
            </a>
          )}
        </div>

        {busy && <div className="notice notice-info small">Проверяю ключ и права в каталоге…</div>}
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
