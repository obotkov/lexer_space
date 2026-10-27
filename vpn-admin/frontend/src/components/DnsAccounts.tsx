import { useState, type FormEvent } from "react";
import { api, type DnsAccount, type DnsAccounts as DnsAccountsData } from "../api";

/** Cloudflare accounts whose zones give new servers a domain: the admin keeps their A records. */
export function DnsAccounts({ data, onChanged }: { data: DnsAccountsData; onChanged: () => void }) {
  const [editing, setEditing] = useState<DnsAccount | "new" | null>(null);
  const [error, setError] = useState("");

  const remove = async (a: DnsAccount) => {
    if (!confirm(`Удалить аккаунт Cloudflare «${a.name}» из админки? Токен будет стёрт, записи в Cloudflare останутся.`)) return;
    try {
      await api.deleteDnsAccount(a.id);
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <>
      <div className="toolbar section-title">
        <h2>DNS: Cloudflare</h2>
        <button className="btn btn-small" onClick={() => setEditing("new")}>
          + Подключить Cloudflare
        </button>
      </div>
      {error && <div className="notice notice-bad small">{error}</div>}

      {data.accounts.length === 0 ? (
        <div className="muted small dns-empty">
          Подключите API-токен Cloudflare, и при создании сервера можно будет выбрать «Домен Cloudflare»: админка сама создаст A-запись на IP
          сервера, а сервер получит на этот домен сертификат Let's Encrypt.
        </div>
      ) : (
        data.accounts.map((a) => (
          <section key={a.id} className="card hoster-card">
            <div className="card-head">
              <div className="hoster-title">
                <span className="provider-badge provider-cloudflare">Cloudflare</span>
                <div>
                  <div className="strong">{a.name}</div>
                  <div className="muted small">{a.ok ? `Доменов: ${a.zones.length}` : ""}</div>
                </div>
              </div>
              <div className="hoster-actions">
                {a.ok ? <span className="badge badge-active">Токен работает</span> : <span className="badge badge-expired">Ошибка</span>}
                <button className="btn btn-small" onClick={() => setEditing(a)}>
                  Изменить
                </button>
                <button className="btn btn-small btn-danger" onClick={() => remove(a)}>
                  Удалить
                </button>
              </div>
            </div>
            {a.ok ? (
              <div className="dns-zones">
                {a.zones.map((z) => (
                  <span key={z.id} className="badge badge-disabled mono">
                    {z.name}
                  </span>
                ))}
              </div>
            ) : (
              <div className="error-text small hoster-error">{a.error}</div>
            )}
          </section>
        ))
      )}

      {editing && (
        <DnsAccountDialog
          account={editing === "new" ? null : editing}
          help={data.help}
          helpUrl={data.help_url}
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

function DnsAccountDialog({
  account,
  help,
  helpUrl,
  onClose,
  onSaved,
}: {
  account: DnsAccount | null;
  help: string;
  helpUrl: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(account?.name ?? "");
  const [token, setToken] = useState("");
  const [shown, setShown] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (account) await api.updateDnsAccount(account.id, { name, token });
      else await api.createDnsAccount({ name, token });
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
          <h2>{account ? `Cloudflare «${account.name}»` : "Подключить Cloudflare"}</h2>
          <button type="button" className="btn btn-small" onClick={onClose} disabled={busy}>
            ✕
          </button>
        </div>

        <label className="field">
          <span>Название в админке</span>
          <input className="input" required value={name} onChange={(e) => setName(e.target.value)} placeholder="Cloudflare — основной" />
        </label>

        <label className="field">
          <span>API-токен</span>
          <div className="input-with-button">
            <input
              className="input mono"
              type={shown ? "text" : "password"}
              required={!account}
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder={account ? "сохранён, оставьте пустым чтобы не менять" : ""}
              autoComplete="off"
            />
            <button type="button" className="btn btn-small" onClick={() => setShown(!shown)}>
              {shown ? "Скрыть" : "Показать"}
            </button>
          </div>
        </label>

        <div className="notice notice-info small">
          {help}{" "}
          <a href={helpUrl} target="_blank" rel="noreferrer">
            Создать токен →
          </a>
        </div>

        {busy && <div className="notice notice-info small">Проверяю токен и сохраняю…</div>}
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
