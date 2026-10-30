import { useEffect, useState, type FormEvent } from "react";
import { api, type Passkey } from "../api";
import { formatDateTime } from "../format";
import { addPasskey, passkeyError, passkeysHereReason } from "../passkey";

/** Passkeys to sign in to the admin with, next to the password. */
export function PasskeysCard() {
  const [items, setItems] = useState<Passkey[] | null>(null);
  const [host, setHost] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = () =>
    api.passkeys().then(
      (r) => {
        setItems(r.items);
        setHost(r.host);
      },
      (e) => setError(e.message),
    );

  useEffect(() => {
    load();
  }, []);

  const add = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await addPasskey(name);
      setName("");
      await load();
    } catch (err) {
      setError(passkeyError(err));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (k: Passkey) => {
    if (!confirm(`Удалить ключ «${k.name}» из админки? Войти с ним больше не получится. С устройства он сам не удалится.`)) return;
    setError("");
    try {
      await api.deletePasskey(k.id);
      await load();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const reason = passkeysHereReason();

  return (
    <div className="card">
      <div className="card-head">
        <div className="strong">Вход через Passkeys</div>
        {items && items.length > 0 && <span className="tag">{items.length}</span>}
      </div>
      <div className="muted small">Вход отпечатком, лицом или ключом безопасности вместо пароля. Пароль продолжает работать. Ключ привязан к домену, на котором создан.</div>
      {items?.map((k) => (
        <div key={k.id} className="passkey-row">
          <div className="passkey-info">
            <div className="strong">{k.name}</div>
            <div className="muted small">
              {k.rp_id !== host && <span className="warn-text">только на {k.rp_id} · </span>}
              {k.last_used_at ? `вход ${formatDateTime(k.last_used_at * 1000)}` : `добавлен ${formatDateTime(k.created_at * 1000)}, ещё не использовался`}
            </div>
          </div>
          <button type="button" className="btn btn-small btn-danger" onClick={() => remove(k)}>
            Удалить
          </button>
        </div>
      ))}
      {reason ? (
        <div className="muted small">{reason}</div>
      ) : (
        <form className="passkey-add" onSubmit={add}>
          <input className="input" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} placeholder="Название, например MacBook" />
          <button className="btn btn-primary" disabled={busy}>
            {busy ? "Жду ключ…" : "Добавить Passkey"}
          </button>
        </form>
      )}
      {error && <div className="error-text small">{error}</div>}
    </div>
  );
}
