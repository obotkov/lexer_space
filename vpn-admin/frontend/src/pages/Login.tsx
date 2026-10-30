import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import { passkeyError, passkeysSupported, signInWithPasskey } from "../passkey";

export function Login({ onLogin }: { onLogin: (username: string) => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const [canPasskey, setCanPasskey] = useState(false);

  useEffect(() => {
    if (passkeysSupported()) api.passkeyAvailable().then((r) => setCanPasskey(r.available), () => undefined);
  }, []);

  const passkey = async () => {
    setBusy(true);
    setError("");
    try {
      onLogin((await signInWithPasskey()).username);
    } catch (err) {
      setError(passkeyError(err));
    } finally {
      setBusy(false);
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const me = await api.login(username, password);
      onLogin(me.username);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={submit}>
        <div className="logo big">
          <Shield /> VPN Admin
        </div>
        <label className="field">
          <span>Логин</span>
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" />
        </label>
        <label className="field">
          <span>Пароль</span>
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
        </label>
        {error && <div className="notice notice-bad">{error}</div>}
        <button className="btn btn-primary wide" disabled={busy}>
          Войти
        </button>
        {canPasskey && (
          <button type="button" className="btn wide" onClick={passkey} disabled={busy}>
            Войти с Passkey
          </button>
        )}
      </form>
    </div>
  );
}

export function Shield() {
  return (
    <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden>
      <path fill="currentColor" d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5z" />
    </svg>
  );
}
