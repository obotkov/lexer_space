import { useEffect, useState, type FormEvent } from "react";
import { api, type DomainCheck, type TlsStatus } from "../api";
import { formatDateTime } from "../format";

const RESTART_WAIT_MS = 6000;

/** HTTPS for the admin itself: Let's Encrypt certificate issued and renewed by the backend (certbot). */
export function TlsCard() {
  const [status, setStatus] = useState<TlsStatus | null>(null);
  const [domain, setDomain] = useState("");
  const [email, setEmail] = useState("");
  const [staging, setStaging] = useState(false);
  const [tos, setTos] = useState(false);
  const [editing, setEditing] = useState(false);
  const [check, setCheck] = useState<DomainCheck | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [redirect, setRedirect] = useState<string | null>(null);

  const load = () =>
    api.tls().then((s) => {
      setStatus(s);
      setDomain((d) => d || s.domain || s.site_domain || (window.location.hostname.match(/[a-z]/i) ? window.location.hostname : ""));
      setEmail((e) => e || s.email);
    }, (e) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  // the backend restarts to switch protocols; follow it to the new address
  useEffect(() => {
    if (!redirect) return;
    const timer = setTimeout(() => (window.location.href = redirect), RESTART_WAIT_MS);
    return () => clearTimeout(timer);
  }, [redirect]);

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

  const checkDomain = () => run("Проверяю домен…", async () => setCheck(await api.tlsCheckDomain(domain)));

  const issue = (e: FormEvent) => {
    e.preventDefault();
    run("Выпускаю сертификат, это займёт до минуты…", async () => {
      const res = await api.tlsIssue(domain, email, staging);
      setRedirect(res.url);
    });
  };

  const renew = () =>
    run("Продлеваю сертификат…", async () => {
      const res = await api.tlsRenew();
      if (res.restarting) setRedirect(window.location.href);
      else await load();
    });

  const disable = () => {
    if (!status || !confirm("Отключить HTTPS? Админка перезапустится и будет работать по обычному HTTP.")) return;
    run("Отключаю HTTPS…", async () => {
      const res = await api.tlsDisable();
      if (res.restarting) setRedirect(`http://${window.location.hostname}:${status.port}/#/system`);
      else await load();
    });
  };

  if (!status) return null;

  if (status.caddy_domain) {
    return (
      <div className="card">
        <div className="card-head">
          <div className="strong">HTTPS</div>
          <span className="badge badge-active">Caddy</span>
        </div>
        <div className="small">
          HTTPS обеспечивает Caddy на порту 443 для <b>{status.caddy_domain}</b>. Сертификат он выпускает и продлевает сам.
        </div>
      </div>
    );
  }

  const cert = status.certificate;
  const showForm = editing || !status.enabled || !status.active;

  return (
    <div className="card">
      <div className="card-head">
        <div className="strong">HTTPS (Let's Encrypt)</div>
        {status.active ? (
          <span className={`badge ${cert?.staging ? "badge-depleted" : "badge-active"}`}>{cert?.staging ? "Тестовый сертификат" : "Включён"}</span>
        ) : status.enabled ? (
          <span className="badge badge-expired">Не работает</span>
        ) : (
          <span className="badge badge-disabled">Выключен</span>
        )}
      </div>

      {status.active && cert && (
        <>
          <dl className="kv">
            <dt>Домен</dt>
            <dd>{cert.domains.join(", ")}</dd>
            <dt>Действует до</dt>
            <dd>
              {formatDateTime(cert.not_after * 1000)} <span className={cert.days_left < 15 ? "error-text" : "muted"}>({cert.days_left} дн.)</span>
            </dd>
            <dt>Выдан</dt>
            <dd>{cert.issuer}</dd>
            <dt>Продление</dt>
            <dd className="small">автоматически, за 30 дней до окончания{status.last_renew_check ? `; последняя проверка ${formatDateTime(status.last_renew_check * 1000)}` : ""}</dd>
          </dl>
          {!editing && (
            <div className="card-actions">
              <button className="btn" onClick={renew} disabled={!!busy}>
                Продлить сейчас
              </button>
              <button className="btn" onClick={() => setEditing(true)} disabled={!!busy}>
                Сменить домен
              </button>
              <span className="spacer" />
              <button className="btn btn-danger" onClick={disable} disabled={!!busy}>
                Отключить HTTPS
              </button>
            </div>
          )}
        </>
      )}

      {status.enabled && !status.active && (
        <div className="notice notice-bad small">
          HTTPS включён, но сертификата нет или он истёк, поэтому админка работает по HTTP. Выпустите сертификат заново.
        </div>
      )}

      {showForm && (
        <form className="tls-form" onSubmit={issue}>
          <div className="muted small">
            Админка получит сертификат Let's Encrypt и будет открываться по <b>https://домен:{status.port}</b>. Порт 443 не нужен. Нужны A-запись домена на этот сервер и
            открытый порт 80:{" "}
            {status.challenge === "nginx"
              ? "Let's Encrypt проверяет домен через nginx сайта-заглушки. Тот же сертификат получит и заглушка."
              : "Let's Encrypt проверяет домен через него, а админка занимает порт только на несколько секунд проверки."}
          </div>
          <div className="field-row">
            <label className="field">
              <span>Домен</span>
              <input
                className="input"
                required
                value={domain}
                onChange={(e) => {
                  setDomain(e.target.value);
                  setCheck(null);
                }}
                placeholder="admin.example.com"
              />
            </label>
            <label className="field">
              <span>Email (необязательно)</span>
              <input className="input" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
            </label>
          </div>
          {check && (
            <div className={`notice small ${check.matches ? "notice-ok" : "notice-bad"}`}>
              {check.resolved.length === 0
                ? `Домен ${check.domain} не найден в DNS. Создайте A-запись на ${check.server_ip ?? "IP этого сервера"}.`
                : check.matches
                  ? `Домен указывает на этот сервер (${check.server_ip}).`
                  : `Домен указывает на ${check.resolved.join(", ")}, а у сервера IP ${check.server_ip ?? "неизвестен"}. Let's Encrypt не сможет проверить домен, пока A-запись не исправлена (DNS обновляется до нескольких часов).`}
            </div>
          )}
          <label className="checkbox">
            <input type="checkbox" checked={staging} onChange={(e) => setStaging(e.target.checked)} />
            Тестовый сертификат: браузеры ему не доверяют, но и лимитов Let's Encrypt нет. Удобно для пробы
          </label>
          <label className="checkbox">
            <input type="checkbox" checked={tos} onChange={(e) => setTos(e.target.checked)} />
            <span>
              Принимаю{" "}
              <a href="https://letsencrypt.org/repository/" target="_blank" rel="noreferrer">
                условия использования Let's Encrypt
              </a>
            </span>
          </label>
          <div className="card-actions">
            <button type="button" className="btn" onClick={checkDomain} disabled={!!busy || !domain}>
              Проверить домен
            </button>
            <button type="submit" className="btn btn-primary" disabled={!!busy || !tos || !domain}>
              Выпустить сертификат
            </button>
            {editing && (
              <button type="button" className="btn" onClick={() => setEditing(false)} disabled={!!busy}>
                Отмена
              </button>
            )}
          </div>
        </form>
      )}

      {busy && <div className="notice notice-info small">{busy}</div>}
      {redirect && (
        <div className="notice notice-ok small">
          Готово. Админка перезапускается, через несколько секунд откроется{" "}
          <a href={redirect}>{redirect}</a>. Войти нужно будет заново.
        </div>
      )}
      {(error || status.last_error) && !redirect && <pre className="log log-error">{error || status.last_error}</pre>}
    </div>
  );
}
