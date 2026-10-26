import { useEffect, useState } from "react";
import { api, type SiteStatus } from "../api";
import { formatDateTime } from "../format";

/** Decoy page that nginx serves on the domain: pick one of the built-in templates or paste your own HTML. */
export function SiteCard() {
  const [status, setStatus] = useState<SiteStatus | null>(null);
  const [previews, setPreviews] = useState<Record<string, string>>({});
  const [custom, setCustom] = useState("");
  const [preview, setPreview] = useState<{ title: string; html: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");

  useEffect(() => {
    api.site().then(
      async (s) => {
        setStatus(s);
        setCustom(s.custom_html);
        const loaded = await Promise.all(s.templates.map((t) => api.siteTemplate(t.id).catch(() => null)));
        setPreviews(Object.fromEntries(loaded.filter((t) => t).map((t) => [t!.id, t!.html])));
      },
      (e) => setError(e.message),
    );
  }, []);

  const run = async (action: () => Promise<SiteStatus>, message: string) => {
    setBusy(true);
    setError("");
    setSaved("");
    try {
      setStatus(await action());
      setSaved(message);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (!status) return error ? <div className="card card-wide error-text">{error}</div> : null;

  // what the visitor sees: placeholders filled in the same way as on the server
  const fill = (html: string) =>
    html
      .split("{{domain}}")
      .join(status.domain || "example.com")
      .split("{{year}}")
      .join(String(new Date().getFullYear()));
  const currentName = status.current === "custom" ? "свой шаблон" : status.templates.find((t) => t.id === status.current)?.name;

  return (
    <div className="card card-wide">
      <div className="card-head">
        <div>
          <div className="strong">Сайт-заглушка</div>
          <div className="muted small">
            Эту страницу видит любой, кто откроет домен без порта админки.
            {currentName && ` Сейчас: ${currentName}${status.updated_at ? `, изменено ${formatDateTime(status.updated_at * 1000)}` : ""}.`}
          </div>
        </div>
        {status.url && (
          <a className="btn btn-small" href={status.url} target="_blank" rel="noreferrer">
            Открыть сайт
          </a>
        )}
      </div>

      {!status.nginx && (
        <div className="notice notice-info small">
          nginx для заглушки не установлен, поэтому страница сохранится, но показываться не будет. Чтобы установить его, выполните на сервере:{" "}
          <code>cd /opt/lexer_space/vpn-admin && sudo SITE_DOMAIN=ваш.домен ./install.sh</code>
        </div>
      )}

      <div className="site-grid">
        {status.templates.map((t) => (
          <div key={t.id} className={`site-tile ${status.current === t.id ? "current" : ""}`}>
            {/* a div, not a <button>: browsers do not paint iframes inside buttons */}
            <div
              role="button"
              tabIndex={0}
              className="site-thumb"
              title="Открыть предпросмотр"
              onClick={() => previews[t.id] && setPreview({ title: t.name, html: previews[t.id] })}
              onKeyDown={(e) => e.key === "Enter" && previews[t.id] && setPreview({ title: t.name, html: previews[t.id] })}
            >
              {previews[t.id] ? <iframe srcDoc={previews[t.id]} sandbox="" tabIndex={-1} title={t.name} /> : <span className="muted small">…</span>}
            </div>
            <div className="site-meta">
              <div className="strong">{t.name}</div>
              <div className="muted small">{t.description}</div>
            </div>
            {status.current === t.id ? (
              <span className="badge badge-active">На сайте</span>
            ) : (
              <button className="btn btn-small" disabled={busy} onClick={() => run(() => api.siteApply(t.id), `Шаблон «${t.name}» опубликован`)}>
                Применить
              </button>
            )}
          </div>
        ))}
      </div>

      <div className="field">
        <span>
          Свой шаблон: один HTML-файл, стили и картинки внутри него или по внешним ссылкам. Можно использовать <code>{"{{domain}}"}</code> и{" "}
          <code>{"{{year}}"}</code>.
        </span>
        <textarea className="input mono site-editor" value={custom} onChange={(e) => setCustom(e.target.value)} placeholder="<!doctype html>…" spellCheck={false} />
      </div>
      <div className="card-actions">
        <button className="btn" disabled={!custom.trim()} onClick={() => setPreview({ title: "Свой шаблон", html: fill(custom) })}>
          Предпросмотр
        </button>
        <button className="btn btn-primary" disabled={busy || !custom.trim()} onClick={() => run(() => api.siteCustom(custom), "Свой шаблон опубликован")}>
          Сохранить и опубликовать
        </button>
        {status.current === "custom" && <span className="badge badge-active">На сайте</span>}
      </div>

      {saved && <div className="notice notice-ok small">{saved}</div>}
      {error && <div className="notice notice-bad small">{error}</div>}

      {preview && (
        <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && setPreview(null)}>
          <div className="modal modal-preview">
            <div className="modal-head">
              <h2>{preview.title}</h2>
              <button className="btn btn-small" onClick={() => setPreview(null)}>
                ✕
              </button>
            </div>
            <iframe className="site-preview" srcDoc={preview.html} sandbox="" title={preview.title} />
          </div>
        </div>
      )}
    </div>
  );
}
