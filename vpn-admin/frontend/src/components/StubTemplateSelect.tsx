import { useEffect, useState } from "react";
import { api, type SiteStatus } from "../api";

/** Decoy page for port 80 of a node: the admin's own site templates, its custom page, or none.
 * `value` null means "not chosen yet": the admin's current template (or the first one) is picked. */
export function StubTemplateSelect({ value, onChange }: { value: string | null; onChange: (id: string) => void }) {
  const [site, setSite] = useState<SiteStatus | null>(null);

  useEffect(() => {
    api.site().then(setSite, () => setSite(null));
  }, []);

  useEffect(() => {
    if (value === null && site) onChange(site.current || site.templates[0]?.id || "");
  }, [value, site, onChange]);

  return (
    <label className="field">
      <span>Сайт-заглушка на порту 80</span>
      <select className="input" value={value ?? ""} onChange={(e) => onChange(e.target.value)} disabled={!site}>
        <option value="">Без заглушки</option>
        {site?.templates.map((t) => (
          <option key={t.id} value={t.id}>
            {t.name} — {t.description}
          </option>
        ))}
        {site?.custom_html && <option value="custom">Свой шаблон из раздела «Система»</option>}
      </select>
      <small className="muted">
        Как сайт-заглушка админки: обычная страница для всех, кто откроет IP или домен сервера в браузере. Порт 443 остаётся свободным
        для VPN.
      </small>
    </label>
  );
}
