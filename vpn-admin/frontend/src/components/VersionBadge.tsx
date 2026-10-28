import type { UpdateCheck } from "../api";

/** The admin's version next to the overview title and, when GitHub has a newer one, a button to it. */
export function VersionBadge({ check, onUpdate }: { check: UpdateCheck | null; onUpdate: () => void }) {
  if (!check) return <span className="version-pill muted">VPN Admin · проверка версии…</span>;
  const current = check.current.version;
  const checkedAt = new Date(check.checked_at * 1000).toLocaleTimeString("ru-RU");
  const title = check.error ?? (check.update_available ? `Есть новая версия, проверено в ${checkedAt}` : `Последняя версия, проверено в ${checkedAt}`);
  // a newer build with the same VERSION (an unbumped commit) still counts as an update
  const latest = check.latest_version && check.latest_version !== current ? `v${check.latest_version}` : "новой версии";

  return (
    <>
      <span className="version-pill" title={title}>
        <span className={`dot ${check.error ? "" : check.update_available ? "dot-warn" : "dot-on"}`} aria-hidden />
        <span>VPN Admin</span>
        <span className="muted">v{current}</span>
        {check.error && <span className="muted small">· не удалось проверить</span>}
      </span>
      {check.update_available && (
        <button className="version-update" onClick={onUpdate} title={`Открыть «Система», чтобы обновиться до ${latest}`}>
          <svg viewBox="0 0 24 24" aria-hidden>
            <path d="M7 18a4.5 4.5 0 0 1-.6-8.96A6 6 0 0 1 18 8a4 4 0 0 1-1 7.9" />
            <path d="M12 12v8m-3-3 3 3 3-3" />
          </svg>
          Обновить до {latest}
        </button>
      )}
    </>
  );
}
