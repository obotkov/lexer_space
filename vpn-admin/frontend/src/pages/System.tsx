import { useCallback, useEffect, useRef, useState } from "react";
import { api, type UpdateCheck, type UpdateStatus, type VersionInfo } from "../api";
import { formatDateTime } from "../format";
import { TlsCard } from "../components/TlsCard";
import { SiteCard } from "../components/SiteCard";

const POLL_MS = 2000;
const ACTIVE_STATES = ["queued", "running"];

const STATE_LABELS: Record<string, string> = {
  queued: "В очереди: ждём, пока сервер подхватит запрос",
  running: "Обновляется",
  done: "Готово",
  failed: "Ошибка",
  stale: "Обновление зависло",
};

const shortSha = (sha: string) => (sha ? sha.slice(0, 7) : "—");
const isoToLocal = (iso: string) => (iso ? new Date(iso).toLocaleString("ru-RU") : "—");

export function System({ check, onCheck }: { check: UpdateCheck | null; onCheck: (c: UpdateCheck) => void }) {
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState("");
  const [restarting, setRestarting] = useState(false);
  const startedTree = useRef<string | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const s = await api.updateStatus();
      setStatus(s);
      setRestarting(false);
      return s;
    } catch {
      // the container is being recreated while the update runs
      setRestarting(true);
      return null;
    }
  }, []);

  useEffect(() => {
    api.version().then(setVersion, (e) => setError(e.message));
    loadStatus();
  }, [loadStatus]);

  const active = restarting || (status !== null && ACTIVE_STATES.includes(status.state));

  // poll while an update is in progress
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(async () => {
      const s = await loadStatus();
      if (s && !ACTIVE_STATES.includes(s.state)) {
        const v = await api.version().catch(() => null);
        if (v) setVersion(v);
        api.checkUpdate(true).then(onCheck, () => undefined);
      }
    }, POLL_MS);
    return () => clearInterval(timer);
  }, [active, loadStatus, onCheck]);

  const runCheck = async () => {
    setChecking(true);
    setError("");
    try {
      onCheck(await api.checkUpdate(true));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setChecking(false);
    }
  };

  const startUpdate = async () => {
    if (!confirm("Скачать новую версию и перезапустить админку? На минуту-две она будет недоступна; VPN и 3x-ui это не затронет.")) return;
    setError("");
    startedTree.current = version?.tree ?? null;
    try {
      setStatus(await api.startUpdate());
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const updated = status?.state === "done" && startedTree.current !== null && version !== null && version.tree !== startedTree.current;

  return (
    <>
      {error && <div className="notice notice-bad">{error}</div>}

      <div className="cards">
        <div className="card">
          <div className="card-head">
            <div className="strong">Текущая версия</div>
            <span className="tag">{version?.version ?? "…"}</span>
          </div>
          <dl className="kv">
            <dt>Коммит</dt>
            <dd className="mono">{version ? shortSha(version.commit) : "…"}</dd>
            <dt>Дата коммита</dt>
            <dd>{version ? isoToLocal(version.commit_date) : "…"}</dd>
            <dt>Собрано</dt>
            <dd>{version ? isoToLocal(version.built_at) : "…"}</dd>
            <dt>Источник</dt>
            <dd className="small">
              {version && (
                <a href={`https://github.com/${version.repo}/tree/${version.branch}/${version.path}`} target="_blank" rel="noreferrer">
                  {version.repo}/{version.path} ({version.branch})
                </a>
              )}
            </dd>
          </dl>
          {version && !version.tree && (
            <div className="muted small">Образ собран не из git-клона, поэтому версия сравнивается только по номеру из файла VERSION.</div>
          )}
        </div>

        <div className="card">
          <div className="card-head">
            <div className="strong">Обновления</div>
            {check && !check.error && (
              <span className={`badge ${check.update_available ? "badge-depleted" : "badge-active"}`}>
                {check.update_available ? "Есть новая версия" : "Актуальная версия"}
              </span>
            )}
          </div>
          {check?.error && <div className="error-text small">{check.error}</div>}
          {check && !check.error && check.update_available && (
            <div>
              Доступна версия <b>{check.latest_version ?? shortSha(check.latest_tree ?? "")}</b>
            </div>
          )}
          {check && <div className="muted small">Проверено {formatDateTime(check.checked_at * 1000)}</div>}
          <div className="card-actions">
            <button className="btn" onClick={runCheck} disabled={checking || active}>
              {checking ? "Проверяю…" : "Проверить обновления"}
            </button>
            {check?.update_available && version?.updater && (
              <button className="btn btn-primary" onClick={startUpdate} disabled={active}>
                Обновить сейчас
              </button>
            )}
          </div>
          {version && !version.updater && (
            <div className="muted small">
              Обновление из админки не настроено на сервере. Обновите вручную: <code>sudo /opt/lexer_space/vpn-admin/update.sh</code>, после этого кнопка
              появится.
            </div>
          )}
        </div>

        <TlsCard />

        <SiteCard />
      </div>

      {check?.update_available && check.commits.length > 0 && (
        <>
          <h2 className="section-title">Что нового</h2>
          <div className="table-wrap">
            <table>
              <tbody>
                {check.commits.map((c) => (
                  <tr key={c.sha}>
                    <td className="mono small">
                      <a href={c.url} target="_blank" rel="noreferrer">
                        {c.sha}
                      </a>
                    </td>
                    <td>{c.message}</td>
                    <td className="small muted num">{isoToLocal(c.date)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {(active || (status && status.state !== "idle")) && (
        <>
          <h2 className="section-title">Ход обновления</h2>
          <div className={`notice ${status?.state === "failed" || status?.state === "stale" ? "notice-bad" : status?.state === "done" ? "notice-ok" : "notice-info"}`}>
            {restarting ? "Админка перезапускается…" : STATE_LABELS[status?.state ?? ""] ?? status?.state}
            {status?.message && !restarting && <span className="muted"> — {status.message}</span>}
            {status?.state === "stale" && <div className="small">Похоже, обновление не завершилось. Проверьте на сервере: journalctl -u vpn-admin-update</div>}
          </div>
          {updated && (
            <div className="notice notice-ok">
              Новая версия установлена.{" "}
              <button className="btn btn-small" onClick={() => window.location.reload()}>
                Перезагрузить страницу
              </button>
            </div>
          )}
          {status?.log && <pre className="log">{status.log}</pre>}
        </>
      )}
    </>
  );
}
