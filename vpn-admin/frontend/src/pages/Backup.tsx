import { useEffect, useState } from "react";
import { api, type BackupFile, type BackupPreview, type BackupRestored, type BackupSection } from "../api";
import { formatDateTime } from "../format";

const MIN_PASSWORD = 8;

/** Settings of the admin to one password-encrypted file, and back from it. */
export function Backup({ onRestored }: { onRestored: () => void }) {
  const [sections, setSections] = useState<BackupSection[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.backupSections().then(setSections, (e) => setError(e.message));
  }, []);

  if (error && !sections) return <div className="notice notice-bad">{error}</div>;
  if (!sections) return <div className="center muted">Загрузка…</div>;
  return (
    <div className="cards backup-cards">
      <ExportCard sections={sections} />
      <ImportCard onRestored={onRestored} />
    </div>
  );
}

function ExportCard({ sections }: { sections: BackupSection[] }) {
  const [chosen, setChosen] = useState<string[]>(sections.map((s) => s.key));
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  const toggle = (key: string) => setChosen((c) => (c.includes(key) ? c.filter((k) => k !== key) : [...c, key]));
  const problem =
    chosen.length === 0
      ? "Выберите хотя бы один раздел"
      : password.length < MIN_PASSWORD
        ? `Пароль — не короче ${MIN_PASSWORD} символов`
        : password !== repeat
          ? "Пароли не совпадают"
          : "";

  const download = async () => {
    setBusy(true);
    setError("");
    setDone("");
    try {
      const file = await api.backupExport(password, chosen);
      const name = `vpn-admin-backup-${new Date().toISOString().slice(0, 16).replace(/[-:]/g, "").replace("T", "-")}.json`;
      const url = URL.createObjectURL(new Blob([JSON.stringify(file, null, 2)], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = name;
      link.click();
      URL.revokeObjectURL(url);
      setDone(`Файл ${name} сохранён. Храните его и пароль отдельно: без пароля бекап не открыть.`);
      setPassword("");
      setRepeat("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <div className="strong">Скачать бекап</div>
      <div className="muted small">
        В файл попадут выбранные разделы вместе с паролями, токенами и API-ключами. Файл шифруется паролем, который вы зададите здесь, поэтому его
        можно восстановить и на другой установке админки.
      </div>
      <div className="backup-sections">
        {sections.map((s) => (
          <label key={s.key} className="checkbox">
            <input type="checkbox" checked={chosen.includes(s.key)} onChange={() => toggle(s.key)} />
            {s.title}
          </label>
        ))}
      </div>
      <div className="field-row backup-passwords">
        <label className="field">
          <span>Пароль бекапа</span>
          <input className="input" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        <label className="field">
          <span>Ещё раз</span>
          <input className="input" type="password" autoComplete="new-password" value={repeat} onChange={(e) => setRepeat(e.target.value)} />
        </label>
      </div>
      {error && <div className="error-text small">{error}</div>}
      {done && <div className="notice notice-ok small">{done}</div>}
      <div className="card-actions">
        <button className="btn btn-primary" onClick={download} disabled={busy || !!problem} title={problem}>
          {busy ? "Готовлю…" : "Скачать бекап"}
        </button>
        {problem && (password || repeat) && <span className="muted small">{problem}</span>}
      </div>
    </div>
  );
}

function ImportCard({ onRestored }: { onRestored: () => void }) {
  const [file, setFile] = useState<BackupFile | null>(null);
  const [fileName, setFileName] = useState("");
  const [password, setPassword] = useState("");
  const [preview, setPreview] = useState<BackupPreview | null>(null);
  const [chosen, setChosen] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<BackupRestored | null>(null);

  const pick = async (input: HTMLInputElement) => {
    const picked = input.files?.[0];
    setPreview(null);
    setResult(null);
    setError("");
    setFile(null);
    setFileName(picked?.name ?? "");
    if (!picked) return;
    try {
      const data = JSON.parse(await picked.text()) as BackupFile;
      if (data?.format !== "vpn-admin-backup") throw new Error("Это не файл бекапа VPN Admin");
      setFile(data);
    } catch (e) {
      setError(e instanceof SyntaxError ? "Файл не читается: это не бекап VPN Admin" : (e as Error).message);
    }
  };

  const open = async () => {
    if (!file) return;
    setBusy(true);
    setError("");
    try {
      const p = await api.backupPreview(file, password);
      setPreview(p);
      setChosen(p.sections.map((s) => s.key));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const toggle = (key: string) => setChosen((c) => (c.includes(key) ? c.filter((k) => k !== key) : [...c, key]));
  const titles = Object.fromEntries((preview?.sections ?? []).map((s) => [s.key, s.title]));
  const lacking = (preview?.sections ?? [])
    .filter((s) => chosen.includes(s.key))
    .flatMap((s) => s.needs.filter((n) => !chosen.includes(n)).map((n) => `«${s.title}» восстанавливаются только вместе с «${titles[n] ?? n}»`));

  const restore = async () => {
    if (!file || !preview) return;
    const names = preview.sections.filter((s) => chosen.includes(s.key)).map((s) => `«${s.title}»`).join(", ");
    if (!confirm(`Заменить ${names} данными из бекапа? Текущие записи этих разделов будут удалены. Копия базы перед восстановлением сохранится на сервере.`)) return;
    setBusy(true);
    setError("");
    try {
      setResult(await api.backupImport(file, password, chosen));
      setPreview(null);
      setPassword("");
      onRestored();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <div className="strong">Восстановить из бекапа</div>
      <div className="muted small">
        Выбранные разделы заменяются целиком: записи, которых нет в бекапе, удаляются. Перед восстановлением админка сохраняет копию своей базы в папке
        данных на сервере.
      </div>
      <label className="field">
        <span>Файл бекапа</span>
        <input className="input" type="file" accept=".json,application/json" onChange={(e) => pick(e.currentTarget)} />
      </label>
      {file && (
        <div className="muted small">
          {fileName}: сделан {formatDateTime(file.created_at * 1000)}
          {file.app_version ? `, версия ${file.app_version}` : ""}
        </div>
      )}
      {file && !preview && (
        <div className="input-with-button">
          <input
            className="input"
            type="password"
            placeholder="Пароль бекапа"
            autoComplete="off"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && password && open()}
          />
          <button className="btn" onClick={open} disabled={busy || !password}>
            {busy ? "Открываю…" : "Открыть"}
          </button>
        </div>
      )}
      {preview && (
        <div className="backup-preview">
          {preview.sections.map((s) => (
            <label key={s.key} className="checkbox backup-preview-row">
              <input type="checkbox" checked={chosen.includes(s.key)} onChange={() => toggle(s.key)} />
              <span>
                <span className="strong">{s.title}</span>
                <span className="muted small">
                  {" "}
                  — в бекапе {s.items.length}, сейчас {s.current}
                </span>
                {s.items.length > 0 && <span className="muted small backup-items">{s.items.join(", ")}</span>}
              </span>
            </label>
          ))}
        </div>
      )}
      {lacking.map((l) => (
        <div key={l} className="notice notice-warn small">
          {l}
        </div>
      ))}
      {error && <div className="error-text small">{error}</div>}
      {result && (
        <div className="notice notice-ok small">
          Восстановлено: {result.restored.map((r) => `${r.title} (${r.count})`).join(", ")}. Копия базы до восстановления: {result.snapshot}
        </div>
      )}
      {preview && (
        <div className="card-actions">
          <button className="btn btn-danger" onClick={restore} disabled={busy || chosen.length === 0 || lacking.length > 0}>
            {busy ? "Восстанавливаю…" : "Восстановить выбранное"}
          </button>
          <button className="btn" onClick={() => setPreview(null)} disabled={busy}>
            Отмена
          </button>
        </div>
      )}
    </div>
  );
}
