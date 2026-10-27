import { useCallback, useEffect, useState, type FormEvent } from "react";
import { api, type DnsAccounts as DnsAccountsData, type HosterAccount, type HosterForm, type HosterInfo, type HosterProvider, type HosterServer, type PanelInfo, type Provision } from "../api";
import { CreateServerDialog } from "../components/CreateServerDialog";
import { DeleteServerDialog } from "../components/DeleteServerDialog";
import { DnsAccounts } from "../components/DnsAccounts";
import { Provisions } from "../components/Provisions";
import { Empty, StatCard } from "../components/ui";

const PROVISION_POLL_MS = 5000;

const STATUS_CLASS: Record<HosterServer["status"], string> = {
  running: "dot-on",
  stopped: "",
  pending: "dot-warn",
  error: "dot-off",
  unknown: "",
};

const hostOf = (url: string) => {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
};

/** IP or host name → where this server already is in the admin (main 3x-ui server or one of its nodes). */
function adminIndex(panels: PanelInfo[]): Map<string, string> {
  const index = new Map<string, string>();
  for (const p of panels) {
    const host = hostOf(p.url);
    if (host) index.set(host, `основной «${p.name}»`);
    for (const n of p.children) index.set(n.address, `узел «${n.name}»`);
  }
  return index;
}

/** Hosting accounts (DigitalOcean, OVHcloud…) whose API keys let the admin see and later create servers. */
export function Hosters({ panels, onChanged }: { panels: PanelInfo[]; onChanged: () => void }) {
  const [providers, setProviders] = useState<Record<string, HosterProvider> | null>(null);
  const [accounts, setAccounts] = useState<HosterInfo[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState<HosterInfo | "new" | null>(null);
  const [creating, setCreating] = useState<HosterInfo | null>(null);
  const [deleting, setDeleting] = useState<{ hoster: HosterInfo; server: HosterServer } | null>(null);
  const [provisions, setProvisions] = useState<Provision[]>([]);
  const [dnsData, setDnsData] = useState<DnsAccountsData | null>(null);

  const load = useCallback(async (refresh = false) => {
    setLoading(true);
    try {
      setAccounts(await api.hosters(refresh));
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadProvisions = useCallback(() => api.provisions().then(setProvisions, (e) => setError((e as Error).message)), []);
  const loadDns = useCallback(() => api.dnsAccounts().then(setDnsData, (e) => setError((e as Error).message)), []);

  useEffect(() => {
    api.hosterProviders().then(setProviders, (e) => setError((e as Error).message));
    load();
    loadProvisions();
    loadDns();
  }, [load, loadProvisions, loadDns]);

  // follow running jobs; when one ends, the new server and node show up elsewhere too
  const running = provisions.filter((p) => p.state === "running").length;
  useEffect(() => {
    if (!running) return;
    const timer = setInterval(loadProvisions, PROVISION_POLL_MS);
    return () => {
      clearInterval(timer);
      load(true);
      onChanged();
    };
  }, [running, loadProvisions, load, onChanged]);

  const remove = async (h: HosterInfo) => {
    if (!confirm(`Удалить аккаунт «${h.name}» из админки? Ключи будут стёрты, серверы у хостинга не пострадают.`)) return;
    try {
      await api.deleteHoster(h.id);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  if (!accounts || !providers) return error ? <div className="notice notice-bad">{error}</div> : <div className="center muted">Загрузка аккаунтов хостингов…</div>;

  const index = adminIndex(panels);
  const servers = accounts.flatMap((a) => a.servers);
  const inAdmin = servers.filter((s) => [...s.ipv4, ...s.ipv6].some((ip) => index.has(ip))).length;

  return (
    <>
      <div className="stats">
        <StatCard label="Аккаунтов" value={accounts.length} hint={accounts.some((a) => !a.ok) ? "есть с ошибкой" : undefined} tone={accounts.some((a) => !a.ok) ? "bad" : undefined} />
        <StatCard label="Серверов у хостингов" value={servers.length} />
        <StatCard label="Работают" value={servers.filter((s) => s.status === "running").length} tone="good" />
        <StatCard label="Уже в админке" value={inAdmin} hint="совпадает IP с сервером или узлом 3x-ui" />
      </div>

      <div className="toolbar section-title">
        <button className="btn btn-primary" onClick={() => setEditing("new")}>
          + Добавить аккаунт
        </button>
        <button className="btn" onClick={() => load(true)} disabled={loading}>
          {loading ? "Обновляю…" : "Обновить"}
        </button>
        <span className="muted small">Поддерживаются: {Object.values(providers).map((p) => p.title).join(", ")}</span>
      </div>

      {error && <div className="notice notice-bad small">{error}</div>}

      {provisions.length > 0 && (
        <Provisions
          items={provisions}
          accounts={accounts}
          providers={providers}
          onChanged={() => {
            loadProvisions();
            load(true);
          }}
        />
      )}

      {provisions.length > 0 && accounts.length > 0 && <h2 className="section-title">Аккаунты</h2>}

      {accounts.length === 0 ? (
        <Empty>
          Добавьте API-ключ хостинга: админка покажет серверы аккаунта, а дальше через него можно будет заказывать новые серверы под VPN.
        </Empty>
      ) : (
        accounts.map((h) => (
          <AccountBlock
            key={h.id}
            hoster={h}
            provider={providers[h.provider]}
            index={index}
            onCreate={() => setCreating(h)}
            onEdit={() => setEditing(h)}
            onDelete={() => remove(h)}
            onDeleteServer={(server) => setDeleting({ hoster: h, server })}
          />
        ))
      )}

      {dnsData && <DnsAccounts data={dnsData} onChanged={loadDns} />}

      {creating && (
        <CreateServerDialog
          hoster={creating}
          dnsAccounts={dnsData?.accounts.filter((a) => a.ok && a.zones.length > 0) ?? []}
          providerTitle={providers[creating.provider]?.title ?? creating.provider}
          panels={panels}
          onClose={() => setCreating(null)}
          onStarted={() => {
            setCreating(null);
            loadProvisions();
          }}
        />
      )}

      {deleting && (
        <DeleteServerDialog
          hoster={deleting.hoster}
          server={deleting.server}
          providerTitle={providers[deleting.hoster.provider]?.title ?? deleting.hoster.provider}
          onClose={() => setDeleting(null)}
          onDeleted={() => {
            setDeleting(null);
            load(true);
            loadProvisions();
            onChanged();
          }}
        />
      )}

      {editing && (
        <HosterDialog
          providers={providers}
          hoster={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            load(true);
          }}
        />
      )}
    </>
  );
}

function AccountBlock({
  hoster: h,
  provider,
  index,
  onCreate,
  onEdit,
  onDelete,
  onDeleteServer,
}: {
  hoster: HosterInfo;
  provider: HosterProvider | undefined;
  index: Map<string, string>;
  onCreate: () => void;
  onEdit: () => void;
  onDelete: () => void;
  onDeleteServer: (server: HosterServer) => void;
}) {
  return (
    <section className="card hoster-card">
      <div className="card-head">
        <div className="hoster-title">
          <span className={`provider-badge provider-${h.provider}`}>{provider?.title ?? h.provider}</span>
          <div>
            <div className="strong">{h.name}</div>
            {h.account && (
              <div className="muted small">
                {[h.account.login, h.account.name, h.account.limits].filter(Boolean).join(" · ")}
              </div>
            )}
          </div>
        </div>
        <div className="hoster-actions">
          {h.ok ? <span className="badge badge-active">Ключ работает</span> : <span className="badge badge-expired">Ошибка</span>}
          {h.account?.balance && (
            <span className="badge badge-disabled" title="Деньги на счёте, расход за текущий месяц и долг — то, что отдаёт API хостера">
              {h.account.balance}
            </span>
          )}
          {h.ok && (
            <button className="btn btn-small btn-primary" onClick={onCreate}>
              + Создать сервер
            </button>
          )}
          <button className="btn btn-small" onClick={onEdit}>
            Изменить
          </button>
          <button className="btn btn-small btn-danger" onClick={onDelete}>
            Удалить
          </button>
        </div>
      </div>

      {!h.ok && <div className="error-text small hoster-error">{h.error}</div>}
      {h.servers_error && <div className="notice notice-bad small">Не удалось получить серверы: {h.servers_error}</div>}

      {h.ok && !h.servers_error && h.servers.length === 0 && <div className="muted small">В аккаунте пока нет серверов.</div>}

      {h.servers.length > 0 && (
        <div className="table-wrap">
          <table className="hoster-servers">
            <thead>
              <tr>
                <th>Сервер</th>
                <th>Статус</th>
                <th>Регион</th>
                <th>Тариф</th>
                <th>IP</th>
                <th>Создан</th>
                <th>В админке</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {h.servers.map((s) => {
                const where = [...s.ipv4, ...s.ipv6].map((ip) => index.get(ip)).find(Boolean);
                return (
                  <tr key={s.id}>
                    <td>
                      <div className="strong">{s.name}</div>
                      <div className="muted small">{s.kind}</div>
                    </td>
                    <td>
                      <span className="status">
                        <span className={`dot ${STATUS_CLASS[s.status]}`} /> {s.status_label || s.status}
                      </span>
                    </td>
                    <td>{s.region || "—"}</td>
                    <td>
                      <div>{s.plan || "—"}</div>
                      {(s.specs || s.price) && <div className="muted small">{[s.specs, s.price].filter(Boolean).join(" · ")}</div>}
                    </td>
                    <td className="mono">
                      {s.ipv4.join(", ") || "—"}
                      {s.ipv6.length > 0 && <div className="muted small hoster-ipv6">{s.ipv6.join(", ")}</div>}
                    </td>
                    <td className="small">{s.created_at ? new Date(s.created_at).toLocaleDateString("ru-RU") : "—"}</td>
                    <td>{where ? <span className="badge badge-main">{where}</span> : <span className="muted">—</span>}</td>
                    <td className="hoster-server-actions">
                      {s.deletable ? (
                        <button className="btn btn-small btn-danger" onClick={() => onDeleteServer(s)}>
                          Удалить
                        </button>
                      ) : (
                        <span className="muted small" title="VPS OVHcloud удаляется только в панели OVHcloud: расторжение подтверждается по почте">
                          в панели хостинга
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/** Empty secret fields; non-secret ones from the stored account or the field default. */
function credentialsFor(provider: HosterProvider, stored?: Record<string, string>): Record<string, string> {
  const credentials: Record<string, string> = {};
  for (const f of provider.fields) credentials[f.key] = f.secret ? "" : stored?.[f.key] ?? f.default ?? "";
  return credentials;
}

function HosterDialog({
  providers,
  hoster,
  onClose,
  onSaved,
}: {
  providers: Record<string, HosterProvider>;
  hoster: HosterInfo | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [form, setForm] = useState<HosterForm>(() => {
    const provider = hoster?.provider ?? Object.keys(providers)[0];
    return { provider, name: hoster?.name ?? "", credentials: credentialsFor(providers[provider], hoster?.credentials) };
  });
  const [shown, setShown] = useState<Record<string, boolean>>({});
  const [test, setTest] = useState<HosterAccount | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  const provider = providers[form.provider];
  const helpUrl = provider.help_urls?.[form.credentials.endpoint] ?? provider.help_url;

  const pickProvider = (id: string) => {
    setForm({ provider: id, name: form.name, credentials: credentialsFor(providers[id]) });
    setTest(null);
    setError("");
  };

  const setField = (key: string, value: string) => {
    setForm((f) => ({ ...f, credentials: { ...f.credentials, [key]: value } }));
    setTest(null);
  };

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

  const submit = (e: FormEvent) => {
    e.preventDefault();
    run("Проверяю ключ и сохраняю…", async () => {
      if (hoster) await api.updateHoster(hoster.id, form);
      else await api.createHoster(form);
      onSaved();
    });
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <form className="modal" onSubmit={submit}>
        <div className="modal-head">
          <h2>{hoster ? `Аккаунт «${hoster.name}»` : "Новый аккаунт хостинга"}</h2>
          <button type="button" className="btn btn-small" onClick={onClose} disabled={!!busy}>
            ✕
          </button>
        </div>

        {!hoster && (
          <div className="field">
            <span>Хостинг</span>
            <div className="segmented">
              {Object.entries(providers).map(([id, p]) => (
                <button key={id} type="button" className={form.provider === id ? "active" : ""} onClick={() => pickProvider(id)}>
                  {p.title}
                </button>
              ))}
            </div>
          </div>
        )}

        <label className="field">
          <span>Название в админке</span>
          <input className="input" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder={`${provider.title} — основной`} />
        </label>

        {provider.fields.map((f) =>
          f.options ? (
            <label key={f.key} className="field">
              <span>{f.label}</span>
              <select className="input" value={form.credentials[f.key]} onChange={(e) => setField(f.key, e.target.value)}>
                {f.options.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <label key={f.key} className="field">
              <span>{f.label}</span>
              <div className="input-with-button">
                <input
                  className="input mono"
                  type={f.secret && !shown[f.key] ? "password" : "text"}
                  required={!f.optional && !(f.secret && hoster?.secrets_set.includes(f.key))}
                  value={form.credentials[f.key]}
                  onChange={(e) => setField(f.key, e.target.value)}
                  placeholder={f.secret && hoster?.secrets_set.includes(f.key) ? "сохранён, оставьте пустым чтобы не менять" : f.placeholder ?? ""}
                  autoComplete="off"
                />
                {f.secret && (
                  <button type="button" className="btn btn-small" onClick={() => setShown((s) => ({ ...s, [f.key]: !s[f.key] }))}>
                    {shown[f.key] ? "Скрыть" : "Показать"}
                  </button>
                )}
              </div>
            </label>
          ),
        )}

        <div className="notice notice-info small">
          {provider.help}{" "}
          <a href={helpUrl} target="_blank" rel="noreferrer">
            Получить ключ →
          </a>
        </div>

        {test && (
          <div className="notice notice-ok small">
            Ключ работает: {[test.login, test.name].filter(Boolean).join(" · ")}
            {test.balance && `, ${test.balance}`}
          </div>
        )}
        {busy && <div className="notice notice-info small">{busy}</div>}
        {error && <div className="notice notice-bad small">{error}</div>}

        <div className="modal-actions">
          <button type="button" className="btn" disabled={!!busy} onClick={() => run("Проверяю ключ…", async () => setTest(await api.testHoster(form, hoster?.id)))}>
            Проверить ключ
          </button>
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose} disabled={!!busy}>
            Отмена
          </button>
          <button type="submit" className="btn btn-primary" disabled={!!busy}>
            Сохранить
          </button>
        </div>
      </form>
    </div>
  );
}
