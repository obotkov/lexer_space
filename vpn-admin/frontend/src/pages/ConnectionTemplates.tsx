import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import {
  api,
  type CdnAccount,
  type ConnectionKind,
  type ConnectionNet,
  type ConnectionOptionValue,
  type ConnectionsData,
  type ConnectionTemplate,
  type ConnectionUsers,
} from "../api";
import { Switch } from "../components/NodeDialog";

const NET_LABEL: Record<ConnectionNet, string> = { tcp: "TCP", udp: "UDP", both: "TCP+UDP" };

const OPTION_LABELS: Record<string, { label: string; hint?: string }> = {
  sni: { label: "Сайт для маскировки (SNI)", hint: "Чужой сайт с TLS 1.3 и HTTP/2. Несколько через запятую: каждому серверу достанется случайный" },
  fingerprint: { label: "Отпечаток TLS-клиента (fingerprint)" },
  flow: {
    label: "Flow для пользователей",
    hint: "В 3x-ui v3 flow хранится у пользователя: xtls-rprx-vision включается тем, у кого он ещё не задан. 3x-ui применяет его только к REALITY по TCP",
  },
  short_ids: { label: "Сколько shortId выдать", hint: "От 1 до 8" },
  mode: { label: "Режим XHTTP" },
  path: { label: "Путь", hint: "Пусто: на каждом сервере свой случайный" },
  service_name: { label: "Имя сервиса gRPC", hint: "Пусто: на каждом сервере своё случайное" },
  method: {
    label: "Шифрование",
    hint: "У пользователя 3x-ui один пароль на все протоколы: в Shadowsocks 2022 попадут те, чей пароль подходит как ключ этого шифрования (так у всех, кого создаёт админка, для aes-128)",
  },
  masquerade: { label: "На посторонние запросы отвечать сайтом-заглушкой сервера" },
  congestion: { label: "Управление перегрузкой" },
  mtu: { label: "MTU" },
  subnet: {
    label: "Подсеть для клиентов",
    hint: "У пользователя 3x-ui один адрес на все WireGuard и AmneziaWG: в подключение попадут только те, чей адрес из этой подсети или у кого адреса ещё нет",
  },
  variant: { label: "Параметры маскировки" },
  dns: { label: "DNS для клиентов" },
  domain: { label: "Домен FakeTLS", hint: "Под какой сайт маскируется прокси Telegram" },
  cdn_account_id: { label: "CDN-аккаунт", hint: "Подключается на странице VPN API Hoster, блок «CDN для белых списков»" },
  cdn_subdomain: {
    label: "Имя CDN-ресурса в Cloudflare",
    hint: "Поддомен в домене Cloudflare сервера: на него выпускается сертификат и создаётся CDN-ресурс, клиенты видят его в SNI. Работают макросы {server}, {region} и другие, но в имени остаются только латиница, цифры и дефис",
  },
  uplink: { label: "Как клиент отправляет данные" },
};

const CHOICE_LABELS: Record<string, Record<string, string>> = {
  flow: { "xtls-rprx-vision": "xtls-rprx-vision", "": "без flow" },
  variant: { classic: "Классические: AmneziaVPN, Mihomo, роутеры Keenetic", full: "AmneziaWG 3.1: только приложения AmneziaVPN/AmneziaWG" },
  mode: { auto: "auto", "packet-up": "packet-up", "stream-up": "stream-up", "stream-one": "stream-one" },
  uplink: {
    "get-header": "GET-запросами, данные в заголовках по 6000 байт: проходит через фильтры, но медленнее",
    "post-body": "POST-запросами (обычный packet-up): быстрее",
  },
};

function portText(t: { port: number; net: ConnectionNet }) {
  return `${t.port || "случайный"}${t.net === "tcp" ? "" : ` / ${NET_LABEL[t.net]}`}`;
}

function summary(t: ConnectionTemplate): string {
  const o = t.options;
  switch (t.kind) {
    case "vless_reality":
      return `${o.sni} · ${o.fingerprint}${o.flow ? ` · ${o.flow}` : ""}`;
    case "vless_xhttp_reality":
      return `${o.sni} · ${o.mode}${o.path ? ` · ${o.path}` : ""}`;
    case "vless_ws_tls":
    case "vmess_ws_tls":
      return `путь ${o.path || "случайный"} · ${o.fingerprint}`;
    case "trojan_grpc_tls":
      return `сервис ${o.service_name || "случайный"} · ${o.fingerprint}`;
    case "shadowsocks":
      return String(o.method);
    case "hysteria2":
      return o.masquerade ? "отвечает сайтом-заглушкой" : "";
    case "tuic":
      return String(o.congestion);
    case "wireguard":
      return `${o.subnet} · MTU ${o.mtu}`;
    case "amneziawg":
      return `${o.subnet} · ${o.variant === "full" ? "AmneziaWG 3.1" : "классические параметры"}`;
    case "mtproto":
      return String(o.domain);
    case "vless_xhttp_cdn":
      return `${o.cdn_subdomain}.<домен Cloudflare> · ${o.uplink === "get-header" ? "GET в заголовках" : "POST"}`;
    default:
      return "";
  }
}

/** Fixed ports that two enabled templates would both take on every server (the later one gets a random port). */
function portClashes(templates: ConnectionTemplate[]): Set<number> {
  const seen = new Map<string, number>();
  const clashes = new Set<number>();
  for (const t of templates) {
    if (!t.enabled || !t.port) continue;
    for (const n of t.net === "both" ? ["tcp", "udp"] : [t.net]) {
      const key = `${t.port}/${n}`;
      if (seen.has(key)) clashes.add(t.id);
      else seen.set(key, t.id);
    }
  }
  return clashes;
}

/** Connections every new server gets: inbounds of the main panel bound to the new node. */
// what a remark can hold; the backend fills them in (connections.macros)
const REMARK_MACROS: [string, string][] = [
  ["{server}", "имя сервера"],
  ["{region}", "регион: 🇩🇪 Германия, Франкфурт"],
  ["{flag}", "флаг страны 🇩🇪"],
  ["{country}", "страна"],
  ["{city}", "город"],
];

export function ConnectionTemplates() {
  const [data, setData] = useState<ConnectionsData | null>(null);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState<ConnectionTemplate | "new" | null>(null);

  const load = useCallback(() => {
    api.connections().then(setData, (e) => setError((e as Error).message));
  }, []);
  useEffect(load, [load]);

  const run = async (action: () => Promise<unknown>) => {
    setError("");
    try {
      await action();
    } catch (e) {
      setError((e as Error).message);
    }
    load();
  };

  const move = (index: number, delta: number) => {
    if (!data) return;
    const ids = data.templates.map((t) => t.id);
    const [id] = ids.splice(index, 1);
    ids.splice(index + delta, 0, id);
    setData({ ...data, templates: ids.map((i) => data.templates.find((t) => t.id === i)!) });
    run(() => api.orderConnections(ids));
  };

  if (!data) return error ? <div className="notice notice-bad">{error}</div> : <div className="muted">Загружаю…</div>;

  const enabled = data.templates.filter((t) => t.enabled);
  const clashes = portClashes(data.templates);
  const tunnels = enabled.filter((t) => t.kind === "wireguard" || t.kind === "amneziawg");
  const subnets = new Set(tunnels.map((t) => String(t.options.subnet)));

  return (
    <>
      <div className="notice notice-info small">
        Эти подключения создаются на каждом новом сервере сразу после того, как он станет узлом основной панели: у каждого сервера свои
        ключи, пути и пароли, порты открываются в ufw. Уже работающему серверу недостающие подключения добавляет кнопка «Раскатать
        подключения» на его карточке в разделе «VPN API Hoster». Сейчас включено: <b>{enabled.length}</b> из {data.templates.length}.
      </div>
      {error && <div className="notice notice-bad small">{error}</div>}

      {subnets.size > 1 && (
        <div className="notice notice-warn small">
          Включены WireGuard/AmneziaWG с разными подсетями ({[...subnets].join(", ")}). В 3x-ui v3 у пользователя один адрес на все такие
          подключения, поэтому пользователи попадут только в те, чья подсеть совпадает с их адресом (обычно в первое по списку). Чтобы
          пользователи были во всех, задайте им одну подсеть, но держите на сервере одно подключение AmneziaWG: два с одной подсетью на
          одном сервере конфликтуют.
        </div>
      )}

      <UsersCard users={data.users} emails={data.emails} onSaved={load} />

      <div className="toolbar section-title">
        <h2>Подключения</h2>
        <button className="btn btn-small btn-primary" onClick={() => setEditing("new")}>
          + Добавить подключение
        </button>
        {data.templates.length > 0 && (
          <button className="btn btn-small" onClick={() => run(() => api.enableAllConnections(enabled.length < data.templates.length))}>
            {enabled.length < data.templates.length ? "Включить все" : "Выключить все"}
          </button>
        )}
      </div>

      {data.templates.length === 0 ? (
        <div className="muted small">Подключений нет: новые серверы будут подключаться к основной панели без них.</div>
      ) : (
        <div className="table-wrap">
          <table className="conn-table">
            <thead>
              <tr>
                <th></th>
                <th>Название</th>
                <th>Тип</th>
                <th>Порт</th>
                <th>Настройки</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {data.templates.map((t, i) => (
                <tr key={t.id} className={t.enabled ? "" : "row-muted"}>
                  <td>
                    <Switch
                      checked={t.enabled}
                      title={t.enabled ? "Создаётся на новых серверах" : "Выключено: на новых серверах не создаётся"}
                      onChange={(v) => run(() => api.enableConnection(t.id, v))}
                    />
                  </td>
                  <td className="strong">{t.remark}</td>
                  <td>
                    {t.kind_title} {t.tls && <span className="tag tag-soft">TLS</span>}
                  </td>
                  <td className="mono">
                    {portText(t)}
                    {clashes.has(t.id) && (
                      <div className="error-text small" title="Этот порт уже занят подключением выше: на сервере это получит случайный порт">
                        порт занят выше
                      </div>
                    )}
                  </td>
                  <td className="muted small conn-options">{summary(t)}</td>
                  <td className="actions">
                    <span className="conn-move">
                      <button className="btn btn-small" disabled={i === 0} onClick={() => move(i, -1)} aria-label="Выше">
                        ↑
                      </button>
                      <button className="btn btn-small" disabled={i === data.templates.length - 1} onClick={() => move(i, 1)} aria-label="Ниже">
                        ↓
                      </button>
                    </span>{" "}
                    <button className="btn btn-small" onClick={() => setEditing(t)}>
                      Изменить
                    </button>{" "}
                    <button
                      className="btn btn-small btn-danger"
                      onClick={() =>
                        confirm(`Удалить подключение «${t.remark}» из списка? На уже созданных серверах оно останется.`) &&
                        run(() => api.deleteConnection(t.id))
                      }
                    >
                      Удалить
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {editing && (
        <TemplateDialog
          template={editing === "new" ? null : editing}
          kinds={data.kinds}
          cdnAccounts={data.cdn_accounts}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null);
            load();
          }}
        />
      )}
    </>
  );
}

function UsersCard({ users, emails, onSaved }: { users: ConnectionUsers; emails: string[]; onSaved: () => void }) {
  const [mode, setMode] = useState(users.mode);
  const [chosen, setChosen] = useState(new Set(users.emails));
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    // chosen users gone from the panels stay listed, so they can be unticked
    const all = [...new Set([...emails, ...users.emails])].sort();
    return q ? all.filter((e) => e.toLowerCase().includes(q)) : all;
  }, [emails, users.emails, query]);

  const dirty = mode !== users.mode || chosen.size !== users.emails.length || users.emails.some((e) => !chosen.has(e));

  const save = async () => {
    setBusy(true);
    setError("");
    try {
      await api.setConnectionUsers({ mode, emails: [...chosen] });
      setSaved(true);
      onSaved();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const toggle = (email: string) => {
    setSaved(false);
    setChosen((s) => {
      const next = new Set(s);
      if (next.has(email)) next.delete(email);
      else next.add(email);
      return next;
    });
  };

  return (
    <section className="card conn-users">
      <div className="card-head">
        <div className="strong">Кого добавлять в подключения нового сервера</div>
      </div>
      <div className="segmented">
        {(
          [
            ["all", "Всех пользователей"],
            ["selected", "Выбранных"],
            ["none", "Никого"],
          ] as const
        ).map(([value, label]) => (
          <button
            key={value}
            type="button"
            className={mode === value ? "active" : ""}
            aria-pressed={mode === value}
            onClick={() => {
              setMode(value);
              setSaved(false);
            }}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="muted small">
        {mode === "all"
          ? "Все пользователи основной панели получат новые подключения: их подписки сразу покажут новый сервер."
          : mode === "selected"
            ? "Только отмеченные пользователи получат новые подключения. Остальных можно добавить потом на вкладке «Пользователи»."
            : "Подключения создаются пустыми: пользователей добавляете сами."}
      </div>
      {mode === "selected" &&
        (emails.length === 0 && users.emails.length === 0 ? (
          <div className="muted small">В основных панелях пока нет пользователей.</div>
        ) : (
          <>
            <input className="input" placeholder="Поиск пользователя" value={query} onChange={(e) => setQuery(e.target.value)} />
            <div className="node-picker conn-emails">
              {shown.map((e) => (
                <label key={e} className="checkbox node-option">
                  <input type="checkbox" checked={chosen.has(e)} onChange={() => toggle(e)} />
                  <span>
                    {e}
                    {!emails.includes(e) && <span className="muted small"> — нет в панелях</span>}
                  </span>
                </label>
              ))}
            </div>
            <div className="muted small">Отмечено: {chosen.size}</div>
          </>
        ))}
      {error && <div className="notice notice-bad small">{error}</div>}
      <div className="card-actions">
        <button className="btn btn-small btn-primary" disabled={busy || !dirty} onClick={save}>
          {busy ? "Сохраняю…" : "Сохранить"}
        </button>
        {saved && !dirty && <span className="muted small">Сохранено</span>}
      </div>
    </section>
  );
}

function defaults(kind: ConnectionKind): Record<string, ConnectionOptionValue> {
  return Object.fromEntries(Object.entries(kind.options).map(([name, o]) => [name, o.default]));
}

function TemplateDialog({
  template,
  kinds,
  cdnAccounts,
  onClose,
  onSaved,
}: {
  template: ConnectionTemplate | null;
  kinds: ConnectionKind[];
  cdnAccounts: CdnAccount[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const [kindId, setKindId] = useState(template?.kind ?? kinds[0].kind);
  const kind = kinds.find((k) => k.kind === kindId) ?? kinds[0];
  const [remark, setRemark] = useState(template?.remark ?? `{server} ${kind.remark}`);
  const [enabled, setEnabled] = useState(template?.enabled ?? true);
  const [port, setPort] = useState(template ? template.port : kind.port);
  const withAccount = (o: Record<string, ConnectionOptionValue>) =>
    "cdn_account_id" in o && !o.cdn_account_id && cdnAccounts.length ? { ...o, cdn_account_id: cdnAccounts[0].id } : o;
  const [options, setOptions] = useState<Record<string, ConnectionOptionValue>>(
    template ? { ...defaults(kind), ...template.options } : withAccount(defaults(kind)),
  );
  const [sni, setSni] = useState<Record<string, string> | null>(null);
  const [checking, setChecking] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const pickKind = (id: string) => {
    const k = kinds.find((x) => x.kind === id)!;
    setKindId(id);
    setRemark(`{server} ${k.remark}`);
    setPort(k.port);
    setOptions(withAccount(defaults(k)));
    setSni(null);
  };

  const set = (name: string, value: ConnectionOptionValue) => {
    setOptions((o) => ({ ...o, [name]: value }));
    if (name === "sni") setSni(null);
  };

  const checkSni = async () => {
    setChecking(true);
    try {
      setSni((await api.checkSni(String(options.sni))).results);
    } catch (e) {
      setSni({ [String(options.sni)]: (e as Error).message });
    } finally {
      setChecking(false);
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    const form = { kind: kindId, remark, enabled, port, options };
    try {
      if (template) await api.updateConnection(template.id, form);
      else await api.createConnection(form);
      onSaved();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <form className="modal modal-wide" onSubmit={submit}>
        <div className="modal-head">
          <h2>{template ? `Подключение «${template.remark}»` : "Новое подключение"}</h2>
          <button type="button" className="btn btn-small" onClick={onClose} disabled={busy}>
            ✕
          </button>
        </div>

        <label className="field">
          <span>Тип</span>
          <select className="input" value={kindId} onChange={(e) => pickKind(e.target.value)} disabled={!!template}>
            {kinds.map((k) => (
              <option key={k.kind} value={k.kind}>
                {k.title}
              </option>
            ))}
          </select>
          <small className="muted">
            {kind.note}. Протокол 3x-ui: {kind.protocol}, {NET_LABEL[kind.net]}.
          </small>
        </label>

        {kindId === "vless_xhttp_cdn" && (
          <div className="notice notice-info small">
            Для серверов, заказанных с доменом Cloudflare. При раскатке админка создаёт в этом домене имя (по умолчанию cdn-имя сервера),
            выпускает на него сертификат Let's Encrypt в облаке CDN (проверка домена — через запись в Cloudflare), создаёт CDN-ресурс с узлом
            в качестве источника по HTTPS и направляет имя на CDN. В ссылки попадает технический адрес CDN, имя — в SNI и Host. Сертификат и
            ресурс создаются до получаса.
            {cdnAccounts.length === 0 && <div className="error-text">CDN-аккаунт ещё не подключён: сначала подключите его на странице VPN API Hoster.</div>}
          </div>
        )}

        {kind.tls && kindId !== "vless_xhttp_cdn" && (
          <div className="notice notice-info small">
            Использует сертификат сервера, который получает установка: Let's Encrypt на домен или IP. Если сервер остался с самоподписанным
            сертификатом, в ссылки попадёт его отпечаток.
          </div>
        )}

        <div className="field">
          <span id="conn-remark">Название</span>
          <input aria-labelledby="conn-remark" className="input" required maxLength={100} value={remark} onChange={(e) => setRemark(e.target.value)} />
          <div className="conn-macros">
            {REMARK_MACROS.map(([macro, hint]) => (
              <button
                key={macro}
                type="button"
                className="btn btn-small mono"
                title={`${hint} — добавить в конец названия`}
                onClick={() => setRemark((r) => `${r.trimEnd()} ${macro}`.trimStart())}
              >
                {macro}
              </button>
            ))}
          </div>
          <small className="muted">
            Макросы заменяются данными сервера при раскатке, так в приложениях видно, какой это сервер: {REMARK_MACROS.map(([m, h]) => `${m} — ${h}`).join(", ")}
          </small>
        </div>

        <div className="field-row">
          <label className="field">
            <span>Порт</span>
            <div className="segmented">
              <button type="button" className={port ? "" : "active"} onClick={() => setPort(0)}>
                Случайный
              </button>
              <button type="button" className={port ? "active" : ""} onClick={() => setPort(port || kind.port || 443)}>
                Свой
              </button>
            </div>
          </label>
          {port > 0 && (
            <label className="field">
              <span>Номер порта ({NET_LABEL[kind.net]})</span>
              <input className="input mono" type="number" min={1} max={65535} required value={port} onChange={(e) => setPort(Number(e.target.value))} />
            </label>
          )}
        </div>
        <small className="muted">
          {port
            ? "Если на сервере этот порт уже занят (панелью, подпиской, сайтом-заглушкой на 80 или другим подключением), подключение получит случайный."
            : "Каждому серверу свой свободный пятизначный порт."}
        </small>

        {Object.entries(kind.options).map(([name, spec]) => {
          const meta = OPTION_LABELS[name] ?? { label: name };
          const value = options[name];
          if (name === "cdn_account_id") {
            return (
              <label key={name} className="field">
                <span>{meta.label}</span>
                <select className="input" required value={String(value || "")} onChange={(e) => set(name, Number(e.target.value))}>
                  <option value="" disabled>
                    {cdnAccounts.length ? "выберите" : "нет подключённых CDN-аккаунтов"}
                  </option>
                  {cdnAccounts.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.provider_title}: {a.name}
                    </option>
                  ))}
                </select>
                {meta.hint && <small className="muted">{meta.hint}</small>}
              </label>
            );
          }
          if (typeof spec.default === "boolean") {
            return (
              <label key={name} className="checkbox">
                <input type="checkbox" checked={!!value} onChange={(e) => set(name, e.target.checked)} />
                {meta.label}
              </label>
            );
          }
          return (
            <label key={name} className="field">
              <span>{meta.label}</span>
              {spec.choices ? (
                <select className="input" value={String(value)} onChange={(e) => set(name, e.target.value)}>
                  {spec.choices.map((c) => (
                    <option key={String(c)} value={String(c)}>
                      {CHOICE_LABELS[name]?.[String(c)] ?? String(c)}
                    </option>
                  ))}
                </select>
              ) : name === "sni" ? (
                <div className="input-with-button">
                  <input className="input mono" required value={String(value ?? "")} onChange={(e) => set(name, e.target.value)} />
                  <button type="button" className="btn btn-small" onClick={checkSni} disabled={checking || !String(value ?? "").trim()}>
                    {checking ? "Проверяю…" : "Проверить"}
                  </button>
                </div>
              ) : (
                <input
                  className={`input${typeof spec.default === "number" ? "" : " mono"}`}
                  type={typeof spec.default === "number" ? "number" : "text"}
                  value={String(value ?? "")}
                  onChange={(e) => set(name, typeof spec.default === "number" ? Number(e.target.value) : e.target.value)}
                />
              )}
              {meta.hint && <small className="muted">{meta.hint}</small>}
              {name === "sni" && sni && (
                <div className="sni-results small">
                  {Object.entries(sni).map(([host, problem]) => (
                    <span key={host} className={problem ? "error-text" : "good-text"}>
                      {host}: {problem || "подходит (TLS 1.3 и HTTP/2)"}
                    </span>
                  ))}
                </div>
              )}
            </label>
          );
        })}

        <label className="checkbox">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Создавать на новых серверах
        </label>

        {error && <div className="notice notice-bad small">{error}</div>}

        <div className="modal-actions">
          <span className="spacer" />
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
            Отмена
          </button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? "Сохраняю…" : "Сохранить"}
          </button>
        </div>
      </form>
    </div>
  );
}
