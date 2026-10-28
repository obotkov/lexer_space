import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import {
  api,
  type CdnAccount,
  type ConnectionCustom,
  type ConnectionKind,
  type ConnectionNet,
  type ConnectionOptionValue,
  type ConnectionsData,
  type ConnectionTemplate,
  type ConnectionUsers,
  type MainInbound,
} from "../api";
import { Switch } from "../components/NodeDialog";

const NET_LABEL: Record<ConnectionNet, string> = { tcp: "TCP", udp: "UDP", both: "TCP+UDP" };

const OPTION_LABELS: Record<string, { label: string; hint?: string }> = {
  sni: { label: "Сайт для маскировки (SNI)", hint: "Чужой сайт с TLS 1.3 и HTTP/2. Несколько через запятую: каждому серверу достанется случайный" },
  fingerprint: { label: "Отпечаток TLS-клиента (fingerprint)" },
  flow: {
    label: "Flow для пользователей",
    hint: "В 3x-ui v3 flow хранится у пользователя: xtls-rprx-vision включается тем, у кого он ещё не задан. 3x-ui применяет его только к VLESS по TCP (REALITY и TLS)",
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
    hint: "Поддомен в домене Cloudflare сервера: на него выпускается сертификат и создаётся CDN-ресурс, клиенты видят его в SNI. У Beget это только название ресурса в его панели: клиенты ходят на технический адрес ….begetcdn.cloud. Работают макросы {server}, {region} и другие, но в имени остаются только латиница, цифры и дефис",
  },
  uplink: { label: "Как клиент отправляет данные" },
  dns_subdomain: {
    label: "Имя DNS-туннеля в Cloudflare",
    hint: "Поддомен в домене Cloudflare сервера: админка делегирует его серверу записью NS (на <имя>-ns.<домен> с IP сервера), и резолверы несут запросы туннеля на его порт 53. Работают макросы {server}, {region} и другие",
  },
  resolvers: {
    label: "DNS-серверы для клиентов",
    hint: "Через них клиенты отправляют запросы туннеля, через запятую: udp://77.88.8.8:53, tcp://…, https://dns.google/dns-query. В режиме белых списков берите тот, что у оператора открыт (например, Яндекс DNS)",
  },
};

// the same option means something else in another kind
const KIND_OPTION_LABELS: Record<string, Record<string, { label: string; hint?: string }>> = {
  vless_tcp_tls: {
    sni: {
      label: "SNI (домен)",
      hint: "Пусто: домен сервера, на который выпущен его сертификат, — так клиенты проверяют настоящий сертификат. Свой домен нужен, только если он тоже указывает на сервер и есть в его сертификате, иначе клиенты его не примут (на сервере без домена их выручает закреплённый отпечаток сертификата)",
    },
  },
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
    case "vless_tcp_tls":
      return `${o.sni || "домен сервера"} · ${o.fingerprint}${o.flow ? ` · ${o.flow}` : ""}`;
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
    case "vless_xdns":
      return `${o.dns_subdomain}.<домен Cloudflare> · ${o.resolvers}`;
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
                  <td className="muted small conn-options">{[summary(t), t.custom && "свой JSON"].filter(Boolean).join(" · ")}</td>
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
  // own JSON: what differs from the form's build; the JSON tab shows the whole of it
  const [tab, setTab] = useState<"form" | "json">("form");
  const [custom, setCustom] = useState<ConnectionCustom | null>(template?.custom ?? null);
  const [jsonText, setJsonText] = useState("");
  const [jsonDirty, setJsonDirty] = useState(false);
  const [jsonBusy, setJsonBusy] = useState(false);
  const [jsonError, setJsonError] = useState("");
  const [importing, setImporting] = useState(false);
  const [importText, setImportText] = useState("");
  const [keepSecrets, setKeepSecrets] = useState(false);
  const [importNotes, setImportNotes] = useState<string[]>([]);

  const pickKind = (id: string) => {
    const k = kinds.find((x) => x.kind === id)!;
    setKindId(id);
    setRemark(`{server} ${k.remark}`);
    setPort(k.port);
    setOptions(withAccount(defaults(k)));
    setSni(null);
    setCustom(null);
    setJsonDirty(false);
    if (tab === "json") loadJson(id, withAccount(defaults(k)), null);
  };

  const loadJson = async (k: string, o: Record<string, ConnectionOptionValue>, c: ConnectionCustom | null) => {
    setJsonBusy(true);
    setJsonError("");
    try {
      setJsonText(JSON.stringify((await api.connectionPreview(k, o, c)).json, null, 2));
      setJsonDirty(false);
    } catch (e) {
      setJsonError((e as Error).message);
    } finally {
      setJsonBusy(false);
    }
  };

  /** The edited JSON turned into the own JSON to keep; throws (shown on the tab) when it does not fit. */
  const commitJson = async (): Promise<ConnectionCustom | null> => {
    if (!jsonDirty) return custom;
    let parsed: unknown;
    try {
      parsed = JSON.parse(jsonText);
    } catch (e) {
      const message = `JSON не читается: ${(e as Error).message}`;
      setJsonError(message);
      setTab("json");
      throw new Error(message);
    }
    try {
      const result = (await api.connectionCustom(kindId, options, parsed)).custom;
      setCustom(result);
      setJsonDirty(false);
      setJsonError("");
      return result;
    } catch (e) {
      setJsonError((e as Error).message);
      setTab("json");
      throw e;
    }
  };

  const showTab = async (next: "form" | "json") => {
    if (next === tab) return;
    if (next === "json") {
      setTab("json");
      loadJson(kindId, options, custom);
      return;
    }
    try {
      await commitJson();
      setTab("form");
    } catch {
      // the error stays on the JSON tab
    }
  };

  const resetJson = () => {
    setCustom(null);
    setImportNotes([]);
    loadJson(kindId, options, null);
  };

  const importConfig = async () => {
    setJsonBusy(true);
    setJsonError("");
    try {
      const r = await api.importConnection(importText, keepSecrets);
      if (template && r.kind !== kindId) {
        const title = kinds.find((k) => k.kind === r.kind)?.title ?? r.kind;
        throw new Error(`Это конфиг типа «${title}», а подключение — «${kind.title}»: загрузите его в новое подключение`);
      }
      const k = kinds.find((x) => x.kind === r.kind)!;
      const nextOptions = withAccount({ ...defaults(k), ...r.options });
      if (!template && r.kind !== kindId) {
        setKindId(r.kind);
        setRemark(`{server} ${k.remark}`);
      }
      setOptions(nextOptions);
      if (r.port) setPort(r.port);
      setCustom(r.custom);
      setImportNotes(r.notes);
      setImporting(false);
      setImportText("");
      setJsonText(JSON.stringify((await api.connectionPreview(r.kind, nextOptions, r.custom)).json, null, 2));
      setJsonDirty(false);
    } catch (e) {
      setJsonError((e as Error).message);
    } finally {
      setJsonBusy(false);
    }
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
    let own: ConnectionCustom | null;
    try {
      own = await commitJson();
    } catch {
      return;
    }
    setBusy(true);
    setError("");
    const form = { kind: kindId, remark, enabled, port, options, custom: own };
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

        <div className="segmented">
          <button type="button" className={tab === "form" ? "active" : ""} aria-pressed={tab === "form"} onClick={() => showTab("form")}>
            Настройки
          </button>
          <button type="button" className={tab === "json" ? "active" : ""} aria-pressed={tab === "json"} onClick={() => showTab("json")}>
            JSON{custom ? " · свой" : ""}
          </button>
        </div>

        {tab === "json" && (
          <JsonTab
            text={jsonText}
            busy={jsonBusy}
            error={jsonError}
            custom={custom}
            notes={importNotes}
            onChange={(t) => {
              setJsonText(t);
              setJsonDirty(true);
            }}
            onReset={resetJson}
            importing={importing}
            onImporting={setImporting}
            importText={importText}
            onImportText={setImportText}
            keepSecrets={keepSecrets}
            onKeepSecrets={setKeepSecrets}
            onImport={importConfig}
          />
        )}

        {tab === "form" && custom && (
          <div className="notice notice-info small">
            У подключения свой JSON: его изменения применяются поверх этих настроек, остальное берётся отсюда.{" "}
            <button type="button" className="link-button" onClick={() => showTab("json")}>
              Открыть JSON
            </button>
          </div>
        )}

        {tab === "form" && (
          <>
        {kindId === "vless_xhttp_cdn" && (
          <div className="notice notice-info small">
            Для серверов, заказанных с доменом Cloudflare. При раскатке админка создаёт в этом домене имя (по умолчанию cdn-имя сервера),
            выпускает на него сертификат Let's Encrypt в облаке CDN, создаёт CDN-ресурс с узлом в качестве источника по HTTPS и направляет
            имя на CDN. В Yandex Cloud домен проверяется через запись в Cloudflare до создания ресурса, в VK Cloud — через сам CDN после него.
            В ссылки попадает технический адрес CDN, имя — в SNI и Host. Сертификат и ресурс создаются до получаса. Beget свой домен не
            раздаёт: клиенты ходят на технический адрес ресурса (….begetcdn.cloud), домен Cloudflare серверу не нужен, а отправка — только через GET.
            {cdnAccounts.length === 0 && <div className="error-text">CDN-аккаунт ещё не подключён: сначала подключите его на странице VPN API Hoster.</div>}
          </div>
        )}

        {kindId === "vless_xdns" && (
          <div className="notice notice-info small">
            Для сетей, где проходит только DNS. Нужен сервер, заказанный с доменом Cloudflare: при раскатке админка создаёт в этом домене
            имя туннеля (по умолчанию t-имя сервера) и делегирует его серверу записью NS на t-имя-ns с IP сервера. Клиенты шлют DNS-запросы
            через указанные DNS-серверы, те приводят их на UDP-порт 53 сервера (он слушает только свой IP, чтобы не мешать systemd-resolved).
            Порт 53 обязателен: если он занят, подключение не создастся. Имя туннеля у каждого сервера своё и подставляется даже поверх
            своего JSON. Делегирование расходится по DNS от нескольких минут до часа; скорость — десятки килобайт в секунду.
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
          const meta = KIND_OPTION_LABELS[kindId]?.[name] ?? OPTION_LABELS[name] ?? { label: name };
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

          </>
        )}

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
          <button type="submit" className="btn btn-primary" disabled={busy || jsonBusy}>
            {busy ? "Сохраняю…" : "Сохранить"}
          </button>
        </div>
      </form>
    </div>
  );
}

/** The template's inbound as JSON: edited in place, or loaded from someone else's config. */
function JsonTab({
  text,
  busy,
  error,
  custom,
  notes,
  onChange,
  onReset,
  importing,
  onImporting,
  importText,
  onImportText,
  keepSecrets,
  onKeepSecrets,
  onImport,
}: {
  text: string;
  busy: boolean;
  error: string;
  custom: ConnectionCustom | null;
  notes: string[];
  onChange: (text: string) => void;
  onReset: () => void;
  importing: boolean;
  onImporting: (on: boolean) => void;
  importText: string;
  onImportText: (text: string) => void;
  keepSecrets: boolean;
  onKeepSecrets: (on: boolean) => void;
  onImport: () => void;
}) {
  const [mains, setMains] = useState<MainInbound[] | null>(null);
  const [mainsError, setMainsError] = useState("");
  const [picked, setPicked] = useState("");
  const [taking, setTaking] = useState(false);

  useEffect(() => {
    if (!importing || mains) return;
    api.mainInbounds().then(
      (r) => {
        setMains(r.inbounds);
        setMainsError(r.errors.join("; "));
        if (r.inbounds.length) setPicked(`${r.inbounds[0].panel_id}:${r.inbounds[0].id}`);
      },
      (e) => setMainsError((e as Error).message),
    );
  }, [importing, mains]);

  const takeMain = async () => {
    const [panelId, inboundId] = picked.split(":").map(Number);
    setTaking(true);
    setMainsError("");
    try {
      onImportText((await api.mainInbound(panelId, inboundId)).text);
    } catch (e) {
      setMainsError((e as Error).message);
    } finally {
      setTaking(false);
    }
  };

  return (
    <div className="field">
      <small className="muted">
        Разделы settings, streamSettings и sniffing инбаунда 3x-ui так, как их получит сервер. <span className="mono">"{"{auto}"}"</span> — значение,
        которое у каждого сервера своё: ключи, пароли, сертификат, случайный путь. Админка хранит только то, что вы изменили, поэтому остальное
        по-прежнему берётся с вкладки «Настройки». Чтобы убрать параметр, поставьте ему <span className="mono">null</span>. Пользователей
        (clients) добавляет админка.
      </small>
      <textarea
        className="input mono json-editor"
        spellCheck={false}
        value={busy && !text ? "Загружаю…" : text}
        onChange={(e) => onChange(e.target.value)}
        disabled={busy}
        aria-label="JSON подключения"
      />
      {error && <div className="notice notice-bad small">{error}</div>}
      {notes.map((n) => (
        <div key={n} className="notice notice-warn small">
          {n}
        </div>
      ))}
      <div className="action-row">
        <button type="button" className="btn btn-small" onClick={() => onImporting(!importing)} disabled={busy}>
          {importing ? "Скрыть загрузку" : "Загрузить чужой конфиг"}
        </button>
        {custom && (
          <button type="button" className="btn btn-small" onClick={onReset} disabled={busy}>
            Сбросить свой JSON
          </button>
        )}
      </div>
      {importing && (
        <div className="json-import">
          <label className="field">
            <span>С основной панели</span>
            <div className="input-with-button">
              <select className="input" value={picked} onChange={(e) => setPicked(e.target.value)} disabled={!mains?.length || taking}>
                {!mains && <option value="">загружаю инбаунды…</option>}
                {mains?.length === 0 && <option value="">инбаундов нет</option>}
                {mains?.map((i) => (
                  <option key={`${i.panel_id}:${i.id}`} value={`${i.panel_id}:${i.id}`}>
                    {i.xdns ? "DNS-туннель · " : ""}
                    {i.server} · {i.remark || i.protocol} · {i.protocol}
                    {i.network ? `/${i.network}` : ""} · {i.port}
                  </option>
                ))}
              </select>
              <button type="button" className="btn btn-small" onClick={takeMain} disabled={!picked || taking || busy}>
                {taking ? "Беру…" : "Взять"}
              </button>
            </div>
            <small className="muted">Админка подставит JSON инбаунда ниже (без пользователей); затем нажмите «Загрузить».</small>
          </label>
          {mainsError && <div className="notice notice-warn small">{mainsError}</div>}
          <textarea
            className="input mono json-editor json-editor-small"
            spellCheck={false}
            placeholder="Инбаунд 3x-ui (экспорт или ответ API), инбаунд Xray или весь конфиг Xray с разделом inbounds"
            value={importText}
            onChange={(e) => onImportText(e.target.value)}
            aria-label="Чужой конфиг"
          />
          <label className="checkbox">
            <input type="checkbox" checked={keepSecrets} onChange={(e) => onKeepSecrets(e.target.checked)} />
            Оставить ключи и пароли из конфига: они будут одинаковыми на всех серверах
          </label>
          <small className="muted">
            По протоколу, сети и защите админка выберет тип подключения, перенесёт порт и всё, чем конфиг отличается от её сборки. Пользователи
            из конфига не переносятся; без галочки ключи, shortId и пароли у каждого сервера будут свои.
          </small>
          <div className="action-row">
            <button type="button" className="btn btn-small btn-primary" onClick={onImport} disabled={busy || importText.trim().length < 2}>
              {busy ? "Загружаю…" : "Загрузить"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
