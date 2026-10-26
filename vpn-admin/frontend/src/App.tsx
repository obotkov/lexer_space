import { useCallback, useEffect, useState } from "react";
import { api, type Overview as OverviewData, type UpdateCheck } from "./api";
import { Login, Shield } from "./pages/Login";
import { Connections } from "./pages/Connections";
import { Nodes } from "./pages/Nodes";
import { Overview } from "./pages/Overview";
import { Servers } from "./pages/Servers";
import { Subscriptions } from "./pages/Subscriptions";
import { System } from "./pages/System";
import { Users } from "./pages/Users";

const TABS = [
  { id: "overview", title: "Обзор" },
  { id: "nodes", title: "Узлы" },
  { id: "connections", title: "Коннекты" },
  { id: "subscriptions", title: "Подписки" },
  { id: "users", title: "Пользователи" },
  { id: "servers", title: "Серверы 3x-ui" },
  { id: "system", title: "Система" },
] as const;
type TabId = (typeof TABS)[number]["id"];

const AUTO_REFRESH_MS = 30_000;

function tabFromHash(): TabId {
  const id = window.location.hash.replace("#/", "");
  return (TABS.find((t) => t.id === id)?.id ?? "overview") as TabId;
}

export function App() {
  const [user, setUser] = useState<string | null | undefined>(undefined);
  const [tab, setTab] = useState<TabId>(tabFromHash);
  const [data, setData] = useState<OverviewData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [updateCheck, setUpdateCheck] = useState<UpdateCheck | null>(null);

  useEffect(() => {
    api.me().then((m) => setUser(m.username), () => setUser(null));
    const onUnauthorized = () => setUser(null);
    const onHash = () => setTab(tabFromHash());
    window.addEventListener("unauthorized", onUnauthorized);
    window.addEventListener("hashchange", onHash);
    return () => {
      window.removeEventListener("unauthorized", onUnauthorized);
      window.removeEventListener("hashchange", onHash);
    };
  }, []);

  const load = useCallback(async (refresh = false) => {
    setLoading(true);
    try {
      setData(await api.overview(refresh));
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!user) return;
    load();
    const timer = setInterval(() => load(), AUTO_REFRESH_MS);
    return () => clearInterval(timer);
  }, [user, load]);

  // background check (cached on the server for 30 minutes) to show the "new version" badge
  useEffect(() => {
    if (user) api.checkUpdate().then(setUpdateCheck, () => undefined);
  }, [user]);

  const go = (id: TabId) => {
    window.location.hash = `#/${id}`;
  };

  const logout = async () => {
    await api.logout().catch(() => undefined);
    setUser(null);
    setData(null);
  };

  if (user === undefined) return <div className="center muted">Загрузка…</div>;
  if (user === null) return <Login onLogin={setUser} />;

  const counts: Partial<Record<TabId, number>> = data
    ? { connections: data.totals.nodes, subscriptions: data.totals.subscriptions, users: data.totals.clients, servers: data.totals.panels }
    : {};

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="logo">
          <Shield /> VPN Admin
        </div>
        <nav>
          {TABS.map((t) => (
            <a key={t.id} href={`#/${t.id}`} className={`nav-item ${tab === t.id ? "active" : ""}`}>
              {t.title}
              {counts[t.id] !== undefined && <span className="nav-count">{counts[t.id]}</span>}
              {t.id === "system" && updateCheck?.update_available && <span className="nav-count nav-new">новое</span>}
            </a>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span className="muted small">{user}</span>
          <button className="btn btn-small" onClick={logout}>
            Выйти
          </button>
        </div>
      </aside>

      <main className="content">
        <header className="topbar">
          <h1>{TABS.find((t) => t.id === tab)?.title}</h1>
          <div className="topbar-right" hidden={tab === "system"}>
            {data && <span className="muted small">обновлено {new Date(data.generated_at * 1000).toLocaleTimeString("ru-RU")}</span>}
            <button className="btn" onClick={() => load(true)} disabled={loading}>
              {loading ? "Обновление…" : "Обновить"}
            </button>
          </div>
        </header>

        {tab === "system" ? (
          <System check={updateCheck} onCheck={setUpdateCheck} />
        ) : error && !data ? (
          <div className="notice notice-bad">{error}</div>
        ) : !data ? (
          <div className="center muted">Загрузка данных с серверов…</div>
        ) : (
          <>
            {error && <div className="notice notice-bad">{error}</div>}
            {tab === "overview" && <Overview data={data} onGoServers={() => go("servers")} />}
            {tab === "nodes" && <Nodes panels={data.panels} onChanged={() => load(true)} />}
            {tab === "connections" && <Connections data={data} onChanged={() => load(true)} />}
            {tab === "subscriptions" && <Subscriptions data={data} onChanged={() => load(true)} />}
            {tab === "users" && <Users data={data} onChanged={() => load(true)} />}
            {tab === "servers" && <Servers panels={data.panels} onChanged={() => load(true)} />}
          </>
        )}
      </main>
    </div>
  );
}
