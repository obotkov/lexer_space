import { useEffect, useState, type FormEvent } from "react";
import { api, type HosterInfo, type HosterServer, type ServerDeletePlan } from "../api";

/** Delete a hosting's server: first the connections of the node it runs (inbounds in the main panel), then the
 * node, then the server itself. */
export function DeleteServerDialog({
  hoster,
  server,
  providerTitle,
  onClose,
  onDeleted,
}: {
  hoster: HosterInfo;
  server: HosterServer;
  providerTitle: string;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const [plan, setPlan] = useState<ServerDeletePlan | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let alive = true;
    api.serverDeletePlan(hoster.id, server.id).then(
      (p) => alive && setPlan(p),
      (e) => alive && setError((e as Error).message),
    );
    return () => {
      alive = false;
    };
  }, [hoster.id, server.id]);

  const inbounds = plan?.nodes.reduce((n, node) => n + node.inbounds.length, 0) ?? 0;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api.deleteHostedServer(hoster.id, server.id);
      onDeleted();
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <form className="modal" onSubmit={submit}>
        <div className="modal-head">
          <h2>Удалить сервер «{server.name}»</h2>
          <button type="button" className="btn btn-small" onClick={onClose} disabled={busy}>
            ✕
          </button>
        </div>

        {!plan && !error && <div className="muted small">Проверяю, какие узлы и подключения работают на этом сервере…</div>}

        {plan && (
          <ol className="delete-steps small">
            {plan.nodes.map((node) => (
              <li key={`${node.panel_id}-${node.node_id}`}>
                {node.inbounds.length > 0 ? (
                  <>
                    Удалить подключения узла «{node.name}» в основной панели «{node.panel_name}» ({node.inbounds.length} шт.):
                    <div className="delete-inbounds">
                      {node.inbounds.map((i) => (
                        <span key={i.id} className="badge badge-disabled">
                          {i.remark || i.protocol} :{i.port}
                        </span>
                      ))}
                    </div>
                    Клиенты останутся в панели, у них пропадут только эти подключения. Затем удалить сам узел.
                  </>
                ) : (
                  <>Удалить узел «{node.name}» из основной панели «{node.panel_name}» (подключений на нём нет).</>
                )}
              </li>
            ))}
            <li>
              Удалить сервер {server.ipv4[0] ?? ""} у {providerTitle}: он будет уничтожен вместе с данными, плата за него прекратится.
              {plan.jobs.length > 0 && " Его задание в блоке «Новые серверы» отметится как удалённое, A-запись Cloudflare, если была, удалится."}
            </li>
          </ol>
        )}
        {plan && plan.nodes.length === 0 && (
          <div className="muted small">Узлом основной панели этот сервер не подключён: удалится только сам сервер.</div>
        )}

        {error && <div className="notice notice-bad small">{error}</div>}

        <div className="modal-actions">
          <button type="button" className="btn" onClick={onClose} disabled={busy}>
            Отмена
          </button>
          <button className="btn btn-danger" disabled={!plan || busy}>
            {busy ? (inbounds ? "Удаляю подключения, узел и сервер…" : "Удаляю…") : "Удалить сервер"}
          </button>
        </div>
      </form>
    </div>
  );
}
