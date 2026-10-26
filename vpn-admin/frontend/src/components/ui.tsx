import { useState, type ReactNode } from "react";
import type { ClientStatus } from "../api";
import { STATUS_LABELS } from "../format";

export function StatCard({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: "good" | "warn" | "bad" }) {
  return (
    <div className={`stat-card ${tone ?? ""}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export function StatusBadge({ status }: { status: ClientStatus }) {
  return <span className={`badge badge-${status}`}>{STATUS_LABELS[status]}</span>;
}

export function OnlineDot({ online }: { online: boolean }) {
  return <span className={`dot ${online ? "dot-on" : ""}`} title={online ? "Онлайн" : "Офлайн"} />;
}

export function CopyButton({ text, label = "Копировать" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // clipboard API needs https; fallback for plain http
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
    }
    setDone(true);
    setTimeout(() => setDone(false), 1200);
  };
  return (
    <button className="btn btn-small" onClick={copy} disabled={!text}>
      {done ? "Скопировано" : label}
    </button>
  );
}

export function TrafficBar({ used, total }: { used: number; total: number }) {
  if (total <= 0) return null;
  const pct = Math.min(100, (used / total) * 100);
  return (
    <div className="bar" title={`${pct.toFixed(0)}%`}>
      <div className={`bar-fill ${pct > 90 ? "bad" : pct > 70 ? "warn" : ""}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function PanelFilter({ panels, value, onChange }: { panels: { id: number; name: string }[]; value: number | 0; onChange: (v: number) => void }) {
  if (panels.length < 2) return null;
  return (
    <select className="input" value={value} onChange={(e) => onChange(Number(e.target.value))}>
      <option value={0}>Все серверы</option>
      {panels.map((p) => (
        <option key={p.id} value={p.id}>
          {p.name}
        </option>
      ))}
    </select>
  );
}
