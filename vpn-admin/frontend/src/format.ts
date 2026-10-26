import type { ClientStatus } from "./api";

export function formatBytes(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, i);
  return `${value.toFixed(value >= 100 || i === 0 ? 0 : value >= 10 ? 1 : 2)} ${units[i]}`;
}

export function formatLimit(total: number): string {
  return total > 0 ? formatBytes(total) : "∞";
}

/** 3x-ui expiryTime: ms timestamp; 0 = no limit; negative = N days after first connection. */
export function formatExpiry(expiry: number): string {
  if (expiry === 0) return "Бессрочно";
  if (expiry < 0) return `${Math.round(-expiry / 86_400_000)} дн. после 1-го входа`;
  const date = new Date(expiry);
  const days = Math.ceil((expiry - Date.now()) / 86_400_000);
  const str = date.toLocaleDateString("ru-RU");
  if (days < 0) return `${str} (истекла)`;
  return `${str} (${days} дн.)`;
}

export function formatUptime(seconds: number | null): string {
  if (!seconds) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  return d > 0 ? `${d} д ${h} ч` : `${h} ч ${Math.floor((seconds % 3600) / 60)} м`;
}

export function formatDateTime(ts: number): string {
  if (!ts) return "—";
  return new Date(ts).toLocaleString("ru-RU");
}

export const STATUS_LABELS: Record<ClientStatus, string> = {
  active: "Активен",
  disabled: "Отключён",
  expired: "Истёк",
  depleted: "Трафик исчерпан",
};

export function plural(n: number, one: string, few: string, many: string): string {
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return one;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return few;
  return many;
}

const GB = 1024 ** 3;

export const bytesToGb = (bytes: number): string => (bytes > 0 ? String(+(bytes / GB).toFixed(2)) : "0");
export const gbToBytes = (gb: string): number => Math.max(0, Math.round(parseFloat(gb.replace(",", ".")) * GB));

/** Local date for <input type="date"> */
export function msToDateInput(ms: number): string {
  const d = new Date(ms);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** End of the chosen day, local time */
export const dateInputToMs = (value: string): number => new Date(`${value}T23:59:59`).getTime();

export const DAY_MS = 86_400_000;
