import { useTheme, type ThemeMode } from "../theme";

const OPTIONS: { mode: ThemeMode; title: string; icon: JSX.Element }[] = [
  {
    mode: "system",
    title: "Системная",
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden>
        <rect x="3" y="4" width="18" height="12" rx="2" />
        <path d="M8 20h8M12 16v4" />
      </svg>
    ),
  },
  {
    mode: "light",
    title: "Светлая",
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden>
        <circle cx="12" cy="12" r="4" />
        <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
      </svg>
    ),
  },
  {
    mode: "dark",
    title: "Тёмная",
    icon: (
      <svg viewBox="0 0 24 24" aria-hidden>
        <path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z" />
      </svg>
    ),
  },
];

/** Системная / светлая / тёмная тема; the choice is remembered in this browser. */
export function ThemeSwitch() {
  const [mode, setMode] = useTheme();
  return (
    <div className="theme-switch" role="radiogroup" aria-label="Тема оформления">
      {OPTIONS.map((o) => (
        <button
          key={o.mode}
          type="button"
          role="radio"
          aria-checked={mode === o.mode}
          title={o.title}
          className={mode === o.mode ? "active" : ""}
          onClick={() => setMode(o.mode)}
        >
          {o.icon}
          <span>{o.title}</span>
        </button>
      ))}
    </div>
  );
}
