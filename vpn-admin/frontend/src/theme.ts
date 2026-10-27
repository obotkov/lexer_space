import { useEffect, useState } from "react";

export type ThemeMode = "system" | "light" | "dark";

// the same key and rule as the inline script in index.html, which applies the theme before the first paint
const STORAGE_KEY = "vpn-admin-theme";
const LIGHT_QUERY = "(prefers-color-scheme: light)";

function savedMode(): ThemeMode {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    return value === "light" || value === "dark" ? value : "system";
  } catch {
    return "system"; // storage blocked: follow the OS
  }
}

function apply(mode: ThemeMode): void {
  const light = mode === "light" || (mode === "system" && window.matchMedia(LIGHT_QUERY).matches);
  document.documentElement.dataset.theme = light ? "light" : "dark";
}

/** Theme choice of this browser; "system" follows the OS setting, also when it changes later. */
export function useTheme(): [ThemeMode, (mode: ThemeMode) => void] {
  const [mode, setMode] = useState<ThemeMode>(savedMode);

  useEffect(() => {
    apply(mode);
    if (mode !== "system") return;
    const media = window.matchMedia(LIGHT_QUERY);
    const onChange = () => apply("system");
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, [mode]);

  const choose = (next: ThemeMode) => {
    try {
      if (next === "system") localStorage.removeItem(STORAGE_KEY);
      else localStorage.setItem(STORAGE_KEY, next);
    } catch {
      /* not remembered, still applied for this page */
    }
    setMode(next);
  };

  return [mode, choose];
}
