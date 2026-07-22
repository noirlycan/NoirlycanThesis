export type Theme = "dark" | "light";

export const THEME_STORAGE_KEY = "noirlycan-theme";
export const DEFAULT_THEME: Theme = "light";

export function readStoredTheme(): Theme {
  if (typeof window === "undefined") {
    return DEFAULT_THEME;
  }
  const fromDom = document.documentElement.dataset.theme;
  if (fromDom === "dark" || fromDom === "light") {
    return fromDom;
  }
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === "dark" || stored === "light") {
      return stored;
    }
  } catch {
    // ignore private mode / storage errors
  }
  return DEFAULT_THEME;
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // ignore private mode / storage errors
  }
}
