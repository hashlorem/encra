import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { PREFERENCE_KEYS, readPreference, writePreference } from "./preferences";

export type Theme = "dark" | "light" | "system";

const THEMES: readonly Theme[] = ["dark", "light", "system"];

function isTheme(value: string | null): value is Theme {
  return value !== null && (THEMES as readonly string[]).includes(value);
}

function systemTheme(): "dark" | "light" {
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function resolveTheme(theme: Theme): "dark" | "light" {
  return theme === "system" ? systemTheme() : theme;
}

/**
 * Apply the stored theme before React mounts, so the first paint already uses
 * the right palette instead of flashing the default.
 */
export function applyStoredTheme(): void {
  const stored = readPreference(PREFERENCE_KEYS.theme);
  const theme = isTheme(stored) ? stored : "light";
  document.documentElement.setAttribute("data-theme", resolveTheme(theme));
}

interface ThemeContextValue {
  theme: Theme;
  resolved: "dark" | "light";
  set: (theme: Theme) => void;
}

// No silent default value: a component rendered outside the provider should fail
// loudly rather than quietly do nothing when it changes the theme.
const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = readPreference(PREFERENCE_KEYS.theme);
    return isTheme(stored) ? stored : "light";
  });
  const [resolved, setResolved] = useState<"dark" | "light">(() => resolveTheme(theme));

  useEffect(() => {
    const next = resolveTheme(theme);
    setResolved(next);
    document.documentElement.setAttribute("data-theme", next);
    writePreference(PREFERENCE_KEYS.theme, theme);
  }, [theme]);

  // Follow the OS while in "system" mode. This previously updated the DOM but
  // not React state, so `resolved` went stale after an OS theme change.
  useEffect(() => {
    if (theme !== "system") return;
    const query = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = () => {
      const next = systemTheme();
      setResolved(next);
      document.documentElement.setAttribute("data-theme", next);
    };
    query.addEventListener("change", handler);
    return () => query.removeEventListener("change", handler);
  }, [theme]);

  const set = useCallback((next: Theme) => setTheme(next), []);
  const value = useMemo(() => ({ theme, resolved, set }), [theme, resolved, set]);

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) throw new Error("useTheme must be used within a ThemeProvider");
  return context;
}
