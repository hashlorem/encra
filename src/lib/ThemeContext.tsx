import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { PrintKind } from "../components/Print";
import { PREFERENCE_KEYS, readPreference, writePreference, type PreferenceKey } from "./preferences";

export type Theme = "dark" | "light" | "system";
export type Palette = "latent" | "darkroom" | "cyanotype" | "evidence";
export type Density = "comfortable" | "compact";

const THEMES: readonly Theme[] = ["dark", "light", "system"];
const PALETTES: readonly Palette[] = ["latent", "darkroom", "cyanotype", "evidence"];
const DENSITIES: readonly Density[] = ["comfortable", "compact"];
const PRINTS: readonly PrintKind[] = ["whorl", "loop", "arch"];

/** A stored value if it is one of `allowed`, else the default. */
function stored<T extends string>(key: PreferenceKey, allowed: readonly T[], fallback: T): T {
  const value = readPreference(key);
  return value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : fallback;
}

const storedTheme = () => stored(PREFERENCE_KEYS.theme, THEMES, "light");
const storedPalette = () => stored(PREFERENCE_KEYS.palette, PALETTES, "latent");
const storedDensity = () => stored(PREFERENCE_KEYS.density, DENSITIES, "comfortable");
const storedPrint = () => stored(PREFERENCE_KEYS.lockPrint, PRINTS, "whorl");

function systemTheme(): "dark" | "light" {
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function resolveTheme(theme: Theme): "dark" | "light" {
  return theme === "system" ? systemTheme() : theme;
}

/** The defaults leave no attribute, so the base tokens apply. */
function setRootAttribute(name: string, value: string, unlessDefault: string): void {
  if (value === unlessDefault) document.documentElement.removeAttribute(name);
  else document.documentElement.setAttribute(name, value);
}

/**
 * Apply the stored appearance before React mounts, so the first paint (the
 * lock screen) already uses it instead of flashing the default. None of it is
 * secret, which is why it can be read before the vault is open.
 */
export function applyStoredTheme(): void {
  document.documentElement.setAttribute("data-theme", resolveTheme(storedTheme()));
  setRootAttribute("data-palette", storedPalette(), "latent");
  setRootAttribute("data-density", storedDensity(), "comfortable");
}

interface ThemeContextValue {
  theme: Theme;
  resolved: "dark" | "light";
  set: (theme: Theme) => void;
  palette: Palette;
  setPalette: (palette: Palette) => void;
  density: Density;
  setDensity: (density: Density) => void;
  /** The print on the lock screen and the rail's Seal button. */
  lockPrint: PrintKind;
  setLockPrint: (print: PrintKind) => void;
}

// No silent default value: a component rendered outside the provider should fail
// loudly rather than quietly do nothing when it changes the theme.
const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(storedTheme);
  const [resolved, setResolved] = useState<"dark" | "light">(() => resolveTheme(theme));
  const [palette, setPaletteState] = useState<Palette>(storedPalette);
  const [density, setDensityState] = useState<Density>(storedDensity);
  const [lockPrint, setLockPrintState] = useState<PrintKind>(storedPrint);

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

  useEffect(() => {
    setRootAttribute("data-palette", palette, "latent");
    writePreference(PREFERENCE_KEYS.palette, palette);
  }, [palette]);

  useEffect(() => {
    setRootAttribute("data-density", density, "comfortable");
    writePreference(PREFERENCE_KEYS.density, density);
  }, [density]);

  useEffect(() => {
    writePreference(PREFERENCE_KEYS.lockPrint, lockPrint);
  }, [lockPrint]);

  const set = useCallback((next: Theme) => setTheme(next), []);
  const setPalette = useCallback((next: Palette) => setPaletteState(next), []);
  const setDensity = useCallback((next: Density) => setDensityState(next), []);
  const setLockPrint = useCallback((next: PrintKind) => setLockPrintState(next), []);
  const value = useMemo(
    () => ({ theme, resolved, set, palette, setPalette, density, setDensity, lockPrint, setLockPrint }),
    [theme, resolved, set, palette, setPalette, density, setDensity, lockPrint, setLockPrint],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) throw new Error("useTheme must be used within a ThemeProvider");
  return context;
}
