export const PREFERENCE_KEYS = {
  theme: "encra-theme",
  palette: "encra-palette",
  density: "encra-density",
  lockPrint: "encra-lock-print",
  lockKeybind: "encra-lock-keybind",
  autoLockBlur: "encra-autolock-blur",
  sound: "encra-sound",
} as const;

export type PreferenceKey = (typeof PREFERENCE_KEYS)[keyof typeof PREFERENCE_KEYS];

/** Keys used by earlier product names, newest first. */
const LEGACY_KEYS: Partial<Record<PreferenceKey, string[]>> = {
  [PREFERENCE_KEYS.theme]: ["cobrypt-theme", "keyrpt-theme"],
  [PREFERENCE_KEYS.lockKeybind]: ["cobrypt-lock-keybind", "keyrpt-lock-keybind"],
  [PREFERENCE_KEYS.autoLockBlur]: ["cobrypt-autolock-blur", "keyrpt-autolock-blur"],
  [PREFERENCE_KEYS.sound]: ["cobrypt-sound"],
};

/**
 * Accessing `localStorage` can throw when storage is disabled. Returning null
 * keeps a locked-down webview from crashing the provider that reads it during
 * its initial render.
 */
function storage(): Storage | null {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

/**
 * Read a preference, migrating a `cobrypt-*` or `keyrpt-*` value on first use.
 * Legacy entries are removed once copied so stale data does not linger.
 */
export function readPreference(key: PreferenceKey): string | null {
  const store = storage();
  if (!store) return null;

  try {
    const current = store.getItem(key);
    if (current !== null) return current;

    const legacyKeys = LEGACY_KEYS[key] ?? [];
    const legacyValue =
      legacyKeys.map((legacyKey) => store.getItem(legacyKey)).find((value) => value !== null) ?? null;
    if (legacyValue !== null) store.setItem(key, legacyValue);
    legacyKeys.forEach((legacyKey) => store.removeItem(legacyKey));
    return legacyValue;
  } catch {
    return null;
  }
}

export function writePreference(key: PreferenceKey, value: string): void {
  try {
    storage()?.setItem(key, value);
  } catch {
    // Storage unavailable; the preference simply will not persist.
  }
}

export function readBooleanPreference(key: PreferenceKey, fallback: boolean): boolean {
  const value = readPreference(key);
  return value === null ? fallback : value === "true";
}

export function writeBooleanPreference(key: PreferenceKey, value: boolean): void {
  writePreference(key, String(value));
}
