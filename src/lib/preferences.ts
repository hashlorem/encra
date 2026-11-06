export const PREFERENCE_KEYS = {
  theme: "cobrypt-theme",
  lockKeybind: "cobrypt-lock-keybind",
  autoLockBlur: "cobrypt-autolock-blur",
  sound: "cobrypt-sound",
} as const;

export type PreferenceKey = (typeof PREFERENCE_KEYS)[keyof typeof PREFERENCE_KEYS];

const LEGACY_KEYS: Partial<Record<PreferenceKey, string>> = {
  [PREFERENCE_KEYS.theme]: "keyrpt-theme",
  [PREFERENCE_KEYS.lockKeybind]: "keyrpt-lock-keybind",
  [PREFERENCE_KEYS.autoLockBlur]: "keyrpt-autolock-blur",
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
 * Read a preference, migrating a legacy `keyrpt-*` value on first use. The
 * legacy entry is removed once copied so stale data does not linger.
 */
export function readPreference(key: PreferenceKey): string | null {
  const store = storage();
  if (!store) return null;

  try {
    const current = store.getItem(key);
    if (current !== null) return current;

    const legacyKey = LEGACY_KEYS[key];
    if (!legacyKey) return null;

    const legacyValue = store.getItem(legacyKey);
    if (legacyValue !== null) {
      store.setItem(key, legacyValue);
      store.removeItem(legacyKey);
    }
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
