/**
 * App-wide clipboard wipe for copied secrets.
 *
 * The timer lives at module level on purpose. It used to belong to the
 * component that did the copy, so closing that page (including locking the
 * vault, which closes every page) cancelled the wipe and left the secret on the
 * clipboard indefinitely.
 */

/** How long a copied secret stays on the clipboard before it is wiped. */
export const CLEAR_AFTER_MS = 30_000;

let wipeTimer: ReturnType<typeof setTimeout> | null = null;
let retryArmed = false;

async function clearClipboard(): Promise<boolean> {
  try {
    await navigator.clipboard.writeText("");
    return true;
  } catch (error) {
    // WebKit can refuse clipboard writes while the window is unfocused (for
    // example right after a blur auto-lock). Try again once focus returns
    // instead of silently leaving the secret behind.
    console.warn("Unable to wipe the clipboard, retrying on next focus", error);
    if (!retryArmed) {
      retryArmed = true;
      window.addEventListener(
        "focus",
        () => {
          retryArmed = false;
          void clearClipboard();
        },
        { once: true },
      );
    }
    return false;
  }
}

/** Start (or restart) the wipe countdown after a secret is copied. */
export function scheduleClipboardWipe(delayMs: number = CLEAR_AFTER_MS): void {
  if (wipeTimer) clearTimeout(wipeTimer);
  wipeTimer = setTimeout(() => {
    wipeTimer = null;
    void clearClipboard();
  }, delayMs);
}

/**
 * Wipe now if a copied secret is still pending. Called when the vault locks.
 *
 * Does nothing when no wipe is pending, so locking does not clobber something
 * the user copied from another app after the countdown already ran out.
 */
export async function wipeClipboardNow(): Promise<boolean> {
  if (wipeTimer === null) return false;
  clearTimeout(wipeTimer);
  wipeTimer = null;
  return clearClipboard();
}
