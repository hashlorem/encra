import { useCallback, useEffect, useRef, useState } from "react";
import { scheduleClipboardWipe } from "./clipboardWipe";

interface UseClipboardOptions {
  /** How long the "copied" indicator stays on, in milliseconds. */
  feedbackMs?: number;
}

/**
 * The single clipboard implementation for the app.
 *
 * The three ad-hoc copies this replaces each had a different defect: no error
 * handling, a wipe timer that was never cancelled (so an earlier copy could
 * erase a later one), and timers left running after unmount.
 *
 * The 30-second wipe is deliberately NOT tied to this component: it must still
 * run after the page closes. See clipboardWipe.ts.
 */
export function useClipboard({ feedbackMs = 1500 }: UseClipboardOptions = {}) {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const feedbackTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (feedbackTimer.current) clearTimeout(feedbackTimer.current);
    },
    [],
  );

  const copy = useCallback(
    async (value: string, id?: string): Promise<boolean> => {
      try {
        await navigator.clipboard.writeText(value);
      } catch (error) {
        console.error("Unable to write to the clipboard", error);
        return false;
      }

      // Restarts the shared countdown, so a stale timer cannot clear the value
      // that was just written.
      scheduleClipboardWipe();

      if (id !== undefined) {
        setCopiedId(id);
        if (feedbackTimer.current) clearTimeout(feedbackTimer.current);
        feedbackTimer.current = setTimeout(() => setCopiedId(null), feedbackMs);
      }
      return true;
    },
    [feedbackMs],
  );

  return { copy, copiedId };
}
