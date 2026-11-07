import { useSyncExternalStore } from "react";

/**
 * The shared TOTP countdown.
 *
 * Kept outside React so the once-per-second tick re-renders only the small
 * countdown component that subscribes to it, instead of every credential card
 * in the list.
 */

let windowSeconds = 30;
let remaining = windowSeconds;
let timer: ReturnType<typeof setInterval> | null = null;
let rolloverHandler: (() => void) | null = null;
let subscriberCount = 0;
const listeners = new Set<() => void>();

function notify() {
  for (const listener of listeners) listener();
}

function tick() {
  if (remaining <= 1) {
    remaining = windowSeconds;
    // A new window started, so any code already rendered is now stale.
    rolloverHandler?.();
  } else {
    remaining -= 1;
  }
  notify();
}

/** Start (or restart) the countdown at the server-reported remaining seconds. */
export function startTotpWindow(seconds: number, period: number) {
  windowSeconds = period > 0 ? period : 30;
  remaining = seconds > 0 ? seconds : windowSeconds;
  if (timer === null) timer = setInterval(tick, 1000);
  notify();
}

/** Stop the countdown when nothing is observing it any more. */
export function stopTotpWindow() {
  if (timer !== null) {
    clearInterval(timer);
    timer = null;
  }
}

/** Called when the window rolls over, so codes can be recomputed. */
export function setTotpRolloverHandler(handler: (() => void) | null) {
  rolloverHandler = handler;
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  subscriberCount += 1;
  return () => {
    listeners.delete(listener);
    subscriberCount -= 1;
    if (subscriberCount === 0) stopTotpWindow();
  };
}

function snapshot() {
  return remaining;
}

export function useTotpRemaining(): number {
  return useSyncExternalStore(subscribe, snapshot, snapshot);
}
