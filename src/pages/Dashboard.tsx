import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { AgentRequestDialog } from "../components/AgentRequestDialog";
import type { AgentRequest } from "../lib/types";
import Vault from "./Vault";
import Journal from "./Journal";
import Tools from "./Tools";
import Activity from "./Activity";
import Settings from "./Settings";
import { Print } from "../components/Print";
import { Wordmark } from "../components/Wordmark";
import { playUnlockChime, playLockChime } from "../lib/chime";
import {
  PREFERENCE_KEYS,
  readBooleanPreference,
  readPreference,
} from "../lib/preferences";

type Module = "vault" | "journal" | "tools" | "activity" | "settings";
/** Why the vault was sealed; Rust turns this into the log wording. */
type SealReason = "button" | "shortcut" | "idle" | "app_switch";

const AUTO_LOCK_MINUTES = 5;
const DEFAULT_LOCK_BINDING = "meta+l";
/** Least time between auto-lock timer resets, so mouse movement does not thrash. */
const ACTIVITY_THROTTLE_MS = 1000;
/** How long the workspace takes to fade before the lock screen shows. */
const SEAL_MS = 160;

const NAV_ITEMS: { id: Module; label: string }[] = [
  { id: "vault", label: "Vault" },
  { id: "journal", label: "Case notes" },
  { id: "tools", label: "Toolbox" },
  { id: "activity", label: "Activity" },
  { id: "settings", label: "Settings" },
];

const SHORTCUT_LABELS: Record<string, string> = {
  "meta+l": "⌘L",
  "meta+shift+l": "⌘⇧L",
  "alt+l": "⌥L",
  "meta+escape": "⌘Esc",
};

function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

interface DashboardProps {
  onLock: () => void;
}

function Dashboard({ onLock }: DashboardProps) {
  const [active, setActive] = useState<Module>("vault");
  const [sealing, setSealing] = useState(false);
  const [agentRequests, setAgentRequests] = useState<AgentRequest[]>([]);

  // Requests from `encra run`: any that arrived while sealed, then each new one.
  const loadAgentRequests = useCallback(() => {
    invoke<AgentRequest[]>("agent_pending")
      .then(setAgentRequests)
      .catch(() => setAgentRequests([]));
  }, []);

  useEffect(() => {
    loadAgentRequests();
    const unlisten = listen("agent-request", loadAgentRequests);
    return () => {
      void unlisten.then((stop) => stop());
    };
  }, [loadAgentRequests]);

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastActivityRef = useRef(0);
  const lockingRef = useRef(false);
  const firstRenderRef = useRef(true);
  const contentRef = useRef<HTMLElement>(null);

  const [lockBinding, setLockBinding] = useState(
    () => readPreference(PREFERENCE_KEYS.lockKeybind) || DEFAULT_LOCK_BINDING,
  );
  const [autoLockBlur, setAutoLockBlur] = useState(() =>
    readBooleanPreference(PREFERENCE_KEYS.autoLockBlur, false),
  );

  useEffect(() => {
    lockingRef.current = false;
    if (readBooleanPreference(PREFERENCE_KEYS.sound, true)) playUnlockChime();
  }, []);

  /** Clear the key in Rust (which also wipes a pending clipboard copy). */
  const sealBackend = useCallback(async (reason: SealReason) => {
    try {
      await invoke("lock_vault", { reason });
    } catch (error) {
      // Lock the UI anyway: failing open would be worse than a noisy log.
      console.error("Unable to clear the vault key while locking", error);
    }
  }, []);

  const handleLock = useCallback(async (reason: SealReason) => {
    if (lockingRef.current) return;
    lockingRef.current = true;
    if (readBooleanPreference(PREFERENCE_KEYS.sound, true)) playLockChime();
    setSealing(true);
    if (!prefersReducedMotion()) await new Promise((resolve) => setTimeout(resolve, SEAL_MS));
    await sealBackend(reason);
    onLock();
  }, [onLock, sealBackend]);

  const handleImmediateLock = useCallback(() => {
    if (lockingRef.current) return;
    lockingRef.current = true;
    // Background webviews throttle timers, so hide the workspace synchronously
    // and skip the fade.
    document.documentElement.classList.add("vault-seal-guard");
    void sealBackend("app_switch");
    onLock();
  }, [onLock, sealBackend]);

  const resetTimer = useCallback(() => {
    const now = Date.now();
    if (now - lastActivityRef.current < ACTIVITY_THROTTLE_MS) return;
    lastActivityRef.current = now;
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => void handleLock("idle"), AUTO_LOCK_MINUTES * 60 * 1000);
  }, [handleLock]);

  useEffect(() => {
    resetTimer();
    const events = ["mousedown", "keydown", "mousemove", "scroll"];
    events.forEach((event) => window.addEventListener(event, resetTimer, { passive: true }));
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
      events.forEach((event) => window.removeEventListener(event, resetTimer));
    };
  }, [resetTimer]);

  // Re-read settings when they change, so a new lock shortcut applies at once.
  useEffect(() => {
    const handler = () => {
      setLockBinding(readPreference(PREFERENCE_KEYS.lockKeybind) || DEFAULT_LOCK_BINDING);
      setAutoLockBlur(readBooleanPreference(PREFERENCE_KEYS.autoLockBlur, false));
    };
    window.addEventListener("encra:settings-changed", handler);
    return () => window.removeEventListener("encra:settings-changed", handler);
  }, []);

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.key === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        window.dispatchEvent(new CustomEvent("encra:search-focus"));
        return;
      }

      const parts = lockBinding.toLowerCase().split("+");
      const key = parts[parts.length - 1];
      const wantsShift = parts.includes("shift");
      const modifierMatches = parts.includes("meta")
        ? event.metaKey || event.ctrlKey
        : event.altKey;
      // Letters match on the physical key: Option+L types "¬" on a Mac keyboard.
      const keyMatches =
        key.length === 1 ? event.code === `Key${key.toUpperCase()}` : event.key.toLowerCase() === key;
      if (keyMatches && modifierMatches && event.shiftKey === wantsShift) {
        event.preventDefault();
        void handleLock("shortcut");
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [lockBinding, handleLock]);

  useEffect(() => {
    if (!autoLockBlur) return;
    const onBlur = () => handleImmediateLock();
    const onVisibilityChange = () => {
      if (document.visibilityState === "hidden") handleImmediateLock();
    };
    window.addEventListener("blur", onBlur);
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      window.removeEventListener("blur", onBlur);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [autoLockBlur, handleImmediateLock]);

  // Switching module unmounts the previous page, which otherwise drops focus to
  // the document body.
  useEffect(() => {
    if (firstRenderRef.current) {
      firstRenderRef.current = false;
      return;
    }
    contentRef.current?.focus();
  }, [active]);

  return (
    <div className={`shell${sealing ? " is-sealing" : ""}`}>
      <aside className="rail" aria-label="Workspace">
        <Wordmark />
        <nav className="rail-nav" aria-label="Primary navigation">
          {NAV_ITEMS.map(({ id, label }) => (
            <button
              key={id}
              onClick={() => setActive(id)}
              aria-current={active === id ? "page" : undefined}
            >
              {label}
            </button>
          ))}
        </nav>
        <button className="seal" onClick={() => void handleLock("button")} disabled={sealing}>
          <Print kind="loop" />
          <span className="seal-copy">
            <span>
              <strong>Seal</strong>{" "}
              <kbd className="meta">{SHORTCUT_LABELS[lockBinding] ?? lockBinding}</kbd>
            </span>
            <span className="meta">Also after {AUTO_LOCK_MINUTES} idle minutes</span>
          </span>
        </button>
      </aside>

      {agentRequests[0] && (
        <AgentRequestDialog key={agentRequests[0].id} request={agentRequests[0]} onDone={loadAgentRequests} />
      )}

      <main className="workspace" ref={contentRef} tabIndex={-1}>
        <div key={active} className="view">
          {active === "vault" && <Vault />}
          {active === "journal" && <Journal />}
          {active === "tools" && <Tools />}
          {active === "activity" && <Activity />}
          {active === "settings" && <Settings />}
        </div>
      </main>
    </div>
  );
}

export default Dashboard;
