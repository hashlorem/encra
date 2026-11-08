import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { AgentRequestDialog } from "../components/AgentRequestDialog";
import { CommandPalette } from "../components/CommandPalette";
import type { AgentRequest, PaletteHit } from "../lib/types";
import type { Module, PageRequest, Requested, ToolId } from "../lib/navigation";
import Vault from "./Vault";
import Journal from "./Journal";
import Tools from "./Tools";
import Activity from "./Activity";
import Settings from "./Settings";
import { Print } from "../components/Print";
import { Wordmark } from "../components/Wordmark";
import { playUnlockChime, playLockChime, playRequestChime } from "../lib/chime";
import { useTheme } from "../lib/ThemeContext";
import {
  PREFERENCE_KEYS,
  readBooleanPreference,
  readPreference,
} from "../lib/preferences";

/** Why the vault was sealed; Rust turns this into the log wording. */
type SealReason = "button" | "shortcut" | "idle" | "app_switch" | "palette";

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
  const { lockPrint } = useTheme();
  const [active, setActive] = useState<Module>("vault");
  const [sealing, setSealing] = useState(false);
  const [agentRequests, setAgentRequests] = useState<AgentRequest[]>([]);
  const [paletteOpen, setPaletteOpen] = useState(false);
  // What the palette asked the page to do. The rail clears it, so returning
  // to a page later doesn't repeat it.
  const [requested, setRequested] = useState<Requested | null>(null);
  const requestSeq = useRef(0);

  const go = useCallback((module: Module, request?: PageRequest) => {
    setActive(module);
    setRequested(request ? { seq: ++requestSeq.current, request } : null);
  }, []);

  // Requests from `encra run`: any that arrived while sealed, then each new one.
  const loadAgentRequests = useCallback(() => {
    invoke<AgentRequest[]>("agent_pending")
      .then(setAgentRequests)
      .catch(() => setAgentRequests([]));
  }, []);

  useEffect(() => {
    loadAgentRequests();
    // The backend reports the queue size on every change: an arrival, an
    // answer, a timeout, a caller giving up. Chime only when it grows.
    let waiting = 0;
    const unlisten = listen<number>("agent-request", (event) => {
      if (event.payload > waiting && readBooleanPreference(PREFERENCE_KEYS.sound, true)) playRequestChime();
      waiting = event.payload;
      loadAgentRequests();
    });
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
      const command = event.metaKey || event.ctrlKey;
      if (command && !event.shiftKey && !event.altKey && event.code === "KeyK") {
        event.preventDefault();
        // ⌘K again closes it. It never opens over another dialog: two focus
        // traps would fight.
        setPaletteOpen((open) => !open && !document.querySelector(".dialog-backdrop"));
        return;
      }
      if (command && !event.shiftKey && !event.altKey && event.code === "KeyF") {
        event.preventDefault();
        if (!document.querySelector(".dialog-backdrop")) window.dispatchEvent(new CustomEvent("encra:search-focus"));
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

  /** Where a palette result leads. */
  const openHit = useCallback((hit: PaletteHit) => {
    setPaletteOpen(false);
    if (hit.group === "login") return go("vault", { kind: "login", id: hit.id });
    if (hit.group === "case") return go("journal", { kind: "case", id: hit.id });
    if (hit.group === "command") return go("tools", { kind: "tool", tool: "kb", search: hit.title });
    const [type, name] = hit.id.split(":");
    if (type === "page") return go(name as Module);
    if (type === "tool") return go("tools", { kind: "tool", tool: name as ToolId });
    if (name === "new-login") return go("vault", { kind: "new-login" });
    if (name === "new-case") return go("journal", { kind: "new-case" });
    if (name === "import") return go("vault", { kind: "import" });
    if (name === "checkup") return go("vault", { kind: "checkup" });
    if (name === "seal") void handleLock("palette");
  }, [go, handleLock]);

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
              onClick={() => go(id)}
              aria-current={active === id ? "page" : undefined}
            >
              {label}
            </button>
          ))}
        </nav>
        <button className="seal" onClick={() => void handleLock("button")} disabled={sealing}>
          <Print kind={lockPrint} />
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

      {paletteOpen && !agentRequests[0] && <CommandPalette onClose={() => setPaletteOpen(false)} onOpen={openHit} />}

      <main className="workspace" ref={contentRef} tabIndex={-1}>
        <div key={active} className="view">
          {active === "vault" && <Vault requested={requested} />}
          {active === "journal" && <Journal requested={requested} />}
          {active === "tools" && <Tools requested={requested} />}
          {active === "activity" && <Activity />}
          {active === "settings" && <Settings />}
        </div>
      </main>
    </div>
  );
}

export default Dashboard;
