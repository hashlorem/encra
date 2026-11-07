import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import Vault from "./Vault";
import Journal from "./Journal";
import Tools from "./Tools";
import Settings from "./Settings";
import { Brand } from "../components/Brand";
import { Icon, type IconName } from "../components/Icon";
import { SnakeEye } from "../components/SnakeEye";
import { playUnlockChime, playLockChime } from "../lib/chime";
import {
  PREFERENCE_KEYS,
  readBooleanPreference,
  readPreference,
} from "../lib/preferences";

type Module = "vault" | "journal" | "tools" | "settings";
type LockPhase = "idle" | "armed" | "moving" | "closing";

const AUTO_LOCK_MINUTES = 5;
const DEFAULT_LOCK_BINDING = "meta+l";
/** Least time between auto-lock timer resets, so mouse movement does not thrash. */
const ACTIVITY_THROTTLE_MS = 1000;

// Static config, so it is not rebuilt on every render.
const NAV_ITEMS: { id: Module; label: string; description: string; icon: IconName }[] = [
  { id: "vault", label: "Vault", description: "Credentials", icon: "key" },
  { id: "journal", label: "Journal", description: "Engagements", icon: "book" },
  { id: "tools", label: "Toolbox", description: "Utilities", icon: "terminal" },
  { id: "settings", label: "Settings", description: "Preferences", icon: "settings" },
];

interface DashboardProps {
  onLock: (immediate?: boolean) => void;
}

function Dashboard({ onLock }: DashboardProps) {
  const [active, setActive] = useState<Module>("vault");
  const [lockPhase, setLockPhase] = useState<LockPhase>("idle");
  const [flightOrigin, setFlightOrigin] = useState({ x: 48, y: 680 });

  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastActivityRef = useRef(0);
  const lockingRef = useRef(false);
  const firstRenderRef = useRef(true);

  const eyeControlRef = useRef<HTMLButtonElement>(null);
  const workspaceEyeRef = useRef<HTMLSpanElement>(null);
  const flightEyeRef = useRef<HTMLSpanElement>(null);
  const flightRef = useRef<HTMLDivElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);

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

  const handleLock = useCallback(async () => {
    if (lockingRef.current) return;
    lockingRef.current = true;
    if (readBooleanPreference(PREFERENCE_KEYS.sound, true)) playLockChime();
    const bounds = eyeControlRef.current?.getBoundingClientRect();
    setFlightOrigin({
      x: bounds ? bounds.left + bounds.width / 2 : 48,
      y: bounds ? bounds.top + bounds.height / 2 : window.innerHeight - 42,
    });
    setLockPhase("armed");

    await new Promise<void>((resolve) => {
      requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
    });

    const trackedTransform = workspaceEyeRef.current
      ?.querySelector<SVGGElement>(".snake-eye-focus")
      ?.style.getPropertyValue("transform");
    if (trackedTransform) {
      flightEyeRef.current
        ?.querySelector<SVGGElement>(".snake-eye-focus")
        ?.style.setProperty("transform", trackedTransform);
    }

    setLockPhase("moving");
    await new Promise((resolve) => setTimeout(resolve, 680));
    setLockPhase("closing");
    await new Promise((resolve) => setTimeout(resolve, 380));
    try {
      await invoke("lock_vault");
    } catch (error) {
      // Lock the UI anyway: failing open would be worse than a noisy log.
      console.error("Unable to clear the vault key while locking", error);
    }
    onLock();
  }, [onLock]);

  const handleImmediateLock = useCallback(() => {
    if (lockingRef.current) return;
    lockingRef.current = true;

    // Background tabs and unfocused webviews throttle animation frames. Cover the
    // workspace synchronously, dispatch the native key wipe, and render the lock
    // screen immediately instead of waiting for a decorative transition.
    document.documentElement.classList.add("vault-seal-guard");
    void invoke("lock_vault").catch((error) => {
      console.error("Unable to clear the vault key during auto-lock", error);
    });
    onLock(true);
  }, [onLock]);

  const resetTimer = useCallback(() => {
    const now = Date.now();
    // Rate-limit: `mousemove` fires continuously and used to rebuild the timeout
    // on every event.
    if (now - lastActivityRef.current < ACTIVITY_THROTTLE_MS) return;
    lastActivityRef.current = now;
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => void handleLock(), AUTO_LOCK_MINUTES * 60 * 1000);
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

  // Re-read settings when they change, so a new lock shortcut applies at once
  // instead of only after the dashboard remounts.
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

      const [modifier, key] = lockBinding.toLowerCase().split("+");
      if (!key) return;
      const modifierMatches =
        modifier === "meta" ? event.metaKey || event.ctrlKey : event.altKey || event.metaKey || event.ctrlKey;
      if (event.key.toLowerCase() === key && modifierMatches) {
        event.preventDefault();
        void handleLock();
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

  // The flight origin is dynamic, so it is written through the CSSOM rather than
  // an inline style attribute (the strict production CSP forbids the latter).
  useEffect(() => {
    const element = flightRef.current;
    if (!element) return;
    element.style.setProperty("--flight-x", `${flightOrigin.x}px`);
    element.style.setProperty("--flight-y", `${flightOrigin.y}px`);
  }, [flightOrigin, lockPhase]);

  // Switching module unmounts the previous page, which otherwise drops focus to
  // the document body.
  useEffect(() => {
    if (firstRenderRef.current) {
      firstRenderRef.current = false;
      return;
    }
    contentRef.current?.focus();
  }, [active]);

  const locking = lockPhase !== "idle";

  return (
    <div className={`dashboard${locking ? " is-sealing" : ""}`}>
      <aside className="sidebar" aria-label="Workspace">
        <div className="sidebar-header">
          <button
            ref={eyeControlRef}
            className="sidebar-lockup"
            onClick={() => void handleLock()}
            disabled={locking}
            aria-label="Lock vault"
          >
            <Brand interactive eyeRef={workspaceEyeRef} />
          </button>
        </div>
        <div className="sidebar-section-label">Workspace</div>
        <nav aria-label="Primary navigation">
          {NAV_ITEMS.map(({ id, label, description, icon }) => (
            <button
              key={id}
              className={active === id ? "active" : ""}
              onClick={() => setActive(id)}
              aria-current={active === id ? "page" : undefined}
            >
              <span className="nav-icon"><Icon name={icon} size={18} /></span>
              <span className="nav-copy"><strong>{label}</strong><small>{description}</small></span>
              {active === id && <span className="nav-active-dot" />}
            </button>
          ))}
        </nav>
      </aside>

      <main className="content">
        <div className="content-inner" ref={contentRef} tabIndex={-1}>
          {active === "vault" && <Vault />}
          {active === "journal" && <Journal />}
          {active === "tools" && <Tools />}
          {active === "settings" && <Settings />}
        </div>
      </main>

      {locking && (
        <>
          <div className="lock-transition-scrim" aria-hidden="true" />
          <div
            ref={flightRef}
            className={`lock-flight lock-flight-${lockPhase}`}
            aria-hidden="true"
          >
            <SnakeEye ref={flightEyeRef} closed={lockPhase === "closing"} />
          </div>
        </>
      )}
    </div>
  );
}

export default Dashboard;
