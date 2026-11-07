import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import LockScreen from "./pages/LockScreen";
import Setup from "./pages/Setup";
import Dashboard from "./pages/Dashboard";

/**
 * Dev-only shortcut that opens the workspace without the vault password.
 *
 * Gated on Vite's DEV flag rather than on a URL query parameter: `import.meta.env.DEV`
 * is statically false in a production build, so the branch is compiled out and the
 * bypass cannot be reached in a shipped app.
 */
const PREVIEW_UNLOCK =
  import.meta.env.DEV && new URLSearchParams(window.location.search).has("preview");

type Stage = "locked" | "setup" | "open";

function App() {
  // The lock screen renders first, before any database read; a brand-new
  // vault switches to setup once the status comes back.
  const [stage, setStage] = useState<Stage>(PREVIEW_UNLOCK ? "open" : "locked");
  const [lockedAt, setLockedAt] = useState<Date | null>(null);

  useEffect(() => {
    if (PREVIEW_UNLOCK) return;
    invoke<string>("vault_status")
      .then((status) => {
        if (status === "new") setStage("setup");
      })
      .catch((error) => console.error("Unable to read the vault status", error));
  }, []);

  useEffect(() => {
    if (stage !== "open") document.documentElement.classList.remove("vault-seal-guard");
  }, [stage]);

  const lock = () => {
    setLockedAt(new Date());
    setStage("locked");
  };

  if (stage === "setup") return <Setup onDone={() => setStage("open")} />;
  if (stage === "locked") return <LockScreen lockedAt={lockedAt} onUnlock={() => setStage("open")} />;
  return <Dashboard onLock={lock} />;
}

export default App;
