import { useEffect, useState } from "react";
import LockScreen from "./pages/LockScreen";
import Dashboard from "./pages/Dashboard";
import { animateWindowMode } from "./lib/windowGeometry";
import { wipeClipboardNow } from "./lib/clipboardWipe";

/**
 * Dev-only shortcut that opens the workspace without the vault password.
 *
 * Gated on Vite's DEV flag rather than on a URL query parameter: `import.meta.env.DEV`
 * is statically false in a production build, so the branch is compiled out and the
 * bypass cannot be reached in a shipped app.
 */
const PREVIEW_UNLOCK =
  import.meta.env.DEV && new URLSearchParams(window.location.search).has("preview");

function App() {
  const [unlocked, setUnlocked] = useState(PREVIEW_UNLOCK);

  useEffect(() => {
    if (!unlocked) document.documentElement.classList.remove("vault-seal-guard");
  }, [unlocked]);

  const unlockWorkspace = () => {
    setUnlocked(true);
    void animateWindowMode(true);
  };

  const lockWorkspace = (immediate = false) => {
    // Every lock path (button, shortcut, idle timer, blur) ends here, so this is
    // the one place a still-pending copied secret gets wiped.
    void wipeClipboardNow();
    setUnlocked(false);
    void animateWindowMode(false, !immediate);
  };

  return (
    <div className="app-root">
      {!unlocked ? (
        <LockScreen onUnlock={unlockWorkspace} />
      ) : (
        <Dashboard onLock={lockWorkspace} />
      )}
    </div>
  );
}

export default App;
