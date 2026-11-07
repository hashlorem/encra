import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Print } from "../components/Print";
import { Wordmark } from "../components/Wordmark";
import { describeError } from "../lib/errors";
import { formatTime } from "../lib/format";
import { APP_VERSION } from "../lib/appInfo";

interface LockScreenProps {
  lockedAt: Date | null;
  onUnlock: () => void;
}

const MIN_MASTER_PASSWORD_CHARS = 12;
const OPEN_MS = 200;

function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function LockScreen({ lockedAt, onUnlock }: LockScreenProps) {
  const [mode, setMode] = useState<"unlock" | "recover">("unlock");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [opening, setOpening] = useState(false);

  const [recoveryCode, setRecoveryCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const open = () => {
    setOpening(true);
    setTimeout(onUnlock, prefersReducedMotion() ? 0 : OPEN_MS);
  };

  const unlock = async () => {
    if (!password || busy) return;
    setBusy(true);
    setError("");
    try {
      const ok = await invoke<boolean>("unlock_vault", { masterPassword: password });
      if (ok) {
        setPassword("");
        open();
      } else {
        setError("That isn’t the master password. This attempt was logged.");
      }
    } catch (err) {
      setError(describeError(err, "Could not unlock the vault."));
    } finally {
      setBusy(false);
    }
  };

  const recover = async () => {
    if (busy || !recoveryCode || !newPassword) return;
    setError("");
    if (newPassword.length < MIN_MASTER_PASSWORD_CHARS) {
      setError(`The new master password needs at least ${MIN_MASTER_PASSWORD_CHARS} characters.`);
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("The two new passwords don’t match.");
      return;
    }
    setBusy(true);
    try {
      const ok = await invoke<boolean>("reset_master_password", { recoveryCode, newPassword });
      if (ok) {
        setRecoveryCode("");
        setNewPassword("");
        setConfirmPassword("");
        open();
      } else {
        setError("That recovery code isn’t valid, or it has already been used.");
      }
    } catch (err) {
      setError(describeError(err, "Could not reset the master password."));
    } finally {
      setBusy(false);
    }
  };

  const switchMode = (next: "unlock" | "recover") => {
    setMode(next);
    setError("");
    // Never keep a code or a password around after leaving a form.
    setPassword("");
    setRecoveryCode("");
    setNewPassword("");
    setConfirmPassword("");
  };

  return (
    <div className={`lock${opening ? " is-opening" : ""}`}>
      <div className="lock-art">
        <Print kind="whorl" />
        <p className="lock-caption">Fig. 1. Plain whorl, synthetic.</p>
      </div>

      <main className="lock-panel">
        <Wordmark />

        {mode === "unlock" ? (
          <form
            className="lock-body"
            onSubmit={(event) => {
              event.preventDefault();
              void unlock();
            }}
          >
            <div>
              <h1 className="title-xl">Sealed.</h1>
              <p className="lead">
                {lockedAt ? `Locked at ${formatTime(lockedAt)}.` : "Enter your master password to open the vault."}
              </p>
            </div>
            <div className="field">
              <label className="label" htmlFor="master-password">Master password</label>
              <div className="input-row">
                <input
                  id="master-password"
                  className="input input-secret"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={busy}
                  autoFocus
                  autoComplete="current-password"
                />
                <button type="button" className="btn-text" onClick={() => setShowPassword((value) => !value)}>
                  {showPassword ? "Hide" : "Show"}
                </button>
              </div>
              {error && <p className="error" role="alert">{error}</p>}
            </div>
            <div className="actions">
              <button className="btn" type="submit" disabled={busy || !password}>
                {busy ? "Checking…" : "Unlock"}
              </button>
              <button type="button" className="btn-text" onClick={() => switchMode("recover")}>
                Use a recovery code instead
              </button>
            </div>
          </form>
        ) : (
          <form
            className="lock-body"
            onSubmit={(event) => {
              event.preventDefault();
              void recover();
            }}
          >
            <div>
              <h1 className="title-xl">Recover.</h1>
              <p className="lead">Each recovery code works once. Using one sets a new master password.</p>
            </div>
            <div className="field">
              <label className="label" htmlFor="recovery-code">Recovery code</label>
              <input
                id="recovery-code"
                className="input input-secret"
                value={recoveryCode}
                onChange={(event) => setRecoveryCode(event.target.value)}
                autoComplete="one-time-code"
                autoFocus
              />
            </div>
            <div className="field">
              <label className="label" htmlFor="new-password">New master password</label>
              <input
                id="new-password"
                className="input input-secret"
                type="password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                autoComplete="new-password"
              />
            </div>
            <div className="field">
              <label className="label" htmlFor="confirm-password">Type it again</label>
              <input
                id="confirm-password"
                className="input input-secret"
                type="password"
                value={confirmPassword}
                onChange={(event) => setConfirmPassword(event.target.value)}
                autoComplete="new-password"
              />
              {error && <p className="error" role="alert">{error}</p>}
            </div>
            <div className="actions">
              <button className="btn" type="submit" disabled={busy || !recoveryCode || !newPassword || !confirmPassword}>
                {busy ? "Re-keying…" : "Set password and unlock"}
              </button>
              <button type="button" className="btn-text" onClick={() => switchMode("unlock")}>
                Back to master password
              </button>
            </div>
          </form>
        )}

        <div className="lock-foot">
          <span>Decrypted on this machine. Nothing is sent anywhere.</span>
          <span className="mono">{APP_VERSION}</span>
        </div>
      </main>
    </div>
  );
}

export default LockScreen;
