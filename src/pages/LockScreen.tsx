import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Icon } from "../components/Icon";
import { CobryptWordmark } from "../components/CobryptWordmark";
import { describeError } from "../lib/errors";
import { APP_VERSION } from "../lib/appInfo";

interface LockScreenProps {
  onUnlock: () => void;
}

const MIN_MASTER_PASSWORD_CHARS = 12;

function LockScreen({ onUnlock }: LockScreenProps) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showRecovery, setShowRecovery] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [recoveryMsg, setRecoveryMsg] = useState("");
  const [recoveryLoading, setRecoveryLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const unlock = async () => {
    if (!password || loading) return;
    setLoading(true);
    setError("");
    try {
      const success = await invoke<boolean>("unlock_vault", { masterPassword: password });
      if (success) {
        setPassword("");
        onUnlock();
      } else {
        setError("Wrong master password.");
      }
    } catch (err) {
      setError(describeError(err, "Could not unlock the vault."));
    } finally {
      setLoading(false);
    }
  };

  const handleRecovery = async () => {
    if (!recoveryCode || !newPassword || recoveryLoading) return;
    setRecoveryMsg("");
    if (newPassword.length < MIN_MASTER_PASSWORD_CHARS) {
      setRecoveryMsg(`The new master password must be at least ${MIN_MASTER_PASSWORD_CHARS} characters.`);
      return;
    }
    setRecoveryLoading(true);
    try {
      const ok = await invoke<boolean>("reset_master_password", { recoveryCode, newPassword });
      if (ok) {
        setRecoveryCode("");
        setNewPassword("");
        onUnlock();
      } else {
        setRecoveryMsg("That recovery code is not valid.");
      }
    } catch (err) {
      setRecoveryMsg(describeError(err, "Could not reset the master password."));
    } finally {
      setRecoveryLoading(false);
    }
  };

  const openRecovery = () => {
    setShowRecovery(true);
    setRecoveryMsg("");
  };

  const closeRecovery = () => {
    setShowRecovery(false);
    setRecoveryMsg("");
    // Do not keep a recovery code or a new password in state after abandoning
    // the form.
    setRecoveryCode("");
    setNewPassword("");
  };

  return (
    <div className="lockscreen">
      <main className="minimal-lock-main">
        <section className="minimal-lock-core" aria-label="Encrypted vault access">
          <h1 className="minimal-lock-wordmark">
            <CobryptWordmark interactive variant="lock" />
          </h1>

          {!showRecovery ? (
            <div className="auth-form minimal-auth-form">
              <label htmlFor="master-password">{loading ? "Verifying locally…" : "Master password"}</label>
              <div className="input-shell">
                <Icon name="key" size={17} />
                <input
                  id="master-password"
                  type={showPassword ? "text" : "password"}
                  placeholder="Enter master password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  onKeyDown={(event) => event.key === "Enter" && void unlock()}
                  disabled={loading}
                  autoFocus
                  autoComplete="current-password"
                />
                <button
                  className="input-action"
                  onClick={() => setShowPassword((value) => !value)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  <Icon name={showPassword ? "eye" : "eye-off"} size={17} />
                </button>
              </div>
              {error && <p className="lock-error" role="alert"><Icon name="x" size={13} />{error}</p>}
              <button className="lock-submit" onClick={() => void unlock()} disabled={loading || !password}>
                {loading ? "Unlocking…" : "Unlock"}
              </button>
              <button className="lock-recovery" onClick={openRecovery}>
                Recovery <Icon name="chevron-right" size={14} />
              </button>
              <p className="form-hint">
                First run? The password you enter becomes your master password and must be at least {MIN_MASTER_PASSWORD_CHARS} characters.
              </p>
            </div>
          ) : (
            <div className="auth-form minimal-auth-form minimal-recovery-form">
              <label htmlFor="recovery-code">Recovery code</label>
              <div className="input-shell">
                <Icon name="shield" size={17} />
                <input
                  id="recovery-code"
                  type="text"
                  placeholder="Enter a single-use code"
                  value={recoveryCode}
                  onChange={(event) => setRecoveryCode(event.target.value)}
                  autoComplete="one-time-code"
                  autoFocus
                />
              </div>
              <label htmlFor="new-password">New master password</label>
              <div className="input-shell">
                <Icon name="key" size={17} />
                <input
                  id="new-password"
                  type="password"
                  placeholder="Create a new master password"
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  onKeyDown={(event) => event.key === "Enter" && void handleRecovery()}
                  autoComplete="new-password"
                />
              </div>
              {recoveryMsg && <p className="lock-error" role="alert"><Icon name="x" size={13} />{recoveryMsg}</p>}
              <button
                className="unlock-btn"
                onClick={() => void handleRecovery()}
                disabled={recoveryLoading || !recoveryCode || !newPassword}
              >
                <Icon name="refresh" size={16} /> {recoveryLoading ? "Re-keying…" : "Re-key and unseal"}
              </button>
              <button className="lock-recovery" onClick={closeRecovery}>
                <Icon name="arrow-left" size={14} /> Master password
              </button>
            </div>
          )}
        </section>
      </main>

      <p className="lock-local-note">Decrypt this workspace locally. No password or vault data will be transmitted.</p>
      <p className="lock-version-note">ENCRA {APP_VERSION}</p>
    </div>
  );
}

export default LockScreen;
