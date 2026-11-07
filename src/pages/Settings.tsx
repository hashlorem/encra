import { useCallback, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save, open } from "@tauri-apps/plugin-dialog";
import { writeTextFile, readTextFile } from "@tauri-apps/plugin-fs";
import { useTheme, type Theme } from "../lib/ThemeContext";
import { Icon } from "../components/Icon";
import { ModalOverlay } from "../components/ModalOverlay";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState } from "../components/EmptyState";
import {
  PREFERENCE_KEYS,
  readBooleanPreference,
  readPreference,
  writeBooleanPreference,
  writePreference,
} from "../lib/preferences";
import { describeError } from "../lib/errors";
import { useClipboard } from "../lib/useClipboard";
import { APP_NAME, APP_VERSION } from "../lib/appInfo";
import type { ActivityEntry } from "../lib/types";

const THEME_OPTIONS: readonly Theme[] = ["dark", "light", "system"];

function Settings() {
  const { theme, set: setTheme } = useTheme();

  const [backupPassword, setBackupPassword] = useState("");
  const [backupMsg, setBackupMsg] = useState("");
  const [exporting, setExporting] = useState(false);
  const [importPassword, setImportPassword] = useState("");
  const [importMsg, setImportMsg] = useState("");
  const [importing, setImporting] = useState(false);
  const [pendingImport, setPendingImport] = useState<{ contents: string } | null>(null);

  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [showReauth, setShowReauth] = useState(false);
  const [reauthPassword, setReauthPassword] = useState("");
  const [reauthError, setReauthError] = useState("");
  const [reauthBusy, setReauthBusy] = useState(false);

  const [activityLog, setActivityLog] = useState<ActivityEntry[]>([]);
  const [showActivity, setShowActivity] = useState(false);
  const [activityLoading, setActivityLoading] = useState(false);

  const [lockKeybind, setLockKeybind] = useState(
    () => readPreference(PREFERENCE_KEYS.lockKeybind) || "meta+l",
  );
  const [autoLockOnBlur, setAutoLockOnBlur] = useState(() =>
    readBooleanPreference(PREFERENCE_KEYS.autoLockBlur, false),
  );
  const [soundEnabled, setSoundEnabled] = useState(() =>
    readBooleanPreference(PREFERENCE_KEYS.sound, true),
  );

  const { copy: copyToClipboard, copiedId } = useClipboard({ feedbackMs: 2000 });

  const updateLockKeybind = (value: string) => {
    setLockKeybind(value);
    writePreference(PREFERENCE_KEYS.lockKeybind, value);
    window.dispatchEvent(new CustomEvent("encra:settings-changed"));
  };

  const toggleAutoLock = () => {
    const next = !autoLockOnBlur;
    setAutoLockOnBlur(next);
    writeBooleanPreference(PREFERENCE_KEYS.autoLockBlur, next);
    window.dispatchEvent(new CustomEvent("encra:settings-changed"));
  };

  const toggleSound = () => {
    const next = !soundEnabled;
    setSoundEnabled(next);
    writeBooleanPreference(PREFERENCE_KEYS.sound, next);
    window.dispatchEvent(new CustomEvent("encra:settings-changed"));
  };

  const loadActivity = useCallback(async () => {
    setShowActivity(true);
    setActivityLoading(true);
    try {
      const log = await invoke<ActivityEntry[]>("get_activity_log");
      setActivityLog(log);
    } catch (error) {
      console.error("Unable to load the activity log", error);
      setActivityLog([]);
    } finally {
      setActivityLoading(false);
    }
  }, []);

  const handleExport = async () => {
    if (exporting) return;
    if (!backupPassword) {
      setBackupMsg("Enter a backup password first.");
      return;
    }
    setExporting(true);
    setBackupMsg("Encrypting…");
    try {
      const encrypted = await invoke<string>("export_backup", { backupPassword });
      const filePath = await save({
        defaultPath: `encra-backup-${new Date().toISOString().slice(0, 10)}.encra`,
        filters: [{ name: "Encra Backup", extensions: ["encra"] }],
      });
      if (filePath) {
        await writeTextFile(filePath, encrypted);
        setBackupMsg("Backup saved.");
        setBackupPassword("");
      } else {
        setBackupMsg("");
      }
    } catch (error) {
      setBackupMsg(describeError(error, "Could not export a backup. Nothing was written."));
    } finally {
      setExporting(false);
    }
  };

  const handleImport = async () => {
    if (importing || pendingImport) return;
    if (!importPassword) {
      setImportMsg("Enter the backup password first.");
      return;
    }
    setImportMsg("");
    try {
      const filePath = await open({
        filters: [{ name: "Encra Backup", extensions: ["encra", "cobrypt", "kpt"] }],
        multiple: false,
      });
      if (!filePath) return;
      const contents = await readTextFile(filePath as string);
      // Import adds to the current vault rather than replacing it, so confirm
      // before touching stored data.
      setPendingImport({ contents });
    } catch (error) {
      setImportMsg(describeError(error, "Could not read that backup file."));
    }
  };

  const confirmImport = async () => {
    if (!pendingImport || importing) return;
    setImporting(true);
    try {
      await invoke("import_backup", {
        // The backend parameter is `bundled`; sending the wrong key here made
        // every import fail before this was fixed.
        bundled: pendingImport.contents,
        backupPassword: importPassword,
      });
      setImportMsg("Import complete.");
      setImportPassword("");
      setPendingImport(null);
    } catch (error) {
      setImportMsg(describeError(error, "Import failed. Nothing was changed in your vault."));
      setPendingImport(null);
    } finally {
      setImporting(false);
    }
  };

  const cancelImport = () => {
    setPendingImport(null);
    setImportPassword("");
    setImportMsg("");
  };

  const handleGenerateCodes = () => {
    setShowReauth(true);
    setReauthPassword("");
    setReauthError("");
  };

  const closeReauth = () => {
    setShowReauth(false);
    // Do not leave the password sitting in component state after the dialog
    // closes, whether it succeeded or not.
    setReauthPassword("");
    setReauthError("");
  };

  const confirmReauth = async () => {
    if (reauthBusy) return;
    setReauthBusy(true);
    setReauthError("");
    try {
      const ok = await invoke<boolean>("verify_master_password", { password: reauthPassword });
      if (!ok) {
        setReauthError("That master password is not correct.");
        return;
      }
      const codes = await invoke<string[]>("generate_recovery_codes");
      setReauthPassword("");
      setShowReauth(false);
      setRecoveryCodes(codes);
    } catch (error) {
      setReauthError(describeError(error, "Could not generate recovery codes."));
    } finally {
      setReauthBusy(false);
    }
  };

  const dismissRecoveryCodes = () => {
    setRecoveryCodes(null);
  };

  const copyAllCodes = () => {
    if (!recoveryCodes) return;
    void copyToClipboard(recoveryCodes.join("\n"), "recovery-codes");
  };

  // Recovery codes are deliberately NOT auto-hidden: the user only ever sees
  // them once, so expiring the view could lose them permanently.

  return (
    <div className="settings-page">
      <div className="page-header">
        <div className="page-heading">
          <span className="eyebrow">Workspace controls</span>
          <h1>Settings</h1>
          <p>Manage recovery, backups, appearance, and your local audit trail.</p>
        </div>
      </div>

      {showReauth && (
        <ModalOverlay onClose={closeReauth} labelledBy="reauth-title">
          <div className="modal">
            <div className="modal-heading">
              <span className="modal-icon"><Icon name="lock" size={18} /></span>
              <div>
                <h4 id="reauth-title">Confirm master password</h4>
                <p>Re-enter your password to regenerate recovery codes.</p>
              </div>
            </div>
            <label className="field-label" htmlFor="reauth-password">Master password</label>
            <input
              id="reauth-password"
              type="password"
              placeholder="Master password"
              value={reauthPassword}
              onChange={(e) => setReauthPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && void confirmReauth()}
              autoComplete="current-password"
            />
            {reauthError && <p className="lock-error" role="alert">{reauthError}</p>}
            <div className="modal-actions">
              <button className="btn-secondary" onClick={closeReauth} disabled={reauthBusy}>Cancel</button>
              <button className="btn-primary" onClick={() => void confirmReauth()} disabled={reauthBusy || !reauthPassword}>
                {reauthBusy ? "Verifying…" : "Confirm"}
              </button>
            </div>
          </div>
        </ModalOverlay>
      )}

      {pendingImport && (
        <ConfirmDialog
          title="Restore this backup?"
          message="The entries in this backup will be added to your current vault. Existing entries are not replaced or removed."
          confirmLabel="Restore backup"
          busy={importing}
          onConfirm={() => void confirmImport()}
          onCancel={cancelImport}
        />
      )}

      {showActivity && (
        <ModalOverlay onClose={() => setShowActivity(false)} labelledBy="activity-title">
          <div className="modal modal-wide activity-modal">
            <div className="modal-heading modal-heading-between">
              <span className="modal-icon"><Icon name="activity" size={18} /></span>
              <div>
                <h4 id="activity-title">Activity log</h4>
                <p>Recent security events recorded on this device.</p>
              </div>
            </div>
            {activityLoading && <p className="inline-message" role="status">Loading…</p>}
            {!activityLoading && activityLog.length === 0 && (
              <EmptyState prompt="$ cat /var/log/encra" output="no activity recorded" />
            )}
            {activityLog.map((entry) => (
              <div key={entry.id} className="activity-row">
                <span className="activity-dot" />
                <span className="activity-action">{entry.action}</span>
                <span className="activity-detail">{entry.detail}</span>
                <span className="activity-time">{entry.timestamp}</span>
              </div>
            ))}
          </div>
        </ModalOverlay>
      )}

      <div className="settings-grid">
        <div className="settings-section settings-section-featured">
          <div className="settings-section-heading">
            <span className="settings-icon"><Icon name="shield" size={19} /></span>
            <div><h3>Recovery codes</h3><p>Emergency access if you forget your master password.</p></div>
          </div>
          {!recoveryCodes ? (
            <div className="settings-action-row">
              <div className="settings-assurance"><Icon name="check" size={14} />Eight single-use codes, encrypted independently</div>
              <button className="btn-primary" onClick={handleGenerateCodes}><Icon name="sparkles" size={15} />Generate codes</button>
            </div>
          ) : (
            <div>
              <div className="recovery-codes-grid">
                {recoveryCodes.map((code, index) => (
                  <code key={code} className="recovery-code">
                    <span>{String(index + 1).padStart(2, "0")}</span>{code}
                  </code>
                ))}
              </div>
              <div className="recovery-warning"><Icon name="shield" size={15} /><span>Store these now — this is the only time they are shown.</span></div>
              <div className="settings-action-row">
                <button className="btn-secondary" onClick={copyAllCodes}>
                  <Icon name={copiedId === "recovery-codes" ? "check" : "copy"} size={15} />
                  {copiedId === "recovery-codes" ? "Copied" : "Copy all"}
                </button>
                <button className="btn-secondary" onClick={dismissRecoveryCodes}>I’ve saved them</button>
              </div>
            </div>
          )}
        </div>

        <div className="settings-section">
          <div className="settings-section-heading">
            <span className="settings-icon"><Icon name="download" size={19} /></span>
            <div><h3>Encrypted backup</h3><p>Export a password-protected copy of your workspace.</p></div>
          </div>
          <div className="settings-input-row">
            <label className="sr-only" htmlFor="backup-password">Backup password</label>
            <input
              id="backup-password"
              className="app-input"
              type="password"
              placeholder="Create a backup password"
              autoComplete="new-password"
              value={backupPassword}
              onChange={(e) => setBackupPassword(e.target.value)}
              disabled={exporting}
            />
            <button className="btn-primary" onClick={() => void handleExport()} disabled={exporting || !backupPassword}>
              <Icon name="download" size={15} />{exporting ? "Exporting…" : "Export"}
            </button>
          </div>
          {backupMsg && <p className="inline-message" role="status">{backupMsg}</p>}
        </div>

        <div className="settings-section">
          <div className="settings-section-heading">
            <span className="settings-icon"><Icon name="upload" size={19} /></span>
            <div><h3>Restore backup</h3><p>Import an Encra backup, or one made by Cobrypt or KeyRPT.</p></div>
          </div>
          <div className="settings-input-row">
            <label className="sr-only" htmlFor="import-password">Backup password</label>
            <input
              id="import-password"
              className="app-input"
              type="password"
              placeholder="Enter the backup password"
              autoComplete="off"
              value={importPassword}
              onChange={(e) => setImportPassword(e.target.value)}
              disabled={importing}
            />
            <button className="btn-secondary" onClick={() => void handleImport()} disabled={importing || !importPassword}>
              <Icon name="upload" size={15} />{importing ? "Importing…" : "Import"}
            </button>
          </div>
          {importMsg && <p className="inline-message" role="status">{importMsg}</p>}
        </div>

        <div className="settings-section">
          <div className="settings-section-heading">
            <span className="settings-icon"><Icon name="activity" size={19} /></span>
            <div><h3>Activity log</h3><p>Review security-sensitive actions performed locally.</p></div>
          </div>
          <button className="btn-secondary" onClick={() => void loadActivity()}>
            <Icon name="activity" size={15} />View activity
          </button>
        </div>

        <div className="settings-section settings-security-card">
          <div className="settings-section-heading">
            <span className="settings-icon"><Icon name="lock" size={19} /></span>
            <div><h3>Security</h3><p>Lock behavior and session controls.</p></div>
          </div>
          <div className="security-controls">
            <label className="security-control-row">
              <span className="security-control-copy">
                <strong>Lock shortcut</strong>
                <small>Seal the vault from anywhere in the workspace.</small>
              </span>
              <select
                className="security-keybind-select"
                value={lockKeybind}
                onChange={(e) => updateLockKeybind(e.target.value)}
                aria-label="Vault lock keyboard shortcut"
              >
                <option value="meta+l">⌘ L</option>
                <option value="meta+shift+l">⌘ ⇧ L</option>
                <option value="alt+l">⌥ L</option>
                <option value="meta+escape">⌘ Esc</option>
              </select>
            </label>
            <div className="security-control-row">
              <span className="security-control-copy">
                <strong>Lock on app switch</strong>
                <small>Seal the vault whenever {APP_NAME} loses focus.</small>
              </span>
              <button
                className={`security-toggle${autoLockOnBlur ? " is-on" : ""}`}
                onClick={toggleAutoLock}
                type="button"
                role="switch"
                aria-checked={autoLockOnBlur}
                aria-label="Lock vault when the app loses focus"
              >
                <span />
              </button>
            </div>
            <div className="security-control-row">
              <span className="security-control-copy">
                <strong>Sound</strong>
                <small>Play a tone when the vault unlocks or seals.</small>
              </span>
              <button
                className={`security-toggle${soundEnabled ? " is-on" : ""}`}
                onClick={toggleSound}
                type="button"
                role="switch"
                aria-checked={soundEnabled}
                aria-label="Play a sound on lock and unlock"
              >
                <span />
              </button>
            </div>
          </div>
        </div>

        <div className="settings-section">
          <div className="settings-section-heading">
            <span className="settings-icon"><Icon name={theme === "light" ? "sun" : "moon"} size={19} /></span>
            <div><h3>Appearance</h3><p>Choose how {APP_NAME} looks on this device.</p></div>
          </div>
          <div className="theme-segment" role="group" aria-label="Color theme">
            {THEME_OPTIONS.map((option) => (
              <button
                key={option}
                className={theme === option ? "active" : ""}
                onClick={() => setTheme(option)}
                aria-pressed={theme === option}
              >
                <Icon name={option === "dark" ? "moon" : option === "light" ? "sun" : "settings"} size={15} />
                {option}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="settings-about">
        <span>encra {APP_VERSION}</span>
        <span className="status-dot" />
        <span>Local-first encrypted security workspace</span>
      </div>
    </div>
  );
}

export default Settings;
