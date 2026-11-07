import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { save, open } from "@tauri-apps/plugin-dialog";
import { writeTextFile, readTextFile } from "@tauri-apps/plugin-fs";
import { useTheme, type Theme } from "../lib/ThemeContext";
import { ModalOverlay } from "../components/ModalOverlay";
import { ConfirmDialog } from "../components/ConfirmDialog";
import {
  PREFERENCE_KEYS,
  readBooleanPreference,
  readPreference,
  writeBooleanPreference,
  writePreference,
} from "../lib/preferences";
import { describeError } from "../lib/errors";
import { groupCode } from "../lib/format";
import { useClipboard } from "../lib/useClipboard";
import { APP_NAME, APP_VERSION } from "../lib/appInfo";

const THEME_OPTIONS: readonly Theme[] = ["light", "dark", "system"];

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


  const [lockKeybind, setLockKeybind] = useState(
    () => readPreference(PREFERENCE_KEYS.lockKeybind) || "meta+l",
  );
  const [autoLockOnBlur, setAutoLockOnBlur] = useState(() =>
    readBooleanPreference(PREFERENCE_KEYS.autoLockBlur, false),
  );
  const [soundEnabled, setSoundEnabled] = useState(() =>
    readBooleanPreference(PREFERENCE_KEYS.sound, true),
  );

  const { copyText, copiedId } = useClipboard(2000);

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
    copyText(recoveryCodes.map(groupCode).join("\n"), "recovery-codes").catch((error) =>
      setReauthError(describeError(error, "Could not copy the codes.")),
    );
  };

  // Recovery codes are deliberately NOT auto-hidden: the user only ever sees
  // them once, so expiring the view could lose them permanently.

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1 className="title-l">Settings</h1>
          <p className="lead">Recovery, backups, locking and appearance. Stored on this machine only.</p>
        </div>
      </header>

      <div className="settings stagger">
        <section aria-labelledby="recovery-heading">
          <div>
            <h2 id="recovery-heading" className="section-title">Recovery codes</h2>
            <p className="meta">For when the master password is forgotten.</p>
          </div>
          <div className="settings-body">
            {!recoveryCodes ? (
              <>
                <p className="lead">
                  Eight single-use codes, each able to set a new master password. Making new ones cancels any
                  you saved before.
                </p>
                <div className="actions">
                  <button className="btn-outline" onClick={handleGenerateCodes}>Make new codes</button>
                </div>
                {reauthError && !showReauth && <p className="error" role="alert">{reauthError}</p>}
              </>
            ) : (
              <>
                <p className="lead">This is the only time these are shown. Write them down or print them now.</p>
                <ol className="codes stagger">
                  {recoveryCodes.map((code) => <li key={code}>{groupCode(code)}</li>)}
                </ol>
                <div className="actions">
                  <button className="btn" onClick={dismissRecoveryCodes}>I’ve saved them</button>
                  <button className="btn-text" onClick={copyAllCodes}>
                    {copiedId === "recovery-codes" ? "Copied" : "Copy all"}
                  </button>
                </div>
              </>
            )}
          </div>
        </section>

        <section aria-labelledby="backup-heading">
          <div>
            <h2 id="backup-heading" className="section-title">Back up</h2>
            <p className="meta">An encrypted copy of everything in the vault.</p>
          </div>
          <div className="settings-body">
            <div className="field">
              <label className="label" htmlFor="backup-password">Backup password</label>
              <input id="backup-password" className="input input-secret" type="password" autoComplete="new-password"
                value={backupPassword} onChange={(e) => setBackupPassword(e.target.value)} disabled={exporting} />
              <span className="meta">At least 8 characters. You’ll need it to restore.</span>
            </div>
            <div className="actions">
              <button className="btn-outline" onClick={() => void handleExport()} disabled={exporting || !backupPassword}>
                {exporting ? "Exporting…" : "Export backup"}
              </button>
              {backupMsg && <span className="status" role="status">{backupMsg}</span>}
            </div>
          </div>
        </section>

        <section aria-labelledby="restore-heading">
          <div>
            <h2 id="restore-heading" className="section-title">Restore</h2>
            <p className="meta">Adds a backup’s entries to this vault.</p>
          </div>
          <div className="settings-body">
            <p className="lead">Works with Encra backups and older Cobrypt or KeyRPT ones. Nothing already here is replaced.</p>
            <div className="field">
              <label className="label" htmlFor="import-password">Backup password</label>
              <input id="import-password" className="input input-secret" type="password" autoComplete="off"
                value={importPassword} onChange={(e) => setImportPassword(e.target.value)} disabled={importing} />
            </div>
            <div className="actions">
              <button className="btn-outline" onClick={() => void handleImport()} disabled={importing || !importPassword}>
                {importing ? "Restoring…" : "Choose backup file"}
              </button>
              {importMsg && <span className="status" role="status">{importMsg}</span>}
            </div>
          </div>
        </section>

        <section aria-labelledby="locking-heading">
          <div>
            <h2 id="locking-heading" className="section-title">Locking</h2>
            <p className="meta">The vault also seals after 5 idle minutes.</p>
          </div>
          <div className="settings-body">
            <label className="inline-select">
              Seal shortcut
              <select value={lockKeybind} onChange={(e) => updateLockKeybind(e.target.value)}>
                <option value="meta+l">⌘L</option>
                <option value="meta+shift+l">⌘⇧L</option>
                <option value="alt+l">⌥L</option>
                <option value="meta+escape">⌘Esc</option>
              </select>
            </label>
            <label className="checkbox">
              <input type="checkbox" checked={autoLockOnBlur} onChange={toggleAutoLock} />
              Seal when I switch to another app
            </label>
            <label className="checkbox">
              <input type="checkbox" checked={soundEnabled} onChange={toggleSound} />
              Play a sound on unlock and seal
            </label>
          </div>
        </section>

        <section aria-labelledby="appearance-heading">
          <div>
            <h2 id="appearance-heading" className="section-title">Appearance</h2>
          </div>
          <div className="settings-body">
            <fieldset className="choice">
              <legend className="sr-only">Theme</legend>
              {THEME_OPTIONS.map((option) => (
                <label key={option} className="checkbox">
                  <input type="radio" name="theme" checked={theme === option} onChange={() => setTheme(option)} />
                  {option === "system" ? "Match the system" : option === "light" ? "Light" : "Dark"}
                </label>
              ))}
            </fieldset>
          </div>
        </section>
      </div>

      <p className="meta">{APP_NAME} {APP_VERSION}. Local-first; the only network call is the breach check.</p>

      {showReauth && (
        <ModalOverlay onClose={closeReauth} labelledBy="reauth-title">
          <form
            className="dialog"
            onSubmit={(event) => {
              event.preventDefault();
              void confirmReauth();
            }}
          >
            <h2 id="reauth-title">Confirm it’s you</h2>
            <p className="lead">Enter the master password to make new recovery codes.</p>
            <div className="field">
              <label className="label" htmlFor="reauth-password">Master password</label>
              <input id="reauth-password" className="input input-secret" type="password" autoComplete="current-password"
                autoFocus value={reauthPassword} onChange={(e) => setReauthPassword(e.target.value)} />
              {reauthError && <p className="error" role="alert">{reauthError}</p>}
            </div>
            <div className="actions">
              <button className="btn" type="submit" disabled={reauthBusy || !reauthPassword}>
                {reauthBusy ? "Checking…" : "Make codes"}
              </button>
              <button className="btn-text" type="button" onClick={closeReauth} disabled={reauthBusy}>Cancel</button>
            </div>
          </form>
        </ModalOverlay>
      )}

      {pendingImport && (
        <ConfirmDialog
          title="Restore this backup?"
          message="Its entries are added to this vault. Nothing already here is replaced or removed."
          confirmLabel="Restore"
          busy={importing}
          onConfirm={() => void confirmImport()}
          onCancel={cancelImport}
        />
      )}
    </div>
  );
}

export default Settings;
