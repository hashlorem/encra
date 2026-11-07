import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Print } from "../components/Print";
import { Wordmark } from "../components/Wordmark";
import { describeError } from "../lib/errors";
import { useClipboard } from "../lib/useClipboard";
import { groupCode } from "../lib/format";

const MIN_CHARS = 12;

function strength(password: string): { level: number; words: string } {
  const length = password.length;
  if (length === 0) return { level: 0, words: `${MIN_CHARS} minimum` };
  if (length < MIN_CHARS) return { level: 1, words: `${length} of ${MIN_CHARS}` };
  if (length < 16) return { level: 2, words: `${length} characters` };
  if (length < 20) return { level: 3, words: `${length} characters` };
  return { level: 4, words: `${length} characters` };
}

interface SetupProps {
  onDone: () => void;
}

/** First run: choose a confirmed master password, then save recovery codes. */
function Setup({ onDone }: SetupProps) {
  const [step, setStep] = useState<1 | 2>(1);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const { copyText, copiedId } = useClipboard(2000);

  const { level, words } = strength(password);
  const matches = confirm.length > 0 && confirm === password;
  const canContinue = password.length >= MIN_CHARS && matches && !busy;

  const loadCodes = async () => {
    setError("");
    try {
      setCodes(await invoke<string[]>("generate_recovery_codes"));
    } catch (err) {
      setError(describeError(err, "Couldn’t make recovery codes."));
    }
  };

  const create = async () => {
    if (!canContinue) return;
    setBusy(true);
    setError("");
    try {
      await invoke("create_vault", { masterPassword: password });
      setPassword("");
      setConfirm("");
      setStep(2);
      await loadCodes();
    } catch (err) {
      setError(describeError(err, "Couldn’t create the vault."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="setup">
      <Print kind="arch" className="setup-watermark" />
      <div className="setup-top">
        <Wordmark />
        <span className="meta">{step} of 2</span>
      </div>

      {step === 1 ? (
        <form
          key="password"
          className="setup-body stagger"
          onSubmit={(event) => {
            event.preventDefault();
            void create();
          }}
        >
          <h1 className="title-xl">New vault.</h1>

          <div className="field">
            <label className="label" htmlFor="new-master">Master password</label>
            <input
              id="new-master"
              className="input input-secret"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="new-password"
              autoFocus
            />
            <div className="strength">
              <span className="strength-bar" data-level={level}><span /></span>
              <span key={words} className="fade">{words}</span>
            </div>
          </div>

          <div className="field">
            <label className="label" htmlFor="confirm-master">Again</label>
            <input
              id="confirm-master"
              className="input input-secret"
              type="password"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              autoComplete="new-password"
            />
            {confirm && !matches && <span className="meta">Doesn’t match</span>}
          </div>

          {error && <p className="error" role="alert">{error}</p>}

          <div className="actions">
            <button className="btn" type="submit" disabled={!canContinue}>
              {busy ? "Creating…" : "Create vault"}
            </button>
          </div>
        </form>
      ) : (
        <div key="codes" className="setup-body stagger">
          <div className="notebook-head">
            <h1 className="title-xl">Recovery codes.</h1>
            <p className="lead">Shown once. Each works once.</p>
          </div>

          {codes ? (
            <ol className="codes stagger">
              {codes.map((code) => (
                <li key={code}>{groupCode(code)}</li>
              ))}
            </ol>
          ) : (
            !error && <p className="status" role="status">Generating…</p>
          )}

          {error && <p className="error" role="alert">{error}</p>}

          <div className="actions">
            {codes ? (
              <>
                <button className="btn" onClick={onDone}>Done</button>
                <button className="btn-text" onClick={() => void copyText(codes.map(groupCode).join("\n"), "codes")}>
                  {copiedId === "codes" ? "Copied" : "Copy"}
                </button>
              </>
            ) : (
              error && (
                <>
                  <button className="btn" onClick={() => void loadCodes()}>Try again</button>
                  <button className="btn-text" onClick={onDone}>Skip</button>
                </>
              )
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default Setup;
