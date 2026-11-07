import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Print } from "../components/Print";
import { Wordmark } from "../components/Wordmark";
import { describeError } from "../lib/errors";
import { useClipboard } from "../lib/useClipboard";

const MIN_CHARS = 12;

function strength(password: string): { level: number; words: string } {
  const length = password.length;
  if (length === 0) return { level: 0, words: `At least ${MIN_CHARS} characters.` };
  if (length < MIN_CHARS) return { level: 1, words: `Too short. ${length} of ${MIN_CHARS} characters.` };
  if (length < 16) return { level: 2, words: `Acceptable. ${length} characters.` };
  if (length < 20) return { level: 3, words: `Good. ${length} characters.` };
  return { level: 4, words: `Strong. ${length} characters.` };
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
      setError(describeError(err, "Could not make recovery codes. You can try again, or make them later in Settings."));
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
      setError(describeError(err, "Could not create the vault."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="setup">
      <Print kind="arch" className="setup-watermark" />
      <div className="setup-top">
        <Wordmark />
        <span className="meta">Step {step} of 2</span>
      </div>

      {step === 1 ? (
        <form
          className="setup-body"
          onSubmit={(event) => {
            event.preventDefault();
            void create();
          }}
        >
          <div className="notebook-head">
            <h1 className="title-xl">Start a vault.</h1>
            <p className="lead">
              Pick the one password that opens everything else. Encra can’t reset it for you, so pick
              something you’ll remember and don’t use anywhere else.
            </p>
          </div>

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
              <span>{words}</span>
            </div>
          </div>

          <div className="field">
            <label className="label" htmlFor="confirm-master">Type it again</label>
            <input
              id="confirm-master"
              className="input input-secret"
              type="password"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              autoComplete="new-password"
            />
            {confirm && <span className="meta">{matches ? "Matches." : "Doesn’t match yet."}</span>}
          </div>

          <p className="lead">
            <strong>After this,</strong> you’ll get eight recovery codes. Each one works once. Print them
            or write them down, and keep them away from this computer.
          </p>

          {error && <p className="error" role="alert">{error}</p>}

          <div className="actions">
            <button className="btn" type="submit" disabled={!canContinue}>
              {busy ? "Creating…" : "Continue"}
            </button>
          </div>
        </form>
      ) : (
        <div className="setup-body">
          <div className="notebook-head">
            <h1 className="title-xl">Save these.</h1>
            <p className="lead">
              If you ever forget the master password, one of these codes lets you set a new one. This is
              the only time they’re shown.
            </p>
          </div>

          {codes ? (
            <ol className="codes">
              {codes.map((code) => (
                <li key={code}>{code}</li>
              ))}
            </ol>
          ) : (
            !error && <p className="status" role="status">Making codes…</p>
          )}

          {error && <p className="error" role="alert">{error}</p>}

          <div className="actions">
            {codes ? (
              <>
                <button className="btn" onClick={onDone}>I’ve saved them</button>
                <button className="btn-text" onClick={() => void copyText(codes.join("\n"), "codes")}>
                  {copiedId === "codes" ? "Copied" : "Copy all"}
                </button>
              </>
            ) : (
              error && (
                <>
                  <button className="btn" onClick={() => void loadCodes()}>Try again</button>
                  <button className="btn-text" onClick={onDone}>Skip for now</button>
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
