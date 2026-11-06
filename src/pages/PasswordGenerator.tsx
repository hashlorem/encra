import { useCallback, useState } from "react";
import { Icon } from "../components/Icon";
import { useClipboard } from "../lib/useClipboard";

const LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
const SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?";

type StrengthTier = "weak" | "fair" | "good" | "strong";

interface Strength {
  score: number;
  label: string;
  tier: StrengthTier;
}

function getStrength(password: string): Strength {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 16) score++;
  if (password.length >= 24) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;

  if (score <= 2) return { score, label: "Weak", tier: "weak" };
  if (score <= 4) return { score, label: "Fair", tier: "fair" };
  if (score <= 5) return { score, label: "Good", tier: "good" };
  return { score, label: "Strong", tier: "strong" };
}

function generatePassword(length: number, charset: string): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);

  // Rejection sampling keeps the distribution uniform; a plain modulo would
  // bias the first characters of the alphabet.
  const ceiling = 256 - (256 % charset.length);
  let result = "";
  let index = 0;
  while (result.length < length) {
    if (index >= bytes.length) {
      crypto.getRandomValues(bytes);
      index = 0;
    }
    const byte = bytes[index++];
    if (byte < ceiling) result += charset[byte % charset.length];
  }
  return result;
}

interface PasswordGeneratorProps {
  onClose?: () => void;
}

function PasswordGenerator({ onClose }: PasswordGeneratorProps) {
  const [length, setLength] = useState(20);
  const [useLower, setUseLower] = useState(true);
  const [useUpper, setUseUpper] = useState(true);
  const [useDigits, setUseDigits] = useState(true);
  const [useSymbols, setUseSymbols] = useState(true);
  const [password, setPassword] = useState("");

  const { copy, copiedId } = useClipboard({ feedbackMs: 2000 });

  const charset = [
    useLower ? LOWERCASE : "",
    useUpper ? UPPERCASE : "",
    useDigits ? DIGITS : "",
    useSymbols ? SYMBOLS : "",
  ].join("");

  // Previously an empty selection silently fell back to the full character set,
  // ignoring what the user asked for.
  const noCharset = charset.length === 0;

  const generate = useCallback(() => {
    if (noCharset) return;
    setPassword(generatePassword(length, charset));
  }, [length, charset, noCharset]);

  const strength = getStrength(password);

  return (
    <div className="pwgen-page">
      <div className="page-header">
        <div className="page-heading-with-back">
          {onClose && (
            <button className="btn-icon" onClick={onClose} aria-label="Back to toolbox">
              <Icon name="arrow-left" size={18} />
            </button>
          )}
          <div className="page-heading">
            <span className="eyebrow">Cryptographic utility</span>
            <h1>Password generator</h1>
            <p>Create strong, unbiased passwords entirely on this device.</p>
          </div>
        </div>
      </div>

      <div className="pwgen-content">
        <section className="pwgen-output-card">
          <div className="pwgen-card-label"><Icon name="key" size={15} />Generated password</div>
          <div className="pwgen-output">
            <label className="sr-only" htmlFor="generated-password">Generated password</label>
            <input
              id="generated-password"
              type="text"
              className="pwgen-field"
              value={password}
              readOnly
              placeholder="Your secure password will appear here"
            />
            <button
              className="btn-icon pwgen-copy"
              onClick={() => void copy(password, "generated")}
              disabled={!password}
              aria-label="Copy generated password"
            >
              <Icon name={copiedId === "generated" ? "check" : "copy"} size={18} />
            </button>
          </div>

          {password ? (
            <div className="pwgen-strength">
              <div className="strength-meta">
                <span className={`strength-${strength.tier}`}>{strength.label}</span>
                <span>{password.length} characters</span>
              </div>
              <div className="strength-bar-bg">
                {/* Width and colour come from data attributes and classes, so no
                    inline style is needed under the strict CSP. */}
                <div
                  className={`strength-bar-fill is-${strength.tier}`}
                  data-score={strength.score}
                />
              </div>
            </div>
          ) : (
            <div className="pwgen-strength-placeholder">
              <Icon name="shield" size={14} />Generated locally using cryptographic randomness
            </div>
          )}
        </section>

        <section className="pwgen-options">
          <div className="option-heading">
            <div><h3>Customize</h3><p>Choose length and character composition.</p></div>
            <strong>{length}</strong>
          </div>
          <div className="option-row option-length">
            <input
              type="range"
              min={8}
              max={64}
              value={length}
              onChange={(event) => setLength(Number(event.target.value))}
              aria-label="Password length"
            />
            <div className="range-labels"><span>8</span><span>64</span></div>
          </div>

          <div className="option-grid">
            <label className="option-check">
              <input type="checkbox" checked={useLower} onChange={(event) => setUseLower(event.target.checked)} />
              <span className="custom-check"><Icon name="check" size={13} /></span>
              <span><strong>Lowercase</strong><small>a–z</small></span>
            </label>
            <label className="option-check">
              <input type="checkbox" checked={useUpper} onChange={(event) => setUseUpper(event.target.checked)} />
              <span className="custom-check"><Icon name="check" size={13} /></span>
              <span><strong>Uppercase</strong><small>A–Z</small></span>
            </label>
            <label className="option-check">
              <input type="checkbox" checked={useDigits} onChange={(event) => setUseDigits(event.target.checked)} />
              <span className="custom-check"><Icon name="check" size={13} /></span>
              <span><strong>Numbers</strong><small>0–9</small></span>
            </label>
            <label className="option-check">
              <input type="checkbox" checked={useSymbols} onChange={(event) => setUseSymbols(event.target.checked)} />
              <span className="custom-check"><Icon name="check" size={13} /></span>
              <span><strong>Symbols</strong><small>!@#$</small></span>
            </label>
          </div>

          {noCharset && (
            <p className="lock-error" role="alert">
              <Icon name="x" size={13} />Select at least one character set.
            </p>
          )}

          <button className="btn-primary btn-generate" onClick={generate} disabled={noCharset}>
            <Icon name="sparkles" size={17} />Generate password
          </button>
        </section>
      </div>
    </div>
  );
}

export default PasswordGenerator;
