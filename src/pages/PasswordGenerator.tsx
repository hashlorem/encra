import { useCallback, useState } from "react";
import { describeError } from "../lib/errors";
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
  onClose: () => void;
}

function PasswordGenerator({ onClose }: PasswordGeneratorProps) {
  const [length, setLength] = useState(20);
  const [useLower, setUseLower] = useState(true);
  const [useUpper, setUseUpper] = useState(true);
  const [useDigits, setUseDigits] = useState(true);
  const [useSymbols, setUseSymbols] = useState(true);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  const { copyText, copiedId } = useClipboard(2000);

  const charset = [
    useLower ? LOWERCASE : "",
    useUpper ? UPPERCASE : "",
    useDigits ? DIGITS : "",
    useSymbols ? SYMBOLS : "",
  ].join("");

  // An empty selection used to fall back silently to every character set.
  const noCharset = charset.length === 0;

  const generate = useCallback(() => {
    if (noCharset) return;
    setPassword(generatePassword(length, charset));
  }, [length, charset, noCharset]);

  const copy = async () => {
    try {
      await copyText(password, "generated");
    } catch (err) {
      setError(describeError(err, "Could not copy the password."));
    }
  };

  const strength = getStrength(password);

  return (
    <div className="page">
      <button className="btn-text back" onClick={onClose}>← Toolbox</button>
      <header className="page-head">
        <div>
          <h1 className="title-l">Password generator</h1>
          <p className="lead">Made on this machine from its secure random source. Nothing is stored until you save it to a login.</p>
        </div>
      </header>

      <section className="field" aria-live="polite">
        <span className="label">Generated</span>
        <p className="generated">{password || <span className="meta">Nothing generated yet.</span>}</p>
        {password && <p className="meta">{strength.label}. {password.length} characters.</p>}
      </section>

      <div className="actions">
        <button className="btn" onClick={generate} disabled={noCharset}>{password ? "Generate another" : "Generate"}</button>
        <button className="btn-text" onClick={() => void copy()} disabled={!password}>
          {copiedId === "generated" ? "Copied" : "Copy"}
        </button>
      </div>
      {error && <p className="error" role="alert">{error}</p>}

      <section className="field">
        <label className="label" htmlFor="pw-length">Length: {length}</label>
        <input id="pw-length" className="range" type="range" min={8} max={64} value={length}
          onChange={(event) => setLength(Number(event.target.value))} />
      </section>

      <fieldset className="options">
        <legend className="label">Characters</legend>
        <label className="checkbox"><input type="checkbox" checked={useLower} onChange={(e) => setUseLower(e.target.checked)} />Lowercase a–z</label>
        <label className="checkbox"><input type="checkbox" checked={useUpper} onChange={(e) => setUseUpper(e.target.checked)} />Uppercase A–Z</label>
        <label className="checkbox"><input type="checkbox" checked={useDigits} onChange={(e) => setUseDigits(e.target.checked)} />Numbers 0–9</label>
        <label className="checkbox"><input type="checkbox" checked={useSymbols} onChange={(e) => setUseSymbols(e.target.checked)} />Symbols !@#$</label>
      </fieldset>
      {noCharset && <p className="error" role="alert">Pick at least one set of characters.</p>}
    </div>
  );
}

export default PasswordGenerator;
