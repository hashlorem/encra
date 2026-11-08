import { Print, type PrintKind } from "./Print";
import { useTheme, type Density, type Palette, type Theme } from "../lib/ThemeContext";

const PALETTES: { id: Palette; name: string; note: string }[] = [
  { id: "latent", name: "Latent Print", note: "Paper, ink and one blue. The default." },
  { id: "darkroom", name: "Darkroom", note: "Warm black under a safelight. By day, a contact sheet." },
  { id: "cyanotype", name: "Cyanotype", note: "Blueprint blue, with pale-gold links at night." },
  { id: "evidence", name: "Evidence bag", note: "Kraft paper and custody-form blue." },
];

const MODES: { id: Theme; label: string }[] = [
  { id: "light", label: "Light" },
  { id: "dark", label: "Dark" },
  { id: "system", label: "Match the system" },
];

const PRINTS: { id: PrintKind; label: string }[] = [
  { id: "whorl", label: "Whorl" },
  { id: "loop", label: "Loop" },
  { id: "arch", label: "Arch" },
];

const DENSITIES: { id: Density; label: string; note: string }[] = [
  { id: "comfortable", label: "Comfortable", note: "Rows are 56 px tall. The default." },
  { id: "compact", label: "Compact", note: "Rows are 40 px tall, so long lists fit more on screen." },
];

const current = (on: boolean) => (on ? " is-current" : "");

/** Theme, light or dark, the lock print and density. Applied as they change. */
export function AppearanceSettings() {
  const { theme, set, palette, setPalette, density, setDensity, lockPrint, setLockPrint } = useTheme();

  return (
    <div className="settings-body is-wide appearance">
      <fieldset>
        <legend className="label">Theme</legend>
        {PALETTES.map((option) => (
          <label key={option.id} className={`theme-row${current(palette === option.id)}`}>
            <input type="radio" name="palette" checked={palette === option.id} onChange={() => setPalette(option.id)} />
            <span className="choice-copy">
              <span className="choice-name">{option.name}</span>
              <span className="meta">{option.note}</span>
            </span>
            <span className="swatch" data-swatch={option.id} aria-hidden="true">
              <Print kind={lockPrint} />
              <span className="swatch-type">Aa</span>
              <span className="swatch-link">Copy</span>
              <span className="swatch-danger">breach</span>
            </span>
          </label>
        ))}
      </fieldset>

      <fieldset className="choice">
        <legend className="label">Light or dark</legend>
        {MODES.map((option) => (
          <label key={option.id} className={`checkbox${current(theme === option.id)}`}>
            <input type="radio" name="theme" checked={theme === option.id} onChange={() => set(option.id)} />
            <span className="choice-name">{option.label}</span>
          </label>
        ))}
      </fieldset>

      <fieldset>
        <legend className="label">Lock-screen print</legend>
        <div className="print-choices">
          {PRINTS.map((option) => (
            <label key={option.id} className={`print-choice${current(lockPrint === option.id)}`}>
              <Print kind={option.id} />
              <span className="checkbox">
                <input type="radio" name="lock-print" checked={lockPrint === option.id} onChange={() => setLockPrint(option.id)} />
                <span className="choice-name">{option.label}</span>
              </span>
            </label>
          ))}
        </div>
        <p className="meta">The Seal button in the rail uses the same print. All three are synthetic, generated, never a real finger.</p>
      </fieldset>

      <fieldset>
        <legend className="label">Density</legend>
        {DENSITIES.map((option) => (
          <label key={option.id} className={`checkbox${current(density === option.id)}`}>
            <input type="radio" name="density" checked={density === option.id} onChange={() => setDensity(option.id)} />
            <span className="choice-copy">
              <span className="choice-name">{option.label}</span>
              <span className="meta">{option.note}</span>
            </span>
          </label>
        ))}
      </fieldset>

      <p className="meta">Saved on this Mac only. The lock screen uses them before the vault is opened, so nothing here is secret.</p>
    </div>
  );
}
