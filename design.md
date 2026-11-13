# Design Contract: Encra

Replaces the "Terminal Authority" contract (Cobrypt, September 2026). The
themes and the screens added in November 2026 (import, check-up, ⌘K, case
indicators and timeline) follow the same rules.

## Product Truth

**What it is:** A local-first encrypted workbench for security work: logins
and one-time codes, case notes, a toolbox (password generator, Nmap parser,
command library) and an activity log of everything that touched the vault.

**Who uses it:** One security practitioner, mid-task. They copy a password,
write down a finding, check what happened while they were away. They are
operating, not browsing.

**Core job:** Hold secrets and case records with the care of an evidence
locker, and make that care visible without making the app feel like a
console cosplay.

**Platform:** Desktop (Tauri 2), macOS first. Light and dark are both
first-class; light is the default.

## Design Direction: Latent Print

**Thesis:** Encra reads like a well-kept lab notebook or a fingerprint lift
card. Paper, ink, typography and thin rules carry the structure. The
fingerprint is the one image, and it means "this is sealed".

### Signature Decisions

**1. The fingerprint is the seal.**
- A synthetic inked print (never a real person's) appears on the lock
  screen, as the Seal control in the rail, and faintly on a few
  record-level surfaces. The lock screen and the Seal control show the
  same print, whorl, loop or arch, chosen in Settings; whorl is the default.
- It is never decoration on a working surface beyond that. One image,
  spent on one meaning.
- Prints are rendered as a CSS mask over `--ink`, so one asset serves both
  themes. See Assets.

**2. Typography does the work boxes used to do.**
- Newsreader (serif) for page titles, record titles and the one-sentence
  summaries. Public Sans for all UI. IBM Plex Mono only for copy-exact
  data: passwords, one-time codes, hashes, IPs, file names, timestamps in
  logs, shortcuts.
- Labels are sentence case at body or meta size. No uppercase
  letter-spaced micro-labels.

**3. Rules, not cards.**
- Structure comes from 1px hairlines (`--rule`), whitespace and alignment.
- No bordered cards, no pills, no chips, no tag badges, no coloured
  left-border callouts, no numbered markers.
- A selected row is a flat `--paper-sunken` fill, nothing else.

**4. Say it in a sentence.**
- Where a dashboard would show stat tiles, write one plain sentence:
  "Twenty-four characters, with letters, numbers and symbols. It didn't
  turn up in any known breach when Encra last checked, on 2 November 2026."
- Status is words, not icons: "in a breach", "2FA", "Sealed."
- Never show data the vault does not actually have.

### Rejected

- Console cosplay (uppercase mono everywhere, pipe-separated status bars,
  `$ prompt` empty states). That was the old contract.
- Card grids, stat tiles, hero sections, gradients, glass, shadows.
- Icons on every button. Text buttons are the default; icons only where
  the target would otherwise be unclear (show/hide, close).
- Colour-coded severity badges. Severity is a word; only "critical" and
  "high" take `--danger`.

## Visual Language

### Colour

Four palettes fill the same nine tokens, each in light and dark. Latent
Print is the default; the others are picked in Settings and set as
`data-palette` on the root element. Nothing outside these tables.

Latent Print:

| Token            | Light     | Dark      | Use |
|------------------|-----------|-----------|-----|
| `--paper`        | `#F2F0EA` | `#141413` | Page background |
| `--paper-raised` | `#F8F7F3` | `#1C1C1A` | Dialogs, menus |
| `--paper-sunken` | `#E5E1D7` | `#2A2926` | Selected row, hover, pressed |
| `--ink`          | `#1B1B1A` | `#ECE9E2` | Primary text, primary button fill, field underlines, prints |
| `--ink-2`        | `#3F3E3B` | `#C9C5BC` | Body copy |
| `--ink-3`        | `#64625D` | `#A09C93` | Meta, labels, inactive nav |
| `--rule`         | `#D9D5CB` | `#3A3935` | Hairlines |
| `--link`         | `#2B47B5` | `#A9B9F2` | Links, text buttons, focus ring |
| `--danger`       | `#A1281E` | `#F0A39A` | Breaches, failed unlocks, delete, high/critical |

The other palettes, light / dark:

| Token            | Darkroom              | Cyanotype             | Evidence bag          |
|------------------|-----------------------|-----------------------|-----------------------|
| `--paper`        | `#F4EFE8` / `#120E0D` | `#EDF2F5` / `#0D2137` | `#DCCBAB` / `#1E1913` |
| `--paper-raised` | `#FAF7F2` / `#1A1513` | `#F6F9FB` / `#132A43` | `#E6D8BD` / `#26201A` |
| `--paper-sunken` | `#E7DFD3` / `#28201C` | `#DCE5EC` / `#1B3653` | `#CDB994` / `#332B22` |
| `--ink`          | `#1D1715` / `#EFE3D8` | `#10213A` / `#EAF1F8` | `#1C1711` / `#EFE5D3` |
| `--ink-2`        | `#3E3531` / `#D2C2B4` | `#2E4058` / `#C8D5E3` | `#3A3126` / `#D5C8B1` |
| `--ink-3`        | `#655A54` / `#A8968A` | `#4F6075` / `#A3B5C9` | `#4E4335` / `#B2A38B` |
| `--rule`         | `#DCD2C4` / `#3A2F29` | `#CCD8E2` / `#2B4763` | `#BFAA84` / `#4A3F32` |
| `--link`         | `#9A4A06` / `#F5B35A` | `#0A5CA8` / `#F2D27C` | `#1D3C8F` / `#AFC6F2` |
| `--danger`       | `#7E0E2A` / `#E97DA0` | `#A8261C` / `#FF9F94` | `#8A1A12` / `#F08C76` |

Checked, not eyeballed: `npm run check:contrast` (`tools/contrast/check.mjs`)
reads the tokens from `global.css` and fails if any text token is under
4.5:1 on any of the three surfaces, or the primary button's label is, at
rest or hovered, in any of the eight palette and mode pairs. The lowest
today: Latent Print 4.67:1 light / 5.31:1 dark, Darkroom 4.74 / 5.63,
Cyanotype 5.05 / 5.89, Evidence bag 4.90 / 5.63, all on `--paper-sunken`.
`--rule` is non-text decoration and is exempt.

The primary button is `--ink` on `--paper` text, so there is no separate
accent colour. Each palette has one hue, its `--link`; `--danger` is the
only other colour, and only for danger.

### Typography

| Size | Face | Use |
|------|------|-----|
| 13px | Public Sans / Plex Mono | Meta, timestamps, shortcuts |
| 15px | Public Sans | Body and UI (base) |
| 17px | Public Sans 600 | Entry titles, field values that matter |
| 20px | Newsreader | One-sentence summaries |
| 26px | Newsreader 500 | Wordmark |
| 40px | Newsreader | Section titles (Vault, Activity) |
| 56px | Newsreader | Lock and record titles |

Line height 1.5 for text, 1.05 for the two display sizes. Weights: 400,
500, 600 only. Fonts are self-hosted (Latin subset, woff2 only) from the
Fontsource packages through `src/styles/fonts.css`; nothing is fetched at
runtime.

### Layout

- Rail (wordmark, nav, Seal) + content. Content is one or two columns:
  list and record, or a single notebook column. No third paradigm.
- 8px spacing grid. 4px is allowed inside a text group (label to field,
  title to meta) and nowhere else.
- Reading width caps at 640px for prose, 920px for tables.
- Radius: 2px on buttons and the selected-row fill. Everything else is
  square.
- Fields are an underline (`1.5px solid --ink`), not a box.

### Density

Comfortable is the default: list rows are 56px, with the name and its meta on
two lines. Compact (`data-density="compact"` on the root) drops list rows,
record facts and finding lines to 40px, the floor for dense rows, puts a
row's name and meta on one line (the name keeps its width; the meta is cut
first), and tightens entry and table padding. Nothing else changes.

### Motion

Smooth everywhere, down to small details, but never bouncy or springy.
Changed 7 November 2026; this replaces "functional only".

- **Tokens:** `--dur-fast` 140ms (hover, press), `--dur` 220ms (crossfades,
  focus lines), `--dur-slow` 360ms (entrances, the strength bar). One easing,
  `--ease` (`cubic-bezier(0.2, 0, 0, 1)`), a fast start that settles softly.
- **Entrances:** screens, records and dialogs rise 6px and fade in. Lists
  stagger 40ms per item, capped at 280ms. The lock print inks in from a blur.
- **Crossfades:** "Copy" to "Copied", a new one-time code, Show and Hide, the
  breach sentence, the strength label.
- **Feedback:** a wrong password shakes the field once. Buttons press to 98%.
  Text buttons draw their underline in from the left. The Seal print turns
  slightly on hover.
- **Fields:** the focus line grows from the left in `--link`, 2px. That line
  is the focus indicator for text fields.
- **Seal:** the workspace fades out over 160ms, then the lock screen shows.
  Lock on blur skips the fade. **Unlock:** the print drifts 8px and fades,
  200ms.
- Entrances use `animation-fill-mode: backwards`, so state classes still
  apply once an animation ends.
- `prefers-reduced-motion`: every animation and transition is switched off.

No skeleton shimmer, no looping animation, nothing that moves while you are
reading.

## Components

- **Buttons.** Primary: solid `--ink`, `--paper` text, one per view at most.
  Secondary: 1px `--ink` outline. Text button: `--link` text, no border.
  Destructive: `--danger` text button, always behind a confirmation.
- **Nav.** Plain text links in the rail. Active is `--ink` weight 600;
  inactive is `--ink-3`.
- **Lists.** Rows separated by `--rule` or by space, never boxed. Two
  lines max per row: name, then meta in `--ink-3`.
- **Records.** Title, one meta line, a definition list on hairlines, then
  the summary sentence, then history.
- **Empty states.** One plain sentence saying what to do next. "No logins
  yet. Add your first one." Not cute, no prompt syntax.
- **Findings** (check-up, indicators). A section title, then one line per
  finding on hairlines, with its action at the end: Change, Review, Show
  all, Copy. A login's line keeps three columns (name, what was found,
  action), so details line up from row to row and section to section;
  logins listed under a summary line indent their name only. A long finding
  collapses to one summary line. Only "In a breach" takes `--danger`.
- **Case tabs.** Notes, Evidence, Indicators, Timeline: text tabs on a
  hairline, the current one with a 2px `--ink` underline.
- **⌘K palette.** Opens near the top of the window: one field, then results
  grouped as Logins, Cases, Commands and Go to, with matched characters
  underlined. The active result is the sunken fill and shows its keys
  (↵ open, ⌘C password, ⌘⇧C code). ⌘F searches within the Vault.
- **Import.** One dialog in steps: what's in the file (counts on hairlines,
  names only), done (the export's path and an offer to delete it), confirm,
  deleted.
- **Icons.** Inline stroke SVG in `Icon.tsx`, 1.6px stroke, only where
  text alone is unclear. Brand icons from simpleicons.org, bundled.

## Assets

- **Fingerprints:** generated by `tools/fingerprint/generate.py` (orientation
  field plus Gabor ridge growth, the same method used to make synthetic
  test prints). Never a photo or scan of a real finger.
- Stored as alpha-only images in `src/assets/prints/` and drawn with
  `mask-image` over `--ink`, so there is one file per print, not one per
  theme. Raster is allowed for prints only; everything else stays SVG.
- Budget: under 150 KB per print.

## Quality Floor

- Visible 2px `--link` focus ring on every interactive element, offset 2px.
  Text fields use the 2px `--link` focus line instead (see Motion).
- Text contrast AA minimum, checked with the table above when a token
  changes.
- Icon-only buttons have an accessible name.
- Targets at least 44px high, or 40px for text buttons inside dense rows.
- Every page works in every palette, light and dark, and in compact
  density, before it ships.

## Performance and Storage

- No new frontend dependency without checking the `vite build` output.
  Fontsource packages are the accepted exception for self-hosted fonts.
- Lists virtualise past ~200 rows: `VirtualList` for fixed-height rows
  (the Vault list), pages of 100 for variable-height ones (Nmap hosts,
  Activity).
- The lock screen renders before any database read.
- Secrets stay in Rust. The webview gets metadata for lists and asks for
  one field at a time; copying happens in Rust.

## Implementation Constraints

- CSP stays self-only for scripts, styles, fonts and connections. The only
  network call is the HIBP range query, and Rust makes it, not the webview.
- The webview has no file system or dialog access. Files are picked with
  dialogs opened from Rust, or dropped on the window and claimed in Rust,
  then read and written there (`src-tauri/src/commands/files.rs`).
- No inline `style` attributes (the production CSP blocks them); dynamic
  values go through the CSSOM.
- Copying: anything the page supplies goes through `copy_text`, and vault
  fields through `copy_credential_field`. Both hide the value from clipboard
  history and wipe it after 30 seconds and on seal. Case indicators and
  evidence hashes aren't secrets and are meant for reports, so they stay on
  the clipboard, but the page only names them (`copy_indicators`,
  `copy_evidence_hash`) and Rust looks up the text.
- Appearance (palette, mode, density, lock print) lives in `localStorage`,
  is applied before the first paint, and is never secret.

## Finish Gate

Before a UI change ships:

1. No card, pill, badge, numbered marker, uppercase micro-label or
   left-border callout crept back in.
2. Nothing shown that the vault doesn't actually hold.
3. Keyboard path, focus ring, every palette in both modes, compact density
   and the empty state all checked, and `npm run check:contrast` passes.
4. Motion confirms a state change or it goes.
5. Would a person have made this, or does it look generated? If the
   latter, remove things until it doesn't.
