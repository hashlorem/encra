# Design Contract — Cobrypt

## Product Truth

**What it is:** Local-first encrypted security workbench for pentesters and security professionals. Password vault, TOTP generator, engagement journal, Nmap parser, command knowledge base.

**Who uses it:** Security practitioners mid-task — checking credentials, logging findings, parsing scan results. They're not browsing; they're operating.

**Core job:** Provide precise, trustworthy tooling for sensitive security workflows. Every interaction must reinforce that the app handles secrets responsibly.

**Platform:** Desktop (Tauri 2), dark-first. No mobile, no web deployment.

## Surface Outcome: Operate

This is an **operational surface** — users complete and repeat security tasks. Hierarchy serves the workflow, density supports scanning, navigation is minimal and predictable. No persuasion, no marketing moments.

## Design Direction: Terminal Authority

**Thesis:** Cobrypt should feel like professional security tooling — the calm precision of a terminal or EDR console, not a consumer app. Confidence comes from restraint and exactness, not ornamentation.

### Signature Decisions (only a security tool would make these)

**1. Monospace for anything copy-exact**
- Passwords, TOTP codes, hashes, Nmap output, command KB entries: all in JetBrains Mono
- Rationale: "copy this precisely" is the literal job. Mono reinforces exactness and signals "this is data, not prose"
- UI chrome (labels, descriptions, nav) stays in Inter for readability
- Rejected: all-mono (fatiguing for navigation), all-sans (loses the "this is exact data" signal)

**2. Flat hairline depth, no shadow-as-elevation**
- 1px borders only, no box-shadow for depth
- Elevation comes from the three-tier background scale: `--bg` → `--surface` → `--surface-raised`
- Rationale: shadows read as "consumer app trying to look premium." Flat hairlines read as tooling
- Rejected: material shadows (too soft/consumer), neumorphism (decorative), glass morphism (trendy)

**3. Functional-only motion tied to state changes**
- Lock ↔ unlock is the one personality moment (SnakeEye animation, flight transition)
- Clipboard copy gets a brief flash/checkmark (~150ms) confirming the action
- Everything else: no animation on load, no skeleton shimmer, no page flourishes
- Rationale: this is a security tool — even motion curves should feel controlled, not playful
- Rejected: micro-interactions on every button (distracting), page transitions (unnecessary), loading skeletons (theater)

**4. Console-style status and telemetry**
- Vault status bar uses terminal conventions (monospace, uppercase labels, pipe separators)
- Lock screen telemetry shows vault state in console format
- Empty states use prompt syntax: `$ vault ls` → "No credentials yet"
- Rationale: security practitioners live in terminals. Console conventions signal "this is for you"
- Rejected: dashboard cards with metrics (generic SaaS), icon-only status (ambiguous), celebratory empty states (wrong tone)

### Rejected Alternatives

- **Card grid dashboard:** Would fragment the workflow. Sidebar nav + content pane keeps focus on one task at a time
- **Hero/marketing moments:** No onboarding tours, no feature highlights. Users know what a password manager is
- **Color-coded severity badges:** Would introduce new hues. Severity uses desaturated variants of existing accent/danger/success only
- **Decorative gradients/glass:** Reads as "trying to look modern." Flat + hairlines is the tooling aesthetic
- **Mascots/beyond SnakeEye:** SnakeEye is the one signature element, tied to lock state. Don't dilute it

## Visual Language

### Color (7 values, no exceptions)

```css
--bg: #080b10              /* near-black, primary background */
--surface: #0f141c         /* cards, panels, one step up */
--surface-raised: #141b25  /* modals, dropdowns, active states */
--border: rgba(255,255,255,0.075)  /* 1px only, never decorative */
--text: #f1f5f4            /* primary text */
--text-muted: #7f8a89      /* secondary text */
--accent: #f2c94c          /* muted gold — brand color, active states, focus */
```

**Accent usage:** Icons, active nav state, wordmark, focus rings. This is the brand color — ties to the eye-and-key identity. Reads as "attention/vault," not generic chrome.

**Accent-strong:** `#ffe07a` — reserved for primary action buttons only ("Save," "Unlock," confirm). One shade up so the single most important action is unambiguous.

**Danger:** `#f27c85` — breach warnings, delete confirmations, critical severity only. Never used elsewhere, so it stays trustworthy.

**Success:** `#f2c94c` (same as accent) — unlock confirmation, "copied," passed checks only.

**Rule:** If a color isn't one of these, it doesn't belong. No decorative color. Severity badges use muted desaturated variants of danger/success/accent — never new hues. (Two low-opacity accent gradients exist for the brand mark and lock glow — see the reconciliation note at the end of this file.)

### Typography

**UI text:** Inter (system font stack fallback) — zero bundle cost, native rendering.

**Data/monospace:** JetBrains Mono (self-hosted, subset to Latin + symbols). Used for:
- Passwords, TOTP codes, hashes
- Command KB entries, Nmap output
- Vault status bar, lock telemetry
- Empty state prompts

**Scale (4 sizes only):**
- 13px: meta/labels
- 14px: body
- 16px: primary content
- 20px: section headers

No display/hero sizing. This app has no hero moments — every screen is a work surface.

### Layout

**Sidebar nav + content pane** (existing Dashboard shape). Don't introduce a second navigation paradigm.

**8px spacing grid, no exceptions.** If something needs 13px, the grid was wrong — restructure, don't break it.

**Cards/panels:** 1px border, no shadow. Depth from the three-tier bg scale.

**Border-radius:** 9px for buttons/inputs, 13px for cards. Consistent, not severe (0px) or soft (16px+).

### Motion

**Functional only.** Every animation must answer "what does this confirm to the user?"

- **Lock ↔ unlock:** SnakeEye animation + flight transition. The one place personality is allowed — marks the most important state change
- **Clipboard copy:** Brief flash/checkmark, ~150ms. Confirms the copy happened
- **Toasts/errors:** Slide in, no bounce, no spring. Controlled, not playful
- **Respect `prefers-reduced-motion`** everywhere

**No animation on:** Page load, skeleton shimmer, page transitions, routine button hovers.

### Component Conventions

**Icons:** Inline SVG in `Icon.tsx`. Don't pull in an icon library (bundle weight + inconsistency).

**SnakeEye:** Singular signature element tied to lock state. Not a general-purpose mascot. One risk, spent once.

**Buttons:**
- Solid accent for primary action (max one per view)
- Outline/ghost for everything else
- No color-coded button soup

**Empty states:** Explain what to do next in plain, direct language. Not cute copy.
- ✓ "No credentials yet. Add your first entry."
- ✗ "Nothing here... yet! 👀"

### Quality Floor (non-negotiable)

- **Keyboard focus:** Visible accent ring on every interactive element, 2px, no exceptions. Keyboard-only flows are common in this audience
- **Contrast:** Text on bg/surface must pass WCAG AA minimum, checked not eyeballed
- **Icon-only buttons:** Accessible label required, not just tooltip
- **Touch targets:** 44px minimum for any clickable element

## Performance & Storage Budget

**Bundle size:** No new frontend dependency without checking bundle impact first (`vite build` output). Prefer 30-line hand-written implementation over a library for anything under that complexity.

**Assets:** SVG only for icons/illustration. No PNG/raster. Self-hosted fonts subset to actual character set (Latin + symbols for hashes/codes).

**Rendering:** Credential list, journal entries, KB entries should virtualize past ~200 rows. Local app with no pagination backend — unbounded lists are a real risk.

**Database discipline:** No storing derived/redundant data that can be recomputed. Every byte in `cobrypt.db` should be user-entered data or required crypto artifact.

**Startup:** Lock screen must render before any DB read. User should never wait on decryption to see the password prompt.

## Implementation Constraints

- **CSP:** Self-only for scripts/styles/fonts. No external fetches except HIBP breach checking
- **Tauri capabilities:** Scoped to `$APPDATA`, `$DOWNLOAD`, `$DESKTOP` only. No shell/process/notification/clipboard plugins
- **No network calls** except HIBP. This app doesn't phone home, ever

## Finish Gate (anti-ui-slop)

Before shipping any UI change, verify:

1. **Noun-swap test:** Would another domain require different hierarchy/controls/states, not just different copy? If no, it's generic
2. **No invented metrics/users/states:** Only render what exists in the actual data
3. **Keyboard/contrast/empty-state paths:** All work, all accessible
4. **No generic defaults:** Card grids, hero sections, decorative gradients, glass morphism — all rejected unless product evidence justifies
5. **Functional motion only:** Every animation confirms a state change or action result
6. **Console conventions honored:** Status bars, empty states, telemetry use terminal patterns

**Block if:** Any generic default survives, any breakage in keyboard/contrast/empty paths, any invented content, any decorative motion.

---

This contract is the spec. Coder implements against it. Reviewer gates on the finish gate.


---

## Token Reconciliation (September 2026)

The implementation drifted from the color block above. This note records the
actual state so the next contributor is not misled by an out-of-date contract.

- **The palette is larger than seven values.** `global.css` defines 30 custom
  properties: the seven listed above plus `--bg-soft`, `--surface-hover`,
  `--border-strong`, `--text-soft`, `--accent-ink`, `--accent-rgb`,
  `--accent-muted`, and the nine `--eye-*` / `--lock-eye-y` tokens the SnakeEye
  mark needs. The seven core values are still the ones that carry meaning;
  the rest are supporting shades derived from them.
- **`--text-muted` is `#7f8a89`, not `#707c7b`** (corrected above). The old
  value survived in two hardcoded `#707c7b` literals in `Journal.tsx` and
  `PasswordGenerator.tsx`; those now read from the token instead.
- **Two accent gradients exist** (`global.css`, the brand mark glow and the lock
  screen glow). They are low-opacity radial washes, not decorative surface
  gradients. Reconsider them before adding a third.
- **`--success` is identical to `--accent` in both themes**, so it carries no
  distinct meaning. Either give it a real value or remove it and use `--accent`.
- **Spacing does not consistently follow the 8px grid.** Many values in
  `global.css` are 2px-scale (7/9/11/13/17/19/21/22/23/25/27/29px). Treat the
  grid as the target for new work, not as a description of what is there.
- **List virtualisation (past ~200 rows) is still outstanding.** Row
  memoisation and an isolated countdown tick are in place; full virtualisation
  is not.
- **Dead CSS remains.** The legacy lock-console block (`global.css` ~410-1044),
  the orphaned `.brand-mark*` rules, and several duplicate selectors are
  unreferenced by any component.
