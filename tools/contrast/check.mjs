#!/usr/bin/env node
// Checks every palette in src/styles/global.css, light and dark, against
// WCAG 2 contrast: each text token must reach 4.5:1 on every surface it can
// sit on, and so must the primary button's label. Exits 1 if any falls short.
//
//   npm run check:contrast

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const CSS = fileURLToPath(new URL("../../src/styles/global.css", import.meta.url));
const TOKENS = ["paper", "paper-raised", "paper-sunken", "ink", "ink-2", "ink-3", "rule", "link", "danger"];
const TEXT = ["ink", "ink-2", "ink-3", "link", "danger"];
const SURFACES = ["paper", "paper-raised", "paper-sunken"];
// The primary button: --paper text on --ink, and on --ink-2 while hovered.
const EXTRA = [["paper", "ink"], ["paper", "ink-2"]];
const MINIMUM = 4.5;

function luminance(hex) {
  const channels = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = channels.map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function ratio(a, b) {
  const [light, dark] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (light + 0.05) / (dark + 0.05);
}

/** { "latent/light": { paper: "#f2f0ea", … }, … } from the :root blocks. */
function palettes(css) {
  const found = {};
  for (const [, selectors, body] of css.matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
    const values = Object.fromEntries(
      [...body.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)].map(([, name, value]) => [name, value.toLowerCase()]),
    );
    if (!values.paper) continue;
    for (const selector of selectors.split(",").map((s) => s.trim())) {
      if (!selector.startsWith(":root") || selector.includes(".swatch")) continue;
      const palette = selector.match(/data-palette="([a-z]+)"/)?.[1] ?? "latent";
      const mode = selector.includes('data-theme="dark"') ? "dark" : "light";
      found[`${palette}/${mode}`] = { ...found[`${palette}/${mode}`], ...values };
    }
  }
  return found;
}

const all = palettes(readFileSync(CSS, "utf8").replace(/\/\*[\s\S]*?\*\//g, ""));
let failures = 0;

for (const [name, values] of Object.entries(all)) {
  const missing = TOKENS.filter((token) => !values[token]);
  if (missing.length) {
    console.log(`${name}: missing ${missing.map((t) => `--${t}`).join(", ")}`);
    failures += 1;
    continue;
  }
  const pairs = [...TEXT.flatMap((text) => SURFACES.map((surface) => [text, surface])), ...EXTRA];
  let worst = null;
  for (const [text, surface] of pairs) {
    const value = ratio(values[text], values[surface]);
    if (value < MINIMUM) {
      console.log(`${name}: --${text} on --${surface} is ${value.toFixed(2)}:1, under ${MINIMUM}:1`);
      failures += 1;
    }
    if (!worst || value < worst.value) worst = { text, surface, value };
  }
  console.log(`${name.padEnd(17)} lowest ${worst.value.toFixed(2)}:1 (--${worst.text} on --${worst.surface})`);
}

const expected = ["latent", "darkroom", "cyanotype", "evidence"].flatMap((p) => [`${p}/light`, `${p}/dark`]);
for (const name of expected.filter((n) => !all[n])) {
  console.log(`${name}: not found in global.css`);
  failures += 1;
}

if (failures) {
  console.log(`\n${failures} problem${failures === 1 ? "" : "s"}.`);
  process.exit(1);
}
console.log(`\nAll ${Object.keys(all).length} palettes pass ${MINIMUM}:1.`);
