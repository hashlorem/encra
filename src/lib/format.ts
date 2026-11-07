/**
 * SQLite stores timestamps as UTC "YYYY-MM-DD HH:MM:SS". These show them in
 * local time, with dates in the "7 November 2026" form.
 */
export function parseStored(timestamp: string): Date | null {
  const date = new Date(timestamp.replace(" ", "T") + (timestamp.endsWith("Z") ? "" : "Z"));
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatDate(timestamp: string): string {
  const date = parseStored(timestamp);
  return date
    ? date.toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" })
    : timestamp;
}

export function formatShortDate(date: Date): string {
  return date.toLocaleDateString("en-GB", { day: "numeric", month: "short" });
}

export function formatTime(date: Date): string {
  return date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
}

function startOfDay(date: Date): number {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
}

/** "Today, 7 November 2026", "Yesterday, …", or just the date. */
export function dayLabel(date: Date, now = new Date()): string {
  const full = date.toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });
  const days = Math.round((startOfDay(now) - startOfDay(date)) / 86_400_000);
  if (days === 0) return `Today, ${full}`;
  if (days === 1) return `Yesterday, ${full}`;
  return full;
}

const NUMBER_WORDS = [
  "Zero", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine", "Ten",
  "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen",
  "Nineteen", "Twenty",
];
const TENS = ["", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety"];

/** Spell out 0–99 for the start of a sentence; larger numbers stay digits. */
export function countWord(n: number): string {
  if (n < NUMBER_WORDS.length) return NUMBER_WORDS[n];
  if (n < 100) {
    const tens = TENS[Math.floor(n / 10)];
    return n % 10 === 0 ? tens : `${tens}-${NUMBER_WORDS[n % 10].toLowerCase()}`;
  }
  return String(n);
}

/** "letters, numbers and symbols" from a list of parts. */
export function joinWords(parts: string[]): string {
  if (parts.length <= 1) return parts.join("");
  return `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}`;
}
