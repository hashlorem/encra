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

/** With seconds, for the activity log, where order within a minute matters. */
export function formatTimeExact(date: Date): string {
  return date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
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

/**
 * A recovery code in groups of four, for reading and writing down. The backend
 * ignores the spaces, so a code typed this way still works.
 */
export function groupCode(code: string): string {
  return code.match(/.{1,4}/g)?.join(" ") ?? code;
}
