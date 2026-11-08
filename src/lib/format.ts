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

/** "12.4 MB", in the decimal units Finder uses. */
export function formatBytes(bytes: number): string {
  if (bytes < 1000) return `${bytes} ${bytes === 1 ? "byte" : "bytes"}`;
  const units = ["KB", "MB", "GB", "TB"];
  let value = bytes / 1000;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

/** "13,002,113 bytes", for records where the exact size matters. */
export function formatExactBytes(bytes: number): string {
  return `${bytes.toLocaleString("en-US")} ${bytes === 1 ? "byte" : "bytes"}`;
}

