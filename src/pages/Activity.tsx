import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { EmptyState } from "../components/EmptyState";
import { describeError } from "../lib/errors";
import { dayLabel, formatTime, parseStored } from "../lib/format";
import type { ActivityEntry } from "../lib/types";

const ACTION_LABELS: Record<string, string> = {
  unlock: "Unlocked",
  unlock_failed: "Unlock failed",
  lock: "Sealed",
  vault_created: "Vault created",
  credential_add: "New login",
  credential_delete: "Login deleted",
  backup_export: "Backup exported",
  backup_import: "Backup restored",
  recovery: "Recovery code used",
  migration: "Vault migrated",
};

interface Day {
  label: string;
  rows: { entry: ActivityEntry; time: string }[];
}

function groupByDay(entries: ActivityEntry[]): Day[] {
  const days: Day[] = [];
  for (const entry of entries) {
    const when = parseStored(entry.timestamp);
    const label = when ? dayLabel(when) : "Unknown date";
    const time = when ? formatTime(when) : entry.timestamp;
    const last = days[days.length - 1];
    if (last && last.label === label) last.rows.push({ entry, time });
    else days.push({ label, rows: [{ entry, time }] });
  }
  return days;
}

function Activity() {
  const [entries, setEntries] = useState<ActivityEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setEntries(await invoke<ActivityEntry[]>("get_activity_log"));
      setError("");
    } catch (err) {
      setError(describeError(err, "Could not read the activity log."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const days = useMemo(() => groupByDay(entries), [entries]);
  const failures = entries.filter((entry) => entry.action === "unlock_failed").length;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1 className="title-l">Activity</h1>
          <p className="lead">
            Everything that touched the vault on this machine, newest first. Showing the latest {entries.length}{" "}
            {entries.length === 1 ? "entry" : "entries"}.
            {failures > 0 && (
              <>
                {" "}
                <span className="error">
                  {failures} failed unlock {failures === 1 ? "attempt" : "attempts"} among them.
                </span>
              </>
            )}
          </p>
        </div>
        <button className="btn-outline" onClick={() => void load()}>Refresh</button>
      </header>

      {error && <p className="error" role="alert">{error}</p>}
      {loading && <p className="status" role="status">Reading the log…</p>}
      {!loading && !error && entries.length === 0 && <EmptyState message="Nothing recorded yet." />}

      {days.map((day) => (
        <section key={day.label} className="day rise">
          <h2 className="section-title">{day.label}</h2>
          <div className="table-scroll">
            <table className="table">
              <tbody>
                {day.rows.map(({ entry, time }) => {
                  const failed = entry.action === "unlock_failed";
                  return (
                    <tr key={entry.id}>
                      <td className="mono">{time}</td>
                      <td className={failed ? "is-danger" : undefined}>{ACTION_LABELS[entry.action] ?? entry.action}</td>
                      <td>{entry.detail}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </div>
  );
}

export default Activity;
