import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { EmptyState } from "../components/EmptyState";
import { describeError } from "../lib/errors";
import { dayLabel, formatTimeExact, parseStored } from "../lib/format";
import type { ActivityEntry, ActivityLog, ActivityPage, ChainStatus } from "../lib/types";

const ACTION_LABELS: Record<string, string> = {
  unlock: "Unlocked",
  unlock_failed: "Unlock failed",
  lock: "Sealed",
  vault_created: "Vault created",
  credential_add: "New login",
  credential_delete: "Login deleted",
  kdf_upgrade: "Key derivation strengthened",
  safety_copy_deleted: "Safety copy deleted",
  agent_access: "Agent access",
  agent_request: "Agent request",
  agent_approved: "Agent request approved",
  agent_denied: "Agent request denied",
  agent_failed: "Agent request failed",
  agent_cancelled: "Agent request cancelled",
  agent_timeout: "Agent request expired",
  agent_refused: "Agent connection refused",
  evidence_added: "Evidence added",
  evidence_deleted: "Evidence removed",
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
    const time = when ? formatTimeExact(when) : entry.timestamp;
    const last = days[days.length - 1];
    if (last && last.label === label) last.rows.push({ entry, time });
    else days.push({ label, rows: [{ entry, time }] });
  }
  return days;
}

function Activity() {
  const [entries, setEntries] = useState<ActivityEntry[]>([]);
  const [chain, setChain] = useState<ChainStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [hasMore, setHasMore] = useState(false);
  const [loadingOlder, setLoadingOlder] = useState(false);

  const load = useCallback(async () => {
    try {
      const log = await invoke<ActivityLog>("get_activity_log");
      setEntries(log.entries);
      setChain(log.chain);
      setHasMore(log.has_more);
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

  const loadOlder = async () => {
    const oldest = entries[entries.length - 1]?.seq;
    if (loadingOlder || oldest == null) return;
    setLoadingOlder(true);
    try {
      const page = await invoke<ActivityPage>("get_activity_older", { beforeSeq: oldest });
      setEntries((current) => [...current, ...page.entries]);
      setHasMore(page.has_more);
    } catch (err) {
      setError(describeError(err, "Could not read older entries."));
    } finally {
      setLoadingOlder(false);
    }
  };

  const days = useMemo(() => groupByDay(entries), [entries]);
  const failures = entries.filter((entry) => entry.action === "unlock_failed").length;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1 className="title-l">Activity</h1>
          <p className="lead">
            Everything that touched the vault on this machine, newest first.
            {hasMore && ` Showing the latest ${entries.length}.`}
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

      {chain && (
        <p key={chain.intact ? "intact" : "broken"} className="summary fade">
          {chain.intact ? (
            <>
              Chain intact across {chain.sealed} {chain.sealed === 1 ? "entry" : "entries"}.
              {chain.pending > 0 && ` ${chain.pending} waiting to be sealed.`}
            </>
          ) : (
            <span className="error">This log was altered outside Encra: {chain.problem}.</span>
          )}
        </p>
      )}

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
                  const failed = entry.action === "unlock_failed" || entry.action === "agent_refused";
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

      {hasMore && (
        <div className="actions">
          <button className="btn-outline" onClick={() => void loadOlder()} disabled={loadingOlder}>
            {loadingOlder ? "Reading…" : "Show older"}
          </button>
        </div>
      )}
    </div>
  );
}

export default Activity;
