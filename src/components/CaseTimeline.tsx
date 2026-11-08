import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { isLoud, kindLabel } from "../lib/cases";
import { describeError } from "../lib/errors";
import { formatDate, formatShortDate, formatTimeExact, parseStored } from "../lib/format";
import type { TimelineEvent } from "../lib/types";

const EVIDENCE_TITLES: Record<string, (name: string) => string> = {
  added: (name) => `Added ${name}`,
  verified: (name) => `Verified ${name}`,
  verify_failed: (name) => `Check failed on ${name}`,
  exported: (name) => `Exported ${name}`,
  export_failed: (name) => `Export failed for ${name}`,
  note: (name) => `Note on ${name}`,
  restored: (name) => `Restored ${name}`,
};

const FAILED = new Set(["verify_failed", "export_failed"]);

function title(event: TimelineEvent): string {
  if (event.source === "case") return "Case opened";
  if (event.source === "evidence") return (EVIDENCE_TITLES[event.action ?? ""] ?? ((name: string) => name))(event.title);
  return event.title;
}

/** "Case", "Evidence", or "Note · Finding, high". */
function kind(event: TimelineEvent): string {
  if (event.source === "case") return "Case";
  if (event.source === "evidence") return "Evidence";
  const type = event.entry_type && event.entry_type !== "note" ? ` · ${kindLabel(event.entry_type)}` : "";
  const severity = event.severity && event.severity !== "info" ? `, ${event.severity}` : "";
  return `Note${type}${severity}`;
}

function loud(event: TimelineEvent): boolean {
  return event.source === "entry" ? isLoud(event.severity) : event.source === "evidence" && FAILED.has(event.action ?? "");
}

/**
 * Everything that happened in a case, oldest first: the case opening, each
 * note, and every step in each evidence file's custody. Built in Rust from
 * the stored times.
 */
export function CaseTimeline({ projectId }: { projectId: string }) {
  const [events, setEvents] = useState<TimelineEvent[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let current = true;
    setEvents(null);
    invoke<TimelineEvent[]>("case_timeline", { projectId })
      .then((list) => current && setEvents(list))
      .catch((err) => current && setError(describeError(err, "Couldn’t build the timeline for this case.")));
    return () => {
      current = false;
    };
  }, [projectId]);

  if (!events) {
    return error ? <p className="error" role="alert">{error}</p> : <p className="status" role="status">Reading the case…</p>;
  }

  return (
    <section className="timeline" aria-label="Timeline">
      <p className="summary">Notes and evidence in the order they happened. Times are this Mac’s clock.</p>
      <ol className="entries stagger">
        {events.map((event, index) => {
          const when = parseStored(event.at);
          return (
            <li key={index}>
              <span className="entry-when">
                {when ? <>{formatShortDate(when)}<br />{formatTimeExact(when)}</> : event.at}
              </span>
              <div className="entry-body">
                <h3 className={loud(event) ? "entry-title sev-high" : "entry-title"}>{title(event)}</h3>
                <span className="meta">{kind(event)}</span>
                {event.detail && <p className="entry-text">{event.detail}</p>}
              </div>
            </li>
          );
        })}
      </ol>
      <div className="actions no-print">
        <button className="btn-outline" onClick={() => window.print()}>Print timeline</button>
      </div>
      <p className="meta print-only">Printed from Encra on {formatDate(new Date().toISOString())}. Times are this Mac’s clock.</p>
    </section>
  );
}
