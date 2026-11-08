import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ConfirmDialog } from "./ConfirmDialog";
import { describeError } from "../lib/errors";
import { formatBytes, formatDate, formatExactBytes, formatShortDate, formatTimeExact, parseStored } from "../lib/format";
import { useClipboard } from "../lib/useClipboard";
import type { Custody, EvidenceCheck, EvidenceItem, EvidenceProgress } from "../lib/types";

const ACTIONS: Record<string, string> = {
  added: "Added",
  verified: "Verified",
  verify_failed: "Check failed",
  exported: "Exported",
  export_failed: "Export failed",
  note: "Note",
  restored: "Restored",
};

const FAILED = new Set(["verify_failed", "export_failed"]);

interface EvidencePanelProps {
  projectId: string;
  /** Goes up by one each time files are dropped on the window. */
  dropToken: number;
  onCount: (count: number) => void;
}

function When({ at }: { at: string }) {
  const when = parseStored(at);
  return (
    <span className="entry-when">
      {when ? <>{formatShortDate(when)}<br />{formatTimeExact(when)}</> : at}
    </span>
  );
}

function CustodyTimeline({ custody }: { custody: Custody }) {
  return (
    <>
      {custody.status.intact ? (
        <p className="meta">Custody record intact, {custody.events.length} {custody.events.length === 1 ? "entry" : "entries"}.</p>
      ) : (
        <p className="error" role="alert">Custody record broken: {custody.status.problem}.</p>
      )}
      <ol className="entries custody">
        {custody.events.map((event) => (
          <li key={event.seq}>
            <When at={event.at} />
            <div className="entry-body">
              <span className={FAILED.has(event.action) ? "entry-title sev-high" : "entry-title"}>{ACTIONS[event.action] ?? event.action}</span>
              {event.detail && <p className="entry-text">{event.detail}</p>}
            </div>
          </li>
        ))}
      </ol>
    </>
  );
}

function Hashes({ item, copy, copiedId }: { item: EvidenceItem; copy: (text: string, id: string) => void; copiedId: string | null }) {
  const rows: [string, string][] = [["SHA-256", item.hashes.sha256], ["SHA-1", item.hashes.sha1], ["MD5", item.hashes.md5]];
  return (
    <dl className="facts hashes">
      {rows.map(([label, value]) => (
        <div key={label} className="fact-pair">
          <dt>{label}</dt>
          <dd>
            <span className="fact-value mono">{value}</span>
            <button className="btn-text no-print" onClick={() => copy(value, `${item.id}:${label}`)}>
              <span key={copiedId === `${item.id}:${label}` ? "done" : "idle"} className="fade">
                {copiedId === `${item.id}:${label}` ? "Copied" : "Copy"}
              </span>
            </button>
          </dd>
        </div>
      ))}
      <div className="fact-pair">
        <dt>Size</dt>
        <dd><span className="fact-value">{formatExactBytes(item.size)}</span></dd>
      </div>
      <div className="fact-pair">
        <dt>From</dt>
        <dd><span className="fact-value mono">{item.source}</span></dd>
      </div>
    </dl>
  );
}

/**
 * A case's evidence: files hashed on intake, stored encrypted, each with its
 * own chain of custody. File paths come from the system dialog or a drop,
 * both handled in Rust; this page never supplies one.
 */
export function EvidencePanel({ projectId, dropToken, onCount }: EvidencePanelProps) {
  const [items, setItems] = useState<EvidenceItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [openId, setOpenId] = useState<string | null>(null);
  const [custody, setCustody] = useState<Record<string, Custody>>({});
  const [progress, setProgress] = useState<EvidenceProgress | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState<{ id: string; check: EvidenceCheck } | null>(null);
  const [note, setNote] = useState("");
  const [pendingDelete, setPendingDelete] = useState<EvidenceItem | null>(null);
  const [printing, setPrinting] = useState(false);
  const { copyText, copiedId } = useClipboard();
  const lastDrop = useRef(dropToken);

  const load = useCallback(async () => {
    try {
      const list = await invoke<EvidenceItem[]>("list_evidence", { projectId });
      setItems(list);
      onCount(list.length);
    } catch (err) {
      setError(describeError(err, "Couldn’t load the evidence for this case."));
    } finally {
      setLoading(false);
    }
  }, [projectId, onCount]);

  const loadCustody = useCallback(async (id: string) => {
    try {
      const record = await invoke<Custody>("evidence_custody", { id });
      setCustody((all) => ({ ...all, [id]: record }));
    } catch (err) {
      setError(describeError(err, "Couldn’t read the custody record."));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (openId) void loadCustody(openId);
    setNote("");
  }, [openId, loadCustody]);

  useEffect(() => {
    const stop = listen<EvidenceProgress>("evidence-progress", (event) => setProgress(event.payload));
    return () => {
      void stop.then((unlisten) => unlisten());
    };
  }, []);

  /** Run one long file operation at a time, with its progress shown. */
  const run = useCallback(async <T,>(label: string, work: () => Promise<T>, fallback: string): Promise<T | undefined> => {
    setBusy(label);
    setError("");
    setProgress(null);
    try {
      return await work();
    } catch (err) {
      setError(describeError(err, fallback));
      return undefined;
    } finally {
      setBusy("");
      setProgress(null);
    }
  }, []);

  const added = useCallback(async (list: EvidenceItem[] | undefined) => {
    if (!list || list.length === 0) return;
    await load();
    setOpenId(list[list.length - 1].id);
  }, [load]);

  const addFiles = async () => {
    const list = await run("Adding", () => invoke<EvidenceItem[]>("add_evidence", { projectId, note: "" }), "Couldn’t add that file.");
    await added(list);
  };

  useEffect(() => {
    if (dropToken === lastDrop.current) return;
    lastDrop.current = dropToken;
    void (async () => {
      const list = await run("Adding", () => invoke<EvidenceItem[]>("add_dropped_evidence", { projectId, note: "" }), "Couldn’t add those files.");
      await added(list);
    })();
  }, [dropToken, projectId, run, added]);

  const verify = async (item: EvidenceItem) => {
    const check = await run("Checking", () => invoke<EvidenceCheck>("verify_evidence", { id: item.id }), "Couldn’t check that file.");
    if (check) setResult({ id: item.id, check });
    await loadCustody(item.id);
  };

  const exportItem = async (item: EvidenceItem) => {
    const check = await run("Exporting", () => invoke<EvidenceCheck | null>("export_evidence", { id: item.id }), "Couldn’t export that file.");
    if (check) setResult({ id: item.id, check });
    await loadCustody(item.id);
  };

  const addNote = async (item: EvidenceItem) => {
    if (!note.trim()) return;
    try {
      await invoke("add_evidence_note", { id: item.id, note });
      setNote("");
      await loadCustody(item.id);
    } catch (err) {
      setError(describeError(err, "Couldn’t add that note."));
    }
  };

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    try {
      await invoke("delete_evidence", { id: pendingDelete.id });
      setOpenId(null);
      await load();
    } catch (err) {
      setError(describeError(err, "Couldn’t remove that file."));
    } finally {
      setPendingDelete(null);
    }
  };

  /** Load every custody record, render them all, then print. */
  const printReport = async () => {
    await Promise.all(items.map((item) => loadCustody(item.id)));
    setPrinting(true);
  };

  // Every file is expanded while printing; back to normal once the print
  // dialog closes.
  useEffect(() => {
    if (!printing) return;
    const done = () => setPrinting(false);
    window.addEventListener("afterprint", done, { once: true });
    window.print();
    return () => window.removeEventListener("afterprint", done);
  }, [printing]);

  const percent = progress && progress.total > 0 ? Math.min(100, Math.round((progress.done / progress.total) * 100)) : null;

  return (
    <section className="evidence" aria-label="Evidence">
      <div className="actions no-print">
        <button className="btn-outline" onClick={() => void addFiles()} disabled={!!busy}>Add files…</button>
        <span className="meta">or drop them on the window. The originals aren’t touched.</span>
      </div>

      {busy && (
        <div className="evidence-progress fade" role="status">
          <span className="meta">
            {busy} {progress?.name ?? "…"}{percent !== null && `, ${percent}%`}
          </span>
          <progress max={100} value={percent ?? undefined} />
        </div>
      )}
      {error && <p className="error" role="alert">{error}</p>}

      {loading && <p className="status" role="status">Loading evidence…</p>}
      {!loading && items.length === 0 && <p className="lead">No evidence in this case yet.</p>}

      <ol className="evidence-list stagger">
        {items.map((item) => {
          const open = printing || item.id === openId;
          const record = custody[item.id];
          const check = result?.id === item.id ? result.check : null;
          return (
            <li key={item.id} className={open ? "is-open" : undefined}>
              <button className="row" aria-expanded={open} onClick={() => setOpenId(open ? null : item.id)}>
                <span className="row-copy">
                  <span className="row-name">{item.name}</span>
                  <span className="meta">
                    {formatBytes(item.size)} · added {formatDate(item.added_at)}
                    {!item.stored && " · record only"}
                  </span>
                </span>
                <span className="row-note mono">{item.hashes.sha256.slice(0, 12)}</span>
              </button>

              {open && (
                <div className="evidence-detail rise">
                  <Hashes item={item} copy={(text, id) => void copyText(text, id)} copiedId={copiedId} />
                  {!item.stored && (
                    <p className="meta">This vault holds the record only. The file was not part of the backup it came from.</p>
                  )}
                  {check && (
                    <p className={check.ok ? "meta fade" : "error fade"} role="status">{check.detail}</p>
                  )}
                  <div className="actions no-print">
                    <button className="btn-outline" onClick={() => void verify(item)} disabled={!!busy || !item.stored}>Verify</button>
                    <button className="btn-text" onClick={() => void exportItem(item)} disabled={!!busy || !item.stored}>Export…</button>
                    <button className="btn-danger" onClick={() => setPendingDelete(item)} disabled={!!busy}>Remove</button>
                  </div>

                  <h3 className="label">Chain of custody</h3>
                  {record ? <CustodyTimeline custody={record} /> : <p className="status" role="status">Reading…</p>}

                  <form
                    className="composer-line no-print"
                    onSubmit={(event) => {
                      event.preventDefault();
                      void addNote(item);
                    }}
                  >
                    <label className="sr-only" htmlFor={`note-${item.id}`}>Custody note</label>
                    <input id={`note-${item.id}`} className="input" placeholder="Handed over, moved, looked at…" value={note}
                      onChange={(event) => setNote(event.target.value)} />
                    <button className="btn-text" type="submit" disabled={!note.trim()}>Add note</button>
                  </form>
                </div>
              )}
            </li>
          );
        })}
      </ol>

      {items.length > 0 && (
        <div className="actions no-print">
          <button className="btn-outline" onClick={() => void printReport()} disabled={!!busy}>Print custody report</button>
        </div>
      )}
      {printing && (
        <p className="meta print-only">Printed from Encra on {formatDate(new Date().toISOString())}. Times are this Mac’s clock.</p>
      )}

      {pendingDelete && (
        <ConfirmDialog
          title={`Remove ${pendingDelete.name}?`}
          message="The encrypted copy and its custody record are deleted. Your original file isn’t touched. This can’t be undone."
          confirmLabel="Remove"
          onConfirm={() => void confirmDelete()}
          onCancel={() => setPendingDelete(null)}
        />
      )}
    </section>
  );
}
