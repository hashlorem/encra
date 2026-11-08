import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ModalOverlay } from "./ModalOverlay";
import { describeError } from "../lib/errors";
import type { ImportPreview, ImportSkipped } from "../lib/types";

type Step = "preview" | "done" | "confirm" | "deleted";

interface ImportDialogProps {
  preview: ImportPreview;
  onClose: () => void;
  /** The logins are in; reload the list. */
  onImported: () => void;
  onCheckup: () => void;
}

const SKIP_REASONS: [keyof ImportSkipped, string][] = [
  ["duplicate", "Already in your vault, or listed twice, skipped"],
  ["no_password", "No password in the file, skipped"],
  ["no_name", "No name or website, skipped"],
  ["too_long", "Too long to store, skipped"],
  ["not_a_login", "Cards, notes and identities, skipped"],
];

const logins = (count: number) => `${count.toLocaleString()} ${count === 1 ? "login" : "logins"}`;

/**
 * Importing an export from another password manager: what's in it, then add
 * it all at once, then offer to delete the plaintext export. Rust holds the
 * file and the passwords; this only ever sees names and counts.
 */
export function ImportDialog({ preview, onClose, onImported, onCheckup }: ImportDialogProps) {
  const [step, setStep] = useState<Step>("preview");
  const [added, setAdded] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const headingRef = useRef<HTMLHeadingElement>(null);

  // Each step starts on its heading, so a stray Enter can't press a button
  // the person hasn't read yet.
  useEffect(() => {
    headingRef.current?.focus();
  }, [step]);

  const cancel = () => {
    void invoke("cancel_import");
    onClose();
  };

  const add = async () => {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      setAdded(await invoke<number>("confirm_import", { token: preview.token }));
      setStep("done");
      onImported();
    } catch (err) {
      setError(describeError(err, "Import failed. Nothing was changed in your vault."));
    } finally {
      setBusy(false);
    }
  };

  const deleteExport = async () => {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await invoke<string>("delete_import_file");
      setStep("deleted");
    } catch (err) {
      setError(describeError(err, "Couldn’t delete the export. Delete it in Finder instead."));
      setStep("done");
    } finally {
      setBusy(false);
    }
  };

  const close = () => {
    if (busy) return;
    if (step === "preview") cancel();
    else if (step === "confirm") setStep("done");
    else onClose();
  };

  const skipped = SKIP_REASONS.filter(([reason]) => preview.skipped[reason] > 0);
  const errorLine = error && <p className="error" role="alert">{error}</p>;

  return (
    <ModalOverlay onClose={close} labelledBy="import-title">
      <div className="dialog import-dialog">
        {step === "preview" && (
          <>
            <div className="record-head">
              <p className="meta">{preview.file_name}, read on this Mac. Nothing is sent anywhere.</p>
              <h2 id="import-title" ref={headingRef} tabIndex={-1}>Import from {preview.source}</h2>
            </div>
            <p className="summary">
              {preview.ready === 0
                ? "There’s nothing new to add from this file."
                : `${logins(preview.ready)} ${preview.ready === 1 ? "is" : "are"} ready to add${
                    preview.with_totp > 0 ? `, ${preview.with_totp.toLocaleString()} of them with a 2FA code` : ""
                  }.`}
            </p>
            {(skipped.length > 0 || preview.totp_unusable > 0) && (
              <dl className="tally">
                {skipped.map(([reason, label]) => (
                  <div key={reason} className="fact-pair">
                    <dt>{label}</dt>
                    <dd className="mono">{preview.skipped[reason].toLocaleString()}</dd>
                  </div>
                ))}
                {preview.totp_unusable > 0 && (
                  <div className="fact-pair">
                    <dt>2FA Encra can’t use, so the login is added without it</dt>
                    <dd className="mono">{preview.totp_unusable.toLocaleString()}</dd>
                  </div>
                )}
              </dl>
            )}
            {preview.sample.length > 0 && (
              <div className="field">
                <span className="meta">{preview.ready > preview.sample.length ? "First few, names only" : "Names only"}</span>
                <ul className="sample">
                  {preview.sample.map((login, index) => (
                    <li key={index}>
                      {login.service} {login.username && <span className="meta">{login.username}</span>}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {errorLine}
            <div className="actions">
              {preview.ready > 0 && (
                <button className="btn" onClick={() => void add()} disabled={busy}>
                  {busy ? "Adding…" : `Add ${logins(preview.ready)}`}
                </button>
              )}
              <button className="btn-text" onClick={cancel} disabled={busy}>{preview.ready > 0 ? "Cancel" : "Close"}</button>
            </div>
            {preview.ready > 0 && <p className="meta">They go in all at once, or not at all.</p>}
          </>
        )}

        {step === "done" && (
          <>
            <h2 id="import-title" ref={headingRef} tabIndex={-1}>{logins(added)} added.</h2>
            <p className="summary">The export file still holds every one of those passwords in plain text.</p>
            <p className="file-line mono">{preview.location}</p>
            {errorLine}
            <div className="actions">
              <button className="btn-danger" onClick={() => setStep("confirm")}>Delete the export…</button>
              <button className="btn-text" onClick={onClose}>Keep it</button>
            </div>
          </>
        )}

        {step === "confirm" && (
          <>
            <h2 id="import-title" ref={headingRef} tabIndex={-1}>Delete {preview.file_name}?</h2>
            <p className="lead">
              It’s deleted from disk, not moved to the Trash, so it can’t be brought back. Your {logins(added)} stay in Encra.
            </p>
            <div className="actions">
              <button className="btn-outline" onClick={() => setStep("done")} disabled={busy}>Cancel</button>
              <button className="btn-danger" onClick={() => void deleteExport()} disabled={busy}>
                {busy ? "Deleting…" : "Delete the file"}
              </button>
            </div>
          </>
        )}

        {step === "deleted" && (
          <>
            <h2 id="import-title" ref={headingRef} tabIndex={-1}>Export deleted.</h2>
            <p className="lead">
              With FileVault on, anything left of it on the disk stays encrypted. Run a vault check-up next to find
              reused and breached passwords among the new logins.
            </p>
            <div className="actions">
              <button className="btn" onClick={onCheckup}>Run a check-up</button>
              <button className="btn-text" onClick={onClose}>Done</button>
            </div>
          </>
        )}
      </div>
    </ModalOverlay>
  );
}
