import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { CheckupView } from "../components/CheckupView";
import { ImportDialog } from "../components/ImportDialog";
import { ModalOverlay } from "../components/ModalOverlay";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState } from "../components/EmptyState";
import { VirtualList } from "../components/VirtualList";
import { Print } from "../components/Print";
import { describeError } from "../lib/errors";
import { formatDate } from "../lib/format";
import { useRequest, type Requested } from "../lib/navigation";
import { useClipboard, type CopyField } from "../lib/useClipboard";
import {
  setTotpRolloverHandler,
  startTotpWindow,
  stopTotpWindow,
  useTotpRemaining,
} from "../lib/totpWindow";
import type {
  CheckProgress,
  Checkup,
  CredentialDetail,
  CredentialInput,
  CredentialSummary,
  ImportPreview,
  TotpCode,
} from "../lib/types";

const EMPTY_FORM: CredentialInput = { service: "", username: "", password: "", url: "", notes: "" };
/** A shown password hides itself again after this long. */
const REVEAL_MS = 30_000;

type Breach = { state: "checking" } | { state: "done"; count: number } | { state: "failed" };

/** "Copy" that crossfades to "Copied" and back. */
function CopyLabel({ done }: { done: boolean }) {
  return <span key={done ? "done" : "idle"} className="fade">{done ? "Copied" : "Copy"}</span>;
}

/** 123 456, or 1234 5678 for eight-digit codes. */
function groupOtp(code: string): string {
  return code.length === 8 ? `${code.slice(0, 4)} ${code.slice(4)}` : code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
}

/** Subscribes to the shared tick so only this line re-renders every second. */
const TotpCountdown = memo(function TotpCountdown() {
  const remaining = useTotpRemaining();
  return <span className="meta">{remaining} seconds left</span>;
});

/** The list's note for a login while the check-up shows: its worst finding. */
function checkupNotes(checkup: Checkup): Map<string, string> {
  const notes = new Map<string, string>();
  const note = (id: string, text: string) => {
    if (!notes.has(id)) notes.set(id, text);
  };
  checkup.breached.forEach(({ login }) => note(login.id, "in a breach"));
  checkup.reused.flat().forEach((login) => note(login.id, "same password"));
  checkup.weak.forEach((login) => note(login.id, "weak"));
  checkup.old.forEach(({ login }) => note(login.id, "over a year old"));
  return notes;
}

function Vault({ requested }: { requested?: Requested | null }) {
  const [credentials, setCredentials] = useState<CredentialSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [detail, setDetail] = useState<CredentialDetail | null>(null);
  const [totp, setTotp] = useState<TotpCode | null>(null);
  const [revealed, setRevealed] = useState<string | null>(null);
  const [breaches, setBreaches] = useState<Record<string, Breach>>({});

  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<CredentialDetail | null>(null);
  const [form, setForm] = useState<CredentialInput>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  const [totpSetup, setTotpSetup] = useState(false);
  const [totpSecret, setTotpSecret] = useState("");
  const [totpBusy, setTotpBusy] = useState(false);
  const [totpError, setTotpError] = useState("");

  // The main panel shows the open login, or the check-up.
  const [view, setView] = useState<"record" | "checkup">("record");
  const [checkup, setCheckup] = useState<Checkup | null>(null);
  const [checking, setChecking] = useState(false);
  const [progress, setProgress] = useState<CheckProgress | null>(null);

  const [importPreview, setImportPreview] = useState<ImportPreview | null>(null);
  const [readingImport, setReadingImport] = useState(false);

  const [pendingDelete, setPendingDelete] = useState<CredentialDetail | null>(null);
  const [deleting, setDeleting] = useState(false);

  const { copyField, copiedId } = useClipboard();
  const searchRef = useRef<HTMLInputElement>(null);
  const detailRequest = useRef(0);
  const revealTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const loadList = useCallback(async (selectAfter?: string) => {
    try {
      const list = await invoke<CredentialSummary[]>("list_credentials");
      setCredentials(list);
      setError("");
      setSelectedId((current) => {
        const wanted = selectAfter ?? current;
        if (wanted && list.some((c) => c.id === wanted)) return wanted;
        return list[0]?.id ?? null;
      });
    } catch (err) {
      setError(describeError(err, "Could not load your logins."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadList();
  }, [loadList]);

  const loadTotp = useCallback(async (id: string) => {
    try {
      const code = await invoke<TotpCode | null>("get_totp", { id });
      setTotp(code);
      if (code) startTotpWindow(code.remaining, code.period);
    } catch (err) {
      setTotp(null);
      setError(describeError(err, "Could not compute the one-time code."));
    }
  }, []);

  const hide = useCallback(() => {
    if (revealTimer.current) clearTimeout(revealTimer.current);
    revealTimer.current = null;
    setRevealed(null);
  }, []);

  // Fetch the open record whenever the selection changes. Older responses are
  // dropped so a slow reply cannot overwrite a newer selection.
  useEffect(() => {
    hide();
    setTotp(null);
    if (!selectedId) {
      setDetail(null);
      return;
    }
    const request = ++detailRequest.current;
    void (async () => {
      try {
        const nextDetail = await invoke<CredentialDetail>("get_credential", { id: selectedId });
        if (request !== detailRequest.current) return;
        setDetail(nextDetail);
        if (nextDetail.has_totp) await loadTotp(selectedId);
      } catch (err) {
        if (request !== detailRequest.current) return;
        setError(describeError(err, "Could not open that login."));
      }
    })();
  }, [selectedId, hide, loadTotp]);

  // A new 30-second window means a new code.
  useEffect(() => {
    setTotpRolloverHandler(() => {
      if (selectedId && detail?.has_totp) void loadTotp(selectedId);
    });
    return () => setTotpRolloverHandler(null);
  }, [selectedId, detail?.has_totp, loadTotp]);

  useEffect(() => () => {
    stopTotpWindow();
    if (revealTimer.current) clearTimeout(revealTimer.current);
  }, []);

  useEffect(() => {
    const handler = () => searchRef.current?.focus();
    window.addEventListener("encra:search-focus", handler);
    return () => window.removeEventListener("encra:search-focus", handler);
  }, []);

  useEffect(() => {
    const stop = listen<CheckProgress>("checkup-progress", (event) => setProgress(event.payload));
    return () => {
      void stop.then((unlisten) => unlisten());
    };
  }, []);

  const loadCheckup = useCallback(async () => {
    try {
      setCheckup(await invoke<Checkup>("vault_checkup"));
    } catch (err) {
      setError(describeError(err, "Couldn’t run the check-up."));
    }
  }, []);

  const showCheckup = useCallback(() => {
    setError("");
    setView("checkup");
    void loadCheckup();
  }, [loadCheckup]);

  /** Open a login from elsewhere (the check-up, the palette). */
  const openLogin = useCallback((id: string) => {
    setSearch("");
    setView("record");
    setSelectedId(id);
  }, []);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return credentials;
    return credentials.filter(
      (c) => c.service.toLowerCase().includes(query) || c.username.toLowerCase().includes(query),
    );
  }, [credentials, search]);

  const reveal = async () => {
    if (!selectedId) return;
    if (revealed !== null) {
      hide();
      return;
    }
    try {
      setRevealed(await invoke<string>("reveal_password", { id: selectedId }));
      revealTimer.current = setTimeout(hide, REVEAL_MS);
    } catch (err) {
      setError(describeError(err, "Could not show that password."));
    }
  };

  const copy = async (field: CopyField) => {
    if (!selectedId) return;
    try {
      await copyField(selectedId, field);
    } catch (err) {
      setError(describeError(err, "Could not copy that."));
    }
  };

  const checkAll = async () => {
    if (checking) return;
    setChecking(true);
    setProgress(null);
    setError("");
    try {
      await invoke<number>("check_all_breaches");
    } catch (err) {
      setError(describeError(err, "The breach check stopped part-way. Results so far are kept."));
    } finally {
      setChecking(false);
      setProgress(null);
      // Whatever finished is stored, so show it either way.
      setBreaches({});
      await Promise.all([loadCheckup(), loadList()]);
    }
  };

  const startImport = async () => {
    if (readingImport || importPreview) return;
    setReadingImport(true);
    setError("");
    try {
      // Rust opens the file dialog, reads and parses the export, and holds it.
      const preview = await invoke<ImportPreview | null>("pick_import_file");
      if (preview) setImportPreview(preview);
    } catch (err) {
      setError(describeError(err, "Couldn’t read that export."));
    } finally {
      setReadingImport(false);
    }
  };

  const checkBreach = async () => {
    const id = selectedId;
    if (!id) return;
    setBreaches((previous) => ({ ...previous, [id]: { state: "checking" } }));
    try {
      const count = await invoke<number>("check_credential_breach", { id });
      setBreaches((previous) => ({ ...previous, [id]: { state: "done", count } }));
    } catch {
      setBreaches((previous) => ({ ...previous, [id]: { state: "failed" } }));
    }
  };

  const openNew = () => {
    setEditing(null);
    setForm(EMPTY_FORM);
    setShowForm(true);
  };

  const editRecord = (record: CredentialDetail) => {
    setEditing(record);
    // A blank password means "keep the current one" on the backend.
    setForm({ service: record.service, username: record.username, password: "", url: record.url, notes: record.notes });
    setShowForm(true);
  };

  const openEdit = () => {
    if (detail) editRecord(detail);
  };

  /** From the check-up's "Change": open the login and its edit form. */
  const changeLogin = async (id: string) => {
    try {
      const record = await invoke<CredentialDetail>("get_credential", { id });
      openLogin(id);
      editRecord(record);
    } catch (err) {
      setError(describeError(err, "Could not open that login."));
    }
  };

  useRequest(requested, (request) => {
    if (request.kind === "login") openLogin(request.id);
    else if (request.kind === "new-login") openNew();
    else if (request.kind === "import") void startImport();
    else if (request.kind === "checkup") showCheckup();
  });

  const closeForm = () => {
    setShowForm(false);
    setForm(EMPTY_FORM);
    setEditing(null);
  };

  const save = async () => {
    if (saving) return;
    if (!form.service.trim()) {
      setError("Give the login a name before saving.");
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await invoke("update_credential", { id: editing.id, input: form });
        closeForm();
        // Refetch the open record too, since its fields just changed.
        setSelectedId(null);
        await loadList(editing.id);
      } else {
        const id = await invoke<string>("add_credential", { input: form });
        closeForm();
        await loadList(id);
      }
    } catch (err) {
      setError(describeError(err, "Could not save that login."));
    } finally {
      setSaving(false);
    }
  };

  const saveTotp = async () => {
    if (!selectedId || !totpSecret || totpBusy) return;
    setTotpBusy(true);
    try {
      await invoke("setup_totp", { credentialId: selectedId, secret: totpSecret });
      setTotpSetup(false);
      setTotpSecret("");
      const id = selectedId;
      setSelectedId(null);
      await loadList(id);
    } catch (err) {
      setTotpError(describeError(err, "Could not save that 2FA secret."));
    } finally {
      setTotpBusy(false);
    }
  };

  /** Add the code from a QR: a screenshot on the clipboard, or an image file
   * picked in a dialog Rust opens. Either way the image stays in Rust. */
  const readQr = async (from: "clipboard" | "file") => {
    if (!selectedId || totpBusy) return;
    setTotpBusy(true);
    setTotpError("");
    try {
      if (from === "file") {
        const added = await invoke<boolean>("setup_totp_from_file", { credentialId: selectedId });
        if (!added) return;
      } else {
        await invoke("setup_totp_from_clipboard", { credentialId: selectedId });
      }
      setTotpSetup(false);
      setTotpSecret("");
      const id = selectedId;
      setSelectedId(null);
      await loadList(id);
    } catch (err) {
      setTotpError(describeError(err, "Couldn’t read a 2FA code from that."));
    } finally {
      setTotpBusy(false);
    }
  };

  const removeTotp = async () => {
    if (!selectedId) return;
    try {
      await invoke("remove_totp", { credentialId: selectedId });
      const id = selectedId;
      setSelectedId(null);
      await loadList(id);
    } catch (err) {
      setError(describeError(err, "Could not remove the one-time code."));
    }
  };

  const confirmDelete = async () => {
    if (!pendingDelete || deleting) return;
    setDeleting(true);
    try {
      await invoke("delete_credential", { id: pendingDelete.id });
      setSelectedId(null);
      await loadList();
    } catch (err) {
      setError(describeError(err, "Could not delete that login."));
    } finally {
      setDeleting(false);
      setPendingDelete(null);
    }
  };

  const breach = selectedId ? breaches[selectedId] : undefined;
  const copied = (field: CopyField) => copiedId === `${selectedId}:${field}`;
  const notes = useMemo(() => (view === "checkup" && checkup ? checkupNotes(checkup) : null), [view, checkup]);

  return (
    <div className="split">
      <section className="split-list" aria-label="Logins">
        <div className="split-list-head">
          <h1 className="title-l">Vault</h1>
          <button className="btn-outline" onClick={openNew}>New login</button>
        </div>
        <div className="list-tools">
          <button className="btn-text" onClick={showCheckup}>Check-up</button>
          <button className="btn-text" onClick={() => void startImport()} disabled={readingImport}>
            {readingImport ? "Reading the export…" : "Import…"}
          </button>
        </div>
        <label className="search">
          <span className="sr-only">Search logins</span>
          <input
            ref={searchRef}
            className="input"
            placeholder={`Search ${credentials.length} ${credentials.length === 1 ? "login" : "logins"}`}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          <kbd className="meta">⌘F</kbd>
        </label>

        {loading && <p className="status" role="status">Opening the vault…</p>}
        {!loading && filtered.length === 0 && (
          <EmptyState message={search ? "Nothing matches that search." : "No logins yet."} />
        )}

        <VirtualList
          className="rows"
          items={filtered}
          getKey={(c) => c.id}
          renderRow={(c) => {
            // This session's check if there was one, else the remembered one.
            const result = breaches[c.id];
            const breached = result ? result.state === "done" && result.count > 0 : c.breached;
            const flag = notes?.get(c.id);
            const note = flag ?? (breached ? "in a breach" : c.has_totp ? "2FA" : "");
            return (
              <button
                className="row"
                aria-current={view === "record" && c.id === selectedId ? "true" : undefined}
                onClick={() => openLogin(c.id)}
              >
                <span className="row-copy">
                  <span className="row-name">{c.service}</span>
                  {c.username && <span className="meta">{c.username}</span>}
                </span>
                {note && <span className={note === "in a breach" ? "row-note is-danger" : "row-note"}>{note}</span>}
              </button>
            );
          }}
        />
      </section>

      <div className="split-main">
        {error && <p className="error" role="alert">{error}</p>}

        {view === "checkup" && !checkup && <p className="status" role="status">Running the check-up…</p>}
        {view === "checkup" && checkup && (
          <CheckupView
            checkup={checkup}
            progress={progress}
            checking={checking}
            onCheckAll={() => void checkAll()}
            onOpen={openLogin}
            onChange={(id) => void changeLogin(id)}
          />
        )}

        {view === "record" && detail && (
          <article key={detail.id} className="record stagger" aria-labelledby="record-title">
            <Print kind="arch" className="record-watermark" />
            <header className="record-head">
              <p className="meta">Added {formatDate(detail.created_at)}</p>
              <h2 id="record-title" className="title-xl">{detail.service}</h2>
              {(detail.username || detail.url) && (
                <p className="lead">{[detail.username, detail.url].filter(Boolean).join(" · ")}</p>
              )}
            </header>

            <dl className="facts">
              <dt>Password</dt>
              <dd>
                <span key={revealed !== null ? "shown" : "hidden"} className={`fact-value secret fade${revealed !== null ? " is-revealed" : ""}`}>
                  {revealed !== null ? revealed : detail.has_password ? "••••••••••••" : "None"}
                </span>
                <button className="btn-text" onClick={() => void reveal()} disabled={!detail.has_password}>
                  {revealed !== null ? "Hide" : "Show"}
                </button>
                <button className="btn-text" onClick={() => void copy("password")} disabled={!detail.has_password}>
                  <CopyLabel done={copied("password")} />
                </button>
              </dd>

              <dt>One-time code</dt>
              <dd>
                {detail.has_totp && totp ? (
                  <>
                    <span key={totp.code} className="otp fade">{groupOtp(totp.code)}</span>
                    <span className="fact-value"><TotpCountdown /></span>
                    <button className="btn-text" onClick={() => void copy("totp")}>
                      <CopyLabel done={copied("totp")} />
                    </button>
                    <button className="btn-danger" onClick={() => void removeTotp()}>Remove</button>
                  </>
                ) : (
                  <>
                    <span className="fact-value meta">None set up</span>
                    <button className="btn-text" onClick={() => { setTotpSecret(""); setTotpError(""); setTotpSetup(true); }}>
                      Add
                    </button>
                  </>
                )}
              </dd>

              {detail.username && (
                <>
                  <dt>Username</dt>
                  <dd>
                    <span className="fact-value">{detail.username}</span>
                    <button className="btn-text" onClick={() => void copy("username")}>
                      <CopyLabel done={copied("username")} />
                    </button>
                  </dd>
                </>
              )}

              {detail.url && (
                <>
                  <dt>Website</dt>
                  <dd>
                    <span className="fact-value">{detail.url}</span>
                    <button className="btn-text" onClick={() => void copy("url")}>
                      <CopyLabel done={copied("url")} />
                    </button>
                  </dd>
                </>
              )}

              {detail.notes && (
                <>
                  <dt>Notes</dt>
                  <dd><span className="fact-value notes">{detail.notes}</span></dd>
                </>
              )}
            </dl>

            {detail.has_password && (
              <p key={breach?.state ?? "unchecked"} className="summary fade">
                {!breach && !detail.breach && "Not checked against known breaches."}
                {!breach && detail.breach && detail.breach.count === 0 &&
                  `Not found in known breaches when Encra checked, on ${formatDate(detail.breach.checked_at)}.`}
                {!breach && detail.breach && detail.breach.count > 0 && (
                  <span className="error">
                    Found in {detail.breach.count.toLocaleString()} known breaches when Encra checked, on{" "}
                    {formatDate(detail.breach.checked_at)}. Change it.
                  </span>
                )}
                {breach?.state === "checking" && "Checking known breaches…"}
                {breach?.state === "failed" && "The breach check couldn’t reach the service."}
                {breach?.state === "done" && breach.count === 0 && "Not found in known breaches."}
                {breach?.state === "done" && breach.count > 0 && (
                  <span className="error">Found in {breach.count.toLocaleString()} known breaches. Change it.</span>
                )}
              </p>
            )}

            <div className="actions">
              <button className="btn-outline" onClick={openEdit}>Edit</button>
              {detail.has_password && (
                <button
                  className="btn-text"
                  onClick={() => void checkBreach()}
                  disabled={breach?.state === "checking"}
                >
                  {breach || detail.breach ? "Check breaches again" : "Check breaches"}
                </button>
              )}
              <button className="btn-danger" onClick={() => setPendingDelete(detail)}>Delete login</button>
            </div>
            <p className="meta">
              Breach checks send only the first five characters of the password’s SHA-1 hash to Have I Been Pwned.
            </p>
          </article>
        )}
      </div>

      {showForm && (
        <ModalOverlay onClose={closeForm} labelledBy="login-form-title">
          <form
            className="dialog"
            onSubmit={(event) => {
              event.preventDefault();
              void save();
            }}
          >
            <h2 id="login-form-title">{editing ? `Edit ${editing.service}` : "New login"}</h2>
            <div className="field">
              <label className="label" htmlFor="login-service">Name</label>
              <input id="login-service" className="input" value={form.service} autoFocus
                onChange={(event) => setForm({ ...form, service: event.target.value })} />
            </div>
            <div className="field">
              <label className="label" htmlFor="login-username">Username</label>
              <input id="login-username" className="input" value={form.username} autoComplete="off"
                onChange={(event) => setForm({ ...form, username: event.target.value })} />
            </div>
            <div className="field">
              <label className="label" htmlFor="login-password">Password</label>
              <input id="login-password" className="input input-secret" type="password" value={form.password}
                autoComplete="new-password"
                onChange={(event) => setForm({ ...form, password: event.target.value })} />
              {editing && <span className="meta">Leave blank to keep the current password.</span>}
            </div>
            <div className="field">
              <label className="label" htmlFor="login-url">Website</label>
              <input id="login-url" className="input" value={form.url} autoComplete="off"
                onChange={(event) => setForm({ ...form, url: event.target.value })} />
            </div>
            <div className="field">
              <label className="label" htmlFor="login-notes">Notes</label>
              <textarea id="login-notes" className="textarea" value={form.notes}
                onChange={(event) => setForm({ ...form, notes: event.target.value })} />
            </div>
            <div className="actions">
              <button className="btn" type="submit" disabled={saving}>{saving ? "Saving…" : "Save"}</button>
              <button className="btn-text" type="button" onClick={closeForm} disabled={saving}>Cancel</button>
            </div>
          </form>
        </ModalOverlay>
      )}

      {totpSetup && (
        <ModalOverlay onClose={() => setTotpSetup(false)} labelledBy="totp-title">
          <form
            className="dialog"
            onSubmit={(event) => {
              event.preventDefault();
              void saveTotp();
            }}
          >
            <h2 id="totp-title">Add a one-time code</h2>
            <div className="field">
              <label className="label" htmlFor="totp-secret">Setup key or otpauth:// link</label>
              <input id="totp-secret" className="input input-secret" value={totpSecret} autoFocus autoComplete="off"
                onChange={(event) => setTotpSecret(event.target.value)}
                onPaste={(event) => {
                  // A screenshot on the clipboard has no text: read it as a QR.
                  if (!event.clipboardData.getData("text")) {
                    event.preventDefault();
                    void readQr("clipboard");
                  }
                }} />
            </div>
            <div className="field">
              <span className="label">Or the QR code</span>
              <div className="actions">
                <button className="btn-outline" type="button" onClick={() => void readQr("clipboard")} disabled={totpBusy}>Paste screenshot</button>
                <button className="btn-text" type="button" onClick={() => void readQr("file")} disabled={totpBusy}>Choose image…</button>
              </div>
              <span className="meta">⌃⇧⌘4 copies a screenshot. Delete any saved screenshot of the QR afterwards.</span>
            </div>
            {totpError && <p className="error" role="alert">{totpError}</p>}
            <div className="actions">
              <button className="btn" type="submit" disabled={totpBusy || !totpSecret}>{totpBusy ? "Saving…" : "Save"}</button>
              <button className="btn-text" type="button" onClick={() => setTotpSetup(false)} disabled={totpBusy}>Cancel</button>
            </div>
          </form>
        </ModalOverlay>
      )}

      {importPreview && (
        <ImportDialog
          preview={importPreview}
          onClose={() => setImportPreview(null)}
          onImported={() => {
            void loadList();
            if (view === "checkup") void loadCheckup();
          }}
          onCheckup={() => {
            setImportPreview(null);
            showCheckup();
          }}
        />
      )}

      {pendingDelete && (
        <ConfirmDialog
          title={`Delete ${pendingDelete.service}?`}
          message="The login and its one-time code are removed from the vault. This can’t be undone."
          confirmLabel="Delete login"
          busy={deleting}
          onConfirm={() => void confirmDelete()}
          onCancel={() => setPendingDelete(null)}
        />
      )}
    </div>
  );
}

export default Vault;
