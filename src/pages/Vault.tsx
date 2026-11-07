import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ModalOverlay } from "../components/ModalOverlay";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState } from "../components/EmptyState";
import { Print } from "../components/Print";
import { describeError } from "../lib/errors";
import { countWord, formatDate, joinWords } from "../lib/format";
import { useClipboard, type CopyField } from "../lib/useClipboard";
import {
  setTotpRolloverHandler,
  startTotpWindow,
  stopTotpWindow,
  useTotpRemaining,
} from "../lib/totpWindow";
import type {
  CredentialDetail,
  CredentialInput,
  CredentialSummary,
  PasswordProfile,
  TotpCode,
} from "../lib/types";

const EMPTY_FORM: CredentialInput = { service: "", username: "", password: "", url: "", notes: "" };
/** A shown password hides itself again after this long. */
const REVEAL_MS = 30_000;

type Breach = { state: "checking" } | { state: "done"; count: number } | { state: "failed" };

/** Subscribes to the shared tick so only this line re-renders every second. */
const TotpCountdown = memo(function TotpCountdown() {
  const remaining = useTotpRemaining();
  return <span className="meta">{remaining} seconds left</span>;
});

function describeShape(profile: PasswordProfile): string {
  if (profile.length === 0) return "No password is stored for this login.";
  const parts: string[] = [];
  if (profile.lowercase && profile.uppercase) parts.push("upper- and lowercase letters");
  else if (profile.lowercase) parts.push("lowercase letters");
  else if (profile.uppercase) parts.push("capital letters");
  if (profile.digits) parts.push("numbers");
  if (profile.symbols) parts.push("symbols");
  const noun = profile.length === 1 ? "character" : "characters";
  return parts.length
    ? `${countWord(profile.length)} ${noun}, with ${joinWords(parts)}.`
    : `${countWord(profile.length)} ${noun}.`;
}

function Vault() {
  const [credentials, setCredentials] = useState<CredentialSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const [detail, setDetail] = useState<CredentialDetail | null>(null);
  const [profile, setProfile] = useState<PasswordProfile | null>(null);
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
      if (code) startTotpWindow(code.remaining);
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
      setProfile(null);
      return;
    }
    const request = ++detailRequest.current;
    void (async () => {
      try {
        const [nextDetail, nextProfile] = await Promise.all([
          invoke<CredentialDetail>("get_credential", { id: selectedId }),
          invoke<PasswordProfile>("describe_password", { id: selectedId }),
        ]);
        if (request !== detailRequest.current) return;
        setDetail(nextDetail);
        setProfile(nextProfile);
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

  const openEdit = () => {
    if (!detail) return;
    setEditing(detail);
    // A blank password means "keep the current one" on the backend.
    setForm({ service: detail.service, username: detail.username, password: "", url: detail.url, notes: detail.notes });
    setShowForm(true);
  };

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
      setError(describeError(err, "Could not save that 2FA secret."));
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

  return (
    <div className="split">
      <section className="split-list" aria-label="Logins">
        <div className="split-list-head">
          <h1 className="title-l">Vault</h1>
          <button className="btn-outline" onClick={openNew}>New login</button>
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
          <kbd className="meta">⌘K</kbd>
        </label>

        {loading && <p className="status" role="status">Opening the vault…</p>}
        {!loading && filtered.length === 0 && (
          <EmptyState
            message={search ? "Nothing matches that search." : "No logins yet. Add your first one."}
            actionLabel={search ? undefined : "New login"}
            onAction={openNew}
          />
        )}

        <ul className="rows">
          {filtered.map((c) => {
            const result = breaches[c.id];
            const breached = result?.state === "done" && result.count > 0;
            return (
              <li key={c.id}>
                <button
                  className="row"
                  aria-current={c.id === selectedId ? "true" : undefined}
                  onClick={() => setSelectedId(c.id)}
                >
                  <span className="row-copy">
                    <span className="row-name">{c.service}</span>
                    {c.username && <span className="meta">{c.username}</span>}
                  </span>
                  {breached ? (
                    <span className="row-note is-danger">in a breach</span>
                  ) : (
                    c.has_totp && <span className="row-note">2FA</span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </section>

      <div className="split-main">
        {error && <p className="error" role="alert">{error}</p>}

        {detail && profile && (
          <article className="record" aria-labelledby="record-title">
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
                <span className={`fact-value secret${revealed !== null ? " is-revealed" : ""}`}>
                  {revealed !== null ? revealed : "•".repeat(Math.min(Math.max(profile.length, 8), 24))}
                </span>
                <button className="btn-text" onClick={() => void reveal()} disabled={profile.length === 0}>
                  {revealed !== null ? "Hide" : "Show"}
                </button>
                <button className="btn-text" onClick={() => void copy("password")} disabled={profile.length === 0}>
                  {copied("password") ? "Copied" : "Copy"}
                </button>
              </dd>

              <dt>One-time code</dt>
              <dd>
                {detail.has_totp && totp ? (
                  <>
                    <span className="otp">{totp.code.replace(/^(\d{3})(\d{3})$/, "$1 $2")}</span>
                    <span className="fact-value"><TotpCountdown /></span>
                    <button className="btn-text" onClick={() => void copy("totp")}>
                      {copied("totp") ? "Copied" : "Copy"}
                    </button>
                    <button className="btn-danger" onClick={() => void removeTotp()}>Remove</button>
                  </>
                ) : (
                  <>
                    <span className="fact-value meta">None set up</span>
                    <button className="btn-text" onClick={() => { setTotpSecret(""); setTotpSetup(true); }}>
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
                      {copied("username") ? "Copied" : "Copy"}
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
                      {copied("url") ? "Copied" : "Copy"}
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

            <p className="summary">
              {describeShape(profile)}{" "}
              {profile.length > 0 && (
                <>
                  {!breach && "It hasn’t been checked against known breaches yet. "}
                  {breach?.state === "checking" && "Checking known breaches… "}
                  {breach?.state === "failed" && "The breach check couldn’t reach the service. "}
                  {breach?.state === "done" && breach.count === 0 && "It didn’t turn up in any known breach just now. "}
                  {breach?.state === "done" && breach.count > 0 && (
                    <span className="error">
                      It turned up in {breach.count.toLocaleString()} known breaches. Change it.{" "}
                    </span>
                  )}
                </>
              )}
            </p>

            <div className="actions">
              <button className="btn-outline" onClick={openEdit}>Edit</button>
              {profile.length > 0 && (
                <button
                  className="btn-text"
                  onClick={() => void checkBreach()}
                  disabled={breach?.state === "checking"}
                >
                  {breach ? "Check breaches again" : "Check breaches"}
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
            <p className="lead">Paste the setup key the service shows next to its QR code. It usually looks like JBSWY3DPEHPK3PXP.</p>
            <div className="field">
              <label className="label" htmlFor="totp-secret">Setup key</label>
              <input id="totp-secret" className="input input-secret" value={totpSecret} autoFocus autoComplete="off"
                onChange={(event) => setTotpSecret(event.target.value)} />
            </div>
            <div className="actions">
              <button className="btn" type="submit" disabled={totpBusy || !totpSecret}>{totpBusy ? "Saving…" : "Save"}</button>
              <button className="btn-text" type="button" onClick={() => setTotpSetup(false)} disabled={totpBusy}>Cancel</button>
            </div>
          </form>
        </ModalOverlay>
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
