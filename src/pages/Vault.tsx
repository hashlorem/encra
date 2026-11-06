import { memo, useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Icon } from "../components/Icon";
import { ModalOverlay } from "../components/ModalOverlay";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState } from "../components/EmptyState";
import { describeError } from "../lib/errors";
import { useClipboard } from "../lib/useClipboard";
import {
  startTotpWindow,
  stopTotpWindow,
  setTotpRolloverHandler,
  useTotpRemaining,
} from "../lib/totpWindow";
import type { Credential, CredentialInput } from "../lib/types";

const EMPTY_FORM: CredentialInput = { service: "", username: "", password: "", url: "", notes: "" };
const IS_MAC = /Mac/i.test(navigator.userAgent);

interface HibpState {
  count: number;
  loading: boolean;
}

/**
 * Isolated countdown. Subscribes to the shared tick directly so a once-per-second
 * update does not re-render the surrounding credential card.
 */
const TotpCountdown = memo(function TotpCountdown() {
  const remaining = useTotpRemaining();
  return (
    <span className={`totp-timer ${remaining <= 5 ? "totp-expiring" : ""}`}>{remaining}s</span>
  );
});

interface CredentialCardProps {
  credential: Credential;
  revealed: boolean;
  hibp?: HibpState;
  onToggleReveal: (id: string) => void;
  onCopy: (value: string) => void;
  onEdit: (credential: Credential) => void;
  onDelete: (credential: Credential) => void;
  onCheckHibp: (credential: Credential) => void;
  onSetupTotp: (id: string) => void;
  onRemoveTotp: (id: string) => void;
}

const CredentialCard = memo(function CredentialCard({
  credential,
  revealed,
  hibp,
  onToggleReveal,
  onCopy,
  onEdit,
  onDelete,
  onCheckHibp,
  onSetupTotp,
  onRemoveTotp,
}: CredentialCardProps) {
  return (
    <div className="cred-card">
      <div className="service-avatar">{credential.service.slice(0, 1).toUpperCase() || "K"}</div>
      <div className="cred-info">
        <strong>{credential.service}</strong>
        <div className="cred-meta">
          <span className="cred-user"><Icon name="user" size={12} />{credential.username}</span>
          {credential.url && <span className="cred-url"><Icon name="globe" size={12} />{credential.url}</span>}
        </div>
      </div>

      {credential.totp_code ? (
        <div className="cred-totp">
          <span className="totp-code">{credential.totp_code}</span>
          <TotpCountdown />
          <button
            className="btn-icon btn-icon-sm"
            onClick={() => onCopy(credential.totp_code ?? "")}
            aria-label={`Copy two-factor code for ${credential.service}`}
          >
            <Icon name="copy" size={14} />
          </button>
          <button
            className="btn-icon btn-icon-sm btn-danger"
            onClick={() => onRemoveTotp(credential.id)}
            aria-label={`Remove two-factor authentication for ${credential.service}`}
          >
            <Icon name="x" size={14} />
          </button>
        </div>
      ) : (
        <div className="cred-totp">
          <button className="btn-soft" onClick={() => onSetupTotp(credential.id)}>
            <Icon name="fingerprint" size={14} /> Add 2FA
          </button>
        </div>
      )}

      <div className="cred-password">
        {/* Read-only text; the adjacent button is the single keyboard-accessible
            control, so this no longer needs its own click handler. */}
        <span className="password-text" aria-hidden={!revealed}>
          {revealed ? credential.password_encrypted : "••••••••"}
        </span>
        <button
          className="btn-icon btn-icon-sm"
          onClick={() => onToggleReveal(credential.id)}
          aria-label={`${revealed ? "Hide" : "Reveal"} password for ${credential.service}`}
        >
          <Icon name={revealed ? "eye-off" : "eye"} size={14} />
        </button>
      </div>

      <div className="cred-actions">
        <button className="btn-icon" onClick={() => onCopy(credential.password_encrypted)} aria-label={`Copy password for ${credential.service}`}>
          <Icon name="copy" size={15} />
        </button>
        <button className="btn-icon" onClick={() => onEdit(credential)} aria-label={`Edit ${credential.service}`}>
          <Icon name="settings" size={15} />
        </button>
        <button
          className="btn-icon"
          onClick={() => onCheckHibp(credential)}
          disabled={hibp?.loading}
          aria-label={`Check ${credential.service} for breach exposure`}
        >
          {hibp?.loading ? <span className="button-spinner" /> : <Icon name="shield" size={15} />}
        </button>
        <button className="btn-icon btn-danger" onClick={() => onDelete(credential)} aria-label={`Delete ${credential.service}`}>
          <Icon name="trash" size={15} />
        </button>
      </div>

      <span className="cred-date">{credential.created_at}</span>

      {hibp && !hibp.loading && (
        <div className="cred-card-footer">
          <span className={`hibp-badge ${hibp.count === 0 ? "hibp-safe" : "hibp-pwned"}`}>
            {hibp.count === -1
              ? "Breach check unavailable"
              : hibp.count === 0
                ? "Not found in breaches"
                : `Found in ${hibp.count.toLocaleString()} breaches`}
          </span>
        </div>
      )}
    </div>
  );
});

function Vault() {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<Credential | null>(null);
  const [form, setForm] = useState<CredentialInput>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);

  const [search, setSearch] = useState("");
  const [revealed, setRevealed] = useState<Set<string>>(new Set());

  const [totpSetupId, setTotpSetupId] = useState<string | null>(null);
  const [totpSecret, setTotpSecret] = useState("");
  const [totpBusy, setTotpBusy] = useState(false);

  const [hibpResults, setHibpResults] = useState<Record<string, HibpState>>({});
  const [pendingDelete, setPendingDelete] = useState<Credential | null>(null);
  const [deleting, setDeleting] = useState(false);

  const { copy } = useClipboard();

  const loadCredentials = useCallback(async () => {
    try {
      const creds = await invoke<Credential[]>("get_credentials");
      setCredentials(creds);
      setError("");
    } catch (err) {
      setError(describeError(err, "Could not load your credentials."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadCredentials();
  }, [loadCredentials]);

  // Recomputed codes when the 30s window rolls over. Without this the displayed
  // codes stayed frozen and became wrong as soon as the window turned over.
  useEffect(() => {
    setTotpRolloverHandler(() => {
      void loadCredentials();
    });
    return () => setTotpRolloverHandler(null);
  }, [loadCredentials]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const seconds = await invoke<number>("get_totp_remaining");
        if (!cancelled) startTotpWindow(seconds);
      } catch {
        if (!cancelled) startTotpWindow(30);
      }
    })();
    return () => {
      cancelled = true;
      stopTotpWindow();
    };
  }, []);

  // Cmd/Ctrl+K focuses search.
  useEffect(() => {
    const handler = () => document.querySelector<HTMLInputElement>(".search-input")?.focus();
    window.addEventListener("cobrypt:search-focus", handler);
    return () => window.removeEventListener("cobrypt:search-focus", handler);
  }, []);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return credentials;
    return credentials.filter(
      (credential) =>
        credential.service.toLowerCase().includes(query) ||
        credential.username.toLowerCase().includes(query),
    );
  }, [credentials, search]);

  const resetForm = useCallback(() => {
    setForm(EMPTY_FORM);
    setEditing(null);
    setShowForm(false);
  }, []);

  const save = async () => {
    if (saving) return;
    if (!form.service.trim()) {
      setError("Enter a service name before saving.");
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await invoke("update_credential", { id: editing.id, input: form });
      } else {
        await invoke("add_credential", { input: form });
      }
      resetForm();
      await loadCredentials();
    } catch (err) {
      setError(describeError(err, "Could not save that credential."));
    } finally {
      setSaving(false);
    }
  };

  const edit = (credential: Credential) => {
    setEditing(credential);
    setForm({
      service: credential.service,
      username: credential.username,
      // Blank means "keep the current password" on the backend.
      password: "",
      url: credential.url,
      notes: credential.notes,
    });
    setShowForm(true);
  };

  const confirmDelete = async () => {
    if (!pendingDelete || deleting) return;
    setDeleting(true);
    try {
      await invoke("delete_credential", { id: pendingDelete.id });
      await loadCredentials();
    } catch (err) {
      setError(describeError(err, "Could not delete that credential."));
    } finally {
      setDeleting(false);
      setPendingDelete(null);
    }
  };

  const toggleReveal = (id: string) => {
    setRevealed((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleCopy = (value: string) => {
    // The shared hook reports failures and cancels a pending wipe from an
    // earlier copy, which the old inline implementation did not.
    void copy(value);
  };

  const setupTotp = async () => {
    if (!totpSetupId || !totpSecret || totpBusy) return;
    setTotpBusy(true);
    try {
      await invoke("setup_totp", { credentialId: totpSetupId, secret: totpSecret });
      setTotpSetupId(null);
      setTotpSecret("");
      await loadCredentials();
    } catch (err) {
      setError(describeError(err, "Could not save that 2FA secret."));
    } finally {
      setTotpBusy(false);
    }
  };

  const removeTotp = async (id: string) => {
    try {
      await invoke("remove_totp", { credentialId: id });
      await loadCredentials();
    } catch (err) {
      setError(describeError(err, "Could not remove two-factor authentication."));
    }
  };

  const checkHibp = async (credential: Credential) => {
    setHibpResults((previous) => ({ ...previous, [credential.id]: { count: 0, loading: true } }));
    try {
      const count = await invoke<number>("check_hibp", { password: credential.password_encrypted });
      setHibpResults((previous) => ({ ...previous, [credential.id]: { count, loading: false } }));
    } catch {
      setHibpResults((previous) => ({ ...previous, [credential.id]: { count: -1, loading: false } }));
    }
  };

  const twoFactorCount = useMemo(
    () => credentials.filter((credential) => credential.totp_code).length,
    [credentials],
  );

  return (
    <div className="vault-page">
      <div className="page-header">
        <div className="page-heading">
          <span className="eyebrow">Encrypted workspace</span>
          <h1>Credential vault</h1>
          <p>Manage every login, secret, and verification code from one protected place.</p>
        </div>
        <div className="header-actions">
          <button className="btn-primary" onClick={() => { resetForm(); setShowForm(true); }}>
            <Icon name="plus" size={16} /> New credential
          </button>
        </div>
      </div>

      <div className="vault-statusbar">
        <span className="status-item"><span className="status-label">credentials</span> <span className="status-value">{credentials.length}</span></span>
        <span className="status-sep">|</span>
        <span className="status-item"><span className="status-label">2fa</span> <span className="status-value">{twoFactorCount}</span></span>
        <span className="status-sep">|</span>
        <span className="status-item"><span className="status-label">state</span> <span className="status-value status-ok">encrypted</span></span>
        <span className="status-sep">|</span>
        <span className="status-item"><span className="status-label">search</span> <span className="status-value">{filtered.length} of {credentials.length}</span></span>
      </div>

      <div className="vault-toolbar">
        <div className="search-shell">
          <Icon name="search" size={17} />
          <label className="sr-only" htmlFor="vault-search">Search credentials</label>
          <input
            id="vault-search"
            type="text"
            className="search-input"
            placeholder="Search by service or username"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          <kbd>{IS_MAC ? "⌘ K" : "Ctrl K"}</kbd>
        </div>
        <span className="result-count">{filtered.length} {filtered.length === 1 ? "item" : "items"}</span>
      </div>

      {error && (
        <p className="lock-error" role="alert">
          <Icon name="x" size={13} />{error}
        </p>
      )}

      {showForm && (
        <ModalOverlay onClose={resetForm} labelledBy="credential-form-title">
          <div className="modal">
            <div className="modal-heading">
              <span className="modal-icon"><Icon name={editing ? "key" : "plus"} size={18} /></span>
              <div>
                <h4 id="credential-form-title">{editing ? "Edit credential" : "Add credential"}</h4>
                <p>{editing ? "Update the selected vault entry." : "Store a new login in your encrypted vault."}</p>
              </div>
            </div>
            <label className="field-label" htmlFor="credential-service">Service</label>
            <input id="credential-service" value={form.service} onChange={(event) => setForm({ ...form, service: event.target.value })} autoFocus />
            <label className="field-label" htmlFor="credential-username">Username</label>
            <input id="credential-username" value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} />
            <label className="field-label" htmlFor="credential-password">Password</label>
            <input id="credential-password" type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} />
            {editing && <span className="form-hint">Leave blank to keep the current password.</span>}
            <label className="field-label" htmlFor="credential-url">URL (optional)</label>
            <input id="credential-url" value={form.url} onChange={(event) => setForm({ ...form, url: event.target.value })} />
            <label className="field-label" htmlFor="credential-notes">Notes (optional)</label>
            <textarea id="credential-notes" value={form.notes} onChange={(event) => setForm({ ...form, notes: event.target.value })} />
            <div className="modal-actions">
              <button className="btn-secondary" onClick={resetForm} disabled={saving}>Cancel</button>
              <button className="btn-primary" onClick={() => void save()} disabled={saving}>
                <Icon name="check" size={15} />{saving ? "Saving…" : editing ? "Update credential" : "Save credential"}
              </button>
            </div>
          </div>
        </ModalOverlay>
      )}

      {totpSetupId && (
        <ModalOverlay onClose={() => setTotpSetupId(null)} labelledBy="totp-setup-title">
          <div className="modal">
            <div className="modal-heading">
              <span className="modal-icon"><Icon name="fingerprint" size={18} /></span>
              <div>
                <h4 id="totp-setup-title">Set up two-factor authentication</h4>
                <p>Add a TOTP secret to generate verification codes here.</p>
              </div>
            </div>
            <p className="form-hint form-hint-tight">
              Paste the secret key from the service (usually a base32 string like JBSWY3DPEHPK3PXP).
            </p>
            <label className="field-label" htmlFor="totp-secret">TOTP secret</label>
            <input
              id="totp-secret"
              value={totpSecret}
              onChange={(event) => setTotpSecret(event.target.value)}
              autoFocus
              autoComplete="off"
            />
            <div className="modal-actions">
              <button className="btn-secondary" onClick={() => setTotpSetupId(null)} disabled={totpBusy}>Cancel</button>
              <button className="btn-primary" onClick={() => void setupTotp()} disabled={totpBusy || !totpSecret}>
                <Icon name="check" size={15} />{totpBusy ? "Saving…" : "Save 2FA"}
              </button>
            </div>
          </div>
        </ModalOverlay>
      )}

      {pendingDelete && (
        <ConfirmDialog
          title={`Delete ${pendingDelete.service}?`}
          message="This removes the credential from your vault. This cannot be undone."
          confirmLabel="Delete credential"
          busy={deleting}
          onConfirm={() => void confirmDelete()}
          onCancel={() => setPendingDelete(null)}
        />
      )}

      <div className="cred-list">
        {loading && <p className="inline-message" role="status">Decrypting your vault…</p>}

        {!loading && filtered.length === 0 && (
          <EmptyState
            prompt={search ? `grep -i "${search}" ~/vault/*` : "ls ~/vault/"}
            output={search ? "no matches" : "no credentials stored"}
            actionLabel={search ? undefined : "add credential"}
            onAction={() => setShowForm(true)}
          />
        )}

        {filtered.map((credential) => (
          <CredentialCard
            key={credential.id}
            credential={credential}
            revealed={revealed.has(credential.id)}
            hibp={hibpResults[credential.id]}
            onToggleReveal={toggleReveal}
            onCopy={handleCopy}
            onEdit={edit}
            onDelete={setPendingDelete}
            onCheckHibp={(target) => void checkHibp(target)}
            onSetupTotp={(id) => { setTotpSetupId(id); setTotpSecret(""); }}
            onRemoveTotp={(id) => void removeTotp(id)}
          />
        ))}
      </div>
    </div>
  );
}

export default Vault;
