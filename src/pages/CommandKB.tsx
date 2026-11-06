import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Icon } from "../components/Icon";
import { ModalOverlay } from "../components/ModalOverlay";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState } from "../components/EmptyState";
import { describeError } from "../lib/errors";
import { useClipboard } from "../lib/useClipboard";
import type { KBEntry, KBInput } from "../lib/types";

const CATEGORIES = [
  "recon", "exploitation", "post_exploit", "priv_esc", "web", "network",
  "crypto", "forensics", "windows", "linux", "general",
];

const EMPTY_FORM: KBInput = { title: "", command: "", description: "", tags: "", category: "general" };

function CommandKB({ onClose }: { onClose?: () => void }) {
  const [entries, setEntries] = useState<KBEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [catFilter, setCatFilter] = useState("all");
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<KBInput>(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<KBEntry | null>(null);
  const [deleting, setDeleting] = useState(false);

  const { copy, copiedId } = useClipboard();

  const load = useCallback(async () => {
    try {
      const list = await invoke<KBEntry[]>("get_kb_entries");
      setEntries(list);
      setError("");
    } catch (err) {
      setError(describeError(err, "Could not load the command library."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    return entries.filter((entry) => {
      const matchesSearch =
        !query ||
        entry.title.toLowerCase().includes(query) ||
        entry.command.toLowerCase().includes(query) ||
        entry.tags.toLowerCase().includes(query);
      const matchesCategory = catFilter === "all" || entry.category === catFilter;
      return matchesSearch && matchesCategory;
    });
  }, [entries, search, catFilter]);

  const save = async () => {
    if (saving) return;
    if (!form.title.trim()) {
      setError("Enter a title for the command.");
      return;
    }
    setSaving(true);
    try {
      await invoke("add_kb_entry", { input: form });
      setForm(EMPTY_FORM);
      setShowForm(false);
      await load();
    } catch (err) {
      setError(describeError(err, "Could not save that command."));
    } finally {
      setSaving(false);
    }
  };

  const confirmDelete = async () => {
    if (!pendingDelete || deleting) return;
    setDeleting(true);
    try {
      await invoke("delete_kb_entry", { id: pendingDelete.id });
      await load();
    } catch (err) {
      setError(describeError(err, "Could not delete that command."));
    } finally {
      setDeleting(false);
      setPendingDelete(null);
    }
  };

  const isFiltering = Boolean(search) || catFilter !== "all";

  return (
    <div className="kb-page">
      <div className="page-header">
        <div className="page-heading-with-back">
          {onClose && (
            <button className="btn-icon" onClick={onClose} aria-label="Back to toolbox">
              <Icon name="arrow-left" size={18} />
            </button>
          )}
          <div className="page-heading">
            <span className="eyebrow">Field reference</span>
            <h1>Command library</h1>
            <p>Save the commands you trust and find them when seconds matter.</p>
          </div>
        </div>
        <button className="btn-primary" onClick={() => setShowForm(true)}>
          <Icon name="plus" size={16} />Add command
        </button>
      </div>

      <div className="kb-toolbar">
        <div className="search-shell">
          <Icon name="search" size={17} />
          <label className="sr-only" htmlFor="kb-search">Search commands</label>
          <input
            id="kb-search"
            className="search-input"
            placeholder="Search commands, tags, or syntax"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>
        <label className="sr-only" htmlFor="kb-category-filter">Filter by category</label>
        <select id="kb-category-filter" value={catFilter} onChange={(event) => setCatFilter(event.target.value)}>
          <option value="all">All categories</option>
          {CATEGORIES.map((category) => (
            <option key={category} value={category}>{category.replace("_", " ")}</option>
          ))}
        </select>
      </div>

      {error && <p className="lock-error" role="alert"><Icon name="x" size={13} />{error}</p>}

      {showForm && (
        <ModalOverlay onClose={() => setShowForm(false)} labelledBy="kb-form-title">
          <div className="modal">
            <div className="modal-heading">
              <span className="modal-icon"><Icon name="terminal" size={18} /></span>
              <div>
                <h4 id="kb-form-title">Add command</h4>
                <p>Store a reusable command and its operating context.</p>
              </div>
            </div>
            <label className="field-label" htmlFor="kb-title">Title</label>
            <input
              id="kb-title"
              value={form.title}
              onChange={(event) => setForm({ ...form, title: event.target.value })}
              placeholder="Python reverse shell"
              autoFocus
            />
            <label className="field-label" htmlFor="kb-command">Command</label>
            <input
              id="kb-command"
              value={form.command}
              onChange={(event) => setForm({ ...form, command: event.target.value })}
            />
            <label className="field-label" htmlFor="kb-description">Description / usage notes</label>
            <textarea
              id="kb-description"
              value={form.description}
              onChange={(event) => setForm({ ...form, description: event.target.value })}
            />
            <label className="field-label" htmlFor="kb-tags">Tags</label>
            <input
              id="kb-tags"
              value={form.tags}
              onChange={(event) => setForm({ ...form, tags: event.target.value })}
              placeholder="comma separated"
            />
            <label className="field-label" htmlFor="kb-category">Category</label>
            <select
              id="kb-category"
              value={form.category}
              onChange={(event) => setForm({ ...form, category: event.target.value })}
            >
              {CATEGORIES.map((category) => (
                <option key={category} value={category}>{category.replace("_", " ")}</option>
              ))}
            </select>
            <div className="modal-actions">
              <button className="btn-secondary" onClick={() => setShowForm(false)} disabled={saving}>Cancel</button>
              <button className="btn-primary" onClick={() => void save()} disabled={saving}>
                <Icon name="check" size={15} />{saving ? "Saving…" : "Save command"}
              </button>
            </div>
          </div>
        </ModalOverlay>
      )}

      {pendingDelete && (
        <ConfirmDialog
          title={`Delete ${pendingDelete.title}?`}
          message="This command will be removed from your library. This cannot be undone."
          confirmLabel="Delete command"
          busy={deleting}
          onConfirm={() => void confirmDelete()}
          onCancel={() => setPendingDelete(null)}
        />
      )}

      <div className="kb-list">
        {loading && <p className="inline-message" role="status">Loading commands…</p>}

        {!loading && filtered.length === 0 && (
          <EmptyState
            prompt={isFiltering ? `grep -i "${search || catFilter}" ~/kb/*` : "ls ~/kb/"}
            output={isFiltering ? "no matches" : "no commands stored"}
            actionLabel={isFiltering ? undefined : "add command"}
            onAction={() => setShowForm(true)}
          />
        )}

        {filtered.map((entry) => (
          <div key={entry.id} className="kb-card">
            <div className="kb-card-header">
              <div className="kb-title">
                <span className="kb-title-icon"><Icon name="command" size={16} /></span>
                <h4>{entry.title}</h4>
              </div>
              <div className="kb-card-meta">
                <span className="kb-category">{entry.category.replace("_", " ")}</span>
                <span className="entry-date">{entry.created_at}</span>
              </div>
            </div>
            {entry.command && (
              <div className="kb-command-row">
                <code className="kb-command">{entry.command}</code>
                <button className="btn-soft" onClick={() => void copy(entry.command, entry.id)}>
                  <Icon name={copiedId === entry.id ? "check" : "copy"} size={14} />
                  {copiedId === entry.id ? "Copied" : "Copy"}
                </button>
              </div>
            )}
            {entry.description && <p className="kb-desc">{entry.description}</p>}
            {entry.tags && (
              <div className="kb-tags">
                {/* Index in the key: duplicate tag values would otherwise collide. */}
                {entry.tags.split(",").map((tag, index) => (
                  <span key={`${tag.trim()}-${index}`} className="kb-tag">{tag.trim()}</span>
                ))}
              </div>
            )}
            <button className="btn-soft btn-danger" onClick={() => setPendingDelete(entry)}>
              <Icon name="trash" size={14} />Delete
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

export default CommandKB;
