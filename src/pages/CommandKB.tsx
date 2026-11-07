import { useCallback, useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
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

function CommandKB({ onClose }: { onClose: () => void }) {
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

  const { copyText, copiedId } = useClipboard();

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

  const copy = async (entry: KBEntry) => {
    try {
      await copyText(entry.command, entry.id);
    } catch (err) {
      setError(describeError(err, "Could not copy that command."));
    }
  };

  return (
    <div className="page">
      <button className="btn-text back" onClick={onClose}>← Toolbox</button>
      <header className="page-head">
        <div>
          <h1 className="title-l">Command library</h1>
          <p className="lead">Commands you trust, with notes on when to reach for them.</p>
        </div>
        <button className="btn-outline" onClick={() => setShowForm(true)}>Add command</button>
      </header>

      <div className="actions">
        <label className="search">
          <span className="sr-only">Search commands</span>
          <input className="input" placeholder="Search titles, commands and tags" value={search}
            onChange={(event) => setSearch(event.target.value)} />
        </label>
        <label className="inline-select">
          Category
          <select value={catFilter} onChange={(event) => setCatFilter(event.target.value)}>
            <option value="all">all</option>
            {CATEGORIES.map((category) => (
              <option key={category} value={category}>{category.replace("_", " ")}</option>
            ))}
          </select>
        </label>
      </div>

      {error && <p className="error" role="alert">{error}</p>}
      {loading && <p className="status" role="status">Loading commands…</p>}
      {!loading && filtered.length === 0 && (
        <EmptyState
          message={isFiltering ? "Nothing matches that search." : "No commands saved yet."}
          actionLabel={isFiltering ? undefined : "Add command"}
          onAction={() => setShowForm(true)}
        />
      )}

      <ol className="entries stagger">
        {filtered.map((entry) => (
          <li key={entry.id}>
            <span className="entry-when">{entry.category.replace("_", " ")}</span>
            <div className="entry-body">
              <h2 className="entry-title">{entry.title}</h2>
              {entry.command && <code className="command">{entry.command}</code>}
              {entry.description && <p className="entry-text">{entry.description}</p>}
              {entry.tags && <p className="meta">{entry.tags.split(",").map((tag) => tag.trim()).filter(Boolean).join(", ")}</p>}
              <div className="actions">
                {entry.command && (
                  <button className="btn-text" onClick={() => void copy(entry)}>
                    {copiedId === entry.id ? "Copied" : "Copy command"}
                  </button>
                )}
                <button className="btn-danger" onClick={() => setPendingDelete(entry)}>Delete</button>
              </div>
            </div>
          </li>
        ))}
      </ol>

      {showForm && (
        <ModalOverlay onClose={() => setShowForm(false)} labelledBy="kb-form-title">
          <form
            className="dialog"
            onSubmit={(event) => {
              event.preventDefault();
              void save();
            }}
          >
            <h2 id="kb-form-title">Add a command</h2>
            <div className="field">
              <label className="label" htmlFor="kb-title">Title</label>
              <input id="kb-title" className="input" value={form.title} autoFocus
                onChange={(event) => setForm({ ...form, title: event.target.value })} />
            </div>
            <div className="field">
              <label className="label" htmlFor="kb-command">Command</label>
              <input id="kb-command" className="input mono" value={form.command}
                onChange={(event) => setForm({ ...form, command: event.target.value })} />
            </div>
            <div className="field">
              <label className="label" htmlFor="kb-description">When to use it</label>
              <textarea id="kb-description" className="textarea" value={form.description}
                onChange={(event) => setForm({ ...form, description: event.target.value })} />
            </div>
            <div className="field">
              <label className="label" htmlFor="kb-tags">Tags</label>
              <input id="kb-tags" className="input" value={form.tags} placeholder="Separated by commas"
                onChange={(event) => setForm({ ...form, tags: event.target.value })} />
            </div>
            <div className="field">
              <label className="label" htmlFor="kb-category">Category</label>
              <select id="kb-category" className="select" value={form.category}
                onChange={(event) => setForm({ ...form, category: event.target.value })}>
                {CATEGORIES.map((category) => (
                  <option key={category} value={category}>{category.replace("_", " ")}</option>
                ))}
              </select>
            </div>
            <div className="actions">
              <button className="btn" type="submit" disabled={saving}>{saving ? "Saving…" : "Save"}</button>
              <button className="btn-text" type="button" onClick={() => setShowForm(false)} disabled={saving}>Cancel</button>
            </div>
          </form>
        </ModalOverlay>
      )}

      {pendingDelete && (
        <ConfirmDialog
          title={`Delete ${pendingDelete.title}?`}
          message="It’s removed from the library. This can’t be undone."
          confirmLabel="Delete command"
          busy={deleting}
          onConfirm={() => void confirmDelete()}
          onCancel={() => setPendingDelete(null)}
        />
      )}
    </div>
  );
}

export default CommandKB;
