import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ModalOverlay } from "../components/ModalOverlay";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState } from "../components/EmptyState";
import { EvidencePanel } from "../components/EvidencePanel";
import { describeError } from "../lib/errors";
import { formatDate, formatShortDate, formatTime, parseStored } from "../lib/format";
import type { EntryInput, JournalEntry, Project, ProjectInput } from "../lib/types";

const KINDS: { value: string; label: string }[] = [
  { value: "note", label: "Note" },
  { value: "finding", label: "Finding" },
  { value: "recon", label: "Recon" },
  { value: "exploitation", label: "Exploitation" },
  { value: "post_exploit", label: "Post-exploitation" },
  { value: "remediation", label: "Remediation" },
];
const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
const STATUS_LABELS: Record<string, string> = {
  planning: "Planning",
  in_progress: "In progress",
  completed: "Closed",
};

const EMPTY_PROJECT: ProjectInput = { name: "", description: "", target: "", methodology: "" };
const EMPTY_ENTRY: Omit<EntryInput, "project_id"> = { title: "", content: "", entry_type: "note", severity: "info" };

function kindLabel(value: string): string {
  return KINDS.find((kind) => kind.value === value)?.label ?? value;
}

/** "Finding, high" with only high and critical in the danger colour. */
function EntryKind({ entry }: { entry: JournalEntry }) {
  const showSeverity = entry.severity && entry.severity !== "info";
  const loud = entry.severity === "high" || entry.severity === "critical";
  return (
    <span className="meta">
      {kindLabel(entry.entry_type)}
      {showSeverity && (
        <>
          , <span className={loud ? "sev-high" : undefined}>{entry.severity}</span>
        </>
      )}
    </span>
  );
}

function Journal() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [entries, setEntries] = useState<JournalEntry[]>([]);
  const [loadingProjects, setLoadingProjects] = useState(true);
  const [loadingEntries, setLoadingEntries] = useState(false);
  const [error, setError] = useState("");

  const [showProjectForm, setShowProjectForm] = useState(false);
  const [projectForm, setProjectForm] = useState<ProjectInput>(EMPTY_PROJECT);
  const [savingProject, setSavingProject] = useState(false);

  const [entryForm, setEntryForm] = useState(EMPTY_ENTRY);
  const [savingEntry, setSavingEntry] = useState(false);

  const [pendingDeleteProject, setPendingDeleteProject] = useState<Project | null>(null);
  const [pendingDeleteEntry, setPendingDeleteEntry] = useState<JournalEntry | null>(null);
  const [deleting, setDeleting] = useState(false);

  const [tab, setTab] = useState<"notes" | "evidence">("notes");
  const [evidenceCount, setEvidenceCount] = useState<number | null>(null);
  const [dropToken, setDropToken] = useState(0);

  // Files dropped on the window go to the open case's evidence. Rust keeps
  // the paths; this only says a drop happened.
  useEffect(() => {
    const stop = listen<number>("evidence-dropped", () => {
      setTab("evidence");
      setDropToken((n) => n + 1);
    });
    return () => {
      void stop.then((unlisten) => unlisten());
    };
  }, []);

  // Drops a slow response for a case the user has already left.
  const entryRequest = useRef(0);

  const loadProjects = useCallback(async (selectAfter?: string) => {
    try {
      const list = await invoke<Project[]>("get_projects");
      setProjects(list);
      setError("");
      setSelectedId((current) => {
        const wanted = selectAfter ?? current;
        if (wanted && list.some((p) => p.id === wanted)) return wanted;
        return list[0]?.id ?? null;
      });
    } catch (err) {
      setError(describeError(err, "Could not load your cases."));
    } finally {
      setLoadingProjects(false);
    }
  }, []);

  const loadEntries = useCallback(async (projectId: string) => {
    const request = ++entryRequest.current;
    setLoadingEntries(true);
    try {
      const list = await invoke<JournalEntry[]>("get_entries", { projectId });
      if (request === entryRequest.current) setEntries(list);
    } catch (err) {
      if (request !== entryRequest.current) return;
      setEntries([]);
      setError(describeError(err, "Could not load the notes for that case."));
    } finally {
      if (request === entryRequest.current) setLoadingEntries(false);
    }
  }, []);

  useEffect(() => {
    void loadProjects();
  }, [loadProjects]);

  useEffect(() => {
    setEntryForm(EMPTY_ENTRY);
    setEvidenceCount(null);
    if (selectedId) void loadEntries(selectedId);
    else setEntries([]);
  }, [selectedId, loadEntries]);

  const project = useMemo(() => projects.find((p) => p.id === selectedId) ?? null, [projects, selectedId]);

  // Newest first, like a notebook you read from the top.
  const ordered = useMemo(
    () => [...entries].sort((a, b) => (a.created_at < b.created_at ? 1 : -1)),
    [entries],
  );

  const createProject = async () => {
    if (savingProject) return;
    if (!projectForm.name.trim()) {
      setError("Give the case a name.");
      return;
    }
    setSavingProject(true);
    try {
      const created = await invoke<Project>("create_project", { input: projectForm });
      setProjectForm(EMPTY_PROJECT);
      setShowProjectForm(false);
      await loadProjects(created.id);
    } catch (err) {
      setError(describeError(err, "Could not open that case."));
    } finally {
      setSavingProject(false);
    }
  };

  const addEntry = async () => {
    if (!selectedId || savingEntry) return;
    if (!entryForm.title.trim()) return;
    setSavingEntry(true);
    try {
      await invoke("add_entry", { input: { ...entryForm, project_id: selectedId } });
      setEntryForm(EMPTY_ENTRY);
      await loadEntries(selectedId);
    } catch (err) {
      setError(describeError(err, "Could not save that note."));
    } finally {
      setSavingEntry(false);
    }
  };

  const confirmDeleteProject = async () => {
    if (!pendingDeleteProject || deleting) return;
    setDeleting(true);
    try {
      await invoke("delete_project", { id: pendingDeleteProject.id });
      setSelectedId(null);
      await loadProjects();
    } catch (err) {
      setError(describeError(err, "Could not delete that case."));
    } finally {
      setDeleting(false);
      setPendingDeleteProject(null);
    }
  };

  const confirmDeleteEntry = async () => {
    if (!pendingDeleteEntry || deleting) return;
    setDeleting(true);
    try {
      await invoke("delete_entry", { id: pendingDeleteEntry.id });
      if (selectedId) await loadEntries(selectedId);
    } catch (err) {
      setError(describeError(err, "Could not delete that note."));
    } finally {
      setDeleting(false);
      setPendingDeleteEntry(null);
    }
  };

  const projectMeta = project
    ? [
        `Opened ${formatDate(project.created_at)}`,
        STATUS_LABELS[project.status] ?? project.status,
        `${entries.length} ${entries.length === 1 ? "entry" : "entries"}`,
        evidenceCount ? `${evidenceCount} ${evidenceCount === 1 ? "file" : "files"}` : "",
      ].filter(Boolean).join(" · ")
    : "";

  return (
    <div className="split">
      <section className="split-list" aria-label="Cases">
        <div className="split-list-head">
          <h1 className="title-l">Cases</h1>
          <button className="btn-outline" onClick={() => setShowProjectForm(true)}>Open a case</button>
        </div>
        {loadingProjects && <p className="status" role="status">Loading cases…</p>}
        {!loadingProjects && projects.length === 0 && (
          <EmptyState message="No cases yet. Open one to start taking notes." />
        )}
        <ul className="rows stagger">
          {projects.map((p) => (
            <li key={p.id}>
              <button className="row" aria-current={p.id === selectedId ? "true" : undefined} onClick={() => setSelectedId(p.id)}>
                <span className="row-copy">
                  <span className="row-name">{p.name}</span>
                  <span className="meta">{STATUS_LABELS[p.status] ?? p.status}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      </section>

      <div className="split-main">
        {error && <p className="error" role="alert">{error}</p>}

        {project && (
          <div key={project.id} className="record rise">
            <header className="notebook-head">
              <p className="meta">{projectMeta}</p>
              <h2 className="title-xl">{project.name}</h2>
              {project.description && <p className="lead">{project.description}</p>}
              {(project.target || project.methodology) && (
                <p className="meta">
                  {[project.target && `Scope: ${project.target}`, project.methodology && `Method: ${project.methodology}`]
                    .filter(Boolean)
                    .join(" · ")}
                </p>
              )}
            </header>

            <div className="case-tabs no-print" role="tablist" aria-label="Case sections">
              <button role="tab" aria-selected={tab === "notes"} onClick={() => setTab("notes")}>Notes</button>
              <button role="tab" aria-selected={tab === "evidence"} onClick={() => setTab("evidence")}>Evidence</button>
            </div>

            {tab === "evidence" ? (
              <EvidencePanel projectId={project.id} dropToken={dropToken} onCount={setEvidenceCount} />
            ) : (
              <>
              <form
                className="composer"
                onSubmit={(event) => {
                  event.preventDefault();
                  void addEntry();
                }}
              >
                <div className="composer-line">
                  <label className="sr-only" htmlFor="entry-title">New entry</label>
                  <input
                    id="entry-title"
                    className="input"
                    placeholder="What did you find?"
                    value={entryForm.title}
                    onChange={(event) => setEntryForm({ ...entryForm, title: event.target.value })}
                  />
                  <label className="inline-select">
                    Kind
                    <select value={entryForm.entry_type} onChange={(event) => setEntryForm({ ...entryForm, entry_type: event.target.value })}>
                      {KINDS.map((kind) => <option key={kind.value} value={kind.value}>{kind.label}</option>)}
                    </select>
                  </label>
                  <label className="inline-select">
                    Severity
                    <select value={entryForm.severity} onChange={(event) => setEntryForm({ ...entryForm, severity: event.target.value })}>
                      {SEVERITIES.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
                    </select>
                  </label>
                </div>
                {entryForm.title && (
                  <>
                    <label className="sr-only" htmlFor="entry-content">Details</label>
                    <textarea
                      id="entry-content"
                      className="textarea"
                      placeholder="Details, indicators, hashes. ⌘↵ saves."
                      value={entryForm.content}
                      onChange={(event) => setEntryForm({ ...entryForm, content: event.target.value })}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
                          event.preventDefault();
                          void addEntry();
                        }
                      }}
                    />
                    <div className="actions">
                      <button className="btn" type="submit" disabled={savingEntry}>{savingEntry ? "Saving…" : "Add entry"}</button>
                      <button className="btn-text" type="button" onClick={() => setEntryForm(EMPTY_ENTRY)}>Discard</button>
                    </div>
                  </>
                )}
              </form>

              {loadingEntries && <p className="status" role="status">Loading notes…</p>}
              {!loadingEntries && ordered.length === 0 && <p className="lead">No entries yet. Write the first one above.</p>}

              <ol className="entries stagger">
                {ordered.map((entry) => {
                  const when = parseStored(entry.created_at);
                  return (
                    <li key={entry.id}>
                      <span className="entry-when">
                        {when ? <>{formatShortDate(when)}<br />{formatTime(when)}</> : entry.created_at}
                      </span>
                      <div className="entry-body">
                        <h3 className="entry-title">{entry.title}</h3>
                        <EntryKind entry={entry} />
                        {entry.content && <p className="entry-text">{entry.content}</p>}
                        <div className="actions no-print">
                          <button className="btn-danger" onClick={() => setPendingDeleteEntry(entry)}>Delete</button>
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ol>

              </>
            )}

            <div className="actions no-print">
              {tab === "notes" && <button className="btn-outline" onClick={() => window.print()}>Print case</button>}
              <button className="btn-danger" onClick={() => setPendingDeleteProject(project)}>Delete case</button>
            </div>
          </div>
        )}
      </div>

      {showProjectForm && (
        <ModalOverlay onClose={() => setShowProjectForm(false)} labelledBy="case-form-title">
          <form
            className="dialog"
            onSubmit={(event) => {
              event.preventDefault();
              void createProject();
            }}
          >
            <h2 id="case-form-title">Open a case</h2>
            <div className="field">
              <label className="label" htmlFor="case-name">Name</label>
              <input id="case-name" className="input" value={projectForm.name} autoFocus
                onChange={(event) => setProjectForm({ ...projectForm, name: event.target.value })} />
            </div>
            <div className="field">
              <label className="label" htmlFor="case-description">What happened</label>
              <textarea id="case-description" className="textarea" value={projectForm.description}
                onChange={(event) => setProjectForm({ ...projectForm, description: event.target.value })} />
            </div>
            <div className="field">
              <label className="label" htmlFor="case-target">Scope</label>
              <input id="case-target" className="input" value={projectForm.target} placeholder="A mailbox, a host, 10.0.2.0/24"
                onChange={(event) => setProjectForm({ ...projectForm, target: event.target.value })} />
            </div>
            <div className="field">
              <label className="label" htmlFor="case-method">Method</label>
              <input id="case-method" className="input" value={projectForm.methodology} placeholder="PICERL, PTES"
                onChange={(event) => setProjectForm({ ...projectForm, methodology: event.target.value })} />
            </div>
            <div className="actions">
              <button className="btn" type="submit" disabled={savingProject}>{savingProject ? "Opening…" : "Open case"}</button>
              <button className="btn-text" type="button" onClick={() => setShowProjectForm(false)} disabled={savingProject}>Cancel</button>
            </div>
          </form>
        </ModalOverlay>
      )}

      {pendingDeleteProject && (
        <ConfirmDialog
          title={`Delete ${pendingDeleteProject.name}?`}
          message="The case, every entry and every evidence file in it are removed. Your original files aren’t touched. This can’t be undone."
          confirmLabel="Delete case"
          busy={deleting}
          onConfirm={() => void confirmDeleteProject()}
          onCancel={() => setPendingDeleteProject(null)}
        />
      )}

      {pendingDeleteEntry && (
        <ConfirmDialog
          title="Delete this entry?"
          message="It’s removed from the case. This can’t be undone."
          confirmLabel="Delete entry"
          busy={deleting}
          onConfirm={() => void confirmDeleteEntry()}
          onCancel={() => setPendingDeleteEntry(null)}
        />
      )}
    </div>
  );
}

export default Journal;
