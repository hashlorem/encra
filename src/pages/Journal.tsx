import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Icon } from "../components/Icon";
import { ModalOverlay } from "../components/ModalOverlay";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { EmptyState } from "../components/EmptyState";
import { describeError } from "../lib/errors";
import type { EntryInput, JournalEntry, Project, ProjectInput } from "../lib/types";

const ENTRY_TYPES = ["recon", "finding", "exploitation", "post_exploit", "note", "remediation"] as const;
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

const EMPTY_PROJECT: ProjectInput = { name: "", description: "", target: "", methodology: "" };
const EMPTY_ENTRY: Omit<EntryInput, "project_id"> = {
  title: "",
  content: "",
  entry_type: "note",
  severity: "info",
};

function Journal() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<string | null>(null);
  const [entries, setEntries] = useState<JournalEntry[]>([]);
  const [loadingProjects, setLoadingProjects] = useState(true);
  const [loadingEntries, setLoadingEntries] = useState(false);
  const [error, setError] = useState("");

  const [showProjectForm, setShowProjectForm] = useState(false);
  const [showEntryForm, setShowEntryForm] = useState(false);
  const [projectForm, setProjectForm] = useState<ProjectInput>(EMPTY_PROJECT);
  const [entryForm, setEntryForm] = useState(EMPTY_ENTRY);
  const [savingProject, setSavingProject] = useState(false);
  const [savingEntry, setSavingEntry] = useState(false);

  const [pendingDeleteProject, setPendingDeleteProject] = useState<Project | null>(null);
  const [pendingDeleteEntry, setPendingDeleteEntry] = useState<JournalEntry | null>(null);
  const [deleting, setDeleting] = useState(false);

  // Guards against a slow response for a previously selected project landing
  // after the user has moved on and overwriting the newer list.
  const entryRequestRef = useRef(0);

  const loadProjects = useCallback(async () => {
    try {
      const list = await invoke<Project[]>("get_projects");
      setProjects(list);
      setError("");
    } catch (err) {
      setError(describeError(err, "Could not load your engagements."));
    } finally {
      setLoadingProjects(false);
    }
  }, []);

  const loadEntries = useCallback(async (projectId: string) => {
    const requestId = ++entryRequestRef.current;
    setLoadingEntries(true);
    try {
      const list = await invoke<JournalEntry[]>("get_entries", { projectId });
      if (requestId !== entryRequestRef.current) return;
      setEntries(list);
    } catch (err) {
      if (requestId !== entryRequestRef.current) return;
      setEntries([]);
      setError(describeError(err, "Could not load the entries for that engagement."));
    } finally {
      if (requestId === entryRequestRef.current) setLoadingEntries(false);
    }
  }, []);

  useEffect(() => {
    void loadProjects();
  }, [loadProjects]);

  useEffect(() => {
    if (selectedProject) void loadEntries(selectedProject);
    else setEntries([]);
  }, [selectedProject, loadEntries]);

  const createProject = async () => {
    if (savingProject) return;
    if (!projectForm.name.trim()) {
      setError("Enter a project name.");
      return;
    }
    setSavingProject(true);
    try {
      await invoke("create_project", { input: projectForm });
      setProjectForm(EMPTY_PROJECT);
      setShowProjectForm(false);
      await loadProjects();
    } catch (err) {
      setError(describeError(err, "Could not create that project."));
    } finally {
      setSavingProject(false);
    }
  };

  const confirmDeleteProject = async () => {
    if (!pendingDeleteProject || deleting) return;
    setDeleting(true);
    try {
      await invoke("delete_project", { id: pendingDeleteProject.id });
      if (selectedProject === pendingDeleteProject.id) setSelectedProject(null);
      await loadProjects();
    } catch (err) {
      setError(describeError(err, "Could not delete that project."));
    } finally {
      setDeleting(false);
      setPendingDeleteProject(null);
    }
  };

  const addEntry = async () => {
    if (!selectedProject || savingEntry) return;
    if (!entryForm.title.trim()) {
      setError("Enter a title for the entry.");
      return;
    }
    setSavingEntry(true);
    try {
      await invoke("add_entry", { input: { ...entryForm, project_id: selectedProject } });
      setEntryForm(EMPTY_ENTRY);
      setShowEntryForm(false);
      await loadEntries(selectedProject);
      await loadProjects();
    } catch (err) {
      setError(describeError(err, "Could not save that entry."));
    } finally {
      setSavingEntry(false);
    }
  };

  const confirmDeleteEntry = async () => {
    if (!pendingDeleteEntry || deleting) return;
    setDeleting(true);
    try {
      await invoke("delete_entry", { id: pendingDeleteEntry.id });
      if (selectedProject) await loadEntries(selectedProject);
    } catch (err) {
      setError(describeError(err, "Could not delete that entry."));
    } finally {
      setDeleting(false);
      setPendingDeleteEntry(null);
    }
  };

  const activeProject = useMemo(
    () => projects.find((project) => project.id === selectedProject) ?? null,
    [projects, selectedProject],
  );

  if (selectedProject) {
    return (
      <div className="journal-page">
        <div className="page-header">
          <div className="page-heading-with-back">
            <button className="btn-icon" onClick={() => setSelectedProject(null)} aria-label="Back to engagements">
              <Icon name="arrow-left" size={18} />
            </button>
            <div className="page-heading">
              <span className="eyebrow">Active engagement</span>
              <h1>{activeProject?.name}</h1>
              <p>{activeProject?.description || "Assessment notes and findings."}</p>
            </div>
          </div>
          <div className="header-actions">
            <button className="btn-secondary" onClick={() => window.print()}>
              <Icon name="download" size={15} />Export PDF
            </button>
            <button className="btn-primary" onClick={() => setShowEntryForm(true)}>
              <Icon name="plus" size={16} />New entry
            </button>
          </div>
        </div>

        {activeProject && (
          <div className="project-meta">
            <span><Icon name="network" size={14} />Target <strong>{activeProject.target || "N/A"}</strong></span>
            <span><Icon name="clipboard" size={14} />Methodology <strong>{activeProject.methodology || "N/A"}</strong></span>
            <span className={`status-badge status-${activeProject.status}`}>{activeProject.status}</span>
          </div>
        )}

        {error && <p className="lock-error" role="alert"><Icon name="x" size={13} />{error}</p>}

        {showEntryForm && (
          <ModalOverlay onClose={() => setShowEntryForm(false)} labelledBy="entry-form-title">
            <div className="modal">
              <div className="modal-heading">
                <span className="modal-icon"><Icon name="file" size={18} /></span>
                <div>
                  <h4 id="entry-form-title">New journal entry</h4>
                  <p>Document an observation, action, or finding.</p>
                </div>
              </div>
              <label className="field-label" htmlFor="entry-title">Title</label>
              <input
                id="entry-title"
                value={entryForm.title}
                onChange={(event) => setEntryForm({ ...entryForm, title: event.target.value })}
                autoFocus
              />
              <label className="field-label" htmlFor="entry-content">Content</label>
              <textarea
                id="entry-content"
                value={entryForm.content}
                onChange={(event) => setEntryForm({ ...entryForm, content: event.target.value })}
                rows={6}
              />
              <div className="form-row">
                <div>
                  <label className="field-label" htmlFor="entry-type">Type</label>
                  <select
                    id="entry-type"
                    value={entryForm.entry_type}
                    onChange={(event) => setEntryForm({ ...entryForm, entry_type: event.target.value })}
                  >
                    {ENTRY_TYPES.map((type) => (
                      <option key={type} value={type}>{type.replace("_", " ")}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="field-label" htmlFor="entry-severity">Severity</label>
                  <select
                    id="entry-severity"
                    value={entryForm.severity}
                    onChange={(event) => setEntryForm({ ...entryForm, severity: event.target.value })}
                  >
                    {SEVERITIES.map((severity) => (
                      <option key={severity} value={severity}>{severity}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="modal-actions">
                <button className="btn-secondary" onClick={() => setShowEntryForm(false)} disabled={savingEntry}>Cancel</button>
                <button className="btn-primary" onClick={() => void addEntry()} disabled={savingEntry}>
                  <Icon name="check" size={15} />{savingEntry ? "Saving…" : "Save entry"}
                </button>
              </div>
            </div>
          </ModalOverlay>
        )}

        {pendingDeleteEntry && (
          <ConfirmDialog
            title="Delete this entry?"
            message="The entry will be removed from this engagement. This cannot be undone."
            confirmLabel="Delete entry"
            busy={deleting}
            onConfirm={() => void confirmDeleteEntry()}
            onCancel={() => setPendingDeleteEntry(null)}
          />
        )}

        <div className="entry-list">
          {loadingEntries && <p className="inline-message" role="status">Loading entries…</p>}
          {!loadingEntries && entries.length === 0 && (
            <EmptyState prompt="$ cat journal/*.md" output="no entries recorded" />
          )}
          {entries.map((entry) => (
            <div key={entry.id} className="entry-card">
              <div className="entry-header">
                <span className={`entry-type-badge severity-${entry.severity}`}>
                  {entry.entry_type.replace("_", " ")} · {entry.severity}
                </span>
                <span className="entry-date">{entry.created_at}</span>
              </div>
              <h4>{entry.title}</h4>
              <pre className="entry-content">{entry.content}</pre>
              <button className="btn-soft btn-danger" onClick={() => setPendingDeleteEntry(entry)}>
                <Icon name="trash" size={14} />Delete
              </button>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="journal-page">
      <div className="page-header">
        <div className="page-heading">
          <span className="eyebrow">Engagement memory</span>
          <h1>Field journal</h1>
          <p>Keep targets, methodology, evidence, and findings organized by engagement.</p>
        </div>
        <button className="btn-primary" onClick={() => setShowProjectForm(true)}>
          <Icon name="plus" size={16} />New project
        </button>
      </div>

      {error && <p className="lock-error" role="alert"><Icon name="x" size={13} />{error}</p>}

      {showProjectForm && (
        <ModalOverlay onClose={() => setShowProjectForm(false)} labelledBy="project-form-title">
          <div className="modal">
            <div className="modal-heading">
              <span className="modal-icon"><Icon name="folder" size={18} /></span>
              <div>
                <h4 id="project-form-title">New project</h4>
                <p>Create a workspace for an engagement.</p>
              </div>
            </div>
            <label className="field-label" htmlFor="project-name">Project name</label>
            <input
              id="project-name"
              value={projectForm.name}
              onChange={(event) => setProjectForm({ ...projectForm, name: event.target.value })}
              autoFocus
            />
            <label className="field-label" htmlFor="project-target">Target</label>
            <input
              id="project-target"
              value={projectForm.target}
              onChange={(event) => setProjectForm({ ...projectForm, target: event.target.value })}
              placeholder="192.168.1.0/24"
            />
            <label className="field-label" htmlFor="project-methodology">Methodology</label>
            <input
              id="project-methodology"
              value={projectForm.methodology}
              onChange={(event) => setProjectForm({ ...projectForm, methodology: event.target.value })}
              placeholder="OSSTMM, PTES"
            />
            <label className="field-label" htmlFor="project-description">Description</label>
            <textarea
              id="project-description"
              value={projectForm.description}
              onChange={(event) => setProjectForm({ ...projectForm, description: event.target.value })}
            />
            <div className="modal-actions">
              <button className="btn-secondary" onClick={() => setShowProjectForm(false)} disabled={savingProject}>Cancel</button>
              <button className="btn-primary" onClick={() => void createProject()} disabled={savingProject}>
                <Icon name="check" size={15} />{savingProject ? "Creating…" : "Create project"}
              </button>
            </div>
          </div>
        </ModalOverlay>
      )}

      {pendingDeleteProject && (
        <ConfirmDialog
          title={`Delete ${pendingDeleteProject.name}?`}
          message="The project and every journal entry inside it will be removed. This cannot be undone."
          confirmLabel="Delete project"
          busy={deleting}
          onConfirm={() => void confirmDeleteProject()}
          onCancel={() => setPendingDeleteProject(null)}
        />
      )}

      <div className="project-grid">
        {loadingProjects && <p className="inline-message" role="status">Loading engagements…</p>}
        {!loadingProjects && projects.length === 0 && (
          <EmptyState prompt="$ ls ~/engagements/" output="no projects on record" />
        )}
        {projects.map((project) => (
          // A real button for the primary action instead of a button wrapping
          // another button, which is invalid and broke keyboard navigation.
          <div key={project.id} className="project-card">
            <div className="project-card-header">
              <span className="project-icon"><Icon name="folder" size={18} /></span>
              <span className={`status-badge status-${project.status}`}>{project.status}</span>
            </div>
            <button className="project-open" onClick={() => setSelectedProject(project.id)}>
              <span className="project-name">{project.name}</span>
            </button>
            <p className="project-target"><Icon name="network" size={13} />{project.target || "Target not set"}</p>
            <p className="project-desc">{project.description}</p>
            <div className="project-card-actions">
              <span className="project-date">{project.updated_at}</span>
              <button
                className="btn-icon btn-icon-sm btn-danger"
                onClick={() => setPendingDeleteProject(project)}
                aria-label={`Delete ${project.name}`}
              >
                <Icon name="trash" size={14} />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default Journal;
