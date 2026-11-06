import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";
import { Icon } from "../components/Icon";
import { describeError } from "../lib/errors";
import type { NmapScan, Project } from "../lib/types";

/** Basename that works for both POSIX and Windows paths. */
function baseName(path: string): string {
  return path.split(/[\\/]/).pop() || "scan.xml";
}

interface ProjectOption {
  id: string;
  name: string;
}

function NmapParser({ onClose }: { onClose?: () => void }) {
  const [scan, setScan] = useState<NmapScan | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState("");
  const [projects, setProjects] = useState<ProjectOption[]>([]);
  const [saveProject, setSaveProject] = useState("");
  const [saveMsg, setSaveMsg] = useState("");
  const [saving, setSaving] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const list = await invoke<Project[]>("get_projects");
        if (!cancelled) setProjects(list.map((project) => ({ id: project.id, name: project.name })));
      } catch (err) {
        if (!cancelled) console.error("Unable to list projects", err);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const parseContent = async (content: string, name: string) => {
    setLoading(true);
    try {
      const result = await invoke<NmapScan>("parse_nmap", { xmlContent: content });
      setScan(result);
      setFileName(name);
      setSaveMsg("");
      setError("");
    } catch (err) {
      setError(describeError(err, "Could not parse that scan file."));
    } finally {
      setLoading(false);
    }
  };

  const handleFile = async () => {
    if (loading) return;
    setError("");
    try {
      const filePath = await open({
        filters: [{ name: "Nmap XML", extensions: ["xml"] }],
        multiple: false,
      });
      if (!filePath) return;
      const content = await readTextFile(filePath as string);
      await parseContent(content, baseName(filePath as string));
    } catch (err) {
      setError(describeError(err, "Could not read that file."));
      setLoading(false);
    }
  };

  const handleDrop = async (event: React.DragEvent) => {
    event.preventDefault();
    setDragOver(false);
    if (loading) return;

    const file = event.dataTransfer.files[0];
    if (!file) return;
    if (!file.name.toLowerCase().endsWith(".xml")) {
      // Previously a non-XML drop was silently ignored.
      setError("Only Nmap XML files can be parsed.");
      return;
    }

    setError("");
    try {
      // Reading the whole file into memory is bounded on the backend by the
      // scan-size cap, which rejects anything oversized before parsing.
      const text = await file.text();
      await parseContent(text, file.name);
    } catch (err) {
      setError(describeError(err, "Could not read that file."));
      setLoading(false);
    }
  };

  const saveToJournal = async () => {
    if (!scan || !saveProject || saving) return;
    setSaving(true);
    setSaveMsg("Saving…");
    try {
      const inputs = scan.hosts.map((host) => {
        const openPorts = host.ports.filter((port) => port.state === "open");
        const portList = openPorts
          .map((port) => `${port.port}/${port.protocol} (${port.service}${port.version ? " " + port.version : ""})`)
          .join(", ");
        const content = openPorts.length > 0
          ? `Host: ${host.ip}${host.hostname ? " (" + host.hostname + ")" : ""}${host.os ? "\nOS: " + host.os : ""}\n\nOpen ports: ${portList}`
          : `Host: ${host.ip} — no open ports detected`;
        return {
          project_id: saveProject,
          title: `${host.ip}${host.hostname ? " (" + host.hostname + ")" : ""}`,
          content,
          entry_type: "recon",
          severity: "info",
        };
      });

      // One transactional call: either every host is recorded or none is.
      const saved = await invoke<number>("add_entries", { inputs });
      setSaveMsg(`Saved ${saved} host${saved === 1 ? "" : "s"} to the journal.`);
    } catch (err) {
      setSaveMsg(describeError(err, "Could not save the scan to the journal."));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="nmap-page"
      onDragOver={(event) => {
        event.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(event) => void handleDrop(event)}
    >
      {dragOver && (
        <div className="drop-overlay">
          <div className="drop-box"><Icon name="upload" size={28} />Drop XML file here</div>
        </div>
      )}

      <div className="page-header">
        <div className="page-heading-with-back">
          {onClose && (
            <button className="btn-icon" onClick={onClose} aria-label="Back to toolbox">
              <Icon name="arrow-left" size={18} />
            </button>
          )}
          <div className="page-heading">
            <span className="eyebrow">Network intelligence</span>
            <h1>Nmap parser</h1>
            <p>Turn XML scan output into a readable service inventory.</p>
          </div>
        </div>
      </div>

      {!scan && (
        <div className="nmap-dropzone">
          {/* A real button, not a span styled as one, so it is focusable and
              announced as a control. */}
          <span className="nmap-drop-icon">
            {loading ? <span className="button-spinner" /> : <Icon name="upload" size={24} />}
          </span>
          <strong>{loading ? "Parsing scan…" : "Drop an Nmap XML file here"}</strong>
          <span>or choose a file from your device</span>
          <button className="btn-secondary" onClick={() => void handleFile()} disabled={loading}>
            <Icon name="folder" size={15} />Browse files
          </button>
          <small>XML files only · processed locally</small>
        </div>
      )}

      {error && (
        <p className="lock-error page-error" role="alert"><Icon name="x" size={13} />{error}</p>
      )}

      {scan && (
        <div className="nmap-results">
          <div className="scan-summary">
            <span className="scan-file-icon"><Icon name="file" size={18} /></span>
            <div className="scan-file"><strong>{fileName}</strong><span>Parsed successfully</span></div>
            <div className="scan-metric"><strong>{scan.total_hosts}</strong><span>Hosts</span></div>
            <div className="scan-metric"><strong>{scan.total_open_ports}</strong><span>Open ports</span></div>
            {projects.length > 0 && (
              <div className="scan-save">
                <label className="sr-only" htmlFor="scan-project">Save scan to project</label>
                <select
                  id="scan-project"
                  value={saveProject}
                  onChange={(event) => setSaveProject(event.target.value)}
                  disabled={saving}
                >
                  <option value="">Save to project…</option>
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>{project.name}</option>
                  ))}
                </select>
                <button className="btn-soft" onClick={() => void saveToJournal()} disabled={!saveProject || saving}>
                  <Icon name="download" size={14} />{saving ? "Saving…" : "Save"}
                </button>
              </div>
            )}
            <button className="btn-icon" onClick={() => void handleFile()} aria-label="Open another file" disabled={loading}>
              <Icon name="refresh" size={16} />
            </button>
            {saveMsg && <span className="scan-message" role="status">{saveMsg}</span>}
          </div>

          {scan.hosts.map((host) => (
            <div key={`${host.ip}-${host.hostname ?? ""}`} className="nmap-host">
              <div className="host-header">
                <span className="host-icon"><Icon name="network" size={16} /></span>
                <strong>{host.ip}</strong>
                {host.hostname && <span className="host-hostname">{host.hostname}</span>}
                {host.os && <span className="host-os">{host.os}</span>}
                <span className="host-port-count">
                  {host.ports.filter((port) => port.state === "open").length} open
                </span>
              </div>

              {host.ports.length > 0 && (
                <div className="port-table">
                  <div className="port-table-header">
                    <span>Port</span><span>Proto</span><span>State</span><span>Service</span><span>Version</span>
                  </div>
                  {host.ports.map((port) => (
                    <div key={`${port.port}-${port.protocol}`} className={`port-row port-${port.state}`}>
                      <span>{port.port}</span>
                      <span>{port.protocol}</span>
                      <span className={`port-state-${port.state}`}>{port.state}</span>
                      <span>{port.service}</span>
                      <span className="text-muted">{port.version || "-"}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default NmapParser;
