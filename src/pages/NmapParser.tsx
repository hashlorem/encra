import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { readTextFile } from "@tauri-apps/plugin-fs";
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

function NmapParser({ onClose }: { onClose: () => void }) {
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
    setSaveMsg("");
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
      setSaveMsg(`Filed ${saved} host${saved === 1 ? "" : "s"} into the case.`);
    } catch (err) {
      setSaveMsg(describeError(err, "Could not file the hosts. Nothing was saved."));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="page"
      onDragOver={(event) => {
        event.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(event) => void handleDrop(event)}
    >
      <button className="btn-text back" onClick={onClose}>← Toolbox</button>
      <header className="page-head">
        <div>
          <h1 className="title-l">Nmap parser</h1>
          <p className="lead">Reads Nmap’s XML output (<span className="mono">-oX</span>) on this machine.</p>
        </div>
        {scan && <button className="btn-outline" onClick={() => void handleFile()} disabled={loading}>Open another file</button>}
      </header>

      {!scan && (
        <div className={`dropzone${dragOver ? " is-over" : ""}`}>
          <p className="lead">{loading ? "Reading the scan…" : "Drop an Nmap XML file here, or choose one."}</p>
          <button className="btn-outline" onClick={() => void handleFile()} disabled={loading}>Choose a file</button>
        </div>
      )}

      {error && <p className="error" role="alert">{error}</p>}

      {scan && (
        <>
          <p className="summary">
            <span className="mono">{fileName}</span>: {scan.total_hosts} {scan.total_hosts === 1 ? "host" : "hosts"} with{" "}
            {scan.total_open_ports} open {scan.total_open_ports === 1 ? "port" : "ports"} between them.
          </p>

          {projects.length > 0 && (
            <div className="actions">
              <label className="inline-select">
                File the hosts into
                <select value={saveProject} onChange={(event) => setSaveProject(event.target.value)} disabled={saving}>
                  <option value="">choose a case</option>
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>{project.name}</option>
                  ))}
                </select>
              </label>
              <button className="btn-outline" onClick={() => void saveToJournal()} disabled={!saveProject || saving}>
                {saving ? "Filing…" : "File hosts"}
              </button>
              {saveMsg && <span className="status" role="status">{saveMsg}</span>}
            </div>
          )}

          <div>
            {scan.hosts.map((host) => {
              const open = host.ports.filter((port) => port.state === "open").length;
              return (
                <section key={`${host.ip}-${host.hostname ?? ""}`} className="host">
                  <div className="host-head">
                    <h2 className="section-title mono">{host.ip}</h2>
                    {host.hostname && <span className="meta">{host.hostname}</span>}
                    {host.os && <span className="meta">{host.os}</span>}
                    <span className="meta">{open} open</span>
                  </div>
                  {host.ports.length > 0 && (
                    <div className="table-scroll">
                      <table className="table">
                        <thead>
                          <tr><th>Port</th><th>State</th><th>Service</th><th>Version</th></tr>
                        </thead>
                        <tbody>
                          {host.ports.map((port) => (
                            <tr key={`${port.port}-${port.protocol}`}>
                              <td className="mono">{port.port}/{port.protocol}</td>
                              <td>{port.state}</td>
                              <td>{port.service}</td>
                              <td>{port.version || "–"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </section>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

export default NmapParser;
