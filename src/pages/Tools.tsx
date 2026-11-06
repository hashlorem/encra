import { lazy, Suspense, useState } from "react";
import { Icon, type IconName } from "../components/Icon";

// Loaded on demand: the toolbox is not on the startup path, so keeping these
// out of the initial bundle makes the lock screen and vault lighter.
const PasswordGenerator = lazy(() => import("./PasswordGenerator"));
const NmapParser = lazy(() => import("./NmapParser"));
const CommandKB = lazy(() => import("./CommandKB"));

type ToolId = "pwgen" | "nmap" | "kb";

interface ToolDefinition {
  id: ToolId;
  icon: IconName;
  tone: string;
  label: string;
  tag: string;
  description: string;
}

const TOOLS: ToolDefinition[] = [
  { id: "pwgen", icon: "wand", tone: "gold", label: "Password generator", tag: "Crypto", description: "Create cryptographically secure passwords with precise length and character controls." },
  { id: "nmap", icon: "network", tone: "violet", label: "Nmap parser", tag: "Network", description: "Turn raw Nmap XML into clear, structured hosts, services, and open-port records." },
  { id: "kb", icon: "terminal", tone: "amber", label: "Command library", tag: "Reference", description: "Keep field-tested commands, payloads, and operational notes close at hand." },
];

function Tools() {
  const [activeTool, setActiveTool] = useState<ToolId | null>(null);

  if (activeTool === "pwgen") {
    return (
      <div className="tool-detail">
        <Suspense fallback={<p className="inline-message" role="status">Loading tool…</p>}>
          <PasswordGenerator onClose={() => setActiveTool(null)} />
        </Suspense>
      </div>
    );
  }
  if (activeTool === "nmap") {
    return (
      <div className="tool-detail">
        <Suspense fallback={<p className="inline-message" role="status">Loading tool…</p>}>
          <NmapParser onClose={() => setActiveTool(null)} />
        </Suspense>
      </div>
    );
  }
  if (activeTool === "kb") {
    return (
      <div className="tool-detail">
        <Suspense fallback={<p className="inline-message" role="status">Loading tool…</p>}>
          <CommandKB onClose={() => setActiveTool(null)} />
        </Suspense>
      </div>
    );
  }

  return (
    <div className="tools-page">
      <div className="page-header">
        <div className="page-heading">
          <span className="eyebrow">Security utilities</span>
          <h1>Toolbox</h1>
          <p>Focused instruments for everyday assessment and investigation work.</p>
        </div>
      </div>
      <div className="tool-grid">
        {TOOLS.map((tool) => (
          <button
            key={tool.id}
            className={`tool-card tool-card-${tool.tone}`}
            onClick={() => setActiveTool(tool.id)}
          >
            <div className="tool-card-top">
              <span className="tool-icon"><Icon name={tool.icon} size={22} /></span>
              <span className="tool-tag">{tool.tag}</span>
            </div>
            <div className="tool-card-copy">
              <h3>{tool.label}</h3>
              <p>{tool.description}</p>
            </div>
            <span className="tool-open">Open tool <Icon name="chevron-right" size={16} /></span>
          </button>
        ))}
      </div>
      <div className="toolbox-note">
        <Icon name="shield" size={16} />
        <span>All tools process data locally. Nothing is uploaded or retained outside your workspace.</span>
      </div>
    </div>
  );
}

export default Tools;
