import { lazy, Suspense, useState } from "react";
import { useRequest, type Requested, type ToolId } from "../lib/navigation";

// Loaded on demand: the toolbox is not on the startup path.
const PasswordGenerator = lazy(() => import("./PasswordGenerator"));
const NmapParser = lazy(() => import("./NmapParser"));
const CommandKB = lazy(() => import("./CommandKB"));

const TOOLS: { id: ToolId; label: string; description: string }[] = [
  { id: "pwgen", label: "Password generator", description: "Random passwords from your machine’s secure random source, with the length and characters you choose." },
  { id: "nmap", label: "Nmap parser", description: "Open an Nmap XML file and read it as hosts and open ports, then file the hosts into a case." },
  { id: "kb", label: "Command library", description: "Commands you trust, with notes on when to use them." },
];

function Tools({ requested }: { requested?: Requested | null }) {
  const [active, setActive] = useState<ToolId | null>(null);
  // A command picked in the palette opens the library filtered to it.
  const [search, setSearch] = useState("");
  const close = () => setActive(null);

  useRequest(requested, (request) => {
    if (request.kind !== "tool") return;
    setSearch(request.search ?? "");
    setActive(request.tool);
  });

  if (active) {
    return (
      <Suspense fallback={<div className="page"><p className="status" role="status">Opening…</p></div>}>
        {active === "pwgen" && <PasswordGenerator onClose={close} />}
        {active === "nmap" && <NmapParser onClose={close} />}
        {active === "kb" && <CommandKB key={search} onClose={close} initialSearch={search} />}
      </Suspense>
    );
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1 className="title-l">Toolbox</h1>
          <p className="lead">Everything here runs on this machine. Nothing is uploaded.</p>
        </div>
      </header>
      <ul className="tool-list stagger">
        {TOOLS.map((tool) => (
          <li key={tool.id}>
            <button className="tool-row" onClick={() => setActive(tool.id)}>
              <span className="tool-name">{tool.label}</span>
              <span className="lead">{tool.description}</span>
              <span className="btn-text" aria-hidden="true">Open</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default Tools;
