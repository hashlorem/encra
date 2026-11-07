import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ModalOverlay } from "./ModalOverlay";
import { describeError } from "../lib/errors";
import type { AgentRequest, CredentialSummary } from "../lib/types";

/** Quote an argument the way a shell would need it, for display only. */
function shellWord(arg: string): string {
  return /^[\w@%+=:,./-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`;
}

interface AgentRequestDialogProps {
  request: AgentRequest;
  onDone: () => void;
}

/**
 * One request from `encra run`. Deny is focused first, and closing the dialog
 * denies, so nothing is approved by accident.
 */
export function AgentRequestDialog({ request, onDone }: AgentRequestDialogProps) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [logins, setLogins] = useState<CredentialSummary[]>([]);
  const [choices, setChoices] = useState<Record<string, string>>({});
  const [remember, setRemember] = useState(true);

  const unmatched = request.matches.filter((m) => m.status !== "found");

  // The picker only appears when a name matched nothing, or more than one.
  useEffect(() => {
    if (unmatched.length === 0) return;
    invoke<CredentialSummary[]>("list_credentials").then(setLogins).catch(() => setLogins([]));
  }, [unmatched.length]);

  const ready = unmatched.every((m) => choices[m.reference]);

  const decide = async (approve: boolean) => {
    if (busy) return;
    setBusy(true);
    try {
      await invoke("agent_decide", { id: request.id, approve, choices, remember });
      onDone();
    } catch (err) {
      setError(describeError(err, "That request couldn’t be answered."));
      setBusy(false);
    }
  };

  const command = request.argv.map(shellWord).join(" ");
  const resolvedDiffers = request.argv[0] !== request.executable;

  return (
    <ModalOverlay onClose={() => void decide(false)} labelledBy="agent-title">
      <div className="dialog agent-dialog">
        <h2 id="agent-title">Agent request</h2>
        <p className="lead">
          A program calling itself <strong>{request.agent}</strong> wants:
        </p>
        <ul className="agent-list">
          {request.matches.map((match) => (
            <li key={match.reference}>
              <span className="mono">{match.reference.replace(/^encra:\/\//, "")}</span>
              {match.status === "found" ? (
                <span className="meta">from {match.login}</span>
              ) : (
                <label className="inline-select">
                  <span className={match.status === "missing" ? "error" : "meta"}>
                    {match.status === "missing" ? "No login by that name." : "More than one login has that name."}
                  </span>
                  <select
                    value={choices[match.reference] ?? ""}
                    onChange={(event) => setChoices({ ...choices, [match.reference]: event.target.value })}
                    aria-label={`Login for ${match.reference}`}
                  >
                    <option value="">Choose a login</option>
                    {logins.map((login) => (
                      <option key={login.id} value={login.id}>
                        {login.service}{login.username ? ` (${login.username})` : ""}
                      </option>
                    ))}
                  </select>
                </label>
              )}
            </li>
          ))}
        </ul>
        {unmatched.length > 0 && (
          <label className="checkbox">
            <input type="checkbox" checked={remember} onChange={(event) => setRemember(event.target.checked)} />
            Remember these matches
          </label>
        )}
        <div className="field">
          <span className="label">To run</span>
          <code className="command">{command}</code>
          {resolvedDiffers && <span className="meta mono">{request.executable}</span>}
        </div>
        <div className="field">
          <span className="label">In</span>
          <code className="command">{request.cwd}</code>
        </div>
        {request.chain.length > 0 && (
          <p className="meta">Started by {request.chain.join(" ← ")}</p>
        )}
        {request.inline_script && (
          <p className="error" role="alert">
            This runs code written on the command line. It can do anything with these values, including print them.
          </p>
        )}
        {error && <p className="error" role="alert">{error}</p>}
        <div className="actions">
          <button className="btn-outline" onClick={() => void decide(false)} disabled={busy} autoFocus>
            Deny
          </button>
          <button className="btn" onClick={() => void decide(true)} disabled={busy || !ready}>
            Approve once
          </button>
        </div>
        <p className="meta">
          Encra checked the caller is its own encra binary. It can’t tell which agent is behind it.
        </p>
      </div>
    </ModalOverlay>
  );
}
