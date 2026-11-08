import { Fragment, useEffect, useRef, useState, type KeyboardEvent } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ModalOverlay } from "./ModalOverlay";
import { describeError } from "../lib/errors";
import type { PaletteHit } from "../lib/types";

const GROUP_LABELS: Record<PaletteHit["group"], string> = {
  login: "Logins",
  case: "Cases",
  command: "Commands",
  go: "Go to",
};

const FOOTER = "Passwords and codes are copied by Encra and cleared after 30 seconds.";

interface CommandPaletteProps {
  onClose: () => void;
  onOpen: (hit: PaletteHit) => void;
}

/** The title with the matched characters underlined, joined into runs. */
function Marked({ text, positions }: { text: string; positions: number[] }) {
  if (positions.length === 0) return <>{text}</>;
  const marked = new Set(positions);
  // Rust counts characters, not UTF-16 units, so split the same way.
  const runs: { text: string; on: boolean }[] = [];
  Array.from(text).forEach((char, index) => {
    const on = marked.has(index);
    const last = runs[runs.length - 1];
    if (last && last.on === on) last.text += char;
    else runs.push({ text: char, on });
  });
  return <>{runs.map((run, index) => <span key={index} className={run.on ? "palette-match" : undefined}>{run.text}</span>)}</>;
}

function Keys({ hit }: { hit: PaletteHit }) {
  return (
    <span className="palette-keys" aria-hidden="true">
      <span>↵ open</span>
      {hit.group === "login" && <span>⌘C password</span>}
      {hit.group === "login" && hit.has_totp && <span>⌘⇧C code</span>}
      {hit.group === "command" && <span>⌘C copy</span>}
    </span>
  );
}

/**
 * ⌘K: one search over logins, cases, commands and Encra's own pages and
 * actions, ranked in Rust. Results are names and ids; copying a password or
 * code goes through the same per-field copy as the Vault page.
 */
export function CommandPalette({ onClose, onOpen }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<PaletteHit[]>([]);
  const [active, setActive] = useState(0);
  const [status, setStatus] = useState("");
  const request = useRef(0);
  const statusTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // A slow answer for an older query is dropped.
  useEffect(() => {
    const id = ++request.current;
    invoke<PaletteHit[]>("palette_search", { query })
      .then((results) => {
        if (id !== request.current) return;
        setHits(results);
        setActive(0);
      })
      .catch((error) => {
        if (id === request.current) say(describeError(error, "Search failed."));
      });
  }, [query]);

  useEffect(() => () => {
    if (statusTimer.current) clearTimeout(statusTimer.current);
  }, []);

  useEffect(() => {
    document.getElementById(`palette-option-${active}`)?.scrollIntoView({ block: "nearest" });
  }, [active, hits]);

  function say(message: string) {
    setStatus(message);
    if (statusTimer.current) clearTimeout(statusTimer.current);
    statusTimer.current = setTimeout(() => setStatus(""), 4000);
  }

  const copy = async (hit: PaletteHit, field: "password" | "totp") => {
    try {
      await invoke("copy_credential_field", { id: hit.id, field });
      say(field === "totp" ? `Copied the code for ${hit.title}.` : `Copied the password for ${hit.title}.`);
    } catch (error) {
      say(describeError(error, "Couldn’t copy that."));
    }
  };

  const copyCommand = async (hit: PaletteHit) => {
    try {
      await invoke("copy_text", { text: hit.subtitle });
      say("Copied the command.");
    } catch (error) {
      say(describeError(error, "Couldn’t copy that."));
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((index) => Math.min(hits.length - 1, index + 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((index) => Math.max(0, index - 1));
    } else if (event.key === "Enter") {
      event.preventDefault();
      if (hits[active]) onOpen(hits[active]);
    } else if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "c") {
      // Copying text selected in the field still works as usual.
      const field = event.currentTarget;
      if (field.selectionStart !== field.selectionEnd) return;
      const hit = hits[active];
      if (hit?.group === "login") {
        event.preventDefault();
        if (event.shiftKey && !hit.has_totp) say(`${hit.title} has no 2FA code.`);
        else void copy(hit, event.shiftKey ? "totp" : "password");
      } else if (hit?.group === "command" && !event.shiftKey) {
        event.preventDefault();
        void copyCommand(hit);
      }
    }
  };

  const activeHit = hits[active];

  return (
    <ModalOverlay onClose={onClose} labelledBy="palette-label" className="is-top">
      <div className="palette">
        <div className="palette-search">
          <label id="palette-label" className="sr-only" htmlFor="palette-input">Go to anything</label>
          <input
            id="palette-input"
            className="input"
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
            aria-activedescendant={activeHit ? `palette-option-${active}` : undefined}
            aria-autocomplete="list"
            autoComplete="off"
            spellCheck={false}
            autoFocus
            placeholder="Logins, cases, commands, pages"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={onKeyDown}
          />
          <kbd className="meta">esc</kbd>
        </div>

        <div id="palette-list" className="palette-results" role="listbox" aria-label="Results">
          {hits.length === 0 && <p className="palette-empty meta">Nothing matches “{query.trim()}”.</p>}
          {hits.map((hit, index) => (
            <Fragment key={`${hit.group}:${hit.id}`}>
              {(index === 0 || hits[index - 1].group !== hit.group) && (
                <div className="palette-group" role="presentation">{GROUP_LABELS[hit.group]}</div>
              )}
              <div
                id={`palette-option-${index}`}
                role="option"
                aria-selected={index === active}
                className={`palette-option${hit.group === "go" ? " is-short" : ""}`}
                onMouseMove={() => setActive(index)}
                onClick={() => onOpen(hit)}
              >
                <span className="palette-copy">
                  <span className="palette-title"><Marked text={hit.title} positions={hit.matched} /></span>
                  {hit.subtitle && <span className={`palette-sub${hit.group === "command" ? " mono" : ""}`}>{hit.subtitle}</span>}
                </span>
                {index === active && <Keys hit={hit} />}
              </div>
            </Fragment>
          ))}
        </div>

        <div className="palette-foot">
          <span key={status || "idle"} className="fade" role="status">{status || FOOTER}</span>
          <kbd className="mono">↑↓ move</kbd>
        </div>
      </div>
    </ModalOverlay>
  );
}
