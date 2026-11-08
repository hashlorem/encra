import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { describeError } from "../lib/errors";
import { useClipboard } from "../lib/useClipboard";
import type { Indicator, IndicatorKind } from "../lib/types";

const GROUPS: { title: string; kinds: IndicatorKind[] }[] = [
  { title: "Domains", kinds: ["domain"] },
  { title: "URLs", kinds: ["url"] },
  { title: "IP addresses", kinds: ["ipv4", "ipv6"] },
  { title: "Email addresses", kinds: ["email"] },
  { title: "File hashes", kinds: ["sha256", "sha1", "md5"] },
  { title: "Vulnerabilities", kinds: ["cve"] },
];

const HASHES: Partial<Record<IndicatorKind, string>> = { sha256: "SHA-256", sha1: "SHA-1", md5: "MD5" };

/** Where it came from, and anything worth knowing about it. */
function noteFor(indicator: Indicator): string {
  const parts: string[] = [];
  const hash = HASHES[indicator.kind];
  if (hash) parts.push(hash);
  if (indicator.note === "possible domain") {
    const tld = indicator.value.split(".").pop();
    parts.push(`possible domain: .${tld} is also a file type`);
  } else if (indicator.note) {
    parts.push(indicator.note);
  }
  const { sources } = indicator;
  parts.push(sources.length > 2 ? `${sources.slice(0, 2).join(", ")} and ${sources.length - 2} more` : sources.join(", "));
  return parts.filter(Boolean).join(" · ");
}

const count = (n: number, one: string, many: string) => `${n.toLocaleString()} ${n === 1 ? one : many}`;

interface CaseIndicatorsProps {
  projectId: string;
  /** The case has a description, which is searched too. */
  described: boolean;
  entries: number;
  files: number;
}

/**
 * Domains, URLs, IPs, emails, hashes and CVEs found in a case's notes and
 * evidence, refanged and checked in Rust. Shown defanged by default so a
 * pasted list can't turn into live links.
 */
export function CaseIndicators({ projectId, described, entries, files }: CaseIndicatorsProps) {
  const [indicators, setIndicators] = useState<Indicator[] | null>(null);
  const [defanged, setDefanged] = useState(true);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const { copyVia, copiedId } = useClipboard();

  useEffect(() => {
    let current = true;
    setIndicators(null);
    invoke<Indicator[]>("case_indicators", { projectId })
      .then((list) => current && setIndicators(list))
      .catch((err) => current && setError(describeError(err, "Couldn’t read the indicators for this case.")));
    return () => {
      current = false;
    };
  }, [projectId]);

  const shown = (indicator: Indicator) => (defanged ? indicator.defanged : indicator.value);

  /** One indicator by its value, or all of them when `value` is null. */
  const copy = async (value: string | null, id: string) => {
    try {
      await copyVia("copy_indicators", { projectId, defanged, value }, id);
    } catch (err) {
      setError(describeError(err, "Couldn’t copy that."));
    }
  };

  const exportCsv = async () => {
    setError("");
    setStatus("");
    try {
      const name = await invoke<string | null>("export_indicators", { projectId, defanged });
      if (name) setStatus(`Saved ${name}.`);
    } catch (err) {
      setError(describeError(err, "Couldn’t export the indicators."));
    }
  };

  if (!indicators) {
    return error ? <p className="error" role="alert">{error}</p> : <p className="status" role="status">Reading the case…</p>;
  }

  // "the case description, 3 entries and 1 evidence file"
  const searched = [
    described && "the case description",
    entries > 0 && count(entries, "entry", "entries"),
    files > 0 && count(files, "evidence file", "evidence files"),
  ].filter((part): part is string => Boolean(part));
  const from = searched.length < 3 ? searched.join(" and ") : `${searched[0]}, ${searched[1]} and ${searched[2]}`;

  return (
    <section className="indicators" aria-label="Indicators">
      <div className="indicators-head">
        <p className="summary">
          {indicators.length > 0
            ? `${count(indicators.length, "indicator", "indicators")} from ${from}.`
            : searched.length === 0
              ? "Nothing in this case yet to find indicators in."
              : `No indicators in ${from}.`}
        </p>
        {indicators.length > 0 && (
          <label className="checkbox no-print">
            <input type="checkbox" checked={defanged} onChange={() => setDefanged((value) => !value)} />
            Defanged
          </label>
        )}
      </div>
      {error && <p className="error" role="alert">{error}</p>}

      {GROUPS.map((group) => {
        const items = indicators.filter((indicator) => group.kinds.includes(indicator.kind));
        if (items.length === 0) return null;
        return (
          <section key={group.title} className="finding">
            <h3 className="section-title">{group.title}</h3>
            {items.map((indicator) => {
              const id = `${indicator.kind}:${indicator.value}`;
              return (
                <div key={id} className="line-row">
                  <span className="indicator-value mono">{shown(indicator)}</span>
                  <span className="indicator-note meta">{noteFor(indicator)}</span>
                  <button className="btn-text no-print" onClick={() => void copy(indicator.value, id)}>
                    <span key={copiedId === id ? "done" : "idle"} className="fade">{copiedId === id ? "Copied" : "Copy"}</span>
                  </button>
                </div>
              );
            })}
          </section>
        );
      })}

      {indicators.length > 0 && (
        <div className="actions no-print">
          <button className="btn-outline" onClick={() => void copy(null, "all")}>
            <span key={copiedId === "all" ? "done" : "idle"} className="fade">
              {copiedId === "all" ? "Copied" : defanged ? "Copy all, defanged" : "Copy all"}
            </span>
          </button>
          <button className="btn-text" onClick={() => void exportCsv()}>Export CSV…</button>
          {status && <span className="status" role="status">{status}</span>}
        </div>
      )}
    </section>
  );
}
