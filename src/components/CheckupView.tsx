import { useState, type ReactNode } from "react";
import { formatDate, formatTime, parseStored } from "../lib/format";
import type { CheckProgress, Checkup, LoginRef } from "../lib/types";

interface CheckupViewProps {
  checkup: Checkup;
  /** Set while every login is being checked against breaches. */
  progress: CheckProgress | null;
  checking: boolean;
  onCheckAll: () => void;
  onOpen: (id: string) => void;
  /** Open the login's edit form, to change its password. */
  onChange: (id: string) => void;
}

/** "A, B and C", the way the mockups list names. */
function names(list: string[]): string {
  return list.length < 2 ? list.join("") : `${list.slice(0, -1).join(", ")} and ${list[list.length - 1]}`;
}

/** "a, b, and c" for the clauses of the summary sentence. */
function clauses(list: string[]): string {
  if (list.length < 3) return list.join(" and ");
  return `${list.slice(0, -1).join(", ")}, and ${list[list.length - 1]}`;
}

/** Service names, with the username where two in one list share a name. */
function labels(logins: LoginRef[]): string[] {
  return logins.map((login) => {
    const twin = logins.some((other) => other !== login && other.service.toLowerCase() === login.service.toLowerCase());
    return twin && login.username ? `${login.service} (${login.username})` : login.service;
  });
}

function summary(checkup: Checkup): string {
  const { total, breached, reused, weak, old, unchecked, last_checked } = checkup;
  if (total === 0) return "No logins to check yet.";
  const sharing = reused.reduce((sum, group) => sum + group.length, 0);
  const found = [
    breached.length > 0 && `${breached.length.toLocaleString()} turned up in a breach`,
    sharing > 0 && `${sharing.toLocaleString()} share a password with another login`,
    weak.length > 0 && `${weak.length.toLocaleString()} ${weak.length === 1 ? "is" : "are"} weak`,
    old.length > 0 && `${old.length.toLocaleString()} ${old.length === 1 ? "hasn’t" : "haven’t"} changed in over a year`,
  ].filter((part): part is string => Boolean(part));
  const of = `Of ${total.toLocaleString()} ${total === 1 ? "login" : "logins"}, `;
  // "None turned up in a breach" only once a breach check has actually run.
  const none = last_checked
    ? "none turned up in a breach, share a password, are weak, or are over a year old"
    : "none share a password, are weak, or are over a year old";
  const sentence = `${of}${found.length > 0 ? clauses(found) : none}.`;
  if (unchecked === 0) return sentence;
  if (unchecked === total) return `${sentence} None of them have been checked against known breaches yet.`;
  return `${sentence} The breach check hasn’t seen ${unchecked.toLocaleString()} of them yet.`;
}

function seen(count: number): string {
  return count === 1 ? "seen in breaches once" : `seen in breaches ${count.toLocaleString()} times`;
}

interface LoginLineProps {
  login: LoginRef;
  /** What was found, after the username: "since 2 March 2025". */
  detail?: string;
  action: string;
  onAction: () => void;
  nested?: boolean;
}

/**
 * One login on a finding line: its name, what was found, then the action,
 * in fixed columns so the details line up from row to row and section to
 * section.
 */
function LoginLine({ login, detail, action, onAction, nested }: LoginLineProps) {
  return (
    <div className={nested ? "line-row is-login is-nested rise" : "line-row is-login"}>
      <span className="line-name">{login.service}</span>
      <span className="line-detail meta">{[login.username, detail].filter(Boolean).join(" · ")}</span>
      <button className="btn-text" onClick={onAction}>{action}</button>
    </div>
  );
}

interface Row {
  login: LoginRef;
  detail?: string;
}

interface FindingProps {
  title: string;
  /** The summary line: a sentence, or one login standing for the rest. */
  summary: ReactNode | Row;
  rows: Row[];
  onOpen: (id: string) => void;
}

const isRow = (value: ReactNode | Row): value is Row => typeof value === "object" && value !== null && "login" in value;

/** A long finding as one summary line; Show all lists every login in it. */
function Finding({ title, summary, rows, onOpen }: FindingProps) {
  const [open, setOpen] = useState(false);
  const toggle = (
    <button className="btn-text" aria-expanded={open} onClick={() => setOpen((value) => !value)}>
      {open ? "Show fewer" : "Show all"}
    </button>
  );
  return (
    <section className="finding">
      <h3 className="section-title">{title}</h3>
      {isRow(summary) ? (
        <div className="line-row is-login">
          <span className="line-name">{summary.login.service}</span>
          <span className="line-detail meta">{summary.detail}</span>
          {toggle}
        </div>
      ) : (
        <div className="line-row">
          <span className="line-copy">{summary}</span>
          {toggle}
        </div>
      )}
      {open && rows.map((row) => (
        <LoginLine key={row.login.id} {...row} action="Open" onAction={() => onOpen(row.login.id)} nested />
      ))}
    </section>
  );
}

/** A short finding: every login on its own line. */
function Short({ title, rows, onOpen }: { title: string; rows: Row[]; onOpen: (id: string) => void }) {
  return (
    <section className="finding">
      <h3 className="section-title">{title}</h3>
      {rows.map((row) => <LoginLine key={row.login.id} {...row} action="Open" onAction={() => onOpen(row.login.id)} />)}
    </section>
  );
}

/**
 * The vault check-up: in a breach, shared passwords, weak ones and old ones,
 * as a sentence and then each finding. Never a password, its length or its
 * makeup; Rust only sends which logins are flagged.
 */
export function CheckupView({ checkup, progress, checking, onCheckAll, onOpen, onChange }: CheckupViewProps) {
  const last = checkup.last_checked ? parseStored(checkup.last_checked) : null;
  const weak = checkup.weak.map((login) => ({ login }));
  const old = checkup.old.map(({ login, since }) => ({ login, detail: `since ${formatDate(since)}` }));
  const percent = progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : null;
  const firstFew = (list: LoginRef[]) => names(labels(list.slice(0, 3)));

  return (
    <article className="record checkup stagger" aria-labelledby="checkup-title">
      <header className="record-head">
        <p className="meta">{last ? `Breach check run on ${formatDate(checkup.last_checked ?? "")} at ${formatTime(last)}` : "No breach check run yet"}</p>
        <h2 id="checkup-title" className="title-xl">Check-up</h2>
      </header>

      <p className="summary">{summary(checkup)}</p>

      {checkup.breached.length > 0 && (
        <section className="finding">
          <h3 className="section-title is-danger">In a breach</h3>
          {checkup.breached.map(({ login, count }) => (
            <LoginLine key={login.id} login={login} detail={seen(count)} action="Change" onAction={() => onChange(login.id)} />
          ))}
        </section>
      )}

      {checkup.reused.length > 0 && (
        <section className="finding">
          <h3 className="section-title">Same password</h3>
          {checkup.reused.map((group) => (
            <ReusedGroup key={group.map((login) => login.id).join()} group={group} onOpen={onOpen} />
          ))}
        </section>
      )}

      {weak.length > 3 && (
        <Finding
          title="Weak"
          summary={<>{firstFew(checkup.weak)} <span className="meta">and {(weak.length - 3).toLocaleString()} more</span></>}
          rows={weak}
          onOpen={onOpen}
        />
      )}
      {weak.length > 0 && weak.length <= 3 && <Short title="Weak" rows={weak} onOpen={onOpen} />}

      {old.length > 1 && (
        <Finding
          title="Not changed in over a year"
          summary={{ login: old[0].login, detail: `${old[0].detail}, and ${(old.length - 1).toLocaleString()} more` }}
          rows={old}
          onOpen={onOpen}
        />
      )}
      {old.length === 1 && <Short title="Not changed in over a year" rows={old} onOpen={onOpen} />}

      {checking && (
        <div className="progress-line fade" role="status">
          <span className="meta">
            {progress ? `Checking ${progress.done.toLocaleString()} of ${progress.total.toLocaleString()}…` : "Checking…"}
          </span>
          <progress max={100} value={percent ?? undefined} />
        </div>
      )}

      <div className="actions">
        <button className="btn-outline" onClick={onCheckAll} disabled={checking || checkup.total === 0}>
          {checkup.last_checked ? "Check all for breaches again" : "Check all for breaches"}
        </button>
        <span className="meta">Only the first 5 characters of each password’s SHA-1 hash leave this Mac.</span>
      </div>
    </article>
  );
}

function ReusedGroup({ group, onOpen }: { group: LoginRef[]; onOpen: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <div className="line-row">
        <span className="line-copy">{names(labels(group))} share one password.</span>
        <button className="btn-text" aria-expanded={open} onClick={() => setOpen((value) => !value)}>
          {open ? "Hide" : "Review"}
        </button>
      </div>
      {open && group.map((login) => (
        <LoginLine key={login.id} login={login} action="Open" onAction={() => onOpen(login.id)} nested />
      ))}
    </>
  );
}
