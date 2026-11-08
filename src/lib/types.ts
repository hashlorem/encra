/**
 * Shapes returned by the Rust backend. Kept in one place so a change to a
 * backend struct surfaces as a compile error here rather than at runtime.
 */

/** A row in the vault list. Carries no password, notes or 2FA secret. */
export interface CredentialSummary {
  id: string;
  service: string;
  username: string;
  has_totp: boolean;
  created_at: string;
  /** The last breach check found this password. */
  breached: boolean;
}

/** What the last breach check found, and when (UTC, "YYYY-MM-DD HH:MM:SS"). */
export interface BreachResult {
  count: number;
  checked_at: string;
}

/** The open record, still without the password or 2FA secret. */
export interface CredentialDetail extends Omit<CredentialSummary, "breached"> {
  url: string;
  notes: string;
  has_password: boolean;
  /** When the password was last set. */
  password_changed_at: string;
  breach: BreachResult | null;
}

export interface TotpCode {
  code: string;
  remaining: number;
  /** Seconds each code lasts, usually 30. */
  period: number;
}

export interface CredentialInput {
  service: string;
  username: string;
  password: string;
  url: string;
  notes: string;
}

export interface Project {
  id: string;
  name: string;
  description: string;
  target: string;
  methodology: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface ProjectInput {
  name: string;
  description: string;
  target: string;
  methodology: string;
}

export interface JournalEntry {
  id: string;
  project_id: string;
  title: string;
  content: string;
  entry_type: string;
  severity: string;
  created_at: string;
}

export interface EntryInput {
  project_id: string;
  title: string;
  content: string;
  entry_type: string;
  severity: string;
}

export interface KBEntry {
  id: string;
  title: string;
  command: string;
  description: string;
  tags: string;
  category: string;
  created_at: string;
}

export interface KBInput {
  title: string;
  command: string;
  description: string;
  tags: string;
  category: string;
}

export interface ActivityEntry {
  id: string;
  /** Position in the log's chain; the cursor for loading older entries. */
  seq: number | null;
  action: string;
  detail: string;
  timestamp: string;
}

/** Result of checking the activity log's HMAC chain against the vault key. */
export interface ChainStatus {
  intact: boolean;
  sealed: number;
  /** Written while locked, sealed at the next unlock. */
  pending: number;
  problem: string | null;
}

/** How one reference matches your logins. Shown to you only. */
export interface AgentMatch {
  reference: string;
  field: string;
  status: "found" | "missing" | "ambiguous";
  login_id: string | null;
  login: string | null;
}

/** A waiting `encra run` request. Never carries a value. */
export interface AgentRequest {
  matches: AgentMatch[];
  id: string;
  agent: string;
  argv: string[];
  executable: string;
  cwd: string;
  references: string[];
  chain: string[];
  inline_script: boolean;
}

export interface AgentStatus {
  enabled: boolean;
  listening: boolean;
  binary: string;
}

export interface ActivityLog {
  entries: ActivityEntry[];
  chain: ChainStatus;
  has_more: boolean;
}

export interface ActivityPage {
  entries: ActivityEntry[];
  has_more: boolean;
}

export interface NmapPort {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string | null;
}

export interface NmapHost {
  ip: string;
  hostname: string | null;
  os: string | null;
  ports: NmapPort[];
}

export interface NmapScan {
  hosts: NmapHost[];
  total_hosts: number;
  total_open_ports: number;
}

export interface EvidenceHashes {
  sha256: string;
  sha1: string;
  md5: string;
}

/** A file in a case's evidence locker. Never its contents. */
export interface EvidenceItem {
  id: string;
  project_id: string;
  name: string;
  source: string;
  size: number;
  hashes: EvidenceHashes;
  added_at: string;
  /** False when only the record is here (restored from a backup). */
  stored: boolean;
}

export interface CustodyEvent {
  seq: number;
  action: string;
  detail: string;
  at: string;
}

export interface Custody {
  events: CustodyEvent[];
  status: { intact: boolean; problem: string | null };
}

export interface EvidenceCheck {
  ok: boolean;
  detail: string;
}

export interface EvidenceProgress {
  name: string;
  done: number;
  total: number;
}

/** A scan Rust opened and parsed, with its file name. */
export interface OpenedScan {
  name: string;
  scan: NmapScan;
}

