# Brief: agent-safe secrets for Encra (`encra run`)

> Line numbers and file names refer to the first commit (Cobrypt 0.1.0), before the rename. Since the rename the database is `encra.db`, and `main.rs` has been split into command modules, so the line numbers no longer match.


(Encra was called Cobrypt when this was written; renamed 7 November 2026.)

Written 7 November 2026 from a read of Bypass (github.com/yaroshevych/bypass,
MIT, commit `d188a30`, 6 November 2026). I read the source; I did not build or
run it. This is a design to plan from, not an approved plan. Nothing here has
been implemented, and the feature touches the vault, so it falls under the
Security-Sensitive Task Protocol in `AGENTS.md`.

## The idea in one paragraph

An AI agent needs a credential to run something (a deploy script, an API call).
Today the only way is to paste the secret into the prompt or a file, where it
ends up in transcripts and the model provider's logs. Instead, the agent runs
`encra-run --env-file .env.deploy -- ./deploy.sh`. The env file holds
references (`DEPLOY_TOKEN=encra://GitHub#password`), not values. `encra-run`
asks the running Encra app over a local socket; Encra shows Stephen who is
asking, for what, and to run which command; on approval it sends the values back
to `encra-run`, which replaces itself with the command (exec), so only that
command gets the secret. The agent sees the command's output, never the value.

## How Bypass does it (what to copy as design, not code)

| Piece | Bypass | File |
| --- | --- | --- |
| Client | `bypass run` parses env files, collects references, sends one request, then `syscall.Exec`s the command with resolved env. Exit code, signals and terminal are preserved because the client process *becomes* the command. | `cmd/bypass/run.go` |
| Transport | Unix socket in `/private/tmp/bypass-<uid>-<hash>/run.sock`. Dir 0700, owner checked, symlinks rejected, socket 0600, `flock` so only one server owns it, stale socket removed only under the lock. | `internal/run/protocol.go` |
| Peer check | Both sides read the peer's UID (`LOCAL_PEERCRED`) and PID (`LOCAL_PEERPID`), look up the peer's executable path and require its SHA-256 to equal their own binary. | `internal/run/auth_darwin.go`, `auth.go` |
| Framing | Versioned binary frames (`BRQ\x01` / `BRS\x01`), 1 MiB cap, every length checked. Secret values travel as raw bytes, never inside JSON strings, and buffers are wiped after use. Mismatched versions fail closed. | `protocol.go` |
| Request | Command argv, working directory, list of references, optional identity. Request is one frame; if the client sends anything else or disconnects, the pending request is cancelled. | `protocol.go` |
| Approval UI | Shows agent name, full command, directory, caller process chain (up to 6 parents via `ps`), and the requested fields *without values*. Back is the default button. Deny / Approve once / Approve for session. | `internal/ui/run_dialog.go` |
| Identity | Optional `NAME-<32..64 hex>` bearer in `BYPASS_IDENTITY`. Server keeps only its SHA-256. It is self-claimed; the docs say so. Stripped from the child's env. | `internal/run/grant.go` |
| Session grants | In memory, per identity + vault + entry + field, until the vault locks or the app exits. | `grant.go`, `internal/ui/run_grants.go` |
| Path hygiene | Executable, script, env files, cwd and vault paths must be absolute and contain no symlinks. Interpreters (`sh`, `python`, `node`...) get their script path checked too. | `internal/run/path.go` |
| Hardening | Core dumps disabled in the client (`RLIMIT_CORE` = 0). | `cmd/bypass/core_limit_unix.go` |

Limits Bypass states itself, which apply to any Encra version too:

- Output is not masked. A command that prints the secret hands it to the agent.
- The launched command and its children hold the secret in plaintext env.
- Locking never retracts a secret already delivered; running commands keep it.
- Peer checks are best-effort against other processes running as the same user.

## One weakness to not copy

Bypass's session grants (v2, `Scope: "identity"`) are bound to identity + entry +
field only, **not to the command or directory** ("across commands and
directories" in `CLI.md`). The identity is a bearer the agent itself holds. So
after one "approve for session", a prompt-injected agent can run
`encra-run -- sh -c 'echo $DEPLOY_TOKEN'` and get the value with no prompt.

For Encra: session grants bind to identity + credential + field + **exact
executable path and its SHA-256** + directory. A different command means a new
prompt. Also flag inline-script commands (`sh -c`, `bash -c`, `python -c`,
`node -e`) in red in the approval dialog, and never offer session approval for
them.

## Fit with Encra as it is today

- **Vault key** lives in `AppState.encryption_key` (Rust side). Secrets can be
  decrypted in Rust and written straight to the socket. The webview never needs
  to see the values for this feature, and it must not.
- **No new Tauri plugin.** The socket server is plain Rust (tokio `UnixListener`)
  inside the app. Spawning happens in `encra-run`, not in the app, so the "no
  shell/process plugins" rule in `AGENTS.md` still holds.
- **Auto-lock on blur** exists (`src/lib/preferences.ts`, `src/App.tsx`). With it
  on, Encra is usually locked while Stephen is in his terminal. That is good:
  a request should bring the window forward, ask for the master password if
  locked, then show the approval. Requests must never resolve while locked
  (audit 2.5 and 7.6 already enforce lock in Rust; keep it that way).
- **Lock path** in `lock_vault` zeroizes the key. Extend it to: clear session
  grants, cancel pending requests (reply "vault locked"), stop accepting.
- **Activity log** (`activity::log_action`) should record every request and
  decision: time, agent name, command, directory, credential + field, decision.
  Never the value. This doubles as a DFIR-style audit trail.
- **References**: credentials are keyed by `service`, which may not be unique.
  Support `encra://<service>[#field]` and `encra://id/<uuid>[#field]`.
  Fields: `password` (default), `username`, `url`, later `totp` (current code).
  Ambiguous or missing match = refuse; don't guess.
- **Socket path**: macOS caps Unix socket paths at about 104 bytes.
  `~/Library/Application Support/<bundle identifier>/...` is close to that
  limit, which is likely why Bypass uses `/private/tmp/bypass-<uid>-<hash>/`.
  Do the same with the dir checks above.
- **Peer check on macOS**: use `proc_pidpath` (libproc) on the peer PID instead
  of shelling out to `ps`. Compare its SHA-256 to the bundled `encra-run`.
  Still best-effort (PID reuse, same-user processes); say so in the UI.

## Suggested phases

1. **v1, approve once only.** `encra-run` binary (second `[[bin]]` in
   `src-tauri`), socket server, request queue, approval dialog, password and
   username fields, activity log entries, Settings toggle "Agent access",
   **off by default**, server only listening while the toggle is on.
2. **v2, session grants** bound to identity + executable hash + directory,
   cleared on lock, with a "Review agent access" list and Clear all.
3. **v3, extras**: `totp` field, multiple references per value
   (`${encra://...}` inside strings), project instructions snippet for agents.

## Tests the protocol requires (from `AGENTS.md`)

- Approve, deny, timeout and client-disconnect paths each end with no secret
  delivered except approve.
- Request while locked never resolves; lock during a pending request cancels it
  and clears grants; state after close and reopen has no grants.
- Malformed, truncated, oversized and wrong-version frames return errors, never
  panic.
- Socket dir and socket permissions are 0700 / 0600; symlinked dir is refused;
  a second server instance is refused.
- Session grant does not authorize a different executable or directory.
- `ENCRA_IDENTITY` never reaches the child environment.
- Activity log has the request and decision and never the value (assert the
  value string is absent from the DB file).
- Hostile self-review: how could a prompt-injected agent get a value without
  a human click, or keep one after lock?

## Open decisions for Stephen

- Reference scheme name (`encra://` assumed here).
- Whether approving needs the master password every time, or only when locked.
- Where `encra-run` installs (`~/.local/bin` vs inside the app bundle with a
  symlink, noting `encra-run` itself rejects symlinked paths for commands,
  not for its own location).
- Whether v1 is worth it before the DFIR redesign ships. Recommendation: after.

## Licence note

Bypass is MIT. This brief ports the design to Rust; no Go code is copied. If any
code is ever copied, keep the MIT notice with it.
