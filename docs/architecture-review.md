# Architecture review, 7 November 2026

> Line numbers and file names refer to commit `b13c9e6`, before the rename. After commit `a4bd07c` the database is `encra.db` and `main.rs` line numbers have shifted.


Read-only review of commit `b13c9e6` (Cobrypt 0.1.0, being renamed to Encra).
I read the Rust backend (`vault.rs`, `main.rs`, `activity.rs`, `backup.rs`,
`hibp.rs`), the Tauri config and the clipboard code. I did not run the tests,
benchmark anything, or run a dependency audit (`cargo-audit` is not installed).
`SECURITY-AUDIT.md` already fixed the big problems; this is the next layer.

## What is already right

- Random DEK wrapped by an Argon2id key, so changing the password re-wraps one
  key instead of re-encrypting everything.
- Per-vault 32-byte salt, `OsRng` everywhere, AES-256-GCM with random nonces.
- Recovery codes: 26 chars from a 32-symbol set = 130 bits each, every code
  Argon2-wrapped, delete-and-replace in one transaction.
- Lock is enforced in Rust (`require_unlocked`), the DEK is zeroized on lock.
- Strict production CSP, no shell or clipboard plugins, HIBP uses k-anonymity
  with a size cap and timeout.

## Findings, most important first

### 1. HIGH: unlocking sends every secret to the webview at once

`get_credentials` (`main.rs:175`) decrypts every password, username, URL, note
and TOTP secret and returns them all to React. Anything that runs in the
webview (a bad dependency, a future XSS, a devtools session) gets the whole
vault in one call, and those strings live in JS memory, where they can't be
wiped, until garbage collection.

Better: the list command returns only what the list shows (id, service,
username, has_totp). Add `reveal_field(id, field)` for the eye icon and
`copy_field(id, field)` that writes the clipboard **from Rust**, so the
password never enters JS at all for the common case. The TOTP code can be one
`get_totp(id)` call for the row on screen.

Bonus for copy-from-Rust: on macOS, mark the pasteboard item with the
`org.nspasteboard.ConcealedType` type (nspasteboard.org convention) so
clipboard managers and Universal Clipboard history skip it. Needs a small Rust
clipboard dependency; check whether the crate supports that marker before
choosing it.

### 2. MEDIUM: account names are stored and logged in plaintext

`service` is the one credential column not encrypted (`main.rs:224`, kept so
`ORDER BY service` works), and the activity log stores
`"added <service>"` in plaintext (`main.rs:231`). Your own threat model says
the attacker may have the database file: they can't read passwords, but they
get the full list of which accounts you have (bank, school, work), which is
useful for phishing.

Better: encrypt `service`, sort in Rust after decrypting (a personal vault is a
few hundred rows; this costs nothing). Log `credential_add` with the id only, or
encrypt the `detail` column. Migration needs the same transactional pattern as
`migrate_plaintext_fields`.

### 3. MEDIUM: ciphertexts are not bound to their row

`vault::encrypt` uses AES-GCM with no associated data. Someone who can *write*
the database file can swap encrypted values between rows or columns (put
the bank password in the forum entry, or an old password back) and every one
still decrypts cleanly.

Better: pass AAD such as `encra:v1:credentials:<id>:password` on encrypt and
decrypt. This needs a ciphertext version prefix so old values still decrypt,
and a one-time re-encrypt migration.

### 4. MEDIUM: Argon2 settings are the library default and not stored

`Argon2::default()` in argon2 0.5 is 19 MiB, 2 passes, 1 lane, which is the
OWASP *minimum*, tuned for servers handling many logins. A desktop vault
unlocks a few times a day and can afford much more, which multiplies the cost of
an offline guess. The parameters also aren't stored with the vault, so they can
never be raised later without breaking existing vaults.

Better: store `kdf = argon2id, m, t, p` in `vault_config`; raise new vaults to
something like 64 to 256 MiB and 3 passes (benchmark on the MacBook, aim for
about half a second); on unlock, if the stored params are older, re-wrap the DEK
with new ones in one transaction. Same for backups and recovery codes.

### 5. LOW: two Argon2 runs per unlock

`unlock_vault` runs `verify_password` (Argon2 PHC hash) and then `derive_key`
(Argon2 again). Unlock takes twice as long as it needs to, and the PHC hash in
the DB is a second offline target. The AES-GCM tag on the wrapped DEK already
proves the password is right, which is how KeePass-style vaults verify.

This conflicts with the `AGENTS.md` rule about separating derivation and
verification, which came from a real bug (the old `master_hash` *was* the key).
Using the AEAD tag doesn't repeat that bug, because nothing derived from the
password is stored. Worth a deliberate decision either way, not a quiet change.
If you keep the hash, at least use the same raised parameters for both.

### 6. LOW: key and plaintext types don't zeroize themselves

`vault.rs` defines a zeroizing `Dek` type but `AppState.encryption_key` holds a
raw `[u8; 32]`, and `decrypt` returns a plain `String`. Use `Zeroizing<...>`
(the crate is already a dependency) so every copy wipes on drop instead of
relying on each call site.

### 7. LOW: database file is world-readable

`~/Library/Application Support/com.cobrypt.desktop/cobrypt.db` is `0644` and
its folder `0755`. On a single-user Mac this mostly matters for other local
accounts and backups, but `0600`/`0700` costs one line at startup.

### 8. LOW: HIBP response size can hint at the prefix

Send the `Add-Padding: true` header so every range response is padded to a
similar size; otherwise TLS record sizes can narrow down which 5-char prefix
was requested.

## Bigger upgrades, if you want them later

- **Touch ID unlock.** Keep a second copy of the DEK wrapped by a key held in the
  macOS Keychain with biometric access control (the Secure Enclave keeps it
  non-exportable). Master password still works and is required after restart or
  a set time. Big UX win, real complexity; after 1 to 4 above.
- **Tauri isolation pattern.** Tauri 2 can route all IPC through a sandboxed
  isolation script that checks every command before it reaches Rust. Useful once
  the frontend grows dependencies; low priority with today's three.
- **Agent access (`encra run`).** See `agent-secrets-brief.md`. Finding 1
  (secrets stay in Rust) is a prerequisite for it to be clean.
- **CI with `cargo audit` and `npm audit`.** There is no CI. Even a local
  `just audit` would catch vulnerable crates.

Not recommended: whole-database encryption (SQLCipher). After finding 2 the
only plaintext left is ids, timestamps and row counts, and SQLCipher adds a
C dependency and a second key-handling path.

## Suggested order

1 → 2 → 3 → 4 share one migration framework (versioned ciphertexts and vault
settings), so plan them together, after the DFIR redesign ships. 6, 7 and 8 are
small and independent. 5 is a decision for Stephen.
