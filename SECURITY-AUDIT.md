# Cobrypt Security Audit Writeup

> **Audience:** Beginner cybersecurity students and junior developers.  
> **Date:** July 2026  
> **Stack:** Tauri 2 + Rust + React 19 + TypeScript + SQLite, AES-256-GCM + Argon2id

---

## 1. Project Overview

**Cobrypt** (formerly KeyRPT) is a local-first encrypted security workbench — a desktop app for managing passwords, TOTP 2FA codes, pentest journals, Nmap scan results, and a security command reference. All data stays on your machine. No cloud accounts. No telemetry.

**Why it needed an audit:** the initial implementation was built quickly to prove the concept works. Speed over safety. The audit found the encryption key itself stored in the database, recovery codes that could permanently destroy access to your passwords, and a hand-rolled Base64 decoder that randomly failed on certain password lengths. All three could lose your data silently.

**What we fixed:** 3 critical bugs, 4 recovery-flow hardening items, and a full field-level encryption migration covering 15 sensitive fields across 4 database tables. 12 Rust tests now verify the fixes.

---

## 2. Vulnerability-by-Vulnerability Breakdown

### 2.1 CRITICAL: Encryption key stored in the database

**What the bug was (plain language):**

The app asked you for a master password, derived an encryption key from it, then stored *that exact key* in the database — base64-encoded, sitting right next to your encrypted passwords. Anyone who got a copy of `keyrpt.db` could decode it and decrypt everything without knowing your password. It's like locking your house and taping the key to the front door.

**Technical detail:**

`vault.rs:177-181` — the original `hash_password()` function:

```rust
pub fn hash_password(password: &str, salt: &[u8]) -> Result<String, String> {
    let key = derive_key(password, salt)?;  // This IS the AES-256 encryption key
    Ok(base64::encode(&key))                // Stored as "master_hash" in the DB
}
```

`derive_key()` runs Argon2id to produce a 32-byte encryption key. `hash_password()` then base64-encodes it and stores it in `vault_config.master_hash`. The `main.rs:164-165` unlock flow then compares the stored value directly with the freshly-derived key.

The same function was used for both *key derivation* (producing the actual encryption key) and *password verification* (checking you typed the right password). These must be separate operations.

**Why it mattered:**

An attacker with file access to your machine — malware, stolen laptop, compromised backup — could:
1. Open `keyrpt.db` with any SQLite viewer
2. `SELECT value FROM vault_config WHERE key = 'master_hash'` → get the base64 key
3. Decode it → recover the raw 32-byte AES-256 key
4. Decrypt every stored password, TOTP secret, and credential

The master password was completely bypassed. All existing credentials were exposed.

**The fix:**

Replaced with a **DEK model** (Data Encryption Key). Three changes:

1. **`vault.rs:92-96`** — New `generate_dek()` creates a random 32-byte key using `OsRng`. This DEK is never shown to the user and never derived from their password.

2. **`vault.rs:99-112`** — New `wrap_dek()` encrypts the DEK with a wrapping key derived from the master password using AES-256-GCM. Only the wrapped (encrypted) DEK is stored in `vault_config.encrypted_dek`.

3. **`vault.rs:178-194`** — `hash_password()` now uses the standard Argon2 PHC string format (`$argon2id$v=19$m=19456,t=2,p=1$...`). This is a non-reversible hash — you can verify a password against it, but you cannot recover the wrapping key from it. `verify_password()` (line 189) uses the `PasswordVerifier` trait for checking.

The wrapping key now exists **only in memory** during an active session. It's never written to disk.

**Verification:**

- `test_legacy_migration_success` — confirms legacy key derivation is deterministic per-password, and wrong passwords produce different hashes
- `test_migration_key_roundtrip` — confirms encrypt→decrypt→re-encrypt with new DEK works, and the old key cannot decrypt new ciphertext
- `test_recovery_code_full_reset_flow` — full create→generate codes→recover→reset→reopen→verify flow against a file-backed database

---

### 2.2 CRITICAL: Recovery could destroy access to existing passwords

**What the bug was (plain language):**

The lock screen had a "reset via recovery code" button. If you used it while the vault was locked, the app would:
1. Accept your recovery code
2. Generate a new encryption key for your new master password
3. Replace the old key with the new one
4. **Skip re-encrypting** your existing passwords (because the old key wasn't in memory)

Result: your passwords were still encrypted with the old key, which was now gone. All your data became permanently undecryptable — and the app gave no warning.

**Technical detail:**

`main.rs:507-520` — the original `reset_master_password()`:

```rust
let old_key = state.encryption_key.lock()?;
if let Some(old_key) = *old_key {  // <-- evaluates to false when vault is LOCKED
    // re-encrypt loop — NEVER RUNS when called from lock screen
}
// new key replaces old key in vault_config
// existing passwords remain encrypted with now-unavailable old key
```

When the vault is locked, `state.encryption_key` is `None`. The `if let Some(old_key)` guard evaluates to `false`, the entire re-encryption block is skipped, but the new key is still written to the database.

Additionally: `activity.rs:61-69` — the original `verify_recovery_code()` deleted the recovery code row **before** the password reset completed. If the reset failed for any reason, the code was already consumed and couldn't be retried.

**Why it mattered:**

A user who forgot their password, used the recovery flow from the lock screen (as the UI invited them to do), would watch the app accept their recovery code, set a new password, unlock... and find all their credentials showing `[decryption failed]`. The data was still in the database, but the key needed to decrypt it was gone forever.

**The fix:**

Complete redesign of the recovery system across three files:

1. **`activity.rs:48-101`** — `generate_recovery_codes()` now wraps the DEK with each code. For every code (26 base32 chars, 130 bits entropy): generates a unique random salt → Argon2id derives a recovery wrapping key → AES-256-GCM wraps the DEK → stores SHA-256 hash of the code, salt, and wrapped DEK.

2. **`activity.rs:106-169`** — `recover_dek()` finds the code by its hash, derives the recovery key, unwraps the DEK. Returns the DEK + row ID. Does NOT delete the code — that's the caller's job inside a transaction.

3. **`activity.rs:178-226`** — `commit_recovery_reset()` runs the actual password change in one BEGIN IMMEDIATE/COMMIT transaction: generates new random KDF salt, derives new wrapping key, wraps the DEK, writes `encrypted_dek`, `password_hash`, and `kdf_salt`, and consumes the recovery code — all atomically. Rollback on any failure.

4. **`main.rs:530-546`** — `reset_master_password()` now calls `recover_dek()` (works from locked state) → `commit_recovery_reset()` (atomic) → sets in-memory DEK (auto-unlocks).

**Verification:**

- `test_recovery_code_roundtrip` — generate codes, recover DEK with valid code, confirm DEK matches original, confirm row deleted by caller prevents reuse
- `test_recovery_code_wrong_code_fails` — wrong code returns `None`, not an error
- `test_recovery_code_full_reset_flow` — file-backed DB: create vault → generate codes → recover from locked → reset → close and reopen → unlock with new password → verify credentials decrypt → confirm old password fails → confirm code consumed
- `test_recovery_reset_rollback_on_failure` — inject schema failure mid-transaction, confirm code NOT consumed, confirm DEK unchanged, confirm old password still works

---

### 2.3 CRITICAL: Hand-rolled Base64 decoder rejected valid ciphertext

**What the bug was (plain language):**

The app used a custom-written Base64 decoder. It had a math error: it stripped the `=` padding characters, then required the remaining length to be divisible by 4. But standard Base64 strings often have remaining lengths of 2 or 3 (that's why the padding exists). The decoder rejected these as "invalid" — including perfectly valid AES-GCM ciphertext produced by the encrypt function.

Password length determined encrypted output length, which determined Base64 output length. At 20 characters (the generated default), it happened to work. At 12, 13, 16, or 17 characters, it would fail — showing `[decryption failed]` even with the correct master password.

**Technical detail:**

`vault.rs:146-161` — the custom decoder:

```rust
let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
if bytes.len() % 4 != 0 {
    return Err("invalid base64 length".into());  // WRONG: rejects valid strings
}
```

A standard Base64 string like `"SGVsbG8="` (encoding "Hello") has one `=` padding. Stripping it gives 6 characters. 6 % 4 = 2 ≠ 0 → error. But this is a perfectly valid Base64 string.

The decrypt path: AES-GCM ciphertext length = plaintext length + 16 (auth tag) + 12 (nonce). For a 12-char password: 12 + 16 + 12 = 40 bytes → 54 base64 chars. Minus padding: 53 chars → 53 % 4 = 1 ≠ 0 → **decrypt fails**.

**Why it mattered:**

The bug was triggered by the password itself — shorter or specific-length passwords became permanently undecryptable. A user could add a credential with a 12-character password, lock the vault, unlock, and see `[decryption failed]` with no explanation. The password wasn't lost — the code literally couldn't read its own encrypted output.

**The fix:**

Replaced the entire handwritten implementation with the `base64` crate (v0.22) — a well-tested, standard implementation used across thousands of Rust projects. `vault.rs:4` adds `use base64::Engine;`, and all calls use `base64::engine::general_purpose::STANDARD.encode()` / `.decode()`. One import, all edge cases handled.

**Verification:**

- `test_end_to_end_field_encryption` — encrypts and decrypts passwords of multiple lengths (12, 25+ chars) across all field types
- All 12 tests pass against the same code paths
- The standard `base64` crate's test suite (upstream) covers thousands of edge cases

---

### 2.4 HIGH: All credential/journal/KB fields stored in plaintext

**What the bug was (plain language):**

Only the password field was encrypted. Your usernames, the websites you use, your notes, TOTP secrets, pentest targets, journal findings, and command references were stored as readable text in the SQLite database. Someone with access to `keyrpt.db` could read all of it without any password.

**Why it mattered:**

A stolen database would reveal:
- Every service you have an account on (usernames, URLs)
- Your notes (which often contain security questions, recovery info)
- TOTP secrets (which generate your 2FA codes — rendering 2FA useless)
- Your pentest targets, findings, and methodology
- Your personal security command reference

The password was protected, but the context around it told a complete story.

**The fix:**

`vault.rs:199-213` — added `encrypt_opt()` and `decrypt_opt()` helpers for optional fields:

```rust
pub fn encrypt_opt(key: &[u8; 32], value: &Option<String>) -> Result<Option<String>, String>
pub fn decrypt_opt(key: &[u8; 32], value: &Option<String>) -> Option<String>
```

Updated every CRUD operation across 4 tables:

| Table | Encrypted fields | Kept plaintext (search/metadata) |
|---|---|---|
| `credentials` | `username`, `password`, `url`, `notes`, `totp_secret` | `id`, `service` |
| `projects` | `description`, `target`, `methodology` | `id`, `name`, `status` |
| `journal_entries` | `title`, `content` | `id`, `project_id`, `entry_type`, `severity` |
| `kb_entries` | `title`, `command`, `description`, `tags` | `id`, `category` |

Search keys (`service`, `name`, `category`) stay plaintext so you can search and filter. Metadata (`entry_type`, `severity`, `status`) stays plaintext — it's not sensitive.

**Migration path (`main.rs:302-361`):** `migrate_plaintext_fields()` runs on any vault with `schema_version = '1'`. It reads each plaintext field, encrypts it with the DEK, and writes back the ciphertext. Sets version to `'2'`. New vaults start at `'2'`. **No database deletion required.**

**Verification:**

- `test_end_to_end_field_encryption` — creates vault, inserts 3 credentials (short pw, long pw with special chars, with TOTP), 1 project, 1 journal entry, 1 KB entry. Re-opens DB. Verifies all fields decrypt correctly. **Then directly queries SQLite** to prove fields are stored as base64 ciphertext (not readable), while metadata fields (service, name, entry_type, severity, category) remain plaintext.

---

### 2.5 HIGH: Lock enforcement was UI-only

**What the bug was (plain language):**

Locking the vault changed the screen back to the lock screen, but the Rust backend didn't actually check whether the vault was unlocked. You could still delete credentials, modify TOTP, create journal entries, import backups — all from a locked state if you could send commands directly (or if a bug in the UI left a backdoor).

**The fix:**

`main.rs:26-32` — `require_unlocked()` and `require_db()` guards added. Every protected command (20 total) now calls `require_unlocked()` at the start. Locked calls return `"vault is locked"` error.

---

### 2.6 HIGH: Backup portability broken

**What the bug was:**

Exporting a backup from one vault and importing into another vault (with a different master password) would import the raw encrypted passwords — which were encrypted with the source vault's key, not the destination's. The imported passwords would show `[decryption failed]`.

**The fix:**

`export_backup()` decrypts passwords with the source DEK before encrypting with the backup password. `import_backup()` decrypts with the backup password, then **re-encrypts with the destination DEK**.

> **Correction (second audit, §7.1):** this fix was incomplete. Only the credential *password* was decrypted on export and re-encrypted on import. Every other sensitive field (`username`, `url`, `notes`, `totp_secret`, and all project, journal, and command fields) was still written as the source vault's raw ciphertext, so a restored backup showed `[decryption failed]` in those fields. The claim that "backups are now portable across different vaults" was wrong at the time and is only true after the fix in §7.1.

---

### 2.7 MEDIUM: Nmap parser missed self-closing XML elements

**The bug:** Nmap XML uses `<address addr="192.168.1.1" />` and `<hostname name="webserver" />` — self-closing elements. The original parser only handled these in the `Event::Start` branch. Self-closing elements trigger `Event::Empty` in quick-xml. Hosts appeared with blank IPs.

**The fix:** `nmap.rs:151-168` — added `b"address"` and `b"hostname"` handlers to the `Event::Empty` match arm.

---

### 2.8 OTHER: Miscellaneous hardening

| Issue | Fix |
|---|---|
| SQLite foreign keys never enabled | `PRAGMA foreign_keys = ON` in `main.rs:583` |
| Password generator had modulo bias | Replaced with rejection sampling: only use random bytes below `256 - (256 % charset.len)` |
| Clipboard never cleared | 30-second auto-clear on copy in `Vault.tsx` |
| CSP disabled, wide filesystem permissions | CSP: `default-src 'self'` + HIBP API only. FS scoped to downloads/desktop |
| Shell plugin exposed but unused | Removed `tauri-plugin-shell` entirely from Cargo.toml, main.rs, and capabilities |
| Global fixed KDF salt | Per-vault random 32-byte salt stored in `vault_config.kdf_salt` |
| Global fixed backup salt | Per-backup random 32-byte salt prepended to `.cobrypt` file (legacy `.kpt` imports remain supported) |
| Vault creation not atomic | Wrapped in `BEGIN IMMEDIATE`/`COMMIT` transaction with rollback |

---

## 3. Database Deletion vs. Real Migration

During the audit, the recommendation was made to simply delete the old database and start fresh. This was rejected twice:

**First time (DEK model upgrade):** Deleting the old DB would be a data-loss event for any real user. Instead, `migrate_legacy_vault()` (`main.rs:204-300`) detects legacy vaults by the presence of `master_hash` with empty `encrypted_dek`/`password_hash`, derives the old key, decrypts all credentials, generates a new random DEK, re-encrypts everything, and clears the legacy field. All in one transaction. Wrong password = rollback, no change.

**Second time (plaintext→encrypted fields):** Same pattern. `migrate_plaintext_fields()` (`main.rs:302-361`) checks `schema_version`, encrypts every plaintext field in-place, and bumps the version. Users upgrade on their next unlock — no manual action, no data loss.

The principle: **"Delete the database" is never an acceptable migration strategy for a tool that stores user data.** Every schema change must ship with an automatic, transactional migration path.

---

## 4. `thread_rng()` vs `OsRng` — A False Alarm

One audit finding flagged that `activity.rs:191` used `rand::thread_rng()` instead of `OsRng`. The concern was inconsistency — `vault.rs` uses `OsRng` everywhere.

**The truth:** `thread_rng()` in Rust is ChaCha12, a properly-seeded CSPRNG. It's not a weak LCG or userspace PRNG — it gets entropy from the OS just like `OsRng` does. The only difference is performance: `OsRng` makes a syscall for every request, while `thread_rng()` uses a per-thread CSPRNG seeded from the OS once.

The swap to `aes_gcm::aead::OsRng` in `activity.rs:191` was done for **consistency**, not security. Both were fine. This is a good example of "looks suspicious" vs "is actually vulnerable" — consistency matters for auditability and avoiding future mistakes, even when the current code is secure.

---

## 5. Final Field-Level Encryption Verification

The `test_end_to_end_field_encryption` test (`main.rs:1048-1190`) goes further than any other test:

1. Creates a file-backed SQLite database (not in-memory — data persists)
2. Inserts data directly via SQL with `vault::encrypt()`
3. Tests multi-length passwords (12 and 25+ chars), multiline notes, TOTP secrets
4. Re-opens the database from disk (simulating app restart)
5. Decrypts every field and asserts correct plaintext values
6. **Raw SQLite query** verifies that stored bytes are base64 (ciphertext), not readable strings
7. Metadata fields (service name, entry type, severity, category) confirmed plaintext

This test proves end-to-end: the encryption path produces ciphertext that survives a restart, the decryption path recovers the correct plaintext, and the database on disk contains no readable secrets.

---

## 6. Lessons for a Security Beginner

### Watch for happy-path-only testing

The original recovery code test (`test_recovery_code_new_password_works`) was a structural test that never actually called `reset_master_password`. It verified the tables existed. That's not testing. The replacement (`test_recovery_code_full_reset_flow`) tests the real function against a file-backed database with close/reopen — proving data survives a restart, not just an in-memory check.

**Pattern:** If your test doesn't close and reopen the database, you haven't proven persistence. If your test doesn't inject a failure mid-operation, you haven't proven rollback.

### Atomic transactions are not optional

Three bugs came from the same root cause: non-atomic multi-step operations. Vault creation wrote two config values separately (a crash between them left a half-initialized vault). Recovery deleted the code before the reset (failure meant a consumed code with no password change). Password reset updated the key and hash separately (a crash meant mismatched state).

**Pattern:** Any multi-step database change must be wrapped in `BEGIN IMMEDIATE`/`COMMIT` with rollback on failure. Never delete a one-time token before the operation succeeds.

### Never use the same function for key derivation and password verification

The original `hash_password()` called `derive_key()` and stored the result. This made the password verifier the encryption key. Key derivation (producing a cryptographic key) and password verification (checking a password) must use separate, non-reversible paths.

**Pattern:** Key derivation → use the key, don't store it. Password verification → use a non-reversible hash (Argon2 PHC, bcrypt). Never mix them.

### TOCTOU is everywhere

The recovery code flow originally verified the code first, then did the reset. Between verification and reset, anything could go wrong. The fix: verify the code, but don't consume it until the entire reset transaction commits.

**Pattern:** Check → Act → Consume, all in one transaction. Never Check → Consume → Act.

### Consistency is a security property

`thread_rng()` vs `OsRng` wasn't a vulnerability, but the inconsistency was a valid concern. When a codebase mixes randomness sources, a future developer might "fix" one to use a weaker source, thinking it doesn't matter because it's already mixed. Uniformity prevents this class of mistake.

**Pattern:** Pick one randomness source for all cryptographic operations. Enforce it with code review, not convention.

### Trust the test suite, not your reasoning

Five times during this audit, a finding was "confirmed by reading the code" but a test proved it wrong. The legacy detection test had an always-true assertion. The recovery test never called the reset function. The original migration test only tested key derivation in isolation.

**Pattern:** A passing test that doesn't exercise the real code path is worse than no test — it gives false confidence. Every test must call the actual production function.

---

## 7. Second audit — September 2026

A follow-up pass over the same code found that several items from the first audit
were either incomplete or had regressions of their own. Everything below was
fixed and is covered by the Rust test suite (22 tests, of which 2 are opt-in live
network checks).

### 7.1 CRITICAL: Backup import was completely broken, and backups were not portable

Two separate defects sat on top of each other:

1. **The import command could never succeed.** The frontend sent the payload
   under the key `encrypted` while the Rust command declared the parameter as
   `bundled`. Tauri rejects the call before any code runs, so "Restore backup"
   failed every time with an argument error.
2. **Only the password field was portable.** `collect_all()` decrypted the
   credential password but wrote `username`, `url`, `notes`, `totp_secret` — and
   every project, journal and command field — as the *source* vault's ciphertext.
   Import re-encrypted only the password, so everything else stayed encrypted
   under a key the destination vault does not have.

**Fixes:** `backup.rs` now decrypts every sensitive field into the plaintext
payload (inside the encrypted envelope) and re-encrypts every one of them with
the destination key on import. The frontend sends the correct `bundled` key. A
`v1.0` payload — which only ever worked when restored into the vault that made
it — is still accepted, but each field is verified to be readable with the
current key, and a foreign-vault payload is rejected with an explanation rather
than silently written back as unreadable bytes.

**Tests:** `test_backup_roundtrip_across_vaults` (file-backed, two different
vault passwords, every field with every table, plus proof the source key can no
longer read the destination's rows),
`test_backup_legacy_payload_is_handled_by_vault_ownership`.

### 7.2 HIGH: Import was not atomic

`restore_all()` ran every `INSERT` without a transaction, and generated primary
keys from only 4 random bytes (32 bits). A failure part-way through — or a key
collision — left a partially imported vault. Journal entries whose project was
absent from the payload were given a fresh, non-existent project id, which
violated the foreign key and aborted the import mid-way.

**Fixes:** the whole restore runs in one `BEGIN IMMEDIATE`/`COMMIT` with
rollback; ids are full 128-bit UUID v4 values; the import payload is normalised
first so every referenced project exists.

**Tests:** `test_backup_import_is_atomic_on_failure` (injects a failure at the
last table and asserts nothing was written),
`test_backup_prepare_creates_missing_project`.

### 7.3 HIGH: Recovery code could be spent twice

`reset_master_password` looked the code up with `recover_dek()` and then called
`commit_recovery_reset()` — two separate calls. Only the second was atomic, so
two concurrent attempts could both pass the lookup before either consumed the
code. This is the same Check → Act → Consume shape the first audit set out to
remove.

**Fix:** `activity::recover_and_reset()` performs the lookup, the password
change, and the code deletion inside a single transaction. Lookup, re-key and
consumption now commit together or not at all. The only production caller is the
command, and the tests were moved onto this same function so they exercise the
real path.

**Tests:** `test_recovery_code_full_reset_flow` (now includes a second reuse
attempt), `test_recovery_reset_rollback_on_failure`.

### 7.4 HIGH: Multi-step writes were not atomic

Five operations performed more than one write without a transaction. The worst
was `migrate_plaintext_fields`, which encrypted five tables and then bumped the
schema version last: a failure part-way through left some fields encrypted and
others plaintext while the version still claimed `v1`, so the next unlock would
re-encrypt the fields that had already succeeded (double encryption).

**Fix:** a shared `in_transaction()` helper now wraps the plaintext migration,
recovery-code generation (a `DELETE` plus eight `INSERT`s), project deletion,
journal entry creation, credential creation/deletion, and the fresh-vault setup.

**Tests:** `test_bulk_entry_insert_is_atomic_on_failure`, plus the existing
migration and recovery tests.

### 7.5 MEDIUM: Panic on a malformed wrapped key

`unwrap_dek()` copied the decrypted plaintext into a fixed 32-byte array without
checking its length. A corrupted or tampered `encrypted_dek` produced a panic
instead of an error, taking the process down.

**Fix:** the length is checked first and returns a descriptive error. Startup no
longer uses `unwrap()`/`expect()` either; a corrupt database produces a readable
failure instead of a raw panic.

**Test:** `test_unwrap_dek_rejects_wrong_length_instead_of_panicking`.

### 7.6 MEDIUM: Secret-touching commands were reachable while locked

`get_totp_code` produced a 2FA code from a plaintext secret with no lock check,
and `check_hibp` handed a plaintext password to a network client with no lock
check. `get_totp_code` was also unused by the frontend.

**Fix:** `check_hibp` now requires an unlocked vault; `get_totp_code` was
removed entirely rather than left as unused attack surface. `parse_nmap` gained
a document-size cap and host/port limits, and `hibp` gained a request timeout and
a bounded response read.

### 7.7 MEDIUM: Weak input validation

`reset_master_password` accepted an empty new password, `export_backup` accepted
an empty backup password, `setup_totp` did not check that the credential existed,
and `validate_secret` accepted secrets below the RFC 4226 floor — a one-character
secret decodes to zero bytes and produced an HMAC over an empty key.

**Fix:** minimum lengths are enforced where a password is *created* (12 chars for
the master password, 8 for a backup password) and deliberately **not** enforced
when verifying an existing password, so a vault created before the rule can still
be unlocked. TOTP secrets must be at least 16 base32 characters (80 bits) and
must decode to at least one byte. Field lengths are capped. Each 2FA code is now
generated only for a credential that exists.

**Tests:** `test_input_validation_rejects_weak_and_oversized_values`,
`test_totp_secret_validation`.

### 7.8 MEDIUM: Recovery codes were generated with a non-CSPRNG-consistent source

`generate_recovery_codes` used `rand::thread_rng()` for the code characters
while every other crypto path used `OsRng`. `thread_rng` is not weak, but mixing
randomness sources is exactly the inconsistency the first audit called out as a
security property. `log_action` also built PRIMARY KEY values from a pair of
random `u64`s, and its insert was best-effort, so a collision would silently drop
an audit entry.

**Fix:** a single `util::os_rng()` is now the only randomness source in the
project, and identifiers come from `util::uuid_v4()`.

**Test:** `test_activity_ids_do_not_collide`.

### 7.9 MEDIUM: Preview unlock backdoor was reachable in production

`App.tsx` unlocked the workspace without a password whenever the hostname was
`localhost` and the URL contained `?preview`. On the platforms where Tauri serves
the app from `localhost`, that was a password-free path into the vault.

**Fix:** the shortcut is gated on Vite's `import.meta.env.DEV`, which is
statically `false` in a production build, so the branch is compiled out.
Additionally, the production Content-Security-Policy no longer allows
`'unsafe-inline'` styles (all six inline style attributes were removed); a
separate `devCsp` keeps the dev server working.

### 7.10 Consistency: DEK lifetime, `OsRng`, and constant-time comparison

- The in-memory DEK is now wrapped in a `Dek` guard whose buffer is zeroed on
  drop, and `lock_vault` overwrites the stored key in place instead of just
  dropping the reference. Plaintext passwords held during the legacy migration
  are wiped afterwards. **This is best-effort only** — it cannot defend against
  swap, hibernation, or an attacker who already controls the machine.
- Every `aes_gcm::aead::OsRng` / `thread_rng` call site was unified through
  `util::os_rng()`.
- The legacy password comparison used `!=` on base64; it now uses a
  constant-time comparison, since that comparison decides whether the caller
  guessed the master password.

### 7.11 Frontend correctness and accessibility

- **Stale 2FA codes (functional bug).** `get_credentials` computed each TOTP code
  once and only the countdown was polled, so displayed codes became wrong as soon
  as the 30-second window turned over. Codes are now recomputed on window
  rollover, and the countdown moved to a small external store so the tick no
  longer re-renders every credential card.
- **Modal accessibility.** `ModalOverlay` never moved, contained, or restored
  focus and had no dialog semantics. It now traps focus, springs it on
  `Tab`/`Shift+Tab`, restores it to the trigger, sets `role="dialog"` /
  `aria-modal`, locks background scroll, handles stacked modals, and only closes
  on a click on the backdrop itself.
- **Destructive actions.** Deleting a credential, project, entry, or command now
  requires confirmation, and async actions are disabled while in flight so a
  double click cannot delete or import twice.
- **Errors.** Twenty-four `console.error`-only paths were replaced with a visible
  message, and raw backend strings are mapped through `lib/errors.ts` so
  database and crypto internals never reach the UI. Every error region is
  announced with `role="alert"`.
- **Labels.** Every modal input has a real or screen-reader-only label.
- **Nested button.** The project card was a `<button>` containing a delete
  `<button>`, which is invalid and broke keyboard focus. The card is now a plain
  container with a real button for the primary action.
- **Light theme.** Journal severity and password strength colours were hardcoded
  dark-theme hex values applied as inline styles, so they ignored the theme
  entirely. They now resolve through the `--danger` / `--accent` / `--text-muted`
  tokens.
- **Window.** `windowGeometry` called `setResizable(false)` on every transition
  and nothing ever restored it, so after the first unlock the window could never
  be resized again. Resizability is now tied to the mode.
- **Clipboard.** Three divergent implementations were replaced by one
  `useClipboard` hook: an earlier copy's wipe timer could erase a later copy, and
  none of them handled a rejected write or cleaned up on unmount.
- **Audio.** The unlock chime never resumed its suspended `AudioContext`, so the
  first chime silently did nothing. It is now resumed on demand and can be turned
  off in Settings.
- **Preferences.** Preference keys are typed, `localStorage` access is guarded,
  and the legacy `keyrpt-*` key is removed after migrating.

### 7.12 Not done in this pass

Stated plainly so it is not mistaken for complete:

- **List virtualisation.** `design.md` asks for it past ~200 rows. The Nmap host
  and port tables are the worst case. Rows are now memoised and the per-second
  tick no longer re-renders the list, but long lists are still fully rendered.
- **Dead CSS.** `global.css` still contains the unused legacy lock-console block
  (~600 lines), orphaned `.brand-mark*` rules, and duplicate selectors. Removing
  them needs visual verification this environment could not provide.
- **Off-grid spacing.** Many spacing values in `global.css` are not multiples of
  the 8px grid the design contract specifies.
- **`migrate_legacy_vault` does not re-encrypt `username`/`url`/`notes`.** Those
  are plaintext in a legacy vault and are encrypted afterwards by
  `migrate_plaintext_fields`, so the end state is correct — but the two steps
  are not one transaction.

- **Light-theme overrides on hardcoded surfaces.** The token work covers the
  Journal and password-strength colours, but several CSS declarations still
  hardcode dark-only values with no `[data-theme="light"]` counterpart: the
  `.drop-overlay` background (`rgb(3, 6, 9)`), the `rgba(255,255,255,0.0xx)`
  surface washes, `.snake-eye-pupil { fill: #060708 }`, and the dark `--danger`
  rgba values. Light mode still shows dark artefacts in those spots.
- **`tauri-plugin-fs` is still exposed to the webview.** The plan was to move
  backup file I/O into Rust and drop the plugin. That was deliberately not done:
  a Rust command taking an arbitrary path from the webview would introduce an
  arbitrary-file-write primitive, which is worse than the read scope it removes.
  Narrowing or removing the `$APPDATA/**` read scope needs a decision about where
  users are allowed to keep backup files, so it was left alone rather than
  guessed at.

### 7.13 Verification performed, and what was not verified

Run and passing:

- `cargo test` — 22 passed, 2 ignored (the two live-network HIBP checks, now
  `#[ignore]`d so the suite is offline and deterministic).
- `cargo clippy --all-targets -- -D warnings` — clean.
- `npx tsc -b && npm run build` — clean.

Checked mechanically against the build output:

- `dist/index.html` contains no inline `style` attribute and no `<style>` block,
  and the minified bundle contains no `style:` object props, so the
  `style-src 'self'` production CSP has nothing to block. The three toolbox pages
  emit as separate chunks with no `modulepreload`, so they stay off the startup
  path.

**Not verified: the app was never actually run.** This environment has no
display, so no Tauri window was launched. The CSP change, the window resizing
behaviour, the modal focus trap, the static `.project-card` restructure, the
removed inline styles, and every visual change are validated only by
type-checking and by reading the built output. They need a real smoke test before
release:

1. Launch on a machine with a display and confirm the vault renders **styled**
   (this is the direct test of the CSP change).
2. Lock → unlock → lock by button, shortcut, auto-lock, and window blur.
3. Export a backup, wipe the vault, import it, and confirm every field in every
   section is readable.
4. Toggle light/dark on every page.
5. Open a large Nmap XML and confirm the host/port tables render.
6. Tab through each modal and confirm focus stays inside it.
