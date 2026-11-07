/**
 * Map an error from the backend to a message that is safe to show the user.
 *
 * Backend errors are useful when they describe something the user can act on
 * (a too-short password, an unreadable backup), and harmful when they leak
 * database or crypto internals. Only messages on this list reach the UI;
 * anything else is logged and replaced with a generic string.
 */
const ERROR_MESSAGES: Array<[prefix: string, message: string]> = [
  ["vault is locked", "The vault is locked. Unlock it and try again."],
  ["Master password must be at least", "Master password is too short. Use at least 12 characters."],
  ["New master password must be at least", "The new master password is too short. Use at least 12 characters."],
  ["Backup password must be at least", "The backup password is too short. Use at least 8 characters."],
  ["Backup password must not be empty", "Enter a backup password."],
  ["secret is too short", "That 2FA secret is too short to be valid."],
  ["secret is empty", "Enter a 2FA secret."],
  ["secret decodes to zero bytes", "That 2FA secret is not valid base32."],
  ["invalid character", "That 2FA secret contains characters that are not valid base32."],
  ["credential not found", "That login no longer exists."],
  ["could not decrypt that field", "That field could not be decrypted with this vault's key."],
  ["no 2FA set up", "This login has no one-time code set up."],
  ["that field is empty", "That field is empty, so there is nothing to copy."],
  ["that login has no password", "This login has no password to check."],
  ["a vault already exists", "A vault already exists. Unlock it instead."],
  ["no vault has been created yet", "No vault exists yet. Restart Encra to set one up."],
  ["scan file is too large", "That scan file is too large to parse."],
  ["scan contains more than", "That scan has an unreasonable number of hosts."],
  ["host has more than", "That scan has an unreasonable number of ports on one host."],
  ["invalid backup format", "That file is not an Encra backup."],
  ["wrong backup password", "Wrong backup password, or the file is damaged."],
  ["key-derivation settings are out of range", "That backup file has invalid settings and was not opened."],
  ["invalid key-derivation settings", "That backup file has invalid settings and was not opened."],
  ["could not make a safety copy", "Couldn’t make a safety copy before upgrading the vault. Check there’s free disk space, then unlock again."],
  ["the safety copy failed", "The safety copy before the upgrade failed its check. Nothing was changed; unlock again to retry."],
  ["unsupported backup version", "That backup was made by a different version of Encra."],
  ["cannot be decrypted with this vault's key", "That backup belongs to a different vault and cannot be restored here."],
  ["import failed", "Import failed. Nothing was changed in your vault."],
  ["HIBP API unreachable", "Could not reach the breach-check service."],
  ["is too long", "One of the fields is too long."],
  ["must not be empty", "A required field is empty."],
];

export function describeError(error: unknown, fallback: string): string {
  const raw =
    typeof error === "string" ? error : error instanceof Error ? error.message : "";

  for (const [prefix, message] of ERROR_MESSAGES) {
    if (raw.startsWith(prefix)) return message;
  }

  if (raw) console.error("Unexpected error surfaced to the user", raw);
  return fallback;
}
