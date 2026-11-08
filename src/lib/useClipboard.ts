import { useCallback, useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export type CopyField = "username" | "password" | "url" | "totp";

/**
 * Every copy goes through Rust. Secrets are marked concealed on macOS, wiped
 * after 30 seconds if the clipboard still holds them, and wiped on lock.
 * Vault fields are copied by id, so the secret never passes through the
 * webview.
 */
export function useClipboard(feedbackMs = 1500) {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );

  const flash = useCallback(
    (id: string) => {
      setCopiedId(id);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopiedId(null), feedbackMs);
    },
    [feedbackMs],
  );

  /** Copy one field of a stored login without it reaching the webview. */
  const copyField = useCallback(
    async (credentialId: string, field: CopyField): Promise<void> => {
      await invoke("copy_credential_field", { id: credentialId, field });
      flash(`${credentialId}:${field}`);
    },
    [flash],
  );

  /** Copy text the page already holds (a generated password, a command). */
  const copyText = useCallback(
    async (text: string, id: string): Promise<void> => {
      await invoke("copy_text", { text });
      flash(id);
    },
    [flash],
  );

  /**
   * Copy something Rust looks up itself, such as a case's indicator or a
   * file's hash. Those aren't secrets, so they stay on the clipboard for a
   * report instead of being wiped at 30 seconds.
   */
  const copyVia = useCallback(
    async (command: string, args: Record<string, unknown>, id: string): Promise<void> => {
      await invoke(command, args);
      flash(id);
    },
    [flash],
  );

  return { copyField, copyText, copyVia, copiedId };
}
