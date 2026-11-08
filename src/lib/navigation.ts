import { useEffect, useRef } from "react";

export type Module = "vault" | "journal" | "tools" | "activity" | "settings";
export type ToolId = "pwgen" | "nmap" | "kb";

/** Something the ⌘K palette asks a page to do once it is showing. */
export type PageRequest =
  | { kind: "login"; id: string }
  | { kind: "new-login" }
  | { kind: "import" }
  | { kind: "checkup" }
  | { kind: "case"; id: string }
  | { kind: "new-case" }
  | { kind: "tool"; tool: ToolId; search?: string };

/** A request with a number, so asking for the same thing twice still counts. */
export interface Requested {
  seq: number;
  request: PageRequest;
}

/**
 * Run `handle` once for each new request. The ref keeps React's development
 * double-run of effects from opening a dialog twice.
 */
export function useRequest(requested: Requested | null | undefined, handle: (request: PageRequest) => void): void {
  const handled = useRef(0);
  const handleRef = useRef(handle);
  handleRef.current = handle;
  useEffect(() => {
    if (!requested || requested.seq === handled.current) return;
    handled.current = requested.seq;
    handleRef.current(requested.request);
  }, [requested]);
}
