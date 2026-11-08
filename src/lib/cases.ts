/** Labels for case notes, shared by the notebook and the timeline. */

export const KINDS: { value: string; label: string }[] = [
  { value: "note", label: "Note" },
  { value: "finding", label: "Finding" },
  { value: "recon", label: "Recon" },
  { value: "exploitation", label: "Exploitation" },
  { value: "post_exploit", label: "Post-exploitation" },
  { value: "remediation", label: "Remediation" },
];

export const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;

export const STATUS_LABELS: Record<string, string> = {
  planning: "Planning",
  in_progress: "In progress",
  completed: "Closed",
};

export function kindLabel(value: string): string {
  return KINDS.find((kind) => kind.value === value)?.label ?? value;
}

/** Only high and critical take the danger colour. */
export function isLoud(severity: string | null | undefined): boolean {
  return severity === "high" || severity === "critical";
}
