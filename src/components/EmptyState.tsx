import { Icon, type IconName } from "./Icon";

interface EmptyStateProps {
  /** Console-style prompt line, e.g. "$ vault ls". */
  prompt: string;
  /** The plain-language result line, e.g. "no credentials stored". */
  output: string;
  actionLabel?: string;
  actionIcon?: IconName;
  onAction?: () => void;
}

/**
 * The one empty-state block. Previously copy-pasted into five pages, which is
 * how the console-prompt convention drifted between them.
 */
export function EmptyState({
  prompt,
  output,
  actionLabel,
  actionIcon = "plus",
  onAction,
}: EmptyStateProps) {
  return (
    <div className="vault-empty">
      <span className="empty-prompt">{prompt}</span>
      <span className="empty-output">{output}</span>
      {actionLabel && onAction && (
        <button className="empty-action" onClick={onAction}>
          <Icon name={actionIcon} size={14} /> {actionLabel}
        </button>
      )}
    </div>
  );
}
