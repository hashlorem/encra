interface EmptyStateProps {
  /** One plain sentence saying what is missing. */
  message: string;
  actionLabel?: string;
  onAction?: () => void;
}

export function EmptyState({ message, actionLabel, onAction }: EmptyStateProps) {
  return (
    <div className="empty">
      <p>{message}</p>
      {actionLabel && onAction && (
        <button className="btn-outline" onClick={onAction}>
          {actionLabel}
        </button>
      )}
    </div>
  );
}
