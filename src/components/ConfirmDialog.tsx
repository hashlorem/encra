import { ModalOverlay } from "./ModalOverlay";

interface ConfirmDialogProps {
  title: string;
  message: string;
  confirmLabel: string;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/** Confirmation gate for destructive or irreversible actions. */
export function ConfirmDialog({
  title,
  message,
  confirmLabel,
  busy = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  return (
    <ModalOverlay onClose={busy ? () => undefined : onCancel} labelledBy="confirm-dialog-title">
      <div className="dialog">
        <h2 id="confirm-dialog-title">{title}</h2>
        <p className="lead">{message}</p>
        <div className="actions">
          <button className="btn-outline" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button className="btn-danger" onClick={onConfirm} disabled={busy}>
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}
