import { Icon } from "./Icon";
import { ModalOverlay } from "./ModalOverlay";

interface ConfirmDialogProps {
  title: string;
  message: string;
  confirmLabel: string;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Confirmation gate for destructive or irreversible actions.
 *
 * Uses only existing design tokens: `btn-secondary` plus the `btn-danger`
 * colour modifier, so the danger colour stays reserved for destructive intent.
 */
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
      <div className="modal">
        <div className="modal-heading">
          <span className="modal-icon"><Icon name="trash" size={18} /></span>
          <div>
            <h4 id="confirm-dialog-title">{title}</h4>
            <p>{message}</p>
          </div>
        </div>
        <div className="modal-actions">
          <button className="btn-secondary" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button className="btn-secondary btn-danger" onClick={onConfirm} disabled={busy}>
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </div>
    </ModalOverlay>
  );
}
