import { useEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";

interface ModalOverlayProps {
  children: ReactNode;
  onClose: () => void;
  /** id of the element that names this dialog, for screen readers. */
  labelledBy?: string;
}

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

/**
 * Modal container: click-outside to close, Escape to close, and a real focus
 * trap so keyboard users cannot tab into the page behind the dialog.
 *
 * Previously focus was never moved into the dialog, never contained, and never
 * restored, and the dialog had no `role` or `aria-modal` at all.
 */
export function ModalOverlay({ children, onClose, labelledBy }: ModalOverlayProps) {
  const overlayRef = useRef<HTMLDivElement>(null);
  // Kept in a ref so the effect does not re-subscribe on every render. Callers
  // pass inline arrow functions, so an effect keyed on `onClose` would tear down
  // and re-add its listener constantly.
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    const overlay = overlayRef.current;
    const previouslyFocused = document.activeElement as HTMLElement | null;

    if (overlay && !overlay.contains(document.activeElement)) {
      const first = overlay.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
      (first ?? overlay).focus();
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        // Stop other listeners (a second stacked modal, the dashboard's lock
        // shortcut) from also reacting to the same press.
        event.stopPropagation();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab" || !overlay) return;

      const focusable = Array.from(overlay.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR));
      if (focusable.length === 0) {
        event.preventDefault();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;

      if (event.shiftKey && (active === first || !overlay.contains(active))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };

    window.addEventListener("keydown", handleKeyDown);

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      previouslyFocused?.focus?.();
    };
  }, []);

  return createPortal(
    <div
      className="modal-overlay"
      ref={overlayRef}
      role="dialog"
      aria-modal="true"
      aria-labelledby={labelledBy}
      tabIndex={-1}
      onClick={(event) => {
        // Only a click on the backdrop itself closes the dialog. Consumers no
        // longer have to remember to stop propagation on interior clicks.
        if (event.target === event.currentTarget) onCloseRef.current();
      }}
    >
      {children}
    </div>,
    document.body,
  );
}
