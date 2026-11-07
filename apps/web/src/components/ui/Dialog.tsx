import { X } from 'lucide-react';
import {
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  type RefObject,
} from 'react';
import { createPortal } from 'react-dom';
import { toast } from 'sonner';
import { cn } from '../../lib/cn';
import { describeError } from '../../lib/errors';
import { Button } from './Button';
import { focusableWithin } from './variants';

const SIZES = {
  sm: 'max-w-md',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
} as const;

/**
 * Open dialogs, bottom to top. Only the top one handles keys; the app root (#root) and every lower dialog are
 * made `inert`, so neither the mouse nor assistive tech can reach what is behind the top dialog.
 */
const stack: HTMLElement[] = [];
let savedBodyStyle: { overflow: string; paddingRight: string } | null = null;

function syncStack() {
  const top = stack[stack.length - 1];
  const root = document.getElementById('root');
  if (root) {
    if (stack.length > 0) root.setAttribute('inert', '');
    else root.removeAttribute('inert');
  }
  for (const el of stack) {
    if (el === top) el.removeAttribute('inert');
    else el.setAttribute('inert', '');
  }
  const body = document.body;
  if (stack.length > 0 && savedBodyStyle === null) {
    // Lock page scroll; pad by the scrollbar width so the page behind does not shift sideways.
    const scrollbar = window.innerWidth - document.documentElement.clientWidth;
    savedBodyStyle = { overflow: body.style.overflow, paddingRight: body.style.paddingRight };
    body.style.overflow = 'hidden';
    if (scrollbar > 0) body.style.paddingRight = `${scrollbar}px`;
  } else if (stack.length === 0 && savedBodyStyle !== null) {
    body.style.overflow = savedBodyStyle.overflow;
    body.style.paddingRight = savedBodyStyle.paddingRight;
    savedBodyStyle = null;
  }
}

export interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Accessible name (rendered as the heading). */
  title: ReactNode;
  /** Accessible description under the title. */
  description?: ReactNode;
  children?: ReactNode;
  /** Action buttons (right-aligned, stacked on mobile). */
  footer?: ReactNode;
  size?: keyof typeof SIZES;
  /** false: Escape, backdrop clicks and the close button are disabled (e.g. while a request runs). */
  dismissible?: boolean;
  /** Element to focus on open (default: first focusable control, or [data-autofocus]). */
  initialFocusRef?: RefObject<HTMLElement | null>;
  hideCloseButton?: boolean;
  className?: string;
}

/**
 * Modal dialog: role="dialog" + aria-modal, labelled by its title and described by its description; focus is
 * trapped inside, Escape and backdrop clicks close it (when dismissible), and focus returns to the element
 * that opened it. Rendered in a portal on <body>.
 */
export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  size = 'md',
  dismissible = true,
  initialFocusRef,
  hideCloseButton = false,
  className,
}: DialogProps) {
  const titleId = useId();
  const descriptionId = useId();
  const containerRef = useRef<HTMLDivElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const pointerDownOutside = useRef(false);
  const latest = useRef({ onOpenChange, dismissible });
  useEffect(() => {
    latest.current = { onOpenChange, dismissible };
  });

  useLayoutEffect(() => {
    if (!open) return;
    const container = containerRef.current;
    const panel = panelRef.current;
    if (!container || !panel) return;
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    stack.push(container);
    syncStack();

    const target =
      initialFocusRef?.current ??
      panel.querySelector<HTMLElement>('[data-autofocus]') ??
      focusableWithin(panel).find((el) => !el.hasAttribute('data-dialog-close')) ??
      panel;
    target.focus({ preventScroll: true });

    const onDocumentKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || stack[stack.length - 1] !== container) return;
      if (latest.current.dismissible) {
        e.preventDefault();
        latest.current.onOpenChange(false);
      }
    };
    document.addEventListener('keydown', onDocumentKeyDown);

    return () => {
      document.removeEventListener('keydown', onDocumentKeyDown);
      const index = stack.indexOf(container);
      if (index >= 0) stack.splice(index, 1);
      syncStack();
      if (opener?.isConnected) opener.focus({ preventScroll: true });
    };
  }, [open, initialFocusRef]);

  if (!open) return null;

  const trapTab = (e: ReactKeyboardEvent<HTMLDivElement>) => {
    if (e.key !== 'Tab' || stack[stack.length - 1] !== containerRef.current) return;
    const panel = panelRef.current;
    if (!panel) return;
    const items = focusableWithin(panel);
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement;
    if (!first || !last) {
      e.preventDefault();
      panel.focus();
      return;
    }
    if (e.shiftKey && (active === first || active === panel || !panel.contains(active))) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (active === last || !panel.contains(active))) {
      e.preventDefault();
      first.focus();
    }
  };

  return createPortal(
    <div ref={containerRef} className="fixed inset-0 z-50" onKeyDown={trapTab}>
      <div className="fixed inset-0 bg-overlay motion-safe:animate-fade-in" aria-hidden="true" />
      <div
        className="fixed inset-0 overflow-y-auto"
        onPointerDown={(e) => {
          pointerDownOutside.current = !panelRef.current?.contains(e.target as Node);
        }}
        onClick={(e) => {
          const outside = !panelRef.current?.contains(e.target as Node);
          if (outside && pointerDownOutside.current && dismissible) onOpenChange(false);
          pointerDownOutside.current = false;
        }}
      >
        <div className="flex min-h-full items-end justify-center p-4 sm:items-center sm:p-6">
          <div
            ref={panelRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby={titleId}
            aria-describedby={description ? descriptionId : undefined}
            tabIndex={-1}
            className={cn(
              'relative w-full rounded-2xl border border-border bg-surface text-foreground shadow-popover',
              'outline-none motion-safe:animate-pop-in',
              SIZES[size],
              className,
            )}
          >
            <div className="flex items-start justify-between gap-4 px-5 pt-5 sm:px-6 sm:pt-6">
              <div className="min-w-0">
                <h2 id={titleId} className="text-lg font-semibold leading-7 tracking-tight">
                  {title}
                </h2>
                {description ? (
                  <div id={descriptionId} className="mt-1 text-sm leading-relaxed text-muted">
                    {description}
                  </div>
                ) : null}
              </div>
              {dismissible && !hideCloseButton ? (
                <button
                  type="button"
                  data-dialog-close=""
                  aria-label="Close"
                  onClick={() => onOpenChange(false)}
                  className="-mr-2 -mt-1 inline-flex size-9 shrink-0 items-center justify-center rounded-lg text-muted transition-colors hover:bg-surface-2 hover:text-foreground"
                >
                  <X className="size-5" aria-hidden="true" />
                </button>
              ) : null}
            </div>
            {children ? <div className="px-5 pt-4 sm:px-6">{children}</div> : null}
            <div className="h-5 sm:h-6" />
            {footer ? (
              <div className="flex flex-col-reverse gap-2 rounded-b-2xl border-t border-border bg-surface-2/60 px-5 py-4 sm:flex-row sm:justify-end sm:px-6">
                {footer}
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </div>,
    document.body,
  );
}

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** 'danger' uses a red confirm button and focuses Cancel first. */
  tone?: 'default' | 'danger';
  /**
   * Runs on confirm. While its promise is pending the dialog shows a spinner and cannot be dismissed. It closes
   * when the promise resolves (unless it resolves to `false`). If it throws, the dialog stays open and shows a
   * toast with the error text, so callers do not need their own error toast.
   */
  onConfirm: () => void | boolean | Promise<void | boolean>;
  confirmDisabled?: boolean;
  /** External busy flag (e.g. a mutation's isPending). */
  loading?: boolean;
}

/** Confirmation for consequential actions: delete drop, revoke sessions, consume the last download... */
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  tone = 'default',
  onConfirm,
  confirmDisabled = false,
  loading = false,
}: ConfirmDialogProps) {
  const [pending, setPending] = useState(false);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  const busy = pending || loading;

  const handleConfirm = async () => {
    setPending(true);
    try {
      const result = await onConfirm();
      if (result !== false) onOpenChange(false);
    } catch (err) {
      toast.error(describeError(err));
    } finally {
      setPending(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!busy) onOpenChange(next);
      }}
      title={title}
      description={description}
      size="sm"
      dismissible={!busy}
      initialFocusRef={tone === 'danger' ? cancelRef : confirmRef}
      footer={
        <>
          <Button
            ref={cancelRef}
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={busy}
          >
            {cancelLabel}
          </Button>
          <Button
            ref={confirmRef}
            variant={tone === 'danger' ? 'danger' : 'primary'}
            loading={busy}
            disabled={confirmDisabled}
            onClick={() => void handleConfirm()}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      {children}
    </Dialog>
  );
}
