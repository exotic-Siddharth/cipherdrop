import { CircleAlert, CircleCheck, Info, TriangleAlert, X, type LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '../../lib/cn';

export type AlertTone = 'info' | 'success' | 'warning' | 'danger';

const TONES: Record<AlertTone, { box: string; icon: string; Icon: LucideIcon }> = {
  info: { box: 'border-primary/25 bg-primary/5 text-foreground', icon: 'text-primary', Icon: Info },
  success: {
    box: 'border-success/30 bg-success/5 text-foreground',
    icon: 'text-success',
    Icon: CircleCheck,
  },
  warning: {
    box: 'border-warning/35 bg-warning/5 text-foreground',
    icon: 'text-warning',
    Icon: TriangleAlert,
  },
  danger: {
    box: 'border-danger/35 bg-danger/5 text-foreground',
    icon: 'text-danger',
    Icon: CircleAlert,
  },
};

export interface AlertProps {
  tone?: AlertTone;
  title?: ReactNode;
  children?: ReactNode;
  /** Override the tone's icon (or pass null for none). */
  icon?: LucideIcon | null;
  /** Buttons/links under the text. */
  action?: ReactNode;
  onDismiss?: () => void;
  /**
   * 'assertive' (role="alert") interrupts screen readers: use it for verdicts that appear after an action,
   * like the integrity failure. 'polite' uses role="status". Default 'off' (static notices).
   */
  live?: 'off' | 'polite' | 'assertive';
  /** Larger, more prominent variant (e.g. "This file was modified in transit or storage."). */
  prominent?: boolean;
  className?: string;
}

/** Inline notice for info, success, warning and error messages. */
export function Alert({
  tone = 'info',
  title,
  children,
  icon,
  action,
  onDismiss,
  live = 'off',
  prominent = false,
  className,
}: AlertProps) {
  const t = TONES[tone];
  const Icon = icon === null ? null : (icon ?? t.Icon);
  const role = live === 'assertive' ? 'alert' : live === 'polite' ? 'status' : undefined;
  return (
    <div
      role={role}
      className={cn(
        'relative flex gap-3 rounded-xl border',
        prominent ? 'border-2 p-5' : 'p-4',
        t.box,
        className,
      )}
    >
      {Icon ? (
        <Icon
          className={cn('shrink-0', prominent ? 'size-6' : 'mt-0.5 size-5', t.icon)}
          aria-hidden="true"
        />
      ) : null}
      <div className={cn('min-w-0 flex-1', onDismiss && 'pr-6')}>
        {title ? (
          <p className={cn('font-semibold text-foreground', prominent ? 'text-base' : 'text-sm')}>
            {title}
          </p>
        ) : null}
        {children ? (
          <div
            className={cn('text-sm leading-relaxed text-foreground/85', title ? 'mt-1' : undefined)}
          >
            {children}
          </div>
        ) : null}
        {action ? <div className="mt-3 flex flex-wrap gap-2">{action}</div> : null}
      </div>
      {onDismiss ? (
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss"
          className="absolute right-2 top-2 inline-flex size-7 items-center justify-center rounded-md text-muted transition-colors hover:bg-surface-2 hover:text-foreground"
        >
          <X className="size-4" aria-hidden="true" />
        </button>
      ) : null}
    </div>
  );
}
