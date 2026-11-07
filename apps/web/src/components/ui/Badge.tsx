import type { LucideIcon } from 'lucide-react';
import type { ComponentProps } from 'react';
import { cn } from '../../lib/cn';

export type BadgeTone = 'neutral' | 'primary' | 'success' | 'warning' | 'danger' | 'outline';

const TONES: Record<BadgeTone, string> = {
  neutral: 'bg-surface-2 text-muted-strong ring-border',
  primary: 'bg-primary/10 text-primary-ink ring-primary/25',
  success: 'bg-success/10 text-success-ink ring-success/25',
  warning: 'bg-warning/10 text-warning-ink ring-warning/30',
  danger: 'bg-danger/10 text-danger-ink ring-danger/25',
  outline: 'bg-transparent text-foreground ring-border-strong',
};

const DOTS: Record<BadgeTone, string> = {
  neutral: 'bg-muted',
  primary: 'bg-primary',
  success: 'bg-success',
  warning: 'bg-warning',
  danger: 'bg-danger',
  outline: 'bg-foreground',
};

export interface BadgeProps extends ComponentProps<'span'> {
  tone?: BadgeTone;
  size?: 'sm' | 'md';
  icon?: LucideIcon;
  /** Leading status dot (when there is no icon). */
  dot?: boolean;
}

/** Small status label. Text colours are the AA "ink" shades on soft tinted fills. */
export function Badge({
  tone = 'neutral',
  size = 'sm',
  icon: Icon,
  dot = false,
  className,
  children,
  ...props
}: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex max-w-full items-center gap-1 whitespace-nowrap rounded-full font-medium ring-1 ring-inset',
        size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-sm',
        TONES[tone],
        className,
      )}
      {...props}
    >
      {Icon ? (
        <Icon className={size === 'sm' ? 'size-3.5' : 'size-4'} aria-hidden="true" />
      ) : dot ? (
        <span className={cn('size-1.5 rounded-full', DOTS[tone])} aria-hidden="true" />
      ) : null}
      <span className="truncate">{children}</span>
    </span>
  );
}
