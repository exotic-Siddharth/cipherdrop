import { CircleAlert, RotateCw, type LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '../../lib/cn';
import { describeError } from '../../lib/errors';
import { Button } from './Button';

export type EmptyStateTone = 'default' | 'danger' | 'warning' | 'success';

const ICON_TONES: Record<EmptyStateTone, string> = {
  default: 'bg-primary/10 text-primary-ink',
  danger: 'bg-danger/10 text-danger-ink',
  warning: 'bg-warning/10 text-warning-ink',
  success: 'bg-success/10 text-success-ink',
};

export interface EmptyStateProps {
  icon?: LucideIcon;
  title: ReactNode;
  description?: ReactNode;
  /** Call to action (Button / ButtonLink). */
  action?: ReactNode;
  tone?: EmptyStateTone;
  /** Dashed outline (use inside lists and cards). */
  bordered?: boolean;
  /** Heading level of the title (default h2; h1 when the state is the whole page, e.g. a 404). */
  titleAs?: 'h1' | 'h2' | 'h3';
  size?: 'sm' | 'md';
  className?: string;
  children?: ReactNode;
}

/** Centered empty/blocked/error state: icon, title, description and an action. */
export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  tone = 'default',
  bordered = false,
  titleAs: Title = 'h2',
  size = 'md',
  className,
  children,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center text-center',
        size === 'md' ? 'gap-3 px-6 py-12' : 'gap-2 px-4 py-8',
        bordered && 'rounded-xl border border-dashed border-border-strong/60',
        className,
      )}
    >
      {Icon ? (
        <span
          className={cn(
            'inline-flex items-center justify-center rounded-full',
            size === 'md' ? 'mb-1 size-12' : 'size-10',
            ICON_TONES[tone],
          )}
        >
          <Icon className={size === 'md' ? 'size-6' : 'size-5'} aria-hidden="true" />
        </span>
      ) : null}
      <Title
        className={cn('font-semibold text-foreground', size === 'md' ? 'text-lg' : 'text-base')}
      >
        {title}
      </Title>
      {description ? (
        <p className="max-w-md text-sm leading-relaxed text-muted-strong">{description}</p>
      ) : null}
      {children}
      {action ? <div className="mt-2 flex flex-wrap justify-center gap-3">{action}</div> : null}
    </div>
  );
}

export interface ErrorStateProps extends Omit<EmptyStateProps, 'description' | 'tone'> {
  /** The thrown error; its user-facing text becomes the description. */
  error?: unknown;
  /** Shows a "Try again" button. */
  onRetry?: () => void;
  retrying?: boolean;
}

/** EmptyState for failed loads, with the error text and a retry button. */
export function ErrorState({
  icon = CircleAlert,
  title,
  error,
  onRetry,
  retrying = false,
  action,
  ...props
}: ErrorStateProps) {
  return (
    <EmptyState
      icon={icon}
      tone="danger"
      title={title}
      description={describeError(error)}
      action={
        onRetry || action ? (
          <>
            {onRetry ? (
              <Button variant="outline" icon={RotateCw} onClick={onRetry} loading={retrying}>
                Try again
              </Button>
            ) : null}
            {action}
          </>
        ) : undefined
      }
      {...props}
    />
  );
}
