import { CircleAlert } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '../../lib/cn';

export interface FieldProps {
  /** id of the control; hint and error get `${id}-hint` / `${id}-error` (see describedBy()). */
  id: string;
  label?: ReactNode;
  /** Keep the label for screen readers only. */
  hideLabel?: boolean;
  hint?: ReactNode;
  error?: ReactNode;
  /** Appends "(optional)" to the label. */
  optional?: boolean;
  /** Rendered at the end of the label row, e.g. a "Forgot password?" link. */
  labelAction?: ReactNode;
  className?: string;
  children: ReactNode;
}

/** Label + control + hint + error layout used by every form control; usable for custom controls too. */
export function Field({
  id,
  label,
  hideLabel = false,
  hint,
  error,
  optional = false,
  labelAction,
  className,
  children,
}: FieldProps) {
  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      {label || labelAction ? (
        <div className="flex items-baseline justify-between gap-3">
          {label ? (
            <label
              htmlFor={id}
              className={cn('text-sm font-medium text-foreground', hideLabel && 'sr-only')}
            >
              {label}
              {optional ? (
                <span className="ml-1 font-normal text-muted-strong">(optional)</span>
              ) : null}
            </label>
          ) : (
            <span />
          )}
          {labelAction ? <div className="text-sm">{labelAction}</div> : null}
        </div>
      ) : null}
      {children}
      {hint ? (
        <p id={`${id}-hint`} className="text-xs leading-relaxed text-muted-strong">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p
          id={`${id}-error`}
          className="flex items-start gap-1.5 text-xs font-medium text-danger-ink"
        >
          <CircleAlert className="mt-px size-3.5 shrink-0" aria-hidden="true" />
          <span>{error}</span>
        </p>
      ) : null}
    </div>
  );
}
