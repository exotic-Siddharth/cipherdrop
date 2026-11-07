import { useId, type ComponentProps, type ReactNode } from 'react';
import { cn } from '../../lib/cn';
import { Field } from './Field';
import { describedBy } from './variants';

export interface TextareaProps extends ComponentProps<'textarea'> {
  label?: ReactNode;
  hideLabel?: boolean;
  hint?: ReactNode;
  error?: ReactNode;
  optional?: boolean;
  /** Show "used / maxLength" under the field (requires maxLength; value must be controlled). */
  showCount?: boolean;
  containerClassName?: string;
}

/** Multi-line text with label, hint, error and an optional character counter (e.g. the 2000-char note). */
export function Textarea({
  id: idProp,
  label,
  hideLabel,
  hint,
  error,
  optional,
  showCount = false,
  maxLength,
  value,
  rows = 4,
  className,
  containerClassName,
  'aria-describedby': ariaDescribedBy,
  ...props
}: TextareaProps) {
  const autoId = useId();
  const id = idProp ?? autoId;
  const count = typeof value === 'string' ? value.length : 0;
  const counterId = `${id}-count`;
  const withCount = showCount && maxLength !== undefined;
  return (
    <Field
      id={id}
      label={label}
      hideLabel={hideLabel}
      hint={hint}
      error={error}
      optional={optional}
      className={containerClassName}
    >
      <textarea
        id={id}
        rows={rows}
        maxLength={maxLength}
        value={value}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(id, {
          hint,
          error,
          extra:
            [withCount ? counterId : undefined, ariaDescribedBy].filter(Boolean).join(' ') ||
            undefined,
        })}
        className={cn(
          'w-full min-w-0 resize-y rounded-lg border border-border-strong bg-surface px-3 py-2 text-sm text-foreground shadow-card',
          'placeholder:text-muted transition-colors',
          'focus-visible:border-primary focus-visible:outline-2 focus-visible:outline-offset-0 focus-visible:outline-primary',
          'aria-invalid:border-danger disabled:cursor-not-allowed disabled:opacity-60',
          className,
        )}
        {...props}
      />
      {withCount ? (
        <p
          id={counterId}
          className={cn(
            'self-end text-xs tabular-nums',
            count >= maxLength ? 'font-medium text-warning-ink' : 'text-muted-strong',
          )}
        >
          {count.toLocaleString()} / {maxLength.toLocaleString()}
        </p>
      ) : null}
    </Field>
  );
}
