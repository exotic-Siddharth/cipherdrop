import { useId, type ComponentProps, type ReactNode } from 'react';
import { cn } from '../../lib/cn';

export interface CheckboxProps extends Omit<ComponentProps<'input'>, 'type'> {
  label: ReactNode;
  description?: ReactNode;
  error?: ReactNode;
  containerClassName?: string;
}

/**
 * Native checkbox with label and description (e.g. "I saved my recovery key", "include the decryption key").
 * Use `checked` + `onChange` (event.target.checked).
 */
export function Checkbox({
  id: idProp,
  label,
  description,
  error,
  className,
  containerClassName,
  disabled,
  'aria-describedby': ariaDescribedBy,
  ...props
}: CheckboxProps) {
  const autoId = useId();
  const id = idProp ?? autoId;
  const descId = description ? `${id}-desc` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  return (
    <div className={cn('flex flex-col gap-1', containerClassName)}>
      <div className="flex items-start gap-3">
        <input
          id={id}
          type="checkbox"
          disabled={disabled}
          aria-invalid={error ? true : undefined}
          aria-describedby={
            [descId, errorId, ariaDescribedBy].filter(Boolean).join(' ') || undefined
          }
          className={cn(
            'mt-0.5 size-4 shrink-0 cursor-pointer rounded border-border-strong accent-primary',
            'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary',
            'disabled:cursor-not-allowed disabled:opacity-50',
            className,
          )}
          {...props}
        />
        <div className="flex min-w-0 flex-col">
          <label
            htmlFor={id}
            className={cn(
              'text-sm font-medium text-foreground',
              disabled ? 'cursor-not-allowed opacity-60' : 'cursor-pointer',
            )}
          >
            {label}
          </label>
          {description ? (
            <p id={descId} className="text-xs leading-relaxed text-muted-strong">
              {description}
            </p>
          ) : null}
        </div>
      </div>
      {error ? (
        <p id={errorId} className="pl-7 text-xs font-medium text-danger-ink">
          {error}
        </p>
      ) : null}
    </div>
  );
}
