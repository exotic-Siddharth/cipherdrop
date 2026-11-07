import { ChevronDown } from 'lucide-react';
import { useId, type ComponentProps, type ReactNode } from 'react';
import { cn } from '../../lib/cn';
import { Field } from './Field';
import { controlClasses, describedBy, type ControlSize } from './variants';

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface SelectProps extends Omit<ComponentProps<'select'>, 'size'> {
  label?: ReactNode;
  hideLabel?: boolean;
  hint?: ReactNode;
  error?: ReactNode;
  optional?: boolean;
  /** Options to render; or pass <option> children instead. */
  options?: readonly SelectOption[];
  selectSize?: ControlSize;
  containerClassName?: string;
}

/** Native <select> (best keyboard, screen-reader and mobile support) styled like the other controls. */
export function Select({
  id: idProp,
  label,
  hideLabel,
  hint,
  error,
  optional,
  options,
  selectSize = 'md',
  className,
  containerClassName,
  children,
  'aria-describedby': ariaDescribedBy,
  ...props
}: SelectProps) {
  const autoId = useId();
  const id = idProp ?? autoId;
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
      <div className="relative flex items-center">
        <select
          id={id}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy(id, { hint, error, extra: ariaDescribedBy })}
          className={controlClasses({
            size: selectSize,
            className: cn('cursor-pointer appearance-none pr-9', className),
          })}
          {...props}
        >
          {options
            ? options.map((o) => (
                <option key={o.value} value={o.value} disabled={o.disabled}>
                  {o.label}
                </option>
              ))
            : children}
        </select>
        <ChevronDown
          className="pointer-events-none absolute right-3 size-4 text-muted"
          aria-hidden="true"
        />
      </div>
    </Field>
  );
}
