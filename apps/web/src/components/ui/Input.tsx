import type { LucideIcon } from 'lucide-react';
import { useId, type ComponentProps, type ReactNode } from 'react';
import { cn } from '../../lib/cn';
import { Field } from './Field';
import { controlClasses, describedBy, type ControlSize } from './variants';

export interface InputProps extends Omit<ComponentProps<'input'>, 'size'> {
  label?: ReactNode;
  hideLabel?: boolean;
  hint?: ReactNode;
  /** Error text: also sets aria-invalid. */
  error?: ReactNode;
  optional?: boolean;
  labelAction?: ReactNode;
  /** Decorative icon inside the start of the field. */
  leadingIcon?: LucideIcon;
  /** Element inside the end of the field (unit, button). */
  trailing?: ReactNode;
  inputSize?: ControlSize;
  /** Monospace text (links, keys, codes). */
  mono?: boolean;
  /** Class of the outer Field wrapper (`className` styles the <input>). */
  containerClassName?: string;
}

/** Text input with label, hint and error wired for assistive tech. `ref` reaches the <input>. */
export function Input({
  id: idProp,
  label,
  hideLabel,
  hint,
  error,
  optional,
  labelAction,
  leadingIcon: LeadingIcon,
  trailing,
  inputSize = 'md',
  mono = false,
  className,
  containerClassName,
  'aria-describedby': ariaDescribedBy,
  ...props
}: InputProps) {
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
      labelAction={labelAction}
      className={containerClassName}
    >
      <div className="relative flex items-center">
        {LeadingIcon ? (
          <LeadingIcon
            className="pointer-events-none absolute left-3 size-4 text-muted"
            aria-hidden="true"
          />
        ) : null}
        <input
          id={id}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy(id, { hint, error, extra: ariaDescribedBy })}
          className={controlClasses({
            size: inputSize,
            mono,
            className: cn(LeadingIcon && 'pl-9', trailing ? 'pr-11' : undefined, className),
          })}
          {...props}
        />
        {trailing ? <div className="absolute right-1.5 flex items-center">{trailing}</div> : null}
      </div>
    </Field>
  );
}
