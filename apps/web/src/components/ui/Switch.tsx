import { useId, type ReactNode } from 'react';
import { cn } from '../../lib/cn';

export interface SwitchProps {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  label: ReactNode;
  description?: ReactNode;
  hideLabel?: boolean;
  disabled?: boolean;
  /** 'inline': [switch] Label. 'row': Label on the left, switch on the right (settings rows). */
  layout?: 'inline' | 'row';
  id?: string;
  className?: string;
  name?: string;
}

/** On/off toggle (button role="switch"); the label is clickable too. */
export function Switch({
  checked,
  onCheckedChange,
  label,
  description,
  hideLabel = false,
  disabled = false,
  layout = 'inline',
  id: idProp,
  className,
  name,
}: SwitchProps) {
  const autoId = useId();
  const id = idProp ?? autoId;
  const labelId = `${id}-label`;
  const descId = `${id}-desc`;

  const control = (
    <button
      id={id}
      type="button"
      role="switch"
      name={name}
      aria-checked={checked}
      aria-labelledby={labelId}
      aria-describedby={description ? descId : undefined}
      disabled={disabled}
      onClick={() => onCheckedChange(!checked)}
      className={cn(
        'relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors',
        'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary',
        'disabled:cursor-not-allowed disabled:opacity-50',
        checked ? 'bg-primary' : 'bg-border-strong',
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          'pointer-events-none inline-block size-5 rounded-full bg-white shadow-sm ring-0 transition-transform',
          checked ? 'translate-x-5' : 'translate-x-0',
        )}
      />
    </button>
  );

  const text = (
    <span className={cn('flex min-w-0 flex-col', hideLabel && 'sr-only')}>
      <span
        id={labelId}
        className={cn('text-sm font-medium text-foreground', !disabled && 'cursor-pointer')}
        onClick={() => !disabled && onCheckedChange(!checked)}
      >
        {label}
      </span>
      {description ? (
        <span id={descId} className="text-xs leading-relaxed text-muted-strong">
          {description}
        </span>
      ) : null}
    </span>
  );

  return (
    <div
      className={cn(
        'flex gap-3',
        layout === 'row' ? 'items-center justify-between' : 'items-start',
        className,
      )}
    >
      {layout === 'row' ? (
        <>
          {text}
          {control}
        </>
      ) : (
        <>
          {control}
          {text}
        </>
      )}
    </div>
  );
}
