import { useId, type ReactNode } from 'react';
import { cn } from '../../lib/cn';

export type ProgressTone = 'primary' | 'success' | 'warning' | 'danger';

const TONES: Record<ProgressTone, string> = {
  primary: 'bg-primary',
  success: 'bg-success',
  warning: 'bg-warning',
  danger: 'bg-danger',
};

const HEIGHTS = { sm: 'h-1.5', md: 'h-2.5', lg: 'h-3.5' } as const;

export interface ProgressBarProps {
  /** Progress in [0, max]. Ignored when indeterminate. */
  value?: number;
  max?: number;
  /** Accessible name; shown above the bar unless hideLabel. */
  label: ReactNode;
  hideLabel?: boolean;
  /** Show the value (valueText, or the percentage) at the end of the label row. */
  showValue?: boolean;
  /** Human text for assistive tech and the value slot, e.g. "12.3 MB of 40 MB". */
  valueText?: string;
  tone?: ProgressTone;
  size?: keyof typeof HEIGHTS;
  indeterminate?: boolean;
  className?: string;
}

/** role="progressbar" with min/max/now (spec 11.1: progress for encryption, upload and download). */
export function ProgressBar({
  value = 0,
  max = 100,
  label,
  hideLabel = false,
  showValue = false,
  valueText,
  tone = 'primary',
  size = 'md',
  indeterminate = false,
  className,
}: ProgressBarProps) {
  const labelId = useId();
  const safeMax = max > 0 ? max : 100;
  const clamped = Math.min(safeMax, Math.max(0, Number.isFinite(value) ? value : 0));
  const percent = (clamped / safeMax) * 100;
  const shownValue = valueText ?? `${Math.round(percent)}%`;
  return (
    <div className={cn('w-full', className)}>
      {!hideLabel || showValue ? (
        <div className="mb-1.5 flex items-baseline justify-between gap-3 text-sm">
          <span
            id={labelId}
            className={cn('min-w-0 truncate text-foreground', hideLabel && 'sr-only')}
          >
            {label}
          </span>
          {showValue && !indeterminate ? (
            <span className="shrink-0 tabular-nums text-muted-strong">{shownValue}</span>
          ) : null}
        </div>
      ) : (
        <span id={labelId} className="sr-only">
          {label}
        </span>
      )}
      <div
        role="progressbar"
        aria-labelledby={labelId}
        aria-valuemin={0}
        aria-valuemax={safeMax}
        aria-valuenow={indeterminate ? undefined : Math.round(clamped)}
        aria-valuetext={indeterminate ? undefined : shownValue}
        aria-busy={indeterminate || undefined}
        className={cn('relative w-full overflow-hidden rounded-full bg-border', HEIGHTS[size])}
      >
        <div
          className={cn(
            'h-full rounded-full',
            TONES[tone],
            indeterminate
              ? 'absolute inset-y-0 left-0 w-2/5 motion-safe:animate-progress-indeterminate'
              : 'transition-[width] duration-300 ease-out',
          )}
          style={indeterminate ? undefined : { width: `${percent}%` }}
        />
      </div>
    </div>
  );
}
