import { HardDrive, TriangleAlert } from 'lucide-react';
import { Card } from '../../../components/ui/Card';
import { cn } from '../../../lib/cn';
import { formatBytes, formatPercent } from '../../../lib/format';
import { meterSeverity, type MeterSeverity } from './meterSeverity';

const FILL: Record<MeterSeverity, string> = {
  ok: 'bg-primary',
  warning: 'bg-warning',
  danger: 'bg-danger',
};
// The unfilled track is a lighter step of the same hue as the fill, so the state reads across the whole bar.
const TRACK: Record<MeterSeverity, string> = {
  ok: 'bg-primary/15',
  warning: 'bg-warning/15',
  danger: 'bg-danger/15',
};
const NOTE: Record<Exclude<MeterSeverity, 'ok'>, string> = {
  warning: 'Running low: delete old drops to free space.',
  danger: 'Almost full: new drops may be refused until you free space.',
};

export interface StorageMeterProps {
  usedBytes: number;
  quotaBytes: number;
  className?: string;
}

/** Storage used / quota (spec 11.2). One bar, direct labels, severity in words as well as colour. */
export function StorageMeter({ usedBytes, quotaBytes, className }: StorageMeterProps) {
  const severity = meterSeverity(usedBytes, quotaBytes);
  const ratio = quotaBytes > 0 ? Math.min(1, usedBytes / quotaBytes) : usedBytes > 0 ? 1 : 0;
  const free = Math.max(0, quotaBytes - usedBytes);
  const text = `${formatBytes(usedBytes)} of ${formatBytes(quotaBytes)} used`;
  return (
    <Card
      as="section"
      aria-labelledby="storage-meter-title"
      className={cn('p-5 sm:p-6', className)}
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex min-w-0 items-center gap-3">
          <span className="inline-flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary-ink">
            <HardDrive className="size-5" aria-hidden="true" />
          </span>
          <div className="min-w-0">
            <h2
              id="storage-meter-title"
              className="text-base font-semibold leading-6 tracking-tight text-foreground"
            >
              Storage
            </h2>
            <p className="text-sm text-muted">{formatBytes(free)} free</p>
          </div>
        </div>
        <p className="shrink-0 text-right">
          <span className="text-2xl font-semibold tracking-tight text-foreground">
            {formatBytes(usedBytes)}
          </span>
          <span className="ml-1 text-sm text-muted-strong">/ {formatBytes(quotaBytes)}</span>
        </p>
      </div>
      <div
        role="meter"
        aria-label="Storage used"
        aria-valuemin={0}
        aria-valuemax={Math.max(quotaBytes, 1)}
        aria-valuenow={Math.min(usedBytes, Math.max(quotaBytes, 1))}
        aria-valuetext={text}
        className={cn('mt-5 h-2.5 w-full overflow-hidden rounded-full', TRACK[severity])}
      >
        <div
          className={cn(
            'h-full rounded-full motion-safe:transition-[width] motion-safe:duration-500',
            FILL[severity],
          )}
          style={{ width: `${ratio * 100}%`, minWidth: usedBytes > 0 ? '0.625rem' : undefined }}
        />
      </div>
      <div className="mt-2 flex flex-col gap-1 text-xs text-muted-strong sm:flex-row sm:items-center sm:justify-between sm:gap-3">
        <span>{formatPercent(ratio, ratio > 0 && ratio < 0.1 ? 1 : 0)} used</span>
        {severity !== 'ok' ? (
          <span
            className={cn(
              'inline-flex items-center gap-1 font-medium',
              severity === 'danger' ? 'text-danger-ink' : 'text-warning-ink',
            )}
          >
            <TriangleAlert className="size-3.5" aria-hidden="true" />
            {NOTE[severity]}
          </span>
        ) : null}
      </div>
    </Card>
  );
}
