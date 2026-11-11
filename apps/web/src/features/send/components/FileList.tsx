import type { ReactNode } from 'react';
import { cn } from '../../../lib/cn';
import { formatBytes } from '../../../lib/format';
import { fileIconFor } from './fileIcons';

export interface FileListItem {
  key: string;
  name: string;
  size: number;
  type: string;
  /** Extra line under the name (progress, verdict). */
  detail?: ReactNode;
  /** Right-aligned actions or badges. */
  trailing?: ReactNode;
}

export interface FileListProps {
  items: readonly FileListItem[];
  /** Accessible name of the list. */
  label: string;
  className?: string;
}

/** Files with type icon, name (never truncated for screen readers), size and per-row actions. */
export function FileList({ items, label, className }: FileListProps) {
  return (
    <ul
      aria-label={label}
      className={cn('divide-y divide-border rounded-lg border border-border', className)}
    >
      {items.map((item) => {
        const Icon = fileIconFor(item.type, item.name);
        return (
          <li
            key={item.key}
            className="grid grid-cols-[2rem_minmax(0,1fr)] items-center gap-x-3 gap-y-2 px-3 py-2.5 sm:grid-cols-[2rem_minmax(0,1fr)_auto] sm:px-4"
          >
            <span
              className="col-start-1 row-start-1 flex size-8 items-center justify-center rounded-md bg-primary/10 text-primary-ink"
              aria-hidden="true"
            >
              <Icon className="size-4" />
            </span>
            <div className="col-start-2 row-start-1 flex min-w-0 items-baseline gap-2">
              <p className="min-w-0 truncate text-sm font-medium text-foreground" title={item.name}>
                {item.name}
              </p>
              <span className="shrink-0 text-xs text-muted tabular-nums">
                {formatBytes(item.size)}
              </span>
            </div>
            {item.trailing ? (
              <div className="col-start-2 row-start-2 flex items-center gap-1.5 sm:col-start-3 sm:row-start-1">
                {item.trailing}
              </div>
            ) : null}
            {item.detail ? (
              <div className="col-start-2 row-start-3 min-w-0 sm:col-start-2 sm:col-end-4 sm:row-start-2">
                {item.detail}
              </div>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}
