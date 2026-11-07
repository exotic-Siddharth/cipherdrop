import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '../../lib/cn';

export interface PageHeaderProps {
  /** The page's <h1>. */
  title: ReactNode;
  description?: ReactNode;
  /** Small line above the title (e.g. "Settings"). */
  eyebrow?: ReactNode;
  icon?: LucideIcon;
  /** Right-aligned page actions (stack under the title on mobile). */
  actions?: ReactNode;
  className?: string;
}

/** Page title block: every page renders exactly one, so each view has a single <h1>. */
export function PageHeader({
  title,
  description,
  eyebrow,
  icon: Icon,
  actions,
  className,
}: PageHeaderProps) {
  return (
    <div
      className={cn(
        'mb-8 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between',
        className,
      )}
    >
      <div className="min-w-0">
        {eyebrow ? <p className="mb-2 text-sm font-medium text-primary-ink">{eyebrow}</p> : null}
        <div className="flex items-center gap-3">
          {Icon ? (
            <span className="inline-flex size-10 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary-ink">
              <Icon className="size-5" aria-hidden="true" />
            </span>
          ) : null}
          <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
            {title}
          </h1>
        </div>
        {description ? (
          <p className="mt-2 max-w-2xl text-base leading-relaxed text-muted-strong">
            {description}
          </p>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
    </div>
  );
}
