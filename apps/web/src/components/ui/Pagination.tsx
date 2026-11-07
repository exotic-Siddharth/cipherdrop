import { ChevronLeft, ChevronRight } from 'lucide-react';
import { cn } from '../../lib/cn';
import { buttonVariants } from './variants';

export interface PaginationProps {
  /** 1-based current page (the API's `page`). */
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
  /** Accessible name of the navigation landmark. */
  label?: string;
  className?: string;
}

type PageItem = number | 'gap';

function pageItems(page: number, pages: number): PageItem[] {
  if (pages <= 7) return Array.from({ length: pages }, (_, i) => i + 1);
  const items: PageItem[] = [1];
  const start = Math.max(2, Math.min(page - 1, pages - 4));
  const end = Math.min(pages - 1, Math.max(page + 1, 5));
  if (start > 2) items.push('gap');
  for (let p = start; p <= end; p += 1) items.push(p);
  if (end < pages - 1) items.push('gap');
  items.push(pages);
  return items;
}

/** "Showing 21–40 of 95" + previous/next and page buttons for `{items,total,page,pageSize}` pages. */
export function Pagination({
  page,
  pageSize,
  total,
  onPageChange,
  label = 'Pagination',
  className,
}: PaginationProps) {
  if (total <= 0) return null;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const current = Math.min(Math.max(1, page), pages);
  const from = (current - 1) * pageSize + 1;
  const to = Math.min(total, current * pageSize);
  const navButton = (enabled: boolean) =>
    buttonVariants({ variant: 'outline', size: 'sm', className: cn(!enabled && 'opacity-50') });

  return (
    <nav
      aria-label={label}
      className={cn('flex flex-col items-center gap-3 sm:flex-row sm:justify-between', className)}
    >
      <p className="text-sm text-muted-strong">
        Showing{' '}
        <span className="font-medium text-foreground tabular-nums">
          {from}–{to}
        </span>{' '}
        of <span className="font-medium text-foreground tabular-nums">{total}</span>
      </p>
      {pages > 1 ? (
        <ul className="flex items-center gap-1">
          <li>
            <button
              type="button"
              className={navButton(current > 1)}
              disabled={current <= 1}
              onClick={() => onPageChange(current - 1)}
              aria-label="Previous page"
            >
              <ChevronLeft aria-hidden="true" />
              <span className="hidden sm:inline">Previous</span>
            </button>
          </li>
          {pageItems(current, pages).map((item, i) =>
            item === 'gap' ? (
              <li
                key={`gap-${i}`}
                className="hidden px-1 text-sm text-muted sm:block"
                aria-hidden="true"
              >
                …
              </li>
            ) : (
              <li key={item} className="hidden sm:block">
                <button
                  type="button"
                  onClick={() => onPageChange(item)}
                  aria-label={`Page ${item}`}
                  aria-current={item === current ? 'page' : undefined}
                  className={buttonVariants({
                    variant: item === current ? 'secondary' : 'ghost',
                    size: 'sm',
                    className: 'min-w-8 px-2 tabular-nums',
                  })}
                >
                  {item}
                </button>
              </li>
            ),
          )}
          <li className="px-2 text-sm text-muted-strong sm:hidden" aria-hidden="true">
            {current} / {pages}
          </li>
          <li>
            <button
              type="button"
              className={navButton(current < pages)}
              disabled={current >= pages}
              onClick={() => onPageChange(current + 1)}
              aria-label="Next page"
            >
              <span className="hidden sm:inline">Next</span>
              <ChevronRight aria-hidden="true" />
            </button>
          </li>
        </ul>
      ) : null}
    </nav>
  );
}
