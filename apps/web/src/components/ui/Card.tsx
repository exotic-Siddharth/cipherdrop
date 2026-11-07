import type { LucideIcon } from 'lucide-react';
import type { ComponentProps, ReactNode } from 'react';
import { cn } from '../../lib/cn';

export interface CardProps extends ComponentProps<'div'> {
  /** Render as a <section> (landmark-like grouping) instead of a <div>. */
  as?: 'div' | 'section' | 'article';
}

/** Surface container: white "paper" in light mode, raised surface in dark mode. */
export function Card({ as: Tag = 'div', className, ...props }: CardProps) {
  return (
    <Tag
      className={cn(
        'rounded-xl border border-border bg-surface text-foreground shadow-card',
        className,
      )}
      {...props}
    />
  );
}

export interface CardHeaderProps extends Omit<ComponentProps<'div'>, 'title'> {
  title?: ReactNode;
  description?: ReactNode;
  icon?: LucideIcon;
  /** Right-aligned actions (buttons, badges). */
  actions?: ReactNode;
  /** Heading level of `title` (default h2). */
  titleAs?: 'h2' | 'h3' | 'h4';
}

/** Card header: optional icon, title, description and actions. Children render below. */
export function CardHeader({
  title,
  description,
  icon: Icon,
  actions,
  titleAs = 'h2',
  className,
  children,
  ...props
}: CardHeaderProps) {
  return (
    <div className={cn('flex flex-col gap-1.5 p-5 pb-0 sm:p-6 sm:pb-0', className)} {...props}>
      {title || actions || Icon ? (
        <div className="flex items-start justify-between gap-4">
          <div className="flex min-w-0 items-start gap-3">
            {Icon ? (
              <span className="mt-0.5 inline-flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary-ink">
                <Icon className="size-5" aria-hidden="true" />
              </span>
            ) : null}
            <div className="min-w-0">
              {title ? <CardTitle as={titleAs}>{title}</CardTitle> : null}
              {description ? <CardDescription>{description}</CardDescription> : null}
            </div>
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
        </div>
      ) : null}
      {children}
    </div>
  );
}

export interface CardTitleProps extends ComponentProps<'h2'> {
  as?: 'h2' | 'h3' | 'h4';
}

export function CardTitle({ as: Tag = 'h2', className, ...props }: CardTitleProps) {
  return (
    <Tag
      className={cn('text-base font-semibold leading-6 tracking-tight text-foreground', className)}
      {...props}
    />
  );
}

export function CardDescription({ className, ...props }: ComponentProps<'p'>) {
  return <p className={cn('mt-1 text-sm leading-relaxed text-muted', className)} {...props} />;
}

export function CardContent({ className, ...props }: ComponentProps<'div'>) {
  return <div className={cn('p-5 sm:p-6', className)} {...props} />;
}

export function CardFooter({ className, ...props }: ComponentProps<'div'>) {
  return (
    <div
      className={cn(
        'flex flex-wrap items-center justify-end gap-3 border-t border-border px-5 py-4 sm:px-6',
        className,
      )}
      {...props}
    />
  );
}
