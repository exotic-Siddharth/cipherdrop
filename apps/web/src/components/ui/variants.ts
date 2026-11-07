/**
 * Class builders shared by the UI kit, exported for lanes that need the same look on other elements
 * (e.g. `<a className={buttonVariants({ variant: 'outline' })}>` for an external link).
 */
import { cn } from '../../lib/cn';

export type ButtonVariant = 'primary' | 'secondary' | 'outline' | 'ghost' | 'danger';
export type ButtonSize = 'sm' | 'md' | 'lg' | 'icon' | 'icon-sm';

const BUTTON_BASE =
  'inline-flex shrink-0 select-none items-center justify-center gap-2 whitespace-nowrap rounded-lg font-medium ' +
  'transition-colors duration-150 focus-visible:outline-2 focus-visible:outline-offset-2 ' +
  'focus-visible:outline-primary disabled:pointer-events-none disabled:opacity-50 ' +
  'aria-disabled:pointer-events-none aria-disabled:opacity-50 [&_svg]:shrink-0';

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary: 'bg-primary text-primary-foreground shadow-card hover:bg-primary-hover',
  secondary:
    'bg-primary/10 text-primary-ink hover:bg-primary/15 dark:bg-primary/15 dark:hover:bg-primary/20',
  outline:
    'border border-border-strong bg-surface text-foreground shadow-card hover:border-muted hover:bg-surface-2',
  ghost: 'text-foreground hover:bg-surface-2',
  danger: 'bg-danger text-danger-foreground shadow-card hover:bg-danger-hover',
};

const BUTTON_SIZES: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-sm [&_svg]:size-4',
  md: 'h-10 px-4 text-sm [&_svg]:size-4',
  lg: 'h-12 px-6 text-base [&_svg]:size-5',
  icon: 'size-10 [&_svg]:size-5',
  'icon-sm': 'size-8 [&_svg]:size-4',
};

export function buttonVariants(
  options: {
    variant?: ButtonVariant;
    size?: ButtonSize;
    fullWidth?: boolean;
    className?: string;
  } = {},
): string {
  const { variant = 'primary', size = 'md', fullWidth = false, className } = options;
  return cn(
    BUTTON_BASE,
    BUTTON_VARIANTS[variant],
    BUTTON_SIZES[size],
    fullWidth && 'w-full',
    className,
  );
}

export type ControlSize = 'sm' | 'md' | 'lg';

const CONTROL_SIZES: Record<ControlSize, string> = {
  sm: 'h-8 text-sm',
  md: 'h-10 text-sm',
  lg: 'h-12 text-base',
};

/** Text-like form controls (input, select). Borders use border-strong for 3:1 non-text contrast. */
export function controlClasses(
  options: { size?: ControlSize; mono?: boolean; className?: string } = {},
): string {
  const { size = 'md', mono = false, className } = options;
  return cn(
    'w-full min-w-0 rounded-lg border border-border-strong bg-surface px-3 text-foreground shadow-card',
    'placeholder:text-muted transition-colors',
    'focus-visible:border-primary focus-visible:outline-2 focus-visible:outline-offset-0 focus-visible:outline-primary',
    'aria-invalid:border-danger aria-invalid:focus-visible:outline-danger',
    // [readonly] attribute, not :read-only (that pseudo-class also matches every <select>).
    'disabled:cursor-not-allowed disabled:opacity-60 [&[readonly]]:bg-surface-2',
    CONTROL_SIZES[size],
    mono && 'font-mono tracking-tight',
    className,
  );
}

/** Wires a control to its Field hint/error/extra descriptions. */
export function describedBy(
  id: string,
  parts: { hint?: unknown; error?: unknown; extra?: string | undefined },
): string | undefined {
  const ids = [
    parts.hint ? `${id}-hint` : undefined,
    parts.error ? `${id}-error` : undefined,
    parts.extra,
  ].filter(Boolean);
  return ids.length ? ids.join(' ') : undefined;
}

/** Focusable descendants in DOM order (dialogs, menus). */
export const FOCUSABLE_SELECTOR = [
  'a[href]',
  'area[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  'iframe',
  '[tabindex]:not([tabindex="-1"])',
  '[contenteditable="true"]',
].join(',');

export function focusableWithin(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    (el) => !el.hasAttribute('inert') && el.getAttribute('aria-hidden') !== 'true',
  );
}
