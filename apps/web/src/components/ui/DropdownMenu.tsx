import type { LucideIcon } from 'lucide-react';
import {
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router';
import { cn } from '../../lib/cn';
import { useAnchoredPosition } from './useAnchoredPosition';
import { buttonVariants, type ButtonSize, type ButtonVariant } from './variants';

export interface DropdownMenuItem {
  label: ReactNode;
  icon?: LucideIcon;
  /** Runs after the menu closes. */
  onSelect?: () => void;
  /** In-app route: renders a router link (keeps open-in-new-tab). */
  to?: string;
  /** Plain URL (e.g. /api/docs): renders an <a>. */
  href?: string;
  tone?: 'default' | 'danger';
  disabled?: boolean;
}

export type DropdownMenuEntry =
  DropdownMenuItem | { type: 'separator' } | { type: 'label'; label: ReactNode };

export interface DropdownMenuProps {
  /** Accessible name of the trigger button, e.g. "Account menu" or "Actions for report.pdf". */
  label: string;
  /** Trigger content (avatar, icon, text). */
  trigger: ReactNode;
  items: DropdownMenuEntry[];
  /** Non-interactive block at the top of the menu (e.g. the signed-in email). */
  header?: ReactNode;
  align?: 'start' | 'end';
  triggerVariant?: ButtonVariant;
  triggerSize?: ButtonSize;
  triggerClassName?: string;
  menuClassName?: string;
}

/** Enabled menu items in DOM order. */
function queryMenuItems(menu: HTMLElement | null): HTMLElement[] {
  return Array.from(
    menu?.querySelectorAll<HTMLElement>('[role="menuitem"]:not([aria-disabled="true"])') ?? [],
  );
}

const isSeparator = (e: DropdownMenuEntry): e is { type: 'separator' } =>
  'type' in e && e.type === 'separator';
const isLabel = (e: DropdownMenuEntry): e is { type: 'label'; label: ReactNode } =>
  'type' in e && e.type === 'label';

/**
 * Menu button (WAI-ARIA menu pattern): click or ArrowDown/ArrowUp opens it and focuses the first/last item;
 * arrows, Home/End and type-ahead move; Escape or Tab closes and returns focus to the trigger; clicking
 * outside closes it. The menu is portaled, so overflow containers (tables) never clip it.
 */
export function DropdownMenu({
  label,
  trigger,
  items,
  header,
  align = 'end',
  triggerVariant = 'ghost',
  triggerSize = 'md',
  triggerClassName,
  menuClassName,
}: DropdownMenuProps) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const focusOnOpen = useRef<'first' | 'last'>('first');
  const triggerId = useId();
  const menuId = useId();
  const style = useAnchoredPosition(
    triggerRef,
    menuRef,
    open,
    align === 'end' ? 'bottom-end' : 'bottom-start',
  );

  const close = (restoreFocus = true) => {
    setOpen(false);
    if (restoreFocus) triggerRef.current?.focus();
  };

  useLayoutEffect(() => {
    if (!open) return;
    const all = queryMenuItems(menuRef.current);
    (focusOnOpen.current === 'last' ? all[all.length - 1] : all[0])?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: PointerEvent) => {
      const target = e.target as Node;
      if (menuRef.current?.contains(target) || triggerRef.current?.contains(target)) return;
      setOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    return () => document.removeEventListener('pointerdown', onPointerDown);
  }, [open]);

  const onMenuKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const all = queryMenuItems(menuRef.current);
    const index = all.indexOf(document.activeElement as HTMLElement);
    const focusAt = (i: number) => all[(i + all.length) % all.length]?.focus();
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        focusAt(index + 1);
        break;
      case 'ArrowUp':
        e.preventDefault();
        focusAt(index - 1);
        break;
      case 'Home':
        e.preventDefault();
        focusAt(0);
        break;
      case 'End':
        e.preventDefault();
        focusAt(all.length - 1);
        break;
      case 'Escape':
        e.preventDefault();
        e.stopPropagation(); // do not also close an enclosing dialog
        close();
        break;
      case 'Tab':
        e.preventDefault();
        close();
        break;
      default:
        if (e.key.length === 1 && /\S/.test(e.key)) {
          const key = e.key.toLowerCase();
          const order = [...all.slice(index + 1), ...all.slice(0, index + 1)];
          order.find((el) => el.textContent?.trim().toLowerCase().startsWith(key))?.focus();
        }
    }
  };

  return (
    <>
      <button
        ref={triggerRef}
        id={triggerId}
        type="button"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => {
          focusOnOpen.current = 'first';
          setOpen((o) => !o);
        }}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
            e.preventDefault();
            focusOnOpen.current = e.key === 'ArrowUp' ? 'last' : 'first';
            setOpen(true);
          }
        }}
        className={buttonVariants({
          variant: triggerVariant,
          size: triggerSize,
          className: triggerClassName,
        })}
      >
        {trigger}
      </button>
      {open
        ? createPortal(
            <div
              ref={menuRef}
              id={menuId}
              role="menu"
              aria-labelledby={triggerId}
              aria-orientation="vertical"
              tabIndex={-1}
              style={style}
              onKeyDown={onMenuKeyDown}
              className={cn(
                'z-50 min-w-52 max-w-[min(20rem,calc(100vw-1rem))] rounded-xl border border-border bg-surface p-1 text-foreground shadow-popover',
                'outline-none motion-safe:animate-pop-in',
                menuClassName,
              )}
            >
              {header ? (
                <div className="border-b border-border px-3 pb-2 pt-1.5 text-sm">{header}</div>
              ) : null}
              <div className={header ? 'pt-1' : undefined}>
                {items.map((entry, i) => {
                  if (isSeparator(entry)) {
                    return <div key={i} role="separator" className="-mx-1 my-1 h-px bg-border" />;
                  }
                  if (isLabel(entry)) {
                    return (
                      <div key={i} className="px-3 pb-1 pt-2 text-xs font-medium text-muted">
                        {entry.label}
                      </div>
                    );
                  }
                  const Icon = entry.icon;
                  const className = cn(
                    'flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-sm outline-none transition-colors',
                    entry.tone === 'danger'
                      ? 'text-danger-ink hover:bg-danger/10 focus:bg-danger/10'
                      : 'text-foreground hover:bg-surface-2 focus:bg-surface-2',
                    entry.disabled && 'cursor-not-allowed opacity-50',
                  );
                  const content = (
                    <>
                      {Icon ? (
                        <Icon
                          className={cn(
                            'size-4 shrink-0',
                            entry.tone === 'danger' ? 'text-danger' : 'text-muted',
                          )}
                          aria-hidden="true"
                        />
                      ) : null}
                      <span className="min-w-0 flex-1 truncate">{entry.label}</span>
                    </>
                  );
                  const activate = () => {
                    close();
                    entry.onSelect?.();
                  };
                  if (entry.to && !entry.disabled) {
                    return (
                      <Link
                        key={i}
                        to={entry.to}
                        role="menuitem"
                        tabIndex={-1}
                        className={className}
                        onClick={activate}
                      >
                        {content}
                      </Link>
                    );
                  }
                  if (entry.href && !entry.disabled) {
                    return (
                      <a
                        key={i}
                        href={entry.href}
                        role="menuitem"
                        tabIndex={-1}
                        className={className}
                        onClick={activate}
                      >
                        {content}
                      </a>
                    );
                  }
                  return (
                    <button
                      key={i}
                      type="button"
                      role="menuitem"
                      tabIndex={-1}
                      aria-disabled={entry.disabled || undefined}
                      className={className}
                      onClick={entry.disabled ? undefined : activate}
                    >
                      {content}
                    </button>
                  );
                })}
              </div>
            </div>,
            document.body,
          )
        : null}
    </>
  );
}
