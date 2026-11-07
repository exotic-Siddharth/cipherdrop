import {
  cloneElement,
  isValidElement,
  useEffect,
  useId,
  useRef,
  useState,
  type ReactElement,
  type ReactNode,
} from 'react';
import { createPortal } from 'react-dom';
import { cn } from '../../lib/cn';
import { useAnchoredPosition } from './useAnchoredPosition';

export interface TooltipProps {
  content: ReactNode;
  /** One focusable element (button, link). It gets aria-describedby while the tooltip shows. */
  children: ReactElement<{ 'aria-describedby'?: string }>;
  side?: 'top' | 'bottom';
  /** Hover delay; keyboard focus shows it immediately. */
  delayMs?: number;
  className?: string;
}

/**
 * Supplementary hint on hover and keyboard focus (role="tooltip", described-by); Escape hides it.
 * Never put essential information only in a tooltip, and give icon-only buttons an aria-label as well.
 */
export function Tooltip({
  content,
  children,
  side = 'top',
  delayMs = 350,
  className,
}: TooltipProps) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const anchorRef = useRef<HTMLSpanElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const style = useAnchoredPosition(anchorRef, tipRef, open, side, 8);

  useEffect(() => () => clearTimeout(timer.current), []);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [open]);

  const show = (delay: number) => {
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setOpen(true), delay);
  };
  const hide = () => {
    clearTimeout(timer.current);
    setOpen(false);
  };

  const child = isValidElement(children)
    ? cloneElement(children, {
        'aria-describedby':
          [children.props['aria-describedby'], open ? id : undefined].filter(Boolean).join(' ') ||
          undefined,
      })
    : children;

  return (
    <span
      ref={anchorRef}
      className="inline-flex"
      onPointerEnter={(e) => {
        if (e.pointerType === 'mouse') show(delayMs);
      }}
      onPointerLeave={hide}
      onFocus={() => show(0)}
      onBlur={hide}
    >
      {child}
      {open
        ? createPortal(
            <div
              ref={tipRef}
              id={id}
              role="tooltip"
              style={style}
              className={cn(
                'pointer-events-none z-[60] max-w-64 rounded-md bg-foreground px-2.5 py-1.5 text-xs font-medium leading-snug text-background shadow-popover',
                'motion-safe:animate-fade-in',
                className,
              )}
            >
              {content}
            </div>,
            document.body,
          )
        : null}
    </span>
  );
}
