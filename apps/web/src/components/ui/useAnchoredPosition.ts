import { useLayoutEffect, useState, type CSSProperties, type RefObject } from 'react';

export type Placement = 'top' | 'bottom' | 'top-start' | 'top-end' | 'bottom-start' | 'bottom-end';

const VIEWPORT_MARGIN = 8;

/**
 * Fixed-position coordinates for a floating element (tooltip, menu) anchored to `anchor`, flipped to the other
 * side when it would overflow and clamped to the viewport. Portaled floats are never clipped by overflow
 * containers such as scrollable tables. Recomputed on resize and on any scroll while open.
 */
export function useAnchoredPosition(
  anchor: RefObject<HTMLElement | null>,
  floating: RefObject<HTMLElement | null>,
  open: boolean,
  placement: Placement = 'bottom',
  offset = 6,
): CSSProperties {
  const [style, setStyle] = useState<CSSProperties>({
    position: 'fixed',
    top: 0,
    left: 0,
    // opacity, not visibility: a menu must be focusable in the same layout pass that positions it.
    opacity: 0,
  });

  useLayoutEffect(() => {
    if (!open) return;
    const update = () => {
      const a = anchor.current?.getBoundingClientRect();
      const f = floating.current;
      if (!a || !f) return;
      const fw = f.offsetWidth;
      const fh = f.offsetHeight;
      const vw = window.innerWidth;
      const vh = window.innerHeight;
      let side: 'top' | 'bottom' = placement.startsWith('top') ? 'top' : 'bottom';
      const fitsBelow = a.bottom + offset + fh <= vh - VIEWPORT_MARGIN;
      const fitsAbove = a.top - offset - fh >= VIEWPORT_MARGIN;
      if (side === 'bottom' && !fitsBelow && fitsAbove) side = 'top';
      else if (side === 'top' && !fitsAbove && fitsBelow) side = 'bottom';
      const top = side === 'bottom' ? a.bottom + offset : a.top - offset - fh;
      const align = placement.endsWith('-start')
        ? 'start'
        : placement.endsWith('-end')
          ? 'end'
          : 'center';
      let left =
        align === 'start' ? a.left : align === 'end' ? a.right - fw : a.left + a.width / 2 - fw / 2;
      left = Math.min(
        Math.max(VIEWPORT_MARGIN, left),
        Math.max(VIEWPORT_MARGIN, vw - fw - VIEWPORT_MARGIN),
      );
      setStyle({ position: 'fixed', top: Math.round(top), left: Math.round(left), opacity: 1 });
    };
    update();
    window.addEventListener('resize', update);
    window.addEventListener('scroll', update, true);
    return () => {
      window.removeEventListener('resize', update);
      window.removeEventListener('scroll', update, true);
    };
  }, [open, placement, offset, anchor, floating]);

  return style;
}
