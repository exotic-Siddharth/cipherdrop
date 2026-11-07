import type { ComponentProps } from 'react';
import { cn } from '../../lib/cn';

/** Keyboard key, e.g. <Kbd>Ctrl</Kbd> + <Kbd>C</Kbd>. */
export function Kbd({ className, ...props }: ComponentProps<'kbd'>) {
  return (
    <kbd
      className={cn(
        'inline-flex min-w-[1.6em] items-center justify-center rounded-md border border-border-strong/60 bg-surface-2 px-1.5 py-px',
        'font-mono text-[0.75em] font-medium text-foreground shadow-[inset_0_-1px_0] shadow-border-strong/40',
        className,
      )}
      {...props}
    />
  );
}
