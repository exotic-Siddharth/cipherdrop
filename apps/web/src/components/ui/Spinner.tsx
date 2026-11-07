import { cn } from '../../lib/cn';

export type SpinnerSize = 'xs' | 'sm' | 'md' | 'lg';

const SIZES: Record<SpinnerSize, string> = {
  xs: 'size-3.5',
  sm: 'size-4',
  md: 'size-5',
  lg: 'size-8',
};

export interface SpinnerProps {
  size?: SpinnerSize;
  /** Announced to screen readers (role="status"). Ignored when `decorative`. */
  label?: string;
  /** Purely visual (inside a button that already sets aria-busy). */
  decorative?: boolean;
  className?: string;
}

/** Loading indicator. Static under prefers-reduced-motion (the arc still reads as "busy"). */
export function Spinner({
  size = 'md',
  label = 'Loading',
  decorative = false,
  className,
}: SpinnerProps) {
  const svg = (
    <svg
      className={cn('motion-safe:animate-spin', SIZES[size], decorative && className)}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
  if (decorative) return svg;
  return (
    <span role="status" className={cn('inline-flex items-center', className)}>
      {svg}
      <span className="sr-only">{label}</span>
    </span>
  );
}

export interface PageLoaderProps {
  label?: string;
  className?: string;
}

/** Centered spinner with a visible label, for route- and page-level loading states. */
export function PageLoader({ label = 'Loading…', className }: PageLoaderProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={cn('grid min-h-[40vh] place-items-center text-muted-strong', className)}
    >
      <div className="flex flex-col items-center gap-3">
        <Spinner size="lg" decorative className="text-primary" />
        <p className="text-sm">{label}</p>
      </div>
    </div>
  );
}
