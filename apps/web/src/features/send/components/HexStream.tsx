import { usePrefersReducedMotion } from '../../../lib/hooks';
import { cn } from '../../../lib/cn';

export interface HexStreamProps {
  /** Lowercase hex of the first 48 bytes of the latest encrypted chunk (real ciphertext), or null. */
  hex: string | null;
  /** Scrolls while true (and motion is allowed). */
  active: boolean;
  className?: string;
}

function groups(hex: string): string {
  return (hex.match(/.{1,2}/g) ?? []).join(' ');
}

/**
 * The memorable touch (spec 11.1): a strip of real ciphertext bytes scrolling during upload. Decorative for
 * assistive technology (the progress region announces status); static under prefers-reduced-motion.
 */
export function HexStream({ hex, active, className }: HexStreamProps) {
  const reduced = usePrefersReducedMotion();
  const text = hex ? groups(hex) : '';
  const scrolling = active && !reduced && text.length > 0;
  return (
    <div
      className={cn(
        'relative overflow-hidden rounded-lg border border-border bg-surface-2/60 px-3 py-2',
        className,
      )}
      aria-hidden="true"
      data-testid="hex-stream"
    >
      <div className="mb-1 flex items-center justify-between text-[11px] font-medium tracking-wide text-muted uppercase">
        <span>Ciphertext leaving your device</span>
        <span className="font-mono normal-case">AES-256-GCM</span>
      </div>
      <div className="relative h-5 overflow-hidden [mask-image:linear-gradient(90deg,transparent,black_8%,black_92%,transparent)]">
        {text ? (
          <div
            className={cn(
              'flex w-max gap-6 font-mono text-xs leading-5 whitespace-nowrap text-primary-ink',
              scrolling && 'animate-hex-scroll',
            )}
          >
            <span>{text}</span>
            <span>{text}</span>
          </div>
        ) : (
          <div className="font-mono text-xs leading-5 text-muted">
            waiting for the first chunk...
          </div>
        )}
      </div>
    </div>
  );
}
