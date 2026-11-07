import { cn } from '../../lib/cn';

export interface LogoProps {
  size?: 'sm' | 'md';
  /** Show the "CipherDrop" wordmark next to the mark (default true). */
  withWordmark?: boolean;
  className?: string;
}

/** The CipherDrop mark (a drop with a keyhole) and wordmark. Decorative: wrap it in a labelled link. */
export function Logo({ size = 'md', withWordmark = true, className }: LogoProps) {
  return (
    <span className={cn('inline-flex items-center gap-2.5', className)}>
      <svg
        viewBox="0 0 32 32"
        className={cn('shrink-0', size === 'sm' ? 'size-7' : 'size-8')}
        aria-hidden="true"
      >
        <rect width="32" height="32" rx="8" className="fill-primary" />
        <path
          d="M16 5.5c-3.9 4.6-7.5 9.4-7.5 13.3a7.5 7.5 0 0 0 15 0c0-3.9-3.6-8.7-7.5-13.3Z"
          className="fill-primary-foreground"
        />
        <circle cx="16" cy="18" r="2.2" className="fill-primary" />
        <rect x="15.05" y="19" width="1.9" height="4.2" rx="0.95" className="fill-primary" />
      </svg>
      {withWordmark ? (
        <span
          className={cn(
            'font-semibold tracking-tight text-foreground',
            size === 'sm' ? 'text-base' : 'text-[1.075rem]',
          )}
        >
          Cipher<span className="text-primary">Drop</span>
        </span>
      ) : null}
    </span>
  );
}
