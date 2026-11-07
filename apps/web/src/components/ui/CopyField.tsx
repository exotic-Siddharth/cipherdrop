import { Check, Copy } from 'lucide-react';
import { useId, type ReactNode } from 'react';
import { toast } from 'sonner';
import { cn } from '../../lib/cn';
import { useCopyToClipboard } from '../../lib/hooks';
import { Button } from './Button';
import { Field } from './Field';
import { controlClasses, describedBy, type ButtonSize, type ButtonVariant } from './variants';

export interface CopyButtonProps {
  value: string;
  /** Visible label, or the accessible name when iconOnly. */
  label?: string;
  copiedLabel?: string;
  iconOnly?: boolean;
  variant?: ButtonVariant;
  size?: Exclude<ButtonSize, 'icon' | 'icon-sm'>;
  onCopied?: () => void;
  className?: string;
}

/** Copy-to-clipboard button with "Copied" feedback (visible + announced). */
export function CopyButton({
  value,
  label = 'Copy',
  copiedLabel = 'Copied',
  iconOnly = false,
  variant = 'outline',
  size = 'md',
  onCopied,
  className,
}: CopyButtonProps) {
  const { copied, copy } = useCopyToClipboard();
  const onClick = async () => {
    if (await copy(value)) onCopied?.();
    else
      toast.error('Copy failed', {
        description: 'Select the text and press Ctrl+C (Cmd+C on a Mac).',
      });
  };
  return (
    <>
      <Button
        variant={variant}
        size={iconOnly ? (size === 'sm' ? 'icon-sm' : 'icon') : size}
        icon={copied ? Check : Copy}
        onClick={() => void onClick()}
        aria-label={iconOnly ? (copied ? copiedLabel : label) : undefined}
        className={cn(copied && 'text-success-ink', className)}
      >
        {iconOnly ? null : copied ? copiedLabel : label}
      </Button>
      <span className="sr-only" aria-live="polite">
        {copied ? 'Copied to clipboard' : ''}
      </span>
    </>
  );
}

export interface CopyFieldProps {
  value: string;
  label: ReactNode;
  hideLabel?: boolean;
  hint?: ReactNode;
  /** Monospace value (default true: links, keys, codes). */
  mono?: boolean;
  copyLabel?: string;
  onCopied?: () => void;
  id?: string;
  className?: string;
}

/** Read-only value + copy button, e.g. the share link. Focusing the field selects it for manual copying. */
export function CopyField({
  value,
  label,
  hideLabel,
  hint,
  mono = true,
  copyLabel = 'Copy',
  onCopied,
  id: idProp,
  className,
}: CopyFieldProps) {
  const autoId = useId();
  const id = idProp ?? autoId;
  return (
    <Field id={id} label={label} hideLabel={hideLabel} hint={hint} className={className}>
      <div className="flex items-center gap-2">
        <input
          id={id}
          readOnly
          value={value}
          spellCheck={false}
          aria-describedby={describedBy(id, { hint })}
          onFocus={(e) => e.currentTarget.select()}
          className={controlClasses({
            mono,
            className: 'flex-1 [&[readonly]]:bg-surface text-[13px]',
          })}
        />
        <CopyButton value={value} label={copyLabel} onCopied={onCopied} />
      </div>
    </Field>
  );
}
