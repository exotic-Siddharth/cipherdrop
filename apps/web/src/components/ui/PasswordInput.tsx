import { Eye, EyeOff, KeyRound } from 'lucide-react';
import { useId, useState, type KeyboardEvent } from 'react';
import { Input, type InputProps } from './Input';

export interface PasswordInputProps extends Omit<InputProps, 'type' | 'trailing'> {
  /** Show the key icon at the start (default true). */
  showIcon?: boolean;
}

/**
 * Password field with a show/hide toggle and a Caps Lock warning. Defaults to
 * autoComplete="current-password"; pass "new-password" on registration and password-change forms.
 */
export function PasswordInput({
  autoComplete = 'current-password',
  showIcon = true,
  id: idProp,
  onKeyDown,
  onKeyUp,
  onBlur,
  hint,
  ...props
}: PasswordInputProps) {
  const autoId = useId();
  const id = idProp ?? autoId;
  const [visible, setVisible] = useState(false);
  const [capsLock, setCapsLock] = useState(false);

  const readCaps = (e: KeyboardEvent<HTMLInputElement>) => {
    if (typeof e.getModifierState === 'function') setCapsLock(e.getModifierState('CapsLock'));
  };

  return (
    <Input
      {...props}
      id={id}
      type={visible ? 'text' : 'password'}
      autoComplete={autoComplete}
      autoCapitalize="off"
      autoCorrect="off"
      spellCheck={false}
      leadingIcon={showIcon ? KeyRound : undefined}
      hint={
        capsLock ? <span className="font-medium text-warning-ink">Caps Lock is on.</span> : hint
      }
      onKeyDown={(e) => {
        readCaps(e);
        onKeyDown?.(e);
      }}
      onKeyUp={(e) => {
        readCaps(e);
        onKeyUp?.(e);
      }}
      onBlur={(e) => {
        setCapsLock(false);
        onBlur?.(e);
      }}
      trailing={
        <button
          type="button"
          className="inline-flex size-8 items-center justify-center rounded-md text-muted transition-colors hover:bg-surface-2 hover:text-foreground focus-visible:outline-2 focus-visible:outline-primary"
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? 'Hide password' : 'Show password'}
          aria-pressed={visible}
          aria-controls={id}
          disabled={props.disabled}
        >
          {visible ? (
            <EyeOff className="size-4" aria-hidden="true" />
          ) : (
            <Eye className="size-4" aria-hidden="true" />
          )}
        </button>
      }
    />
  );
}
