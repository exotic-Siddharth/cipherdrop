import type { LucideIcon } from 'lucide-react';
import type { ComponentProps, ReactNode } from 'react';
import { Link, type LinkProps } from 'react-router';
import { Spinner } from './Spinner';
import { buttonVariants, type ButtonSize, type ButtonVariant } from './variants';

interface ButtonOwnProps {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Leading lucide icon (replaced by a spinner while loading). */
  icon?: LucideIcon;
  /** Trailing lucide icon. */
  iconRight?: LucideIcon;
  /** Busy state: disabled, spinner, aria-busy. */
  loading?: boolean;
  fullWidth?: boolean;
}

export interface ButtonProps extends ComponentProps<'button'>, ButtonOwnProps {}

function ButtonContent({
  icon: Icon,
  iconRight: IconRight,
  loading,
  children,
}: Pick<ButtonOwnProps, 'icon' | 'iconRight' | 'loading'> & { children?: ReactNode }) {
  return (
    <>
      {loading ? <Spinner decorative size="sm" /> : Icon ? <Icon aria-hidden="true" /> : null}
      {children}
      {IconRight && !loading ? <IconRight aria-hidden="true" /> : null}
    </>
  );
}

/**
 * Button: variants primary | secondary | outline | ghost | danger; sizes sm | md | lg | icon | icon-sm.
 * Icon-only buttons (size "icon") need an aria-label. Defaults to type="button".
 * While `loading` the button stays focusable (aria-disabled + aria-busy) but ignores activation, including a
 * form's implicit submit, so keyboard focus is never dropped mid-request.
 */
export function Button({
  variant = 'primary',
  size = 'md',
  icon,
  iconRight,
  loading = false,
  fullWidth = false,
  className,
  disabled,
  type = 'button',
  onClick,
  children,
  ...props
}: ButtonProps) {
  return (
    <button
      type={type}
      className={buttonVariants({ variant, size, fullWidth, className })}
      disabled={disabled}
      aria-disabled={loading || undefined}
      aria-busy={loading || undefined}
      onClick={(e) => {
        if (loading) {
          e.preventDefault();
          return;
        }
        onClick?.(e);
      }}
      {...props}
    >
      <ButtonContent icon={icon} iconRight={iconRight} loading={loading}>
        {children}
      </ButtonContent>
    </button>
  );
}

export interface ButtonLinkProps extends LinkProps, Omit<ButtonOwnProps, 'loading'> {
  className?: string;
}

/** A router link styled as a button (navigation must stay a link for open-in-new-tab and history). */
export function ButtonLink({
  variant = 'primary',
  size = 'md',
  icon,
  iconRight,
  fullWidth = false,
  className,
  children,
  ...props
}: ButtonLinkProps) {
  return (
    <Link className={buttonVariants({ variant, size, fullWidth, className })} {...props}>
      <ButtonContent icon={icon} iconRight={iconRight}>
        {children}
      </ButtonContent>
    </Link>
  );
}
