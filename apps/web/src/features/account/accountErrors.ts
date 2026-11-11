/**
 * User-facing messages for the account flows. Login-style failures stay generic on purpose (the server answers
 * 401 for an unknown email, a wrong password, a locked account and a wrong second factor alike), so nothing here
 * helps enumerate accounts.
 */
import { isApiError } from '../../lib/api';
import { describeError } from '../../lib/errors';

export type AccountErrorContext =
  | 'login'
  | 'mfa'
  | 'totp'
  | 'register'
  | 'unlock'
  | 'password'
  | 'recovery-start'
  | 'recovery-complete'
  | 'verify'
  | 'generic';

function cryptoCode(err: unknown): string | null {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === 'string' ? code : null;
}

export function accountErrorMessage(
  err: unknown,
  context: AccountErrorContext = 'generic',
): string {
  const code = cryptoCode(err);
  if (code === 'WRONG_PASSWORD') {
    if (context === 'unlock') return 'Wrong password. Your vault stays locked.';
    if (context === 'password') return 'Your current password is incorrect.';
    if (context === 'verify') return 'Wrong password.';
    if (context === 'recovery-start' || context === 'recovery-complete') {
      return 'That recovery key does not match this account.';
    }
    return 'Wrong password.';
  }
  if (code === 'KDF_PARAMS') {
    return 'The server asked for unsafe key-derivation settings, so the request was refused.';
  }
  if (code === 'TYPE_ERROR' || (err instanceof TypeError && context.startsWith('recovery'))) {
    return context.startsWith('recovery')
      ? 'That does not look like a recovery key. It has 32 characters in 8 groups of 4.'
      : 'Something was wrong with the input. Check it and try again.';
  }
  if (isApiError(err)) {
    if (err.code === 'RATE_LIMITED' || err.status === 0 || err.status >= 500) {
      return describeError(err);
    }
    switch (context) {
      case 'login':
        return 'Incorrect email or password. Repeated failures temporarily lock the account.';
      case 'mfa':
        return 'That code was not accepted. Check the code, or go back and sign in again if it took too long.';
      case 'totp':
        return 'That code was not accepted. Wait for the next code in your app and try again.';
      case 'register':
        if (err.code === 'CONFLICT') {
          return 'An account with this email already exists. Try logging in instead.';
        }
        return describeError(err);
      case 'recovery-start':
        return 'That email and recovery key do not match an account.';
      case 'recovery-complete':
        return err.status === 401
          ? 'The recovery session expired or the code was wrong. Check the code, or start again.'
          : describeError(err);
      case 'verify':
        return err.status === 401 ? 'Wrong password or wrong two-factor code.' : describeError(err);
      case 'password':
        return err.status === 401 ? 'Your current password is incorrect.' : describeError(err);
      default:
        return describeError(err);
    }
  }
  return describeError(err);
}
