import type { StrengthScore } from '../../lib/passwordStrength';

/** Passwords protect a vault key that anyone holding a database copy can attack offline: keep a real floor. */
export const MIN_NEW_PASSWORD_LENGTH = 10;
/** zxcvbn score 0-4; below this the form refuses ("Too weak" and "Weak"). */
export const MIN_STRENGTH_SCORE = 2;
/** When the strength estimator is unavailable (still loading or failed), fall back to length alone. */
const FALLBACK_MIN_LENGTH = 12;

/** Error text for a new password, or null when it is acceptable. */
export function validateNewPassword(password: string, score: StrengthScore | null): string | null {
  if (!password) return 'Enter a password.';
  if (password.length < MIN_NEW_PASSWORD_LENGTH) {
    return `Use at least ${MIN_NEW_PASSWORD_LENGTH} characters.`;
  }
  if (score !== null && score < MIN_STRENGTH_SCORE) {
    return 'That password is too easy to guess. Add more words or characters.';
  }
  if (score === null && password.length < FALLBACK_MIN_LENGTH) {
    return `Use at least ${FALLBACK_MIN_LENGTH} characters.`;
  }
  return null;
}
