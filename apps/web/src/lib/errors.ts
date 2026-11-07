/**
 * User-facing error text for toasts and error states. Server messages are written for users (apps/api
 * lib/errors.ts) and never contain secrets; crypto errors are identified by their stable `code`, which
 * survives Worker boundaries.
 */
import { isApiError } from './http';

/** Retry-After as a single unit, rounded UP so the user never retries before the limit resets. */
export function formatWait(seconds: number): string {
  if (seconds < 60) return `${Math.max(1, Math.ceil(seconds))} s`;
  if (seconds < 3600) return `${Math.ceil(seconds / 60)} min`;
  return `${Math.ceil(seconds / 3600)} h`;
}

const CRYPTO_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  INTEGRITY: 'This file was modified in transit or storage. Download blocked.',
  WRONG_PASSWORD: 'Wrong password.',
  KDF_PARAMS: 'This link asks for unsafe key-derivation settings, so it was refused.',
  INVALID_LINK: 'This link is incomplete. Ask the sender to copy the whole link.',
});

export function isAbortError(err: unknown): boolean {
  return (
    (err instanceof DOMException || err instanceof Error) &&
    (err as { name?: string }).name === 'AbortError'
  );
}

/** A short sentence describing `err` for the user. */
export function describeError(
  err: unknown,
  fallback = 'Something went wrong. Please try again.',
): string {
  if (isApiError(err)) {
    switch (err.code) {
      case 'RATE_LIMITED':
        return err.retryAfter
          ? `Too many attempts. Try again in ${formatWait(err.retryAfter)}.`
          : 'Too many attempts. Wait a moment and try again.';
      case 'INTERNAL':
        return 'Something went wrong on our side. Please try again.';
      case 'INVALID_RESPONSE':
        return 'The server sent an unexpected response. Please try again.';
      default:
        return err.message || fallback;
    }
  }
  if (isAbortError(err)) return 'Cancelled.';
  const code = (err as { code?: unknown } | null)?.code;
  if (typeof code === 'string' && code in CRYPTO_MESSAGES) return CRYPTO_MESSAGES[code] ?? fallback;
  return fallback;
}
