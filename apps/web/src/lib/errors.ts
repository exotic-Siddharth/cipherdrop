/**
 * User-facing error text for toasts and error states. Server messages are written for users (apps/api
 * lib/errors.ts) and never contain secrets; crypto errors are identified by their stable `code`, which
 * survives Worker boundaries.
 */
import {
  FeatureDisabledDetailsSchema,
  QuotaExceededDetailsSchema,
  UploadBudgetDetailsSchema,
  type SwitchableFeature,
} from '@cipherdrop/shared';
import { formatBytes, formatDate, pluralize } from './format';
import { isApiError, type ApiError } from './http';

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

/** The API refused an admin route because the account has no two-step verification (403, MFA_REQUIRED). */
export function isMfaRequired(err: unknown): boolean {
  return (
    isApiError(err) &&
    err.status === 403 &&
    (err.details as { reason?: unknown } | null | undefined)?.reason === 'MFA_REQUIRED'
  );
}

/** A correct login proof for a suspended account (403, ACCOUNT_SUSPENDED; server-6). */
export function isAccountSuspended(err: unknown): boolean {
  return (
    isApiError(err) &&
    err.status === 403 &&
    (err.details as { reason?: unknown } | null | undefined)?.reason === 'ACCOUNT_SUSPENDED'
  );
}

/** The API wants a recent sign-in or step-up of this admin session first (403, STEP_UP_REQUIRED). */
export function isStepUpRequired(err: unknown): boolean {
  return (
    isApiError(err) &&
    err.status === 403 &&
    (err.details as { reason?: unknown } | null | undefined)?.reason === 'STEP_UP_REQUIRED'
  );
}

export function isAbortError(err: unknown): boolean {
  return (
    (err instanceof DOMException || err instanceof Error) &&
    (err as { name?: string }).name === 'AbortError'
  );
}

const FEATURE_DISABLED_MESSAGES: Readonly<Record<SwitchableFeature, string>> = Object.freeze({
  anonymousUploads: 'This server accepts uploads from signed-in users only. Log in to send files.',
  registration: 'This server is not accepting new accounts right now.',
});

/**
 * The budget refuses a create that would go over it (it counts declared bytes, deleted drops included), so the
 * copy says what the limit is and that this drop does not fit, not that the sender has used it all.
 */
function uploadBudgetText(err: ApiError): string {
  const budget = UploadBudgetDetailsSchema.safeParse(err.details);
  const sent = budget.success
    ? `Without an account you can send up to ${formatBytes(budget.data.limitBytes)} per ${pluralize(budget.data.windowHours, 'hour')}, and this drop would go over that.`
    : 'This drop would go over the limit for sending without an account.';
  const wait = err.retryAfter ? `Try again in ${formatWait(err.retryAfter)}` : 'Try again later';
  return `${sent} ${wait}, or sign in to send more.`;
}

function quotaText(err: ApiError, fallback: string): string {
  const quota = QuotaExceededDetailsSchema.safeParse(err.details);
  if (quota.success && quota.data.probationEndsAt) {
    return `This drop does not fit in your storage. New accounts can store up to ${formatBytes(quota.data.quotaBytes)} until ${formatDate(quota.data.probationEndsAt)}. Delete a drop, or wait until then.`;
  }
  return err.message || fallback;
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
      case 'UPLOAD_BUDGET_EXCEEDED':
        return uploadBudgetText(err);
      case 'QUOTA_EXCEEDED':
        return quotaText(err, fallback);
      case 'STORAGE_FULL':
        return "This server's storage is full, so it is not accepting new uploads right now. Please try again later.";
      case 'FEATURE_DISABLED': {
        const details = FeatureDisabledDetailsSchema.safeParse(err.details);
        return details.success
          ? FEATURE_DISABLED_MESSAGES[details.data.feature]
          : err.message || fallback;
      }
      case 'FORBIDDEN':
        return isAccountSuspended(err)
          ? 'This account is suspended, so you cannot sign in. Contact the operator of this server if you think this is a mistake.'
          : err.message || fallback;
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
