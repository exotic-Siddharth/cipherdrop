/**
 * AppError and helpers. The error middleware turns them into `{error:{code, message, details?}}` (spec section 10).
 * Messages are user-facing and must never contain secrets, keys, tokens or plaintext metadata.
 */
import type {
  ErrorCode,
  FeatureDisabledDetails,
  ForbiddenReason,
  GoneReason,
  SwitchableFeature,
  UploadBudgetDetails,
} from '@cipherdrop/shared';

export class AppError extends Error {
  readonly status: number;
  readonly code: ErrorCode;
  readonly details?: unknown;
  /** Sets the Retry-After header (seconds) on 429/503 responses. */
  readonly retryAfterSec?: number;
  /**
   * A 429 because the server is at capacity, not because this client went over a limit: the request was refused
   * before anything was checked, so limiters created with `refundServerBusy` do not count it (lib/rateLimit.ts).
   */
  readonly serverBusy: boolean;

  constructor(
    status: number,
    code: ErrorCode,
    message: string,
    details?: unknown,
    options: { retryAfterSec?: number; cause?: unknown; serverBusy?: boolean } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'AppError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.retryAfterSec = options.retryAfterSec;
    this.serverBusy = options.serverBusy ?? false;
  }
}

export function isAppError(err: unknown): err is AppError {
  return err instanceof AppError;
}

/** 400 VALIDATION_ERROR. `details` is usually `{issues:[{path, message, code}]}`. */
export const validationError = (message = 'Invalid request', details?: unknown) =>
  new AppError(400, 'VALIDATION_ERROR', message, details);
export const badRequest = validationError;

/** 401 UNAUTHORIZED. Keep auth failures generic (no user enumeration). */
export const unauthorized = (message = 'Unauthorized', details?: unknown) =>
  new AppError(401, 'UNAUTHORIZED', message, details);

export const forbidden = (message = 'Forbidden') => new AppError(403, 'FORBIDDEN', message);

/** 403 FEATURE_DISABLED: an operator switch (ALLOW_ANONYMOUS_UPLOADS, ALLOW_REGISTRATION) is off. */
export const featureDisabled = (feature: SwitchableFeature, message: string) =>
  new AppError(403, 'FEATURE_DISABLED', message, { feature } satisfies FeatureDisabledDetails);

/**
 * 403 FORBIDDEN with `details.reason` MFA_REQUIRED: an admin without two-step verification on an admin route.
 * Admin routes can reveal reporter-supplied decryption keys, so the role alone is not enough (review server-3).
 */
export const mfaRequired = (
  message = 'Admin access needs two-step verification. Turn it on in Settings, Security, then try again.',
) => new AppError(403, 'FORBIDDEN', message, { reason: 'MFA_REQUIRED' satisfies ForbiddenReason });

/**
 * 403 FORBIDDEN with `details.reason` ACCOUNT_SUSPENDED (server-6). Sent only after a correct login proof, so an
 * attacker without the password learns nothing about the account.
 */
export const accountSuspended = (
  message = 'This account is suspended. Contact the operator of this server if you think this is a mistake.',
) =>
  new AppError(403, 'FORBIDDEN', message, {
    reason: 'ACCOUNT_SUSPENDED' satisfies ForbiddenReason,
  });

export const notFound = (message = 'Not found') => new AppError(404, 'NOT_FOUND', message);

export const conflict = (message = 'Conflict', details?: unknown) =>
  new AppError(409, 'CONFLICT', message, details);

const GONE_MESSAGES: Record<GoneReason, string> = {
  EXPIRED: 'This drop has expired',
  EXHAUSTED: 'This drop has no downloads left',
  DELETED: 'This drop was deleted',
  DISABLED: 'This drop was disabled by a moderator',
};

/** 410 GONE with `details.reason` (spec section 10, GET /drops/:id). */
export const gone = (reason: GoneReason, message: string = GONE_MESSAGES[reason]) =>
  new AppError(410, 'GONE', message, { reason });

export const payloadTooLarge = (message = 'Payload too large', details?: unknown) =>
  new AppError(413, 'PAYLOAD_TOO_LARGE', message, details);

/** 413 QUOTA_EXCEEDED: the user's storage quota (or the per-drop byte limit) would be exceeded. */
export const quotaExceeded = (message = 'Storage quota exceeded', details?: unknown) =>
  new AppError(413, 'QUOTA_EXCEEDED', message, details);

/**
 * 429 UPLOAD_BUDGET_EXCEEDED: this drop would take this client (IPv4 address or IPv6 /48) over its rolling
 * budget of anonymous drop bytes. Retry-After is when enough of it frees up; signed-in senders are not affected.
 */
export const uploadBudgetExceeded = (retryAfterSec: number, details: UploadBudgetDetails) =>
  new AppError(
    429,
    'UPLOAD_BUDGET_EXCEEDED',
    'This drop would go over the limit for sending without an account. Try again later, or sign in to send more.',
    details,
    { retryAfterSec },
  );

export const rateLimited = (retryAfterSec?: number) =>
  new AppError(429, 'RATE_LIMITED', 'Too many requests, please try again later', undefined, {
    retryAfterSec,
  });

/**
 * 507 STORAGE_FULL: the instance is full (GLOBAL_STORAGE_CAP_BYTES reached, or the blob volume's free space
 * would fall below STORAGE_MIN_FREE_BYTES). One answer for both, with no numbers: clients learn nothing about
 * the disk.
 */
export const storageFull = () =>
  new AppError(
    507,
    'STORAGE_FULL',
    'This server is not accepting new uploads right now because its storage is full. Try again later.',
  );

/**
 * 429 RATE_LIMITED for a full server-side queue (ctx.argon2): the same answer as rateLimited for the client, but
 * marked serverBusy so that per-client limiters with `refundServerBusy` take the request back.
 */
export const serverBusy = (retryAfterSec: number) =>
  new AppError(429, 'RATE_LIMITED', 'Too many requests, please try again later', undefined, {
    retryAfterSec,
    serverBusy: true,
  });

export const internal = (message = 'Internal server error', cause?: unknown) =>
  new AppError(500, 'INTERNAL', message, undefined, { cause });

/** 501 for S4 route stubs only (lanes replace every use). */
export const notImplemented = (what = 'This endpoint') =>
  new AppError(501, 'INTERNAL', `${what} is not implemented yet`);
