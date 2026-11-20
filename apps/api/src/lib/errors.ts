/**
 * AppError and helpers. The error middleware turns them into `{error:{code, message, details?}}` (spec section 10).
 * Messages are user-facing and must never contain secrets, keys, tokens or plaintext metadata.
 */
import type {
  ErrorCode,
  FeatureDisabledDetails,
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

  constructor(
    status: number,
    code: ErrorCode,
    message: string,
    details?: unknown,
    options: { retryAfterSec?: number; cause?: unknown } = {},
  ) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'AppError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.retryAfterSec = options.retryAfterSec;
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
 * 429 UPLOAD_BUDGET_EXCEEDED: this client (IPv4 address or IPv6 /48) has created its rolling budget of
 * anonymous drop bytes. Retry-After is when enough of it frees up; signed-in senders are not affected.
 */
export const uploadBudgetExceeded = (retryAfterSec: number, details: UploadBudgetDetails) =>
  new AppError(
    429,
    'UPLOAD_BUDGET_EXCEEDED',
    'You have sent a lot without an account recently. Try again later, or sign in to send more.',
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

export const internal = (message = 'Internal server error', cause?: unknown) =>
  new AppError(500, 'INTERNAL', message, undefined, { cause });

/** 501 for S4 route stubs only (lanes replace every use). */
export const notImplemented = (what = 'This endpoint') =>
  new AppError(501, 'INTERNAL', `${what} is not implemented yet`);
