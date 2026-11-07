/**
 * AppError and helpers. The error middleware turns them into `{error:{code, message, details?}}` (spec section 10).
 * Messages are user-facing and must never contain secrets, keys, tokens or plaintext metadata.
 */
import type { ErrorCode, GoneReason } from '@cipherdrop/shared';

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

export const rateLimited = (retryAfterSec?: number) =>
  new AppError(429, 'RATE_LIMITED', 'Too many requests, please try again later', undefined, {
    retryAfterSec,
  });

export const internal = (message = 'Internal server error', cause?: unknown) =>
  new AppError(500, 'INTERNAL', message, undefined, { cause });

/** 501 for S4 route stubs only (lanes replace every use). */
export const notImplemented = (what = 'This endpoint') =>
  new AppError(501, 'INTERNAL', `${what} is not implemented yet`);
