/**
 * 404 and error middleware: every error becomes `{error:{code, message, details?}}` (spec section 10).
 * Stack traces and internal messages never reach the client. 5xx are logged with the request id only
 * (no bodies, no headers).
 */
import { Prisma } from '@prisma/client';
import type { ErrorRequestHandler, RequestHandler } from 'express';
import { ZodError } from 'zod';
import type { AppContext } from '../context';
import {
  AppError,
  internal,
  isAppError,
  notFound,
  payloadTooLarge,
  validationError,
} from '../lib/errors';
import { logger as defaultLogger } from '../lib/logger';

export const notFoundHandler: RequestHandler = (_req, _res, next) => {
  next(notFound());
};

/** Map anything thrown to an AppError. */
export function toAppError(err: unknown): AppError {
  if (isAppError(err)) return err;
  if (err instanceof ZodError) {
    return validationError('Invalid request', {
      issues: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message, code: i.code })),
    });
  }
  if (err instanceof Prisma.PrismaClientKnownRequestError) {
    if (err.code === 'P2002') return new AppError(409, 'CONFLICT', 'Already exists');
    if (err.code === 'P2025') return notFound();
  }
  // body-parser errors (express.json / express.raw)
  const type = (err as { type?: unknown } | null)?.type;
  if (type === 'entity.too.large') return payloadTooLarge();
  if (type === 'entity.parse.failed') return validationError('Malformed JSON body');
  if (
    type === 'encoding.unsupported' ||
    type === 'charset.unsupported' ||
    type === 'request.aborted' ||
    type === 'request.size.invalid' ||
    type === 'entity.verify.failed'
  ) {
    return validationError('Unreadable request body');
  }
  return internal('Internal server error', err);
}

export const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  const appErr = toAppError(err);
  const log = (req.app.locals as { ctx?: AppContext }).ctx?.logger ?? defaultLogger;
  if (appErr.status >= 500) {
    const cause = appErr === err ? appErr.cause : err;
    log.error(
      {
        reqId: (req as typeof req & { id?: string }).id,
        err: cause instanceof Error ? cause : appErr,
      },
      'request failed',
    );
  }
  if (res.headersSent) {
    // e.g. a chunk stream failed mid-response: we cannot send JSON any more.
    next(err);
    return;
  }
  if (appErr.retryAfterSec !== undefined)
    res.setHeader('Retry-After', String(appErr.retryAfterSec));
  res.status(appErr.status).json({
    error: {
      code: appErr.code,
      message: appErr.message,
      ...(appErr.details !== undefined ? { details: appErr.details } : {}),
    },
  });
};
