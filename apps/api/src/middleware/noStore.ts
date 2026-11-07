import type { RequestHandler } from 'express';

/**
 * `Cache-Control: no-store` on EVERY /api response (spec section 10), including errors, 404s, rate-limit
 * responses and static Swagger UI assets: the header is forced again right before the headers are written,
 * so later middleware (serve-static, handlers) cannot override it.
 */
export const noStore: RequestHandler = (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  const writeHead = res.writeHead;
  res.writeHead = function patchedWriteHead(
    this: typeof res,
    ...args: Parameters<typeof writeHead>
  ) {
    if (!this.headersSent) this.setHeader('Cache-Control', 'no-store');
    return writeHead.apply(this, args);
  } as typeof writeHead;
  next();
};
