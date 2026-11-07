/**
 * Bearer access-token authentication (spec section 10 "Tokens").
 * Both middlewares verify the JWT (HS256, issuer, audience) and then reject a session id present in the
 * Redis denylist `${KEY_PREFIX}:revoked:sid:<sid>` IMMEDIATELY (Review Focus 5). No DB lookup per request.
 *
 * - requireAuth: 401 without a valid token.
 * - optionalAuth: anonymous when there is no Authorization header; an invalid/expired token is still a 401
 *   (so the SPA refreshes instead of silently acting anonymously).
 */
import type { Request, RequestHandler } from 'express';
import { getCtx } from '../context';
import { unauthorized } from '../lib/errors';
import { verifyAccessToken } from '../lib/jwt';
import { isSidDenylisted } from '../lib/redis';
import { bearerToken } from '../lib/tokens';
import type { AuthUser } from '../types/express';

async function authenticate(req: Request): Promise<AuthUser> {
  const token = bearerToken(req);
  if (!token) throw unauthorized();
  const claims = verifyAccessToken(token);
  if (await isSidDenylisted(getCtx(req).redis, claims.sid)) throw unauthorized();
  return { id: claims.sub, role: claims.role, sid: claims.sid };
}

export const requireAuth: RequestHandler = async (req, _res, next) => {
  req.user = await authenticate(req);
  next();
};

export const optionalAuth: RequestHandler = async (req, _res, next) => {
  if (req.headers.authorization) req.user = await authenticate(req);
  next();
};

/** The authenticated user, or a 401 (for handlers behind requireAuth). */
export function authUser(req: Request): AuthUser {
  if (!req.user) throw unauthorized();
  return req.user;
}
