import type { Role } from '@cipherdrop/shared';
import type { RequestHandler } from 'express';
import { getCtx } from '../context';
import { forbidden, unauthorized } from '../lib/errors';

/**
 * RBAC (spec section 12): use after requireAuth. The token's role must match AND the role is re-checked in
 * the database, so a demotion takes effect immediately rather than when the 15-minute access token expires.
 */
export function requireRole(role: Role): RequestHandler {
  return async (req, _res, next) => {
    if (!req.user) throw unauthorized();
    if (req.user.role !== role) throw forbidden();
    const current = await getCtx(req).prisma.user.findUnique({
      where: { id: req.user.id },
      select: { role: true },
    });
    if (!current || current.role !== role) throw forbidden();
    next();
  };
}
