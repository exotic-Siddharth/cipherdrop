import type { Role } from '@cipherdrop/shared';
import type { RequestHandler } from 'express';
import { getCtx } from '../context';
import { forbidden, mfaRequired, unauthorized } from '../lib/errors';

/**
 * RBAC (spec section 12): use after requireAuth. The token's role must match AND the role is re-checked in
 * the database, so a demotion takes effect immediately rather than when the 15-minute access token expires.
 *
 * ADMIN also needs two-step verification on the account (review server-3): admin routes return reporter-supplied
 * decryption keys and mint review grants, the one place where plaintext of other people's drops is reachable, so a
 * stolen admin password alone must not open them. Checked in the same query, so turning 2FA off closes the console
 * at once. A non-admin gets the plain 403 first, with no hint about 2FA.
 */
export function requireRole(role: Role): RequestHandler {
  return async (req, _res, next) => {
    if (!req.user) throw unauthorized();
    if (req.user.role !== role) throw forbidden();
    const current = await getCtx(req).prisma.user.findUnique({
      where: { id: req.user.id },
      select: { role: true, totpEnabledAt: true },
    });
    if (!current || current.role !== role) throw forbidden();
    if (role === 'ADMIN' && current.totpEnabledAt === null) throw mfaRequired();
    next();
  };
}
