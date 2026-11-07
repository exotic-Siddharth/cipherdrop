import type { Role } from '@cipherdrop/shared';

/** Authenticated caller set by requireAuth / optionalAuth (claims of a non-denylisted access token). */
export interface AuthUser {
  id: string;
  role: Role;
  sid: string;
}

declare global {
  namespace Express {
    interface Request {
      /** Set by requireAuth/optionalAuth. */
      user?: AuthUser;
      /** Parsed `req.params` (validate()); Express 5 params stay raw strings. */
      validatedParams?: unknown;
      /** Parsed `req.query` (validate()); Express 5 `req.query` is a read-only getter. */
      validatedQuery?: unknown;
    }
  }
}

export {};
