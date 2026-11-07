/**
 * JWTs (spec section 10 "Tokens"): HS256 only, explicit algorithm list, issuer and audience checks.
 * Access tokens: claims {sub, role, sid}, audience "cipherdrop:access", TTL ACCESS_TOKEN_TTL_SEC.
 * Purpose tokens (mfaToken 5 min, recoveryToken 10 min): audience "cipherdrop:<purpose>" + `purpose` claim,
 * so a purpose token can never pass as an access token and vice versa.
 */
import { RoleSchema, type Role } from '@cipherdrop/shared';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { env } from '../config/env';
import { unauthorized } from './errors';

const ISSUER = 'cipherdrop';
const ACCESS_AUDIENCE = 'cipherdrop:access';

export type TokenPurpose = 'mfa' | 'recovery';
const purposeAudience = (purpose: TokenPurpose) => `cipherdrop:${purpose}`;

const AccessClaimsSchema = z.object({
  sub: z.string().min(1),
  role: RoleSchema,
  sid: z.string().min(1),
  iat: z.number().optional(),
  exp: z.number().optional(),
});
export type AccessClaims = z.infer<typeof AccessClaimsSchema>;

export interface PurposeClaims {
  sub: string;
  purpose: TokenPurpose;
  iat?: number;
  exp?: number;
  [claim: string]: unknown;
}

export function signAccessToken(user: { id: string; role: Role }, sid: string): string {
  return jwt.sign({ role: user.role, sid }, env.JWT_ACCESS_SECRET, {
    algorithm: 'HS256',
    subject: user.id,
    issuer: ISSUER,
    audience: ACCESS_AUDIENCE,
    expiresIn: env.ACCESS_TOKEN_TTL_SEC,
  });
}

/** Verify an access token; any failure is a generic 401. (The sid denylist is checked by middleware/auth.) */
export function verifyAccessToken(token: string): AccessClaims {
  try {
    const payload = jwt.verify(token, env.JWT_ACCESS_SECRET, {
      algorithms: ['HS256'],
      issuer: ISSUER,
      audience: ACCESS_AUDIENCE,
    });
    return AccessClaimsSchema.parse(payload);
  } catch {
    throw unauthorized();
  }
}

/** Short-lived single-purpose token. `extra` claims must not reuse reserved names. */
export function signPurposeToken(
  purpose: TokenPurpose,
  userId: string,
  ttlSec: number,
  extra: Record<string, string | number | boolean> = {},
): string {
  return jwt.sign({ ...extra, purpose }, env.JWT_ACCESS_SECRET, {
    algorithm: 'HS256',
    subject: userId,
    issuer: ISSUER,
    audience: purposeAudience(purpose),
    expiresIn: ttlSec,
  });
}

export function verifyPurposeToken(purpose: TokenPurpose, token: string): PurposeClaims {
  try {
    const payload = jwt.verify(token, env.JWT_ACCESS_SECRET, {
      algorithms: ['HS256'],
      issuer: ISSUER,
      audience: purposeAudience(purpose),
    });
    if (typeof payload !== 'object' || payload === null) throw new Error('bad payload');
    const claims = payload as Record<string, unknown>;
    if (claims.purpose !== purpose || typeof claims.sub !== 'string' || !claims.sub) {
      throw new Error('bad claims');
    }
    return claims as PurposeClaims;
  } catch {
    throw unauthorized();
  }
}
