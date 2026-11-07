import { randomBytes } from 'node:crypto';
import type { Request } from 'express';

/** Opaque random token, b64url (default 32 bytes = 43 chars). Store only sha256B64url(token). */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** `Authorization: Bearer <token>` value, or null. Used for upload/download tokens and access tokens. */
export function bearerToken(req: Pick<Request, 'headers'>): string | null {
  const header = req.headers.authorization;
  if (!header) return null;
  const match = /^Bearer[ ]+([A-Za-z0-9._~+/-]+=*)$/i.exec(header.trim());
  return match?.[1] ?? null;
}
