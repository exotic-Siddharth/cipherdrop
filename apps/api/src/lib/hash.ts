/**
 * Server-side hashing primitives (R3): node:crypto only. End-to-end crypto lives in packages/crypto.
 * Every token and hash comparison must go through timingSafeEqualStr.
 */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export type BytesLike = string | Uint8Array;

export function sha256(data: BytesLike): Buffer {
  return createHash('sha256').update(data).digest();
}

/** Lowercase hex SHA-256 (chunk hashes, R5). */
export function sha256Hex(data: BytesLike): string {
  return createHash('sha256').update(data).digest('hex');
}

/** b64url(SHA-256(data)): token hashes; equals the client's hashForServer() for 32-byte keys. */
export function sha256B64url(data: BytesLike): string {
  return createHash('sha256').update(data).digest('base64url');
}

export function hmacSha256(key: BytesLike, data: BytesLike): Buffer {
  return createHmac('sha256', key).update(data).digest();
}

/** Constant-time string comparison (equal-length buffers; a length mismatch returns false). */
export function timingSafeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) {
    // Burn comparable time so the length check is not a much faster path.
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}

/** Alias named in spec section 5 (lib/hash: timingSafeEqualB64). */
export const timingSafeEqualB64 = timingSafeEqualStr;

/**
 * Strict base64url decode: returns null unless `s` is the canonical unpadded encoding (and has
 * `expectedBytes` bytes when given). Presented keys must be exactly 32 bytes (R3).
 */
export function decodeB64url(s: string, expectedBytes?: number): Buffer | null {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) return null;
  const buf = Buffer.from(s, 'base64url');
  if (buf.toString('base64url') !== s) return null;
  if (expectedBytes !== undefined && buf.length !== expectedBytes) return null;
  return buf;
}
