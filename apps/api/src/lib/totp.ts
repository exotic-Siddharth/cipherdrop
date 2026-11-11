/**
 * Server-side TOTP (spec section 10, R3): otpauth for RFC 6238 codes (SHA1, 6 digits, 30 s, a window of
 * one step either way) and node:crypto AES-256-GCM for secrets at rest under TOTP_ENC_KEY.
 *
 * Replay protection: a code is accepted only when its step is strictly greater than the user's
 * `totpLastStep`; callers persist the returned step atomically (UPDATE ... WHERE totpLastStep < step).
 * Errors never contain a secret or a code.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { HOTP, Secret, TOTP } from 'otpauth';
import { env } from '../config/env';
import { timingSafeEqualStr } from './hash';

export const TOTP_ISSUER = 'CipherDrop';
export const TOTP_PERIOD_SEC = 30;
export const TOTP_DIGITS = 6;
const TOTP_ALGORITHM = 'SHA1';
const TOTP_WINDOW = 1;
const SECRET_BYTES = 20;

const BLOB_VERSION = 'v1';
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const AAD_PREFIX = 'cipherdrop/v1/totp-secret:';

const CODE_RE = /^\d{6}$/;

/** A fresh 160-bit secret, base32 (32 chars). */
export function generateTotpSecret(): string {
  return new Secret({ size: SECRET_BYTES }).base32;
}

/** otpauth://totp/CipherDrop:<account>?secret=...&issuer=CipherDrop&algorithm=SHA1&digits=6&period=30 */
export function totpOtpauthUrl(secretBase32: string, account: string): string {
  return new TOTP({
    issuer: TOTP_ISSUER,
    label: account,
    algorithm: TOTP_ALGORITHM,
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD_SEC,
    secret: Secret.fromBase32(secretBase32),
  }).toString();
}

export interface MatchTotpOptions {
  /** Defaults to the current time. */
  now?: Date;
  /** Replay guard: only steps strictly greater than this are accepted. */
  afterStep?: number | null;
}

/** The step (30 s counter) a valid code belongs to, or null (malformed, outside the window or replayed). */
export function matchTotpStep(
  secretBase32: string,
  code: string,
  options: MatchTotpOptions = {},
): number | null {
  if (typeof code !== 'string' || !CODE_RE.test(code)) return null;
  const secret = Secret.fromBase32(secretBase32);
  const nowMs = (options.now ?? new Date()).getTime();
  const current = Math.floor(nowMs / 1000 / TOTP_PERIOD_SEC);
  const afterStep = options.afterStep ?? null;
  let matched: number | null = null;
  // Compare every candidate in the window (no early exit) with a constant-time comparison.
  for (let delta = -TOTP_WINDOW; delta <= TOTP_WINDOW; delta++) {
    const step = current + delta;
    const expected = HOTP.generate({
      secret,
      algorithm: TOTP_ALGORITHM,
      digits: TOTP_DIGITS,
      counter: step,
    });
    const ok = timingSafeEqualStr(expected, code);
    if (ok && (afterStep === null || step > afterStep) && matched === null) matched = step;
  }
  return matched;
}

function decodeKey(keyB64: string): Buffer {
  const key = Buffer.from(keyB64, 'base64');
  if (key.length !== 32) throw new Error('TOTP_ENC_KEY must decode to 32 bytes');
  return key;
}

const aadFor = (userId: string) => Buffer.from(`${AAD_PREFIX}${userId}`, 'utf8');

/** `v1.<b64url(nonce 12 || ciphertext || tag 16)>`, bound to the user id through the AAD. */
export function encryptTotpSecret(
  secretBase32: string,
  userId: string,
  keyB64: string = env.TOTP_ENC_KEY,
): string {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', decodeKey(keyB64), nonce, {
    authTagLength: TAG_BYTES,
  });
  cipher.setAAD(aadFor(userId));
  const ciphertext = Buffer.concat([cipher.update(secretBase32, 'utf8'), cipher.final()]);
  const body = Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]);
  return `${BLOB_VERSION}.${body.toString('base64url')}`;
}

/** Decrypt a stored secret. Throws a generic Error on any malformed, foreign or tampered blob. */
export function decryptTotpSecret(
  blob: string,
  userId: string,
  keyB64: string = env.TOTP_ENC_KEY,
): string {
  const fail = () => new Error('Cannot decrypt the stored TOTP secret');
  const dot = typeof blob === 'string' ? blob.indexOf('.') : -1;
  if (dot < 0 || blob.slice(0, dot) !== BLOB_VERSION) throw fail();
  const encoded = blob.slice(dot + 1);
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw fail();
  const body = Buffer.from(encoded, 'base64url');
  if (body.length <= NONCE_BYTES + TAG_BYTES) throw fail();
  const nonce = body.subarray(0, NONCE_BYTES);
  const tag = body.subarray(body.length - TAG_BYTES);
  const ciphertext = body.subarray(NONCE_BYTES, body.length - TAG_BYTES);
  try {
    const decipher = createDecipheriv('aes-256-gcm', decodeKey(keyB64), nonce, {
      authTagLength: TAG_BYTES,
    });
    decipher.setAAD(aadFor(userId));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch {
    throw fail();
  }
}

export interface TotpUser {
  id: string;
  /** Encrypted secret to check against (the enabled one, or the pending one during enable). */
  totpSecretEnc: string | null;
  totpLastStep: number | null;
}

export interface VerifyTotpOptions {
  now?: Date;
  keyB64?: string;
}

/** Verify a code against the user's stored secret with replay protection: the accepted step, or null. */
export function verifyTotp(
  user: TotpUser,
  code: string,
  options: VerifyTotpOptions = {},
): number | null {
  if (!user.totpSecretEnc) return null;
  const secret = decryptTotpSecret(user.totpSecretEnc, user.id, options.keyB64);
  return matchTotpStep(secret, code, { now: options.now, afterStep: user.totpLastStep });
}
