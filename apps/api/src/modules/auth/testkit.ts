/**
 * Test-only helpers for the B1 suites (auth, me). Client values are derived with the real @cipherdrop/crypto
 * at KDF_MIN, exactly as the SPA would derive them; TOTP codes come from an independent otpauth generator.
 * Not imported by application code.
 */
import {
  KDF_MIN,
  b64urlEncode,
  createAccountBundle,
  deriveAccountKeys,
  type AccountBundle,
  type KdfParams,
} from '@cipherdrop/crypto';
import { REFRESH_COOKIE_NAME, type Me } from '@cipherdrop/shared';
import type { Express } from 'express';
import { Secret, TOTP } from 'otpauth';
import request, { type Response } from 'supertest';
import { expect } from 'vitest';
import { uniqueEmail } from '../../../test/factories';

export interface RegisteredUser {
  email: string;
  password: string;
  bundle: AccountBundle;
  /** b64url authKey, as the client sends it. */
  authKey: string;
  user: Me;
  accessToken: string;
  /** `cd_rt=<token>` for a Cookie header. */
  cookie: string;
}

export const bearer = (token: string) => `Bearer ${token}`;

/** The refresh token set by a response, or null. */
export function refreshTokenFrom(res: Response): string | null {
  const raw = res.headers['set-cookie'] as unknown;
  const list = Array.isArray(raw) ? (raw as string[]) : typeof raw === 'string' ? [raw] : [];
  for (const c of list) {
    const m = new RegExp(`^${REFRESH_COOKIE_NAME}=([^;]*)`).exec(c);
    if (m && m[1]) return decodeURIComponent(m[1]);
  }
  return null;
}

/** The raw Set-Cookie header for cd_rt, or null. */
export function refreshSetCookie(res: Response): string | null {
  const raw = res.headers['set-cookie'] as unknown;
  const list = Array.isArray(raw) ? (raw as string[]) : typeof raw === 'string' ? [raw] : [];
  return list.find((c) => c.startsWith(`${REFRESH_COOKIE_NAME}=`)) ?? null;
}

export function cookieFrom(res: Response): string {
  const token = refreshTokenFrom(res);
  if (!token) throw new Error('response did not set the refresh cookie');
  return `${REFRESH_COOKIE_NAME}=${token}`;
}

/** Register through the API with a client-derived bundle (Argon2id at KDF_MIN). */
export async function registerViaApi(
  app: Express,
  options: { email?: string; password?: string; ip?: string } = {},
): Promise<RegisteredUser> {
  const email = options.email ?? uniqueEmail('b1');
  const password = options.password ?? `pw ${email} 2026`;
  const bundle = await createAccountBundle(password, KDF_MIN);
  const authKey = b64urlEncode(bundle.authKey);
  const res = await request(app)
    .post('/api/auth/register')
    .set('X-Forwarded-For', options.ip ?? '198.51.100.10')
    .send({
      email,
      authKey,
      kdf: bundle.kdf,
      wrappedAccountKey: bundle.wrappedAccountKey,
      wrappedAccountKeyRecovery: bundle.wrappedAccountKeyRecovery,
      recoveryAuthHash: bundle.recoveryAuthHash,
    });
  expect(res.status, JSON.stringify(res.body)).toBe(201);
  return {
    email,
    password,
    bundle,
    authKey,
    user: res.body.user as Me,
    accessToken: res.body.accessToken as string,
    cookie: cookieFrom(res),
  };
}

/** Client login flow: prelogin -> derive authKey from the password -> login. */
export async function loginViaApi(
  app: Express,
  email: string,
  password: string,
  headers: Record<string, string> = {},
): Promise<Response> {
  const pre = await request(app).post('/api/auth/prelogin').set(headers).send({ email });
  expect(pre.status).toBe(200);
  const { authKey } = await deriveAccountKeys(password, pre.body.kdf as KdfParams);
  return request(app)
    .post('/api/auth/login')
    .set(headers)
    .send({ email, authKey: b64urlEncode(authKey) });
}

/** A session from a full login (no MFA). */
export async function newSession(
  app: Express,
  u: Pick<RegisteredUser, 'email' | 'password'>,
  headers: Record<string, string> = {},
): Promise<{ accessToken: string; cookie: string; sid: string }> {
  const res = await loginViaApi(app, u.email, u.password, headers);
  expect(res.status, JSON.stringify(res.body)).toBe(200);
  expect(res.body.mfaRequired).toBe(false);
  const accessToken = res.body.accessToken as string;
  return { accessToken, cookie: cookieFrom(res), sid: sidOf(accessToken) };
}

/** The sid claim of an access token (no verification). */
export function sidOf(accessToken: string): string {
  const payload = JSON.parse(
    Buffer.from(accessToken.split('.')[1] ?? '', 'base64url').toString('utf8'),
  ) as { sid: string };
  return payload.sid;
}

/** An independent TOTP generator (spec parameters). R23: pass offsetMs 30_000 for the next step's code. */
export function totpCode(secretBase32: string, offsetMs = 0): string {
  return TOTP.generate({
    secret: Secret.fromBase32(secretBase32),
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    timestamp: Date.now() + offsetMs,
  });
}

/** A 6-digit code that is NOT valid for any step in the +-1 window. */
export function wrongTotpCode(secretBase32: string): string {
  const valid = new Set([-30_000, 0, 30_000].map((o) => totpCode(secretBase32, o)));
  for (let n = 0; ; n++) {
    const candidate = String((123456 + n * 7919) % 1_000_000).padStart(6, '0');
    if (!valid.has(candidate)) return candidate;
  }
}

/** setup + enable through the API, using the code of the current step. */
export async function enableTotpViaApi(
  app: Express,
  accessToken: string,
): Promise<{ secret: string; backupCodes: string[] }> {
  const setup = await request(app)
    .post('/api/auth/mfa/totp/setup')
    .set('Authorization', bearer(accessToken));
  expect(setup.status, JSON.stringify(setup.body)).toBe(200);
  const secret = setup.body.secret as string;
  const enable = await request(app)
    .post('/api/auth/mfa/totp/enable')
    .set('Authorization', bearer(accessToken))
    .send({ code: totpCode(secret) });
  expect(enable.status, JSON.stringify(enable.body)).toBe(200);
  return { secret, backupCodes: enable.body.backupCodes as string[] };
}
