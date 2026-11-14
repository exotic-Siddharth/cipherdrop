/**
 * Account/session services for lane B1 (spec sections 7.5, 10, 12).
 *
 * Sessions are token families: one Session row per login, one RefreshToken row per issued refresh token
 * (stored as sha256B64url). Rotation marks the presented token used; presenting a used token again is reuse:
 * the session is revoked, its sid denylisted and SESSION_REUSE_DETECTED audited. The one exception is a lost
 * response: a replay within REFRESH_GRACE_MS of the rotation, while the successor is unused, replaces that
 * successor (which is kept as a used token, so presenting it later is reuse). Revoking a session always writes
 * the sid denylist so its access tokens die at once (Review Focus 5).
 *
 * Never log or echo authKeys, tokens, codes, secrets or wrapped keys.
 */
import { randomInt } from 'node:crypto';
import { CROCKFORD_ALPHABET } from '@cipherdrop/crypto/constants';
import {
  LIMITS,
  REFRESH_COOKIE_NAME,
  REFRESH_COOKIE_PATH,
  type AutoLockMinutes,
  type Me,
} from '@cipherdrop/shared';
import type { Session, User } from '@prisma/client';
import type { Request, Response } from 'express';
import type { AppContext } from '../../context';
import { forbidden, unauthorized, validationError } from '../../lib/errors';
import { decodeB64url, sha256B64url, timingSafeEqualStr } from '../../lib/hash';
import { ipPrefix } from '../../lib/ip';
import { signAccessToken } from '../../lib/jwt';
import { denylistSid } from '../../lib/redis';
import { randomToken } from '../../lib/tokens';
import { verifyTotp } from '../../lib/totp';
import { verifyAccountAuthKey } from './authKeyHash';
import { summarizeUserAgent } from '../../lib/userAgent';

export const GENERIC_LOGIN_ERROR = 'Invalid email or password';
export const GENERIC_RECOVERY_ERROR = 'Invalid email or recovery key';
export const MFA_TOKEN_TTL_SEC = 5 * 60;
export const RECOVERY_TOKEN_TTL_SEC = 10 * 60;
export const MAX_FAILED_LOGINS = 10;
export const LOCKOUT_MS = 15 * 60_000;

type Req = Pick<Request, 'ip' | 'headers'>;

const DAY_MS = 86_400_000;

/** Me DTO (spec section 10). */
export function toMe(user: User): Me {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    totpEnabled: user.totpEnabledAt !== null,
    autoLockMinutes: user.autoLockMinutes as AutoLockMinutes,
    storageQuotaBytes: Number(user.storageQuotaBytes),
    storageUsedBytes: Number(user.storageUsedBytes),
    createdAt: user.createdAt.toISOString(),
  };
}

/** R3: a presented authKey / recoveryAuthKey must b64url-decode to exactly 32 bytes, else 400. */
export function keyBytes(b64: string, field: string): Buffer {
  const bytes = decodeB64url(b64, 32);
  if (!bytes) {
    throw validationError('Invalid request', {
      issues: [{ path: `body.${field}`, message: 'Expected 32 bytes (base64url)', code: 'custom' }],
    });
  }
  return bytes;
}

/** The KDF parameters of a user as sent to clients. */
export function kdfOf(user: User) {
  return {
    salt: user.kdfSalt,
    memoryKiB: user.kdfMemoryKiB,
    iterations: user.kdfIterations,
    parallelism: user.kdfParallelism,
  };
}

const userAgentOf = (req: Req) => {
  const ua = req.headers['user-agent'];
  return summarizeUserAgent(Array.isArray(ua) ? ua[0] : ua);
};

const refreshExpiry = (ctx: AppContext, from: Date) =>
  new Date(from.getTime() + ctx.env.REFRESH_TOKEN_TTL_DAYS * DAY_MS);

export interface IssuedSession {
  session: Session;
  accessToken: string;
  refreshToken: string;
  refreshExpiresAt: Date;
}

/** A new session (token family) with its first refresh token and an access token bound to its sid. */
export async function createSession(ctx: AppContext, user: User, req: Req): Promise<IssuedSession> {
  const now = ctx.now();
  const refreshToken = randomToken();
  const refreshExpiresAt = refreshExpiry(ctx, now);
  const session = await ctx.prisma.session.create({
    data: {
      userId: user.id,
      userAgent: userAgentOf(req),
      ipPrefix: ipPrefix(req.ip),
      createdAt: now,
      lastUsedAt: now,
      expiresAt: refreshExpiresAt,
      tokens: {
        create: {
          tokenHash: sha256B64url(refreshToken),
          createdAt: now,
          expiresAt: refreshExpiresAt,
        },
      },
    },
  });
  return {
    session,
    accessToken: signAccessToken(user, session.id),
    refreshToken,
    refreshExpiresAt,
  };
}

const cookieOptions = (ctx: AppContext) => ({
  httpOnly: true,
  secure: ctx.env.COOKIE_SECURE,
  sameSite: 'strict' as const,
  path: REFRESH_COOKIE_PATH,
});

export function setRefreshCookie(
  ctx: AppContext,
  res: Response,
  token: string,
  expires: Date,
): void {
  res.cookie(REFRESH_COOKIE_NAME, token, { ...cookieOptions(ctx), expires });
}

export function clearRefreshCookie(ctx: AppContext, res: Response): void {
  res.clearCookie(REFRESH_COOKIE_NAME, cookieOptions(ctx));
}

/** The refresh token from the cd_rt cookie when it is well-formed (32 bytes b64url), else null. */
export function refreshTokenOf(req: Request): string | null {
  const value = (req.cookies as Record<string, unknown> | undefined)?.[REFRESH_COOKIE_NAME];
  if (typeof value !== 'string' || !decodeB64url(value, 32)) return null;
  return value;
}

/** Revoke one session and denylist its sid (idempotent). True when this call revoked it. */
export async function revokeSession(ctx: AppContext, sessionId: string): Promise<boolean> {
  const result = await ctx.prisma.session.updateMany({
    where: { id: sessionId, revokedAt: null },
    data: { revokedAt: ctx.now() },
  });
  await denylistSid(ctx.redis, sessionId, ctx.env.ACCESS_TOKEN_TTL_SEC);
  return result.count === 1;
}

/** Revoke every live session of a user (optionally except one sid); returns the revoked ids. */
export async function revokeUserSessions(
  ctx: AppContext,
  userId: string,
  options: { exceptSid?: string } = {},
): Promise<string[]> {
  const sessions = await ctx.prisma.session.findMany({
    where: {
      userId,
      revokedAt: null,
      ...(options.exceptSid ? { id: { not: options.exceptSid } } : {}),
    },
    select: { id: true },
  });
  const ids = sessions.map((s) => s.id);
  if (ids.length === 0) return ids;
  await ctx.prisma.session.updateMany({
    where: { id: { in: ids }, revokedAt: null },
    data: { revokedAt: ctx.now() },
  });
  await Promise.all(ids.map((id) => denylistSid(ctx.redis, id, ctx.env.ACCESS_TOKEN_TTL_SEC)));
  return ids;
}

async function handleReuse(ctx: AppContext, session: Session, req: Req): Promise<never> {
  if (await revokeSession(ctx, session.id)) {
    await ctx.audit.record({
      userId: session.userId,
      action: 'SESSION_REUSE_DETECTED',
      req,
      metadata: { sessionId: session.id },
    });
  }
  throw unauthorized();
}

export interface RotatedRefresh {
  user: User;
  accessToken: string;
  refreshToken: string;
  refreshExpiresAt: Date;
}

/**
 * A rotated token presented again less than this long after its rotation, while its successor is still unused,
 * is taken as a lost response (the browser never got the successor), not as reuse. See docs/DESIGN.md.
 */
export const REFRESH_GRACE_MS = 30_000;

const inGraceWindow = (usedAt: Date, now: Date) =>
  now.getTime() - usedAt.getTime() < REFRESH_GRACE_MS;

/** Rotate a refresh token (spec section 10). Any problem is a 401; reuse also revokes the family. */
export async function rotateRefresh(
  ctx: AppContext,
  token: string,
  req: Req,
): Promise<RotatedRefresh> {
  const found = await ctx.prisma.refreshToken.findUnique({
    where: { tokenHash: sha256B64url(token) },
    include: { session: { include: { user: true } } },
  });
  if (!found) throw unauthorized();
  const { session } = found;
  const now = ctx.now();
  if (found.usedAt && !inGraceWindow(found.usedAt, now)) return handleReuse(ctx, session, req);
  if (session.revokedAt || session.expiresAt <= now || found.expiresAt <= now) {
    throw unauthorized();
  }
  const refreshToken = randomToken();
  const refreshExpiresAt = refreshExpiry(ctx, now);
  // Claim the token and issue its successor in ONE transaction: a failure rolls the claim back, so a
  // retry is not mistaken for reuse (C-28). A token that is already claimed is a replay: inside the grace
  // window, and only while its successor is unused, that successor is retired and replaced (same session);
  // otherwise it is reuse. The successor is retired by marking it used, not deleted: a genuine lost response
  // never delivered it, so whoever presents it later is contesting the family and is caught as reuse (and
  // logout still finds its session). Its row lock plus the count check leave at most one live successor. The
  // FOR UPDATE on the presented token queues concurrent replays, so each later one (a fresh READ COMMITTED
  // snapshot) sees and retires the successor the previous one issued instead of finding none and revoking.
  const claimed = await ctx.prisma.$transaction(async (tx) => {
    const claim = await tx.refreshToken.updateMany({
      where: { id: found.id, usedAt: null },
      data: { usedAt: now },
    });
    if (claim.count !== 1) {
      const [row] = await tx.$queryRaw<{ usedAt: Date | null }[]>`
        SELECT "usedAt" FROM "RefreshToken" WHERE "id" = ${found.id} FOR UPDATE`;
      if (!row?.usedAt || !inGraceWindow(row.usedAt, now)) return false;
      const replaced = await tx.refreshToken.updateMany({
        where: { rotatedFromId: found.id, usedAt: null },
        data: { usedAt: now },
      });
      if (replaced.count !== 1) return false;
    }
    await tx.refreshToken.create({
      data: {
        sessionId: session.id,
        tokenHash: sha256B64url(refreshToken),
        createdAt: now,
        expiresAt: refreshExpiresAt,
        rotatedFromId: found.id,
      },
    });
    await tx.session.update({
      where: { id: session.id },
      data: { lastUsedAt: now, expiresAt: refreshExpiresAt },
    });
    return true;
  });
  if (!claimed) return handleReuse(ctx, session, req);
  return {
    user: session.user,
    accessToken: signAccessToken(session.user, session.id),
    refreshToken,
    refreshExpiresAt,
  };
}

/* ---- Backup codes: 10 x 10 Crockford chars (xxxxx-xxxxx), SHA-256 at rest, single use ---- */

const CROCKFORD_ALIASES: Record<string, string> = { I: '1', L: '1', O: '0' };

/** Canonical 10-symbol form (upper case, no dash, Crockford aliases), or null if it cannot be a backup code. */
export function normalizeBackupCode(code: string): string | null {
  const s = code.trim().replace(/-/g, '').toUpperCase();
  if (s.length !== 10) return null;
  let out = '';
  for (const ch of s) {
    const c = CROCKFORD_ALIASES[ch] ?? ch;
    if (!CROCKFORD_ALPHABET.includes(c)) return null;
    out += c;
  }
  return out;
}

const backupCodeHash = (userId: string, normalized: string) =>
  sha256B64url(`${userId}:${normalized}`);

function generateBackupCode(): string {
  let s = '';
  for (let i = 0; i < 10; i++) s += CROCKFORD_ALPHABET[randomInt(CROCKFORD_ALPHABET.length)];
  return `${s.slice(0, 5)}-${s.slice(5)}`.toLowerCase();
}

/** Replace the user's backup codes with 10 fresh ones; returns them formatted (shown once). */
export async function issueBackupCodes(ctx: AppContext, userId: string): Promise<string[]> {
  const codes = Array.from({ length: LIMITS.BACKUP_CODE_COUNT }, generateBackupCode);
  await ctx.prisma.$transaction([
    ctx.prisma.backupCode.deleteMany({ where: { userId } }),
    ctx.prisma.backupCode.createMany({
      data: codes.map((c) => ({
        userId,
        codeHash: backupCodeHash(userId, normalizeBackupCode(c) as string),
      })),
    }),
  ]);
  return codes;
}

/* ---- Second factor ---- */

const TOTP_RE = /^\d{6}$/;

export type SecondFactor = 'totp' | 'backup';

/**
 * Verify (and consume) a TOTP code, or a backup code when `allowBackup`. TOTP steps are persisted
 * atomically (replay protection); a backup code is marked used atomically and audited BACKUP_CODE_USED.
 * A failure is audited MFA_CHALLENGE_FAILED. Returns the factor used, or null.
 */
export async function verifySecondFactor(
  ctx: AppContext,
  user: User,
  code: string,
  req: Req,
  options: { allowBackup: boolean; context: string },
): Promise<SecondFactor | null> {
  const factor = await checkSecondFactor(ctx, user, code.trim(), options.allowBackup);
  if (factor === 'backup') {
    await ctx.audit.record({
      userId: user.id,
      action: 'BACKUP_CODE_USED',
      req,
      metadata: { context: options.context },
    });
  }
  if (factor === null) {
    await ctx.audit.record({
      userId: user.id,
      action: 'MFA_CHALLENGE_FAILED',
      req,
      metadata: { context: options.context },
    });
  }
  return factor;
}

async function checkSecondFactor(
  ctx: AppContext,
  user: User,
  code: string,
  allowBackup: boolean,
): Promise<SecondFactor | null> {
  if (!user.totpEnabledAt || !user.totpSecretEnc) return null;
  if (TOTP_RE.test(code)) {
    const step = verifyTotp(user, code, { now: ctx.now(), keyB64: ctx.env.TOTP_ENC_KEY });
    if (step === null) return null;
    const saved = await ctx.prisma.user.updateMany({
      where: { id: user.id, OR: [{ totpLastStep: null }, { totpLastStep: { lt: step } }] },
      data: { totpLastStep: step },
    });
    return saved.count === 1 ? 'totp' : null;
  }
  if (!allowBackup) return null;
  const normalized = normalizeBackupCode(code);
  if (!normalized) return null;
  const presented = backupCodeHash(user.id, normalized);
  const unused = await ctx.prisma.backupCode.findMany({
    where: { userId: user.id, usedAt: null },
    select: { id: true, codeHash: true },
  });
  let matchId: string | null = null;
  for (const c of unused) {
    if (timingSafeEqualStr(c.codeHash, presented) && matchId === null) matchId = c.id;
  }
  if (!matchId) return null;
  const used = await ctx.prisma.backupCode.updateMany({
    where: { id: matchId, usedAt: null },
    data: { usedAt: ctx.now() },
  });
  return used.count === 1 ? 'backup' : null;
}

/** The user behind an access token; a deleted user is a 401. */
export async function loadUser(ctx: AppContext, userId: string): Promise<User> {
  const user = await ctx.prisma.user.findUnique({ where: { id: userId } });
  if (!user) throw unauthorized();
  return user;
}

/**
 * Re-authentication on signed-in routes: the current authKey, plus a TOTP or backup code when TOTP is on.
 * Wrong proofs are 403 (not 401) so the SPA does not treat them as an expired session.
 */
export async function requireAccountProof(
  ctx: AppContext,
  user: User,
  proof: { authKey: string; code?: string },
  req: Req,
  context: string,
): Promise<void> {
  const bytes = keyBytes(proof.authKey, 'authKey');
  if (!(await verifyAccountAuthKey(user.authKeyHash, bytes))) throw forbidden('Incorrect password');
  if (!user.totpEnabledAt) return;
  if (!proof.code) {
    throw validationError('A two-factor code is required', {
      issues: [{ path: 'body.code', message: 'Required when TOTP is enabled', code: 'custom' }],
    });
  }
  const factor = await verifySecondFactor(ctx, user, proof.code, req, {
    allowBackup: true,
    context,
  });
  if (!factor) throw forbidden('Invalid two-factor code');
}
