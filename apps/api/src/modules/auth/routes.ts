/**
 * /api/auth routes (spec sections 7.5 and 10, R3, R9, R10). Zero-knowledge: the server only ever sees
 * HKDF-derived auth keys (b64url, 32 bytes), hashes and wrapped keys; none of them is logged or echoed.
 *
 * Error policy:
 * - unauthenticated proofs (login, MFA step, recovery) fail with a generic 401;
 * - a wrong re-authentication proof on a signed-in route (current authKey, TOTP/backup code) is a 403, so the
 *   SPA does not mistake it for an expired session and refresh;
 * - lockout (10 consecutive failures -> 15 min) answers exactly like a wrong password.
 * Rate limits (ctx.rateLimit): prelogin + login per IP+email, loginMfa per IP, register and recovery per IP,
 * and `reauth` (10 per 15 min per user) on the signed-in re-authentication routes.
 */
import { KDF_DEFAULT } from '@cipherdrop/crypto/constants';
import {
  AuthSuccessSchema,
  BackupCodesRegenerateRequestSchema,
  BackupCodesResponseSchema,
  LoginMfaRequestSchema,
  LoginRequestSchema,
  LoginResponseSchema,
  PasswordChangeRequestSchema,
  PreloginRequestSchema,
  PreloginResponseSchema,
  RecoveryCompleteRequestSchema,
  RecoveryRotateRequestSchema,
  RecoveryStartRequestSchema,
  RecoveryStartResponseSchema,
  RefreshResponseSchema,
  RegisterRequestSchema,
  SessionIdParamsSchema,
  SessionListResponseSchema,
  TotpDisableRequestSchema,
  TotpEnableRequestSchema,
  TotpSetupResponseSchema,
  VaultSchema,
  type SessionInfo,
} from '@cipherdrop/shared';
import { Prisma, type User } from '@prisma/client';
import type { Request, Response } from 'express';
import type { AppContext } from '../../context';
import { hashAuthKey } from '../../lib/argon2';
import { conflict, forbidden, notFound, unauthorized, validationError } from '../../lib/errors';
import { hmacSha256, sha256B64url, timingSafeEqualStr } from '../../lib/hash';
import { ipKey } from '../../lib/ip';
import { signPurposeToken, verifyPurposeToken } from '../../lib/jwt';
import { createRouter, type AppRouter } from '../../lib/router';
import { encryptTotpSecret, generateTotpSecret, totpOtpauthUrl, verifyTotp } from '../../lib/totp';
import { authUser } from '../../middleware/auth';
import { verifyAccountAuthKey, verifyAccountAuthKeyOrDummy } from './authKeyHash';
import {
  GENERIC_LOGIN_ERROR,
  GENERIC_RECOVERY_ERROR,
  LOCKOUT_MS,
  MAX_FAILED_LOGINS,
  MFA_TOKEN_TTL_SEC,
  RECOVERY_TOKEN_TTL_SEC,
  clearRefreshCookie,
  createSession,
  issueBackupCodes,
  kdfOf,
  keyBytes,
  loadUser,
  refreshTokenOf,
  requireAccountProof,
  revokeSession,
  revokeUserSessions,
  rotateRefresh,
  setRefreshCookie,
  toMe,
  verifySecondFactor,
} from './service';

const INVALID_CODE = 'Invalid or expired code';
const EMAIL_TAKEN = 'An account with this email already exists';
const INVALID_RECOVERY_TOKEN = 'Invalid or expired recovery token';

/** Compared against when the email is unknown, so a recovery attempt costs the same either way. */
const DUMMY_RECOVERY_HASH = sha256B64url('cipherdrop/v1/dummy-recovery-auth');

/** Binds a recovery token to the current recovery key: completing recovery (which rotates it) kills the token. */
const recoveryVersion = (recoveryAuthHash: string) =>
  sha256B64url(`cipherdrop/v1/recovery-token:${recoveryAuthHash}`).slice(0, 22);

const emailOf = (req: Request) => {
  const email = (req.body as { email?: unknown } | undefined)?.email;
  return typeof email === 'string' ? email : '';
};

const isUniqueViolation = (err: unknown) =>
  err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002';

export function authRoutes(ctx: AppContext): AppRouter {
  const r = createRouter('/api/auth');
  const tags = ['auth'];
  const { prisma } = ctx;

  const perIpEmail = (req: Request) => `${ipKey(req.ip)}|${sha256B64url(emailOf(req))}`;
  const preloginLimit = ctx.rateLimit({ name: 'prelogin', key: perIpEmail });
  const loginLimit = ctx.rateLimit({ name: 'login', key: perIpEmail });
  const loginMfaLimit = ctx.rateLimit({ name: 'loginMfa', key: (req) => ipKey(req.ip) });
  const registerLimit = ctx.rateLimit({ name: 'register', key: (req) => ipKey(req.ip) });
  const recoveryStartLimit = ctx.rateLimit({
    name: 'recovery',
    key: (req) => `start|${ipKey(req.ip)}`,
  });
  const recoveryCompleteLimit = ctx.rateLimit({
    name: 'recovery',
    key: (req) => `complete|${ipKey(req.ip)}`,
  });
  const reauthLimit = ctx.rateLimit({
    name: 'reauth',
    windowMs: 15 * 60_000,
    limit: 10,
    key: (req) => `user|${req.user?.id ?? ipKey(req.ip)}`,
  });

  /** Issue a session + cookie for `user`; returns the AuthSuccess body. */
  async function signIn(user: User, req: Request, res: Response) {
    const issued = await createSession(ctx, user, req);
    setRefreshCookie(ctx, res, issued.refreshToken, issued.refreshExpiresAt);
    return { user: toMe(user), accessToken: issued.accessToken };
  }

  /** A failed login proof: count it, lock after MAX_FAILED_LOGINS (spec section 10). */
  async function registerLoginFailure(user: User, req: Request, auditFailure: boolean) {
    const updated = await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginCount: { increment: 1 } },
      select: { failedLoginCount: true },
    });
    if (auditFailure) await ctx.audit.record({ userId: user.id, action: 'LOGIN_FAILURE', req });
    if (updated.failedLoginCount >= MAX_FAILED_LOGINS) {
      await prisma.user.update({
        where: { id: user.id },
        data: { failedLoginCount: 0, lockedUntil: new Date(ctx.now().getTime() + LOCKOUT_MS) },
      });
      await ctx.audit.record({ userId: user.id, action: 'LOGIN_LOCKED', req });
    }
  }

  const isLocked = (user: User) => user.lockedUntil !== null && user.lockedUntil > ctx.now();

  /** Full login success: reset the failure counter, sign in, audit. */
  async function completeLogin(user: User, req: Request, res: Response, mfa: string | null) {
    const fresh = await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginCount: 0, lockedUntil: null },
    });
    const body = await signIn(fresh, req, res);
    await ctx.audit.record({ userId: user.id, action: 'LOGIN_SUCCESS', req, metadata: { mfa } });
    return body;
  }

  r.route(
    {
      method: 'post',
      path: '/prelogin',
      summary: 'KDF parameters for an email (deterministic fake salt for unknown emails)',
      tags,
      request: { body: PreloginRequestSchema },
      responses: { 200: { description: 'KDF parameters', schema: PreloginResponseSchema } },
    },
    preloginLimit,
    async (req, res) => {
      const email = req.body.email;
      // Computed for every request so known and unknown emails cost the same.
      const fakeSalt = hmacSha256(ctx.env.PRELOGIN_SECRET, email.toLowerCase())
        .subarray(0, 16)
        .toString('base64url');
      const user = await prisma.user.findUnique({ where: { email } });
      res.json({ kdf: user ? kdfOf(user) : { salt: fakeSalt, ...KDF_DEFAULT } });
    },
  );

  r.route(
    {
      method: 'post',
      path: '/register',
      summary: 'Register a zero-knowledge account (sets the cd_rt cookie)',
      tags,
      request: { body: RegisterRequestSchema },
      responses: {
        201: { description: 'Registered and signed in', schema: AuthSuccessSchema },
        409: { description: 'Email already registered (CONFLICT)' },
      },
    },
    registerLimit,
    async (req, res) => {
      const body = req.body;
      const bytes = keyBytes(body.authKey, 'authKey');
      // R16: a 409 is an accepted, rate-limited enumeration risk (there is no email channel). Checking first
      // avoids a Prisma P2002 error log in the common case; the unique index still guards the race.
      const taken = await prisma.user.findUnique({
        where: { email: body.email },
        select: { id: true },
      });
      if (taken) throw conflict(EMAIL_TAKEN);
      const authKeyHash = await hashAuthKey(bytes);
      let user: User;
      try {
        user = await prisma.user.create({
          data: {
            email: body.email,
            authKeyHash,
            kdfSalt: body.kdf.salt,
            kdfMemoryKiB: body.kdf.memoryKiB,
            kdfIterations: body.kdf.iterations,
            kdfParallelism: body.kdf.parallelism,
            wrappedAccountKey: body.wrappedAccountKey,
            wrappedAccountKeyRecovery: body.wrappedAccountKeyRecovery,
            recoveryAuthHash: body.recoveryAuthHash,
            storageQuotaBytes: BigInt(ctx.env.USER_DEFAULT_QUOTA_BYTES),
          },
        });
      } catch (err) {
        if (isUniqueViolation(err)) throw conflict(EMAIL_TAKEN);
        throw err;
      }
      const result = await signIn(user, req, res);
      await ctx.audit.record({ userId: user.id, action: 'REGISTER', req });
      res.status(201).json(result);
    },
  );

  r.route(
    {
      method: 'post',
      path: '/login',
      summary: 'Log in with the derived authKey (MFA step when TOTP is enabled)',
      tags,
      request: { body: LoginRequestSchema },
      responses: {
        200: {
          description: 'Signed in, or mfaRequired with an mfaToken',
          schema: LoginResponseSchema,
        },
        401: { description: 'Generic authentication failure (also while locked out)' },
      },
    },
    loginLimit,
    async (req, res) => {
      const bytes = keyBytes(req.body.authKey, 'authKey');
      const user = await prisma.user.findUnique({ where: { email: req.body.email } });
      // Always one Argon2id verification, so unknown, locked and wrong look alike in timing.
      const ok = await verifyAccountAuthKeyOrDummy(user?.authKeyHash, bytes);
      if (!user) throw unauthorized(GENERIC_LOGIN_ERROR);
      if (isLocked(user)) {
        await ctx.audit.record({
          userId: user.id,
          action: 'LOGIN_FAILURE',
          req,
          metadata: { locked: true },
        });
        throw unauthorized(GENERIC_LOGIN_ERROR);
      }
      if (!ok) {
        await registerLoginFailure(user, req, true);
        throw unauthorized(GENERIC_LOGIN_ERROR);
      }
      if (user.totpEnabledAt) {
        res.json({
          mfaRequired: true,
          mfaToken: signPurposeToken('mfa', user.id, MFA_TOKEN_TTL_SEC),
        });
        return;
      }
      res.json({ mfaRequired: false, ...(await completeLogin(user, req, res, null)) });
    },
  );

  r.route(
    {
      method: 'post',
      path: '/login/mfa',
      summary: 'Complete a login with a TOTP or backup code (sets the cd_rt cookie)',
      tags,
      request: { body: LoginMfaRequestSchema },
      responses: {
        200: { description: 'Signed in', schema: AuthSuccessSchema },
        401: { description: 'Wrong, replayed or expired code/token' },
      },
    },
    loginMfaLimit,
    async (req, res) => {
      const claims = verifyPurposeToken('mfa', req.body.mfaToken);
      const user = await prisma.user.findUnique({ where: { id: claims.sub } });
      if (!user || !user.totpEnabledAt) throw unauthorized(INVALID_CODE);
      if (isLocked(user)) throw unauthorized(INVALID_CODE);
      const factor = await verifySecondFactor(ctx, user, req.body.code, req, {
        allowBackup: true,
        context: 'login',
      });
      if (!factor) {
        // MFA failures count toward the same lockout (MFA_CHALLENGE_FAILED is already audited).
        await registerLoginFailure(user, req, false);
        throw unauthorized(INVALID_CODE);
      }
      res.json(await completeLogin(user, req, res, factor));
    },
  );

  r.route(
    {
      method: 'post',
      path: '/refresh',
      summary: 'Rotate the refresh cookie and issue a new access token (reuse revokes the session)',
      tags,
      auth: 'refreshCookie',
      responses: { 200: { description: 'New access token', schema: RefreshResponseSchema } },
    },
    async (req, res) => {
      const token = refreshTokenOf(req);
      if (!token) {
        clearRefreshCookie(ctx, res);
        throw unauthorized();
      }
      try {
        const rotated = await rotateRefresh(ctx, token, req);
        setRefreshCookie(ctx, res, rotated.refreshToken, rotated.refreshExpiresAt);
        res.json({ user: toMe(rotated.user), accessToken: rotated.accessToken });
      } catch (err) {
        clearRefreshCookie(ctx, res);
        throw err;
      }
    },
  );

  r.route(
    {
      method: 'post',
      path: '/logout',
      summary: 'Revoke the current session and clear the cookie',
      tags,
      auth: 'refreshCookie',
      responses: { 204: { description: 'Signed out' } },
    },
    async (req, res) => {
      const token = refreshTokenOf(req);
      if (token) {
        const found = await prisma.refreshToken.findUnique({
          where: { tokenHash: sha256B64url(token) },
          select: { session: { select: { id: true, userId: true } } },
        });
        if (found && (await revokeSession(ctx, found.session.id))) {
          await ctx.audit.record({ userId: found.session.userId, action: 'LOGOUT', req });
        }
      }
      clearRefreshCookie(ctx, res);
      res.status(204).end();
    },
  );

  r.route(
    {
      method: 'get',
      path: '/vault',
      summary: 'Wrapped account key and KDF parameters for a local vault unlock',
      tags,
      auth: 'user',
      responses: { 200: { description: 'Vault material', schema: VaultSchema } },
    },
    async (req, res) => {
      const user = await loadUser(ctx, authUser(req).id);
      res.json({ wrappedAccountKey: user.wrappedAccountKey, kdf: kdfOf(user) });
    },
  );

  r.route(
    {
      method: 'post',
      path: '/password',
      summary: 'Change password: re-wrapped account key; other sessions revoked and denylisted',
      tags,
      auth: 'user',
      request: { body: PasswordChangeRequestSchema },
      responses: {
        204: { description: 'Password changed' },
        403: { description: 'Wrong currentAuthKey (FORBIDDEN)' },
      },
    },
    reauthLimit,
    async (req, res) => {
      const me = authUser(req);
      const user = await loadUser(ctx, me.id);
      const body = req.body;
      const current = keyBytes(body.currentAuthKey, 'currentAuthKey');
      const next = keyBytes(body.newAuthKey, 'newAuthKey');
      if (!(await verifyAccountAuthKey(user.authKeyHash, current)))
        throw forbidden('Incorrect password');
      await prisma.user.update({
        where: { id: user.id },
        data: {
          authKeyHash: await hashAuthKey(next),
          kdfSalt: body.kdf.salt,
          kdfMemoryKiB: body.kdf.memoryKiB,
          kdfIterations: body.kdf.iterations,
          kdfParallelism: body.kdf.parallelism,
          wrappedAccountKey: body.wrappedAccountKey,
          failedLoginCount: 0,
          lockedUntil: null,
        },
      });
      const revoked = await revokeUserSessions(ctx, user.id, { exceptSid: me.sid });
      await ctx.audit.record({
        userId: user.id,
        action: 'PASSWORD_CHANGED',
        req,
        metadata: { revokedSessions: revoked.length },
      });
      res.status(204).end();
    },
  );

  r.route(
    {
      method: 'post',
      path: '/recovery/start',
      summary: 'Start recovery with the recovery auth key (generic 401 on mismatch)',
      tags,
      request: { body: RecoveryStartRequestSchema },
      responses: {
        200: {
          description: 'Recovery token and wrapped account key',
          schema: RecoveryStartResponseSchema,
        },
        401: { description: 'Generic recovery failure' },
      },
    },
    recoveryStartLimit,
    async (req, res) => {
      const presented = sha256B64url(keyBytes(req.body.recoveryAuthKey, 'recoveryAuthKey'));
      const user = await prisma.user.findUnique({ where: { email: req.body.email } });
      const matches = timingSafeEqualStr(user?.recoveryAuthHash ?? DUMMY_RECOVERY_HASH, presented);
      if (!user || !matches) throw unauthorized(GENERIC_RECOVERY_ERROR);
      res.json({
        recoveryToken: signPurposeToken('recovery', user.id, RECOVERY_TOKEN_TTL_SEC, {
          rv: recoveryVersion(user.recoveryAuthHash),
        }),
        wrappedAccountKeyRecovery: user.wrappedAccountKeyRecovery,
        mfaRequired: user.totpEnabledAt !== null,
      });
    },
  );

  r.route(
    {
      method: 'post',
      path: '/recovery/complete',
      summary: 'Set a new password and rotate the recovery key; all sessions revoked',
      tags,
      request: { body: RecoveryCompleteRequestSchema },
      responses: {
        200: { description: 'Signed in', schema: AuthSuccessSchema },
        400: { description: 'The recovery key was not rotated, or invalid input' },
        401: { description: 'Invalid recovery token or TOTP code' },
      },
    },
    recoveryCompleteLimit,
    async (req, res) => {
      const body = req.body;
      const claims = verifyPurposeToken('recovery', body.recoveryToken);
      const user = await prisma.user.findUnique({ where: { id: claims.sub } });
      if (
        !user ||
        typeof claims.rv !== 'string' ||
        !timingSafeEqualStr(claims.rv, recoveryVersion(user.recoveryAuthHash))
      ) {
        throw unauthorized(INVALID_RECOVERY_TOKEN);
      }
      if (timingSafeEqualStr(body.recoveryAuthHash, user.recoveryAuthHash)) {
        throw validationError('The recovery key must be rotated', {
          issues: [
            {
              path: 'body.recoveryAuthHash',
              message: 'Must be a new recovery key',
              code: 'custom',
            },
          ],
        });
      }
      const next = keyBytes(body.newAuthKey, 'newAuthKey');
      if (user.totpEnabledAt) {
        if (!body.code) throw unauthorized('A two-factor code is required');
        const factor = await verifySecondFactor(ctx, user, body.code, req, {
          allowBackup: true,
          context: 'recovery',
        });
        if (!factor) throw unauthorized(INVALID_CODE);
      }
      const updated = await prisma.user.updateMany({
        // Single use: only succeeds while the recovery key the token was issued for is still current.
        where: { id: user.id, recoveryAuthHash: user.recoveryAuthHash },
        data: {
          authKeyHash: await hashAuthKey(next),
          kdfSalt: body.kdf.salt,
          kdfMemoryKiB: body.kdf.memoryKiB,
          kdfIterations: body.kdf.iterations,
          kdfParallelism: body.kdf.parallelism,
          wrappedAccountKey: body.wrappedAccountKey,
          wrappedAccountKeyRecovery: body.wrappedAccountKeyRecovery,
          recoveryAuthHash: body.recoveryAuthHash,
          failedLoginCount: 0,
          lockedUntil: null,
        },
      });
      if (updated.count !== 1) throw unauthorized(INVALID_RECOVERY_TOKEN);
      const revoked = await revokeUserSessions(ctx, user.id);
      await ctx.audit.record({
        userId: user.id,
        action: 'RECOVERY_USED',
        req,
        metadata: { revokedSessions: revoked.length },
      });
      const fresh = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
      res.json(await signIn(fresh, req, res));
    },
  );

  r.route(
    {
      method: 'post',
      path: '/recovery/rotate',
      summary: 'Replace the recovery key (R9); sessions stay signed in',
      tags,
      auth: 'user',
      request: { body: RecoveryRotateRequestSchema },
      responses: {
        204: { description: 'Recovery key rotated' },
        403: { description: 'Wrong authKey or two-factor code (FORBIDDEN)' },
      },
    },
    reauthLimit,
    async (req, res) => {
      const user = await loadUser(ctx, authUser(req).id);
      const body = req.body;
      await requireAccountProof(ctx, user, body, req, 'recovery-rotate');
      await prisma.user.update({
        where: { id: user.id },
        data: {
          wrappedAccountKeyRecovery: body.wrappedAccountKeyRecovery,
          recoveryAuthHash: body.recoveryAuthHash,
        },
      });
      await ctx.audit.record({ userId: user.id, action: 'RECOVERY_KEY_ROTATED', req });
      res.status(204).end();
    },
  );

  r.route(
    {
      method: 'post',
      path: '/mfa/totp/setup',
      summary: 'Create a pending TOTP secret (encrypted at rest)',
      tags,
      auth: 'user',
      responses: {
        200: { description: 'Secret and otpauth URL', schema: TotpSetupResponseSchema },
        409: { description: 'TOTP is already enabled (CONFLICT)' },
      },
    },
    async (req, res) => {
      const user = await loadUser(ctx, authUser(req).id);
      if (user.totpEnabledAt) throw conflict('Two-factor authentication is already enabled');
      const secret = generateTotpSecret();
      await prisma.user.update({
        where: { id: user.id },
        data: { totpPendingSecretEnc: encryptTotpSecret(secret, user.id, ctx.env.TOTP_ENC_KEY) },
      });
      res.json({ secret, otpauthUrl: totpOtpauthUrl(secret, user.email) });
    },
  );

  r.route(
    {
      method: 'post',
      path: '/mfa/totp/enable',
      summary: 'Verify a code, enable TOTP and issue 10 backup codes',
      tags,
      auth: 'user',
      request: { body: TotpEnableRequestSchema },
      responses: {
        200: { description: 'Backup codes (shown once)', schema: BackupCodesResponseSchema },
        403: { description: 'Wrong code (FORBIDDEN)' },
        409: { description: 'Already enabled, or no pending setup (CONFLICT)' },
      },
    },
    reauthLimit,
    async (req, res) => {
      const user = await loadUser(ctx, authUser(req).id);
      if (user.totpEnabledAt) throw conflict('Two-factor authentication is already enabled');
      const pending = user.totpPendingSecretEnc;
      if (!pending) throw conflict('Start the two-factor setup first');
      const step = verifyTotp(
        { id: user.id, totpSecretEnc: pending, totpLastStep: user.totpLastStep },
        req.body.code,
        { now: ctx.now(), keyB64: ctx.env.TOTP_ENC_KEY },
      );
      if (step === null) {
        await ctx.audit.record({
          userId: user.id,
          action: 'MFA_CHALLENGE_FAILED',
          req,
          metadata: { context: 'enable' },
        });
        throw forbidden('Invalid two-factor code');
      }
      const enabled = await prisma.user.updateMany({
        where: { id: user.id, totpEnabledAt: null, totpPendingSecretEnc: pending },
        data: {
          totpSecretEnc: pending,
          totpPendingSecretEnc: null,
          totpEnabledAt: ctx.now(),
          totpLastStep: step,
        },
      });
      if (enabled.count !== 1) throw conflict('Two-factor setup changed, start again');
      const backupCodes = await issueBackupCodes(ctx, user.id);
      await ctx.audit.record({ userId: user.id, action: 'MFA_ENABLED', req });
      res.json({ backupCodes });
    },
  );

  r.route(
    {
      method: 'post',
      path: '/mfa/totp/disable',
      summary: 'Disable TOTP (authKey + code)',
      tags,
      auth: 'user',
      request: { body: TotpDisableRequestSchema },
      responses: {
        204: { description: 'TOTP disabled' },
        403: { description: 'Wrong authKey or code (FORBIDDEN)' },
        409: { description: 'TOTP is not enabled (CONFLICT)' },
      },
    },
    reauthLimit,
    async (req, res) => {
      const user = await loadUser(ctx, authUser(req).id);
      if (!user.totpEnabledAt) throw conflict('Two-factor authentication is not enabled');
      await requireAccountProof(ctx, user, req.body, req, 'totp-disable');
      await prisma.$transaction([
        prisma.user.update({
          where: { id: user.id },
          data: {
            totpSecretEnc: null,
            totpPendingSecretEnc: null,
            totpEnabledAt: null,
            totpLastStep: null,
          },
        }),
        prisma.backupCode.deleteMany({ where: { userId: user.id } }),
      ]);
      await ctx.audit.record({ userId: user.id, action: 'MFA_DISABLED', req });
      res.status(204).end();
    },
  );

  r.route(
    {
      method: 'post',
      path: '/mfa/backup-codes',
      summary: 'Regenerate backup codes',
      tags,
      auth: 'user',
      request: { body: BackupCodesRegenerateRequestSchema },
      responses: {
        200: { description: 'New backup codes (shown once)', schema: BackupCodesResponseSchema },
        403: { description: 'Wrong code (FORBIDDEN)' },
        409: { description: 'TOTP is not enabled (CONFLICT)' },
      },
    },
    reauthLimit,
    async (req, res) => {
      const user = await loadUser(ctx, authUser(req).id);
      if (!user.totpEnabledAt) throw conflict('Two-factor authentication is not enabled');
      const factor = await verifySecondFactor(ctx, user, req.body.code, req, {
        allowBackup: false,
        context: 'backup-codes',
      });
      if (!factor) throw forbidden('Invalid two-factor code');
      const backupCodes = await issueBackupCodes(ctx, user.id);
      await ctx.audit.record({ userId: user.id, action: 'BACKUP_CODES_REGENERATED', req });
      res.json({ backupCodes });
    },
  );

  r.route(
    {
      method: 'get',
      path: '/sessions',
      summary: 'List sessions (current flag via sid)',
      tags,
      auth: 'user',
      responses: { 200: { description: 'Sessions', schema: SessionListResponseSchema } },
    },
    async (req, res) => {
      const me = authUser(req);
      const sessions = await prisma.session.findMany({
        where: { userId: me.id, revokedAt: null, expiresAt: { gt: ctx.now() } },
        orderBy: [{ lastUsedAt: 'desc' }, { id: 'desc' }],
      });
      const items: SessionInfo[] = sessions.map((s) => ({
        id: s.id,
        current: s.id === me.sid,
        userAgent: s.userAgent,
        ipPrefix: s.ipPrefix,
        createdAt: s.createdAt.toISOString(),
        lastUsedAt: s.lastUsedAt.toISOString(),
        expiresAt: s.expiresAt.toISOString(),
      }));
      res.json(items);
    },
  );

  r.route(
    {
      method: 'delete',
      path: '/sessions/:id',
      summary: 'Revoke one session (denylists its sid)',
      tags,
      auth: 'user',
      request: { params: SessionIdParamsSchema },
      responses: { 204: { description: 'Revoked' }, 404: { description: 'Unknown session' } },
    },
    async (req, res) => {
      const me = authUser(req);
      const session = await prisma.session.findFirst({
        where: { id: req.validatedParams.id, userId: me.id, revokedAt: null },
        select: { id: true },
      });
      if (!session) throw notFound('Session not found');
      if (await revokeSession(ctx, session.id)) {
        await ctx.audit.record({
          userId: me.id,
          action: 'SESSION_REVOKED',
          req,
          metadata: { sessionId: session.id },
        });
      }
      res.status(204).end();
    },
  );

  r.route(
    {
      method: 'post',
      path: '/sessions/revoke-others',
      summary: 'Revoke every other session (denylists their sids)',
      tags,
      auth: 'user',
      responses: { 204: { description: 'Revoked' } },
    },
    async (req, res) => {
      const me = authUser(req);
      const revoked = await revokeUserSessions(ctx, me.id, { exceptSid: me.sid });
      if (revoked.length > 0) {
        await ctx.audit.record({
          userId: me.id,
          action: 'SESSION_REVOKED',
          req,
          metadata: { scope: 'others', count: revoked.length },
        });
      }
      res.status(204).end();
    },
  );

  return r;
}
