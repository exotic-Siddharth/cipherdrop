/**
 * /api/auth routes (spec section 10 "Auth & account", R9). S4 STUB: every handler answers 501.
 * B1 owns this file: replace the handlers, keep the defs (they are the validated + OpenAPI contract), add the
 * rate limiters (ctx.rateLimit: prelogin/login per IP+email, loginMfa, register, recovery).
 */
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
} from '@cipherdrop/shared';
import type { AppContext } from '../../context';
import { notImplemented } from '../../lib/errors';
import { createRouter, type AppRouter } from '../../lib/router';

export function authRoutes(_ctx: AppContext): AppRouter {
  const r = createRouter('/api/auth');
  const tags = ['auth'];
  const stub = () => {
    throw notImplemented();
  };

  r.route(
    {
      method: 'post',
      path: '/prelogin',
      summary: 'KDF parameters for an email (deterministic fake salt for unknown emails)',
      tags,
      request: { body: PreloginRequestSchema },
      responses: { 200: { description: 'KDF parameters', schema: PreloginResponseSchema } },
    },
    stub,
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
    stub,
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
    stub,
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
    stub,
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
    stub,
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
    stub,
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
    stub,
  );
  r.route(
    {
      method: 'post',
      path: '/password',
      summary: 'Change password: re-wrapped account key; other sessions revoked and denylisted',
      tags,
      auth: 'user',
      request: { body: PasswordChangeRequestSchema },
      responses: { 204: { description: 'Password changed' } },
    },
    stub,
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
    stub,
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
        401: { description: 'Invalid recovery token or TOTP code' },
      },
    },
    stub,
  );
  r.route(
    {
      method: 'post',
      path: '/recovery/rotate',
      summary: 'Replace the recovery key (R9); sessions stay signed in',
      tags,
      auth: 'user',
      request: { body: RecoveryRotateRequestSchema },
      responses: { 204: { description: 'Recovery key rotated' } },
    },
    stub,
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
      },
    },
    stub,
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
      },
    },
    stub,
  );
  r.route(
    {
      method: 'post',
      path: '/mfa/totp/disable',
      summary: 'Disable TOTP (authKey + code)',
      tags,
      auth: 'user',
      request: { body: TotpDisableRequestSchema },
      responses: { 204: { description: 'TOTP disabled' } },
    },
    stub,
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
      },
    },
    stub,
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
    stub,
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
    stub,
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
    stub,
  );

  return r;
}
