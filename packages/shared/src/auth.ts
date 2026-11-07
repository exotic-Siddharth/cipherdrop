/**
 * Auth & account contracts (spec section 10 "Auth & account", R9). The server never sees passwords:
 * clients send HKDF-derived auth keys (b64url, 32 bytes) and keys wrapped in the browser.
 */
import { z } from 'zod';
import { AUTO_LOCK_OPTIONS } from './constants';
import {
  AuthKeySchema,
  EmailSchema,
  IdSchema,
  IsoDateTimeSchema,
  KdfParamsSchema,
  MfaCodeSchema,
  RoleSchema,
  Sha256B64urlSchema,
  TotpCodeSchema,
  WrappedKeySchema,
} from './common';

export const AutoLockMinutesSchema = z.union([
  z.literal(AUTO_LOCK_OPTIONS[0]),
  z.literal(AUTO_LOCK_OPTIONS[1]),
  z.literal(AUTO_LOCK_OPTIONS[2]),
]);

/** The signed-in user as returned by /auth/* and /me. Byte counts are JSON numbers (< 2^53). */
export const MeSchema = z.object({
  id: IdSchema,
  email: z.string(),
  role: RoleSchema,
  totpEnabled: z.boolean(),
  autoLockMinutes: AutoLockMinutesSchema,
  storageQuotaBytes: z.number().int().nonnegative(),
  storageUsedBytes: z.number().int().nonnegative(),
  createdAt: IsoDateTimeSchema,
});
export type Me = z.infer<typeof MeSchema>;

/** Body of a successful login/register/refresh/recovery; the refresh token is set as the cd_rt cookie. */
export const AuthSuccessSchema = z.object({
  user: MeSchema,
  /** JWT HS256 (15 min), claims {sub, role, sid}; keep it in memory only. */
  accessToken: z.string().min(1),
});
export type AuthSuccess = z.infer<typeof AuthSuccessSchema>;

/* POST /auth/prelogin */
export const PreloginRequestSchema = z.object({ email: EmailSchema });
export type PreloginRequest = z.infer<typeof PreloginRequestSchema>;
/** Unknown emails get a deterministic fake salt with default params: identical shape, no enumeration. */
export const PreloginResponseSchema = z.object({ kdf: KdfParamsSchema });
export type PreloginResponse = z.infer<typeof PreloginResponseSchema>;

/* POST /auth/register -> 201 AuthSuccess (+ cookie); 409 if the email exists. */
export const RegisterRequestSchema = z.object({
  email: EmailSchema,
  authKey: AuthKeySchema,
  kdf: KdfParamsSchema,
  wrappedAccountKey: WrappedKeySchema,
  wrappedAccountKeyRecovery: WrappedKeySchema,
  recoveryAuthHash: Sha256B64urlSchema,
});
export type RegisterRequest = z.infer<typeof RegisterRequestSchema>;

/* POST /auth/login */
export const LoginRequestSchema = z.object({ email: EmailSchema, authKey: AuthKeySchema });
export type LoginRequest = z.infer<typeof LoginRequestSchema>;

export const LoginSuccessSchema = AuthSuccessSchema.extend({ mfaRequired: z.literal(false) });
export const LoginMfaRequiredSchema = z.object({
  mfaRequired: z.literal(true),
  /** Short-lived JWT (5 min) with purpose "mfa"; exchange it at /auth/login/mfa. */
  mfaToken: z.string().min(1),
});
export const LoginResponseSchema = z.discriminatedUnion('mfaRequired', [
  LoginSuccessSchema,
  LoginMfaRequiredSchema,
]);
export type LoginResponse = z.infer<typeof LoginResponseSchema>;

/* POST /auth/login/mfa -> AuthSuccess (+ cookie) */
export const LoginMfaRequestSchema = z.object({
  mfaToken: z.string().min(1),
  /** 6-digit TOTP or a backup code. */
  code: MfaCodeSchema,
});
export type LoginMfaRequest = z.infer<typeof LoginMfaRequestSchema>;

/* POST /auth/refresh (cookie) -> {user, accessToken} + rotated cookie */
export const RefreshResponseSchema = AuthSuccessSchema;
export type RefreshResponse = z.infer<typeof RefreshResponseSchema>;

/* GET /auth/vault */
export const VaultSchema = z.object({
  wrappedAccountKey: WrappedKeySchema,
  kdf: KdfParamsSchema,
});
export type Vault = z.infer<typeof VaultSchema>;

/* POST /auth/password -> 204 (other sessions revoked and denylisted) */
export const PasswordChangeRequestSchema = z.object({
  currentAuthKey: AuthKeySchema,
  newAuthKey: AuthKeySchema,
  kdf: KdfParamsSchema,
  wrappedAccountKey: WrappedKeySchema,
});
export type PasswordChangeRequest = z.infer<typeof PasswordChangeRequestSchema>;

/* POST /auth/recovery/start (generic 401 on mismatch or unknown email) */
export const RecoveryStartRequestSchema = z.object({
  email: EmailSchema,
  recoveryAuthKey: AuthKeySchema,
});
export type RecoveryStartRequest = z.infer<typeof RecoveryStartRequestSchema>;
export const RecoveryStartResponseSchema = z.object({
  /** Short-lived JWT (10 min) with purpose "recovery". */
  recoveryToken: z.string().min(1),
  wrappedAccountKeyRecovery: WrappedKeySchema,
  mfaRequired: z.boolean(),
});
export type RecoveryStartResponse = z.infer<typeof RecoveryStartResponseSchema>;

/* POST /auth/recovery/complete -> AuthSuccess (+ cookie); the recovery key MUST be rotated. */
export const RecoveryCompleteRequestSchema = z.object({
  recoveryToken: z.string().min(1),
  /** Required when TOTP is enabled. */
  code: MfaCodeSchema.optional(),
  newAuthKey: AuthKeySchema,
  kdf: KdfParamsSchema,
  wrappedAccountKey: WrappedKeySchema,
  wrappedAccountKeyRecovery: WrappedKeySchema,
  recoveryAuthHash: Sha256B64urlSchema,
});
export type RecoveryCompleteRequest = z.infer<typeof RecoveryCompleteRequestSchema>;

/* POST /auth/recovery/rotate (R9) -> 204, audited RECOVERY_KEY_ROTATED, sessions stay signed in */
export const RecoveryRotateRequestSchema = z.object({
  authKey: AuthKeySchema,
  /** Required when TOTP is enabled. */
  code: MfaCodeSchema.optional(),
  wrappedAccountKeyRecovery: WrappedKeySchema,
  recoveryAuthHash: Sha256B64urlSchema,
});
export type RecoveryRotateRequest = z.infer<typeof RecoveryRotateRequestSchema>;

/* POST /auth/mfa/totp/setup -> secret stored as pending (encrypted at rest) */
export const TotpSetupResponseSchema = z.object({
  /** Base32 TOTP secret for manual entry. */
  secret: z.string().min(16),
  /** otpauth://totp/... URI rendered locally as a QR code. */
  otpauthUrl: z.string().startsWith('otpauth://'),
});
export type TotpSetupResponse = z.infer<typeof TotpSetupResponseSchema>;

/* POST /auth/mfa/totp/enable -> {backupCodes} */
export const TotpEnableRequestSchema = z.object({ code: TotpCodeSchema });
export type TotpEnableRequest = z.infer<typeof TotpEnableRequestSchema>;

/** 10 single-use backup codes, `xxxxx-xxxxx`, shown once. */
export const BackupCodesResponseSchema = z.object({
  backupCodes: z.array(z.string().min(10)).length(10),
});
export type BackupCodesResponse = z.infer<typeof BackupCodesResponseSchema>;

/* POST /auth/mfa/totp/disable -> 204 */
export const TotpDisableRequestSchema = z.object({ authKey: AuthKeySchema, code: MfaCodeSchema });
export type TotpDisableRequest = z.infer<typeof TotpDisableRequestSchema>;

/* POST /auth/mfa/backup-codes -> {backupCodes} (regenerate) */
export const BackupCodesRegenerateRequestSchema = z.object({ code: TotpCodeSchema });
export type BackupCodesRegenerateRequest = z.infer<typeof BackupCodesRegenerateRequestSchema>;

/* GET /auth/sessions -> SessionInfo[] */
export const SessionInfoSchema = z.object({
  id: IdSchema,
  /** True for the session of the presented access token (matched via sid). */
  current: z.boolean(),
  /** UA summary such as "Chrome on Windows" (never the raw user-agent string). */
  userAgent: z.string().nullable(),
  /** IPv4 /24 or IPv6 /48 prefix. */
  ipPrefix: z.string().nullable(),
  createdAt: IsoDateTimeSchema,
  lastUsedAt: IsoDateTimeSchema,
  expiresAt: IsoDateTimeSchema,
});
export type SessionInfo = z.infer<typeof SessionInfoSchema>;
export const SessionListResponseSchema = z.array(SessionInfoSchema);
export type SessionListResponse = z.infer<typeof SessionListResponseSchema>;

/** Path params of DELETE /auth/sessions/:id. */
export const SessionIdParamsSchema = z.object({ id: IdSchema });
