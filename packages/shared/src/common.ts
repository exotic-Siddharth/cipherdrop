/**
 * Shared primitives: enums mirroring the Prisma schema, opaque-blob formats, errors and paging (spec section 10).
 *
 * Every byte string is base64url WITHOUT padding. The server stores and returns these blobs verbatim and
 * never parses ciphertext; it only validates formats, sizes and counts.
 */
import { z } from 'zod';
import {
  KDF_MAX,
  KDF_MIN,
  MAX_ENCRYPTED_MANIFEST_CHARS,
  NONCE_BYTES,
  TAG_BYTES,
  WRAPPED_KEY_CHARS,
} from '@cipherdrop/crypto/constants';

/* ---- Enums (must match apps/api/prisma/schema.prisma; an API test checks the sync) ---- */

export const RoleSchema = z.enum(['USER', 'ADMIN']);
export type Role = z.infer<typeof RoleSchema>;

export const DropStatusSchema = z.enum([
  'UPLOADING',
  'READY',
  'EXHAUSTED',
  'EXPIRED',
  'DELETED',
  'DISABLED',
]);
export type DropStatus = z.infer<typeof DropStatusSchema>;

export const ReportReasonSchema = z.enum(['MALWARE', 'PHISHING', 'ILLEGAL', 'COPYRIGHT', 'OTHER']);
export type ReportReason = z.infer<typeof ReportReasonSchema>;

export const ReportStatusSchema = z.enum(['OPEN', 'RESOLVED', 'DISMISSED']);
export type ReportStatus = z.infer<typeof ReportStatusSchema>;

export const AuditActionSchema = z.enum([
  'REGISTER',
  'LOGIN_SUCCESS',
  'LOGIN_FAILURE',
  'LOGIN_LOCKED',
  'MFA_CHALLENGE_FAILED',
  'MFA_ENABLED',
  'MFA_DISABLED',
  'BACKUP_CODE_USED',
  'BACKUP_CODES_REGENERATED',
  'PASSWORD_CHANGED',
  'RECOVERY_USED',
  'RECOVERY_KEY_ROTATED',
  'SESSION_REVOKED',
  'SESSION_REUSE_DETECTED',
  'LOGOUT',
  'ACCOUNT_DELETED',
  'DROP_CREATED',
  'DROP_COMPLETED',
  'DROP_OPENED',
  'DROP_UNLOCK_FAILED',
  'DROP_DELETED',
  'DROP_EXPIRED',
  'DROP_EXHAUSTED',
  'DROP_REPORTED',
  'DROP_DISABLED',
  'ADMIN_REVIEW_GRANT',
]);
export type AuditAction = z.infer<typeof AuditActionSchema>;

/** `details.reason` of a 410 GONE drop response. */
export const GoneReasonSchema = z.enum(['EXPIRED', 'EXHAUSTED', 'DELETED', 'DISABLED']);
export type GoneReason = z.infer<typeof GoneReasonSchema>;

/* ---- Errors and paging ---- */

export const ErrorCodeSchema = z.enum([
  'VALIDATION_ERROR',
  'UNAUTHORIZED',
  'FORBIDDEN',
  'NOT_FOUND',
  'CONFLICT',
  'GONE',
  'RATE_LIMITED',
  'PAYLOAD_TOO_LARGE',
  'QUOTA_EXCEEDED',
  'INTERNAL',
]);
export type ErrorCode = z.infer<typeof ErrorCodeSchema>;

/** Every error response: `{error:{code, message, details?}}`. */
export const ErrorBodySchema = z.object({
  error: z.object({
    code: ErrorCodeSchema,
    message: z.string(),
    details: z.unknown().optional(),
  }),
});
export type ErrorBody = z.infer<typeof ErrorBodySchema>;

/** 410 details: `{reason}`. */
export const GoneDetailsSchema = z.object({ reason: GoneReasonSchema });
export type GoneDetails = z.infer<typeof GoneDetailsSchema>;

/** `?page&pageSize` (query strings are coerced). */
export const PageQuerySchema = z.object({
  page: z.coerce.number().int().min(1).max(100_000).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
});
export type PageQuery = z.infer<typeof PageQuerySchema>;

/** `{items,total,page,pageSize}` */
export function pageSchema<T extends z.ZodTypeAny>(item: T) {
  return z.object({
    items: z.array(item),
    total: z.number().int().nonnegative(),
    page: z.number().int().min(1),
    pageSize: z.number().int().min(1),
  });
}
export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

/**
 * `z.array(item).min(min).max(max)` that never validates more than max+1 elements. zod 3 otherwise parses
 * EVERY element of an oversized array and reports one issue each (memory/CPU DoS, npm advisory for
 * zod < 4.6.6; the spec pins zod 3). Use it for every array in a request schema.
 */
export function boundedArray<T extends z.ZodTypeAny>(item: T, max: number, min = 0) {
  return z.preprocess(
    (v) => (Array.isArray(v) && v.length > max ? v.slice(0, max + 1) : v),
    z.array(item).min(min).max(max),
  );
}

/* ---- Opaque blob formats ---- */

export const B64URL_RE = /^[A-Za-z0-9_-]+$/;
/** Canonical unpadded base64url of exactly 32 bytes: 43 chars, the last one carries 4 data bits. */
export const B64URL_32_RE = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
/** Canonical unpadded base64url of exactly 16 bytes: 22 chars, the last one carries 2 data bits. */
export const B64URL_16_RE = /^[A-Za-z0-9_-]{21}[AQgw]$/;
/** wrap(k, 32-byte key) = b64url(nonce 12 || ciphertext 32 || tag 16) = exactly 80 chars. */
export const WRAPPED_KEY_RE = new RegExp(`^[A-Za-z0-9_-]{${WRAPPED_KEY_CHARS}}$`);

/** b64url of exactly 32 bytes: auth keys (HKDF-bits 256), SHA-256 hashes, the drop key in reports. */
export const B64Url32Schema = z
  .string()
  .regex(B64URL_32_RE, 'Expected base64url (no padding) of exactly 32 bytes');
/** b64url of exactly 16 bytes: dropId, fileId, KDF salt. */
export const B64Url16Schema = z
  .string()
  .regex(B64URL_16_RE, 'Expected base64url (no padding) of exactly 16 bytes');
/** A wrapped 32-byte key (wrappedAccountKey, wrappedAccountKeyRecovery, wrappedDropKey, ownerWrappedKey). */
export const WrappedKeySchema = z
  .string()
  .regex(WRAPPED_KEY_RE, `Expected a wrapped key: ${WRAPPED_KEY_CHARS} base64url chars`);
/** b64url(nonce || AES-GCM(manifestKey, ...)): at least nonce + tag + 1 byte, at most 64 KiB encoded. */
export const EncryptedManifestSchema = z
  .string()
  .min(Math.ceil(((NONCE_BYTES + TAG_BYTES + 1) * 4) / 3))
  .max(MAX_ENCRYPTED_MANIFEST_CHARS)
  .regex(B64URL_RE, 'Expected base64url (no padding)');

/** Client-derived auth key (b64url of 32 bytes); the server rejects any other length with 400 (R3). */
export const AuthKeySchema = B64Url32Schema;
/** b64url(SHA-256(x)) as produced by hashForServer. */
export const Sha256B64urlSchema = B64Url32Schema;

export const DropIdSchema = B64Url16Schema;
export const FileIdSchema = B64Url16Schema;
/** Server-generated cuid ids (users, sessions, reports...). */
export const IdSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9_-]+$/, 'Invalid id');

/** Opaque bearer tokens issued by the server: b64url(32 random bytes). */
export const OpaqueTokenSchema = B64Url32Schema;

export const IsoDateTimeSchema = z.string().datetime({ offset: true });

export const EmailSchema = z.string().trim().toLowerCase().email().max(254);

/** Argon2id parameters. Bounds are KDF_MIN..KDF_MAX, so weaker params are refused with 400. */
export const KdfParamsSchema = z.object({
  salt: B64Url16Schema,
  memoryKiB: z.number().int().min(KDF_MIN.memoryKiB).max(KDF_MAX.memoryKiB),
  iterations: z.number().int().min(KDF_MIN.iterations).max(KDF_MAX.iterations),
  parallelism: z.number().int().min(KDF_MIN.parallelism).max(KDF_MAX.parallelism),
});
export type KdfParamsDto = z.infer<typeof KdfParamsSchema>;

/** Six-digit TOTP code. */
export const TotpCodeSchema = z
  .string()
  .trim()
  .regex(/^\d{6}$/, 'Expected a 6-digit code');
/** A TOTP code or a backup code (`xxxxx-xxxxx`, Crockford, case-insensitive, dash optional). */
export const MfaCodeSchema = z
  .string()
  .trim()
  .regex(/^(\d{6}|[0-9A-Za-z]{5}-?[0-9A-Za-z]{5})$/, 'Expected a 6-digit code or a backup code');
