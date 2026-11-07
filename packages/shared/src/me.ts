/**
 * /me contracts (spec section 10, R6). OwnerDropSummary carries the encrypted manifest and the owner-wrapped
 * drop key so the dashboard can decrypt names locally with the vault's account key.
 */
import { z } from 'zod';
import { AutoLockMinutesSchema, MeSchema } from './auth';
import {
  AuditActionSchema,
  AuthKeySchema,
  DropIdSchema,
  DropStatusSchema,
  EncryptedManifestSchema,
  IdSchema,
  IsoDateTimeSchema,
  MfaCodeSchema,
  PageQuerySchema,
  WrappedKeySchema,
  pageSchema,
} from './common';

/* GET /me, PATCH /me/settings */
export const MeResponseSchema = z.object({ user: MeSchema });
export type MeResponse = z.infer<typeof MeResponseSchema>;

export const MeSettingsRequestSchema = z.object({ autoLockMinutes: AutoLockMinutesSchema });
export type MeSettingsRequest = z.infer<typeof MeSettingsRequestSchema>;

/* DELETE /me -> 204 (deletes the user, their drops and blobs) */
export const DeleteMeRequestSchema = z.object({
  authKey: AuthKeySchema,
  /** Required when TOTP is enabled. */
  code: MfaCodeSchema.optional(),
});
export type DeleteMeRequest = z.infer<typeof DeleteMeRequestSchema>;

/* GET /me/audit?action&page&pageSize -> Page<AuditEventDto> */
export const AuditEventDtoSchema = z.object({
  id: IdSchema,
  action: AuditActionSchema,
  dropId: z.string().nullable(),
  /** IPv4 /24 or IPv6 /48 prefix, e.g. "203.0.113.0/24". */
  ipPrefix: z.string().nullable(),
  /** UA summary, e.g. "Chrome on Windows". */
  userAgent: z.string().nullable(),
  /** Never contains plaintext names, keys or tokens. */
  metadata: z.record(z.unknown()).nullable(),
  createdAt: IsoDateTimeSchema,
});
export type AuditEventDto = z.infer<typeof AuditEventDtoSchema>;

export const MeAuditQuerySchema = PageQuerySchema.extend({ action: AuditActionSchema.optional() });
export type MeAuditQuery = z.infer<typeof MeAuditQuerySchema>;
export const AuditEventPageSchema = pageSchema(AuditEventDtoSchema);
export type AuditEventPage = z.infer<typeof AuditEventPageSchema>;

/* GET /me/drops?status=active|expired|all&page&pageSize -> Page<OwnerDropSummary>, newest first (R6) */
/** active = UPLOADING|READY; expired = EXPIRED|EXHAUSTED|DISABLED; all = everything except DELETED. */
export const MeDropsStatusSchema = z.enum(['active', 'expired', 'all']);
export type MeDropsStatus = z.infer<typeof MeDropsStatusSchema>;
export const MeDropsQuerySchema = PageQuerySchema.extend({
  status: MeDropsStatusSchema.default('active'),
});
export type MeDropsQuery = z.infer<typeof MeDropsQuerySchema>;

export const OwnerDropSummarySchema = z.object({
  id: DropIdSchema,
  status: DropStatusSchema,
  fileCount: z.number().int().nonnegative(),
  /** Total ciphertext bytes. */
  totalBytes: z.number().int().nonnegative(),
  maxDownloads: z.number().int().positive(),
  downloadCount: z.number().int().nonnegative(),
  downloadsRemaining: z.number().int().nonnegative(),
  expiresAt: IsoDateTimeSchema,
  createdAt: IsoDateTimeSchema,
  lastOpenedAt: IsoDateTimeSchema.nullable(),
  passwordProtected: z.boolean(),
  encryptedManifest: EncryptedManifestSchema,
  /** wrap(AK, DK, "cipherdrop/v1/wrap/owner"); null for drops created without an unlocked vault. */
  ownerWrappedKey: WrappedKeySchema.nullable(),
});
export type OwnerDropSummary = z.infer<typeof OwnerDropSummarySchema>;
export const OwnerDropPageSchema = pageSchema(OwnerDropSummarySchema);
export type OwnerDropPage = z.infer<typeof OwnerDropPageSchema>;
