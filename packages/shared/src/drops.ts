/**
 * Drop contracts (spec sections 9 and 10 "Drops", R5, R11). Plaintext metadata only ever travels inside
 * `encryptedManifest`; the server sees ids, sizes, counts, hashes and wrapped keys.
 */
import { z } from 'zod';
import { DOWNLOAD_OPTIONS, LIMITS, SHA256_HEX_RE } from './constants';
import {
  AuthKeySchema,
  B64Url32Schema,
  boundedArray,
  DropIdSchema,
  DropStatusSchema,
  EncryptedManifestSchema,
  FileIdSchema,
  IsoDateTimeSchema,
  KdfParamsSchema,
  OpaqueTokenSchema,
  ReportReasonSchema,
  Sha256B64urlSchema,
  WrappedKeySchema,
} from './common';

const { CHUNK_SIZE, TAG_BYTES, MAX_FILES_PER_DROP, USER_MAX_EXPIRY_HOURS } = LIMITS;

/** Smallest/largest ciphertext size of a file split into `chunkCount` chunks (spec section 7.2). */
export function ciphertextBytesRange(chunkCount: number): { min: number; max: number } {
  const max = chunkCount * (CHUNK_SIZE + TAG_BYTES);
  // chunkCount = max(1, ceil(size / CHUNK_SIZE)): with 2+ chunks the final chunk holds >= 1 plaintext byte.
  const min =
    chunkCount === 1 ? TAG_BYTES : (chunkCount - 1) * CHUNK_SIZE + 1 + TAG_BYTES * chunkCount;
  return { min, max };
}

export const MaxDownloadsSchema = z.union([
  z.literal(DOWNLOAD_OPTIONS[0]),
  z.literal(DOWNLOAD_OPTIONS[1]),
  z.literal(DOWNLOAD_OPTIONS[2]),
  z.literal(DOWNLOAD_OPTIONS[3]),
  z.literal(DOWNLOAD_OPTIONS[4]),
  z.literal(DOWNLOAD_OPTIONS[5]),
  z.literal(DOWNLOAD_OPTIONS[6]),
  z.literal(DOWNLOAD_OPTIONS[7]),
]);

export const CreateDropFileSchema = z
  .object({
    id: FileIdSchema,
    ciphertextBytes: z.number().int().min(TAG_BYTES).max(Number.MAX_SAFE_INTEGER),
    chunkCount: z.number().int().min(1).max(1_000_000),
  })
  .superRefine((f, ctx) => {
    const { min, max } = ciphertextBytesRange(f.chunkCount);
    if (f.ciphertextBytes < min || f.ciphertextBytes > max) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['ciphertextBytes'],
        message: `ciphertextBytes must be within [${min}, ${max}] for chunkCount ${f.chunkCount}`,
      });
    }
  });
export type CreateDropFile = z.infer<typeof CreateDropFileSchema>;

export const DropPasswordSchema = z.object({
  kdf: KdfParamsSchema,
  wrappedDropKey: WrappedKeySchema,
  /** b64url(SHA-256(authKey)) */
  authKeyHash: Sha256B64urlSchema,
});
export type DropPassword = z.infer<typeof DropPasswordSchema>;

/* POST /drops (optional user) -> 201 CreateDropResponse */
export const CreateDropRequestSchema = z.object({
  encryptedManifest: EncryptedManifestSchema,
  files: boundedArray(CreateDropFileSchema, MAX_FILES_PER_DROP, 1).superRefine((files, ctx) => {
    const seen = new Set<string>();
    files.forEach((f, i) => {
      if (seen.has(f.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: [i, 'id'],
          message: 'file ids must be unique within a drop',
        });
      }
      seen.add(f.id);
    });
  }),
  /** Whole hours; the API enforces the per-caller ceiling (anonymous 72 h, user 720 h). */
  expiresInHours: z.number().int().min(1).max(USER_MAX_EXPIRY_HOURS),
  /** One of DOWNLOAD_OPTIONS; anonymous drops allow at most 10. */
  maxDownloads: MaxDownloadsSchema,
  password: DropPasswordSchema.optional(),
  /** wrap(AK, DK, "cipherdrop/v1/wrap/owner"); required for session-authenticated creates (R7). */
  ownerWrappedKey: WrappedKeySchema.optional(),
});
export type CreateDropRequest = z.infer<typeof CreateDropRequestSchema>;

export const CreateDropResponseSchema = z.object({
  dropId: DropIdSchema,
  /** Shown once; lets an anonymous sender delete the drop (X-Owner-Token). */
  ownerToken: OpaqueTokenSchema,
  /** Bearer token for chunk PUTs, upload-status and complete; useless once the drop is READY. */
  uploadToken: OpaqueTokenSchema,
  expiresAt: IsoDateTimeSchema,
});
export type CreateDropResponse = z.infer<typeof CreateDropResponseSchema>;

/* ---- Path params / headers ---- */

export const DropIdParamsSchema = z.object({ id: DropIdSchema });
export type DropIdParams = z.infer<typeof DropIdParamsSchema>;

export const ChunkParamsSchema = z.object({
  id: DropIdSchema,
  fileId: FileIdSchema,
  index: z
    .string()
    .regex(/^(0|[1-9]\d{0,5})$/, 'index must be a non-negative integer')
    .transform(Number),
});
export type ChunkParams = z.infer<typeof ChunkParamsSchema>;

/** PUT chunk header: lowercase hex SHA-256 of the ciphertext body (R5). */
export const ChunkUploadHeadersSchema = z.object({
  'x-chunk-sha256': z.string().regex(SHA256_HEX_RE, 'Expected lowercase hex SHA-256'),
});

/** DELETE /drops/:id header for anonymous owners. */
export const OwnerTokenHeadersSchema = z.object({
  'x-owner-token': OpaqueTokenSchema.optional(),
});

/* GET /drops/:id/upload-status (Bearer uploadToken) -> UploadStatus (R11) */
export const UploadStatusSchema = z.object({
  files: z.array(
    z.object({
      id: FileIdSchema,
      chunkCount: z.number().int().positive(),
      received: z.array(
        z.object({
          index: z.number().int().nonnegative(),
          sha256: z.string().regex(SHA256_HEX_RE),
        }),
      ),
    }),
  ),
});
export type UploadStatus = z.infer<typeof UploadStatusSchema>;

/* POST /drops/:id/complete (Bearer uploadToken) -> {status:"READY"}; 409 with details if incomplete */
export const CompleteDropResponseSchema = z.object({ status: z.literal('READY') });
export type CompleteDropResponse = z.infer<typeof CompleteDropResponseSchema>;

/** `error.details` of the 409 returned by complete. */
export const CompleteConflictDetailsSchema = z.object({
  missing: z.array(z.object({ fileId: FileIdSchema, indexes: z.array(z.number().int()) })),
  sizeMismatch: z
    .array(
      z.object({
        fileId: FileIdSchema,
        expectedBytes: z.number().int(),
        receivedBytes: z.number().int(),
      }),
    )
    .optional(),
});
export type CompleteConflictDetails = z.infer<typeof CompleteConflictDetailsSchema>;

/* GET /drops/:id -> DropMeta; 404 unknown; 410 GONE with details.reason */
export const DropMetaSchema = z.object({
  id: DropIdSchema,
  status: DropStatusSchema,
  fileCount: z.number().int().nonnegative(),
  /** Total ciphertext bytes. */
  totalBytes: z.number().int().nonnegative(),
  expiresAt: IsoDateTimeSchema,
  maxDownloads: z.number().int().positive(),
  downloadsRemaining: z.number().int().nonnegative(),
  passwordProtected: z.boolean(),
  /** null when password-protected: released only by /unlock. */
  encryptedManifest: EncryptedManifestSchema.nullable(),
  /** Argon2id params of a password drop (validate with assertKdfParams before deriving), else null. */
  passwordKdf: KdfParamsSchema.nullable(),
  createdAt: IsoDateTimeSchema,
});
export type DropMeta = z.infer<typeof DropMetaSchema>;

/* POST /drops/:id/unlock -> {wrappedDropKey, encryptedManifest}; 401 on mismatch; rate limited */
export const UnlockRequestSchema = z.object({ authKey: AuthKeySchema });
export type UnlockRequest = z.infer<typeof UnlockRequestSchema>;
export const UnlockResponseSchema = z.object({
  wrappedDropKey: WrappedKeySchema,
  encryptedManifest: EncryptedManifestSchema,
});
export type UnlockResponse = z.infer<typeof UnlockResponseSchema>;

/* POST /drops/:id/open -> grant; consumes one download atomically (spec section 9) */
export const OpenRequestSchema = z.object({
  /** Required for password-protected drops. */
  authKey: AuthKeySchema.optional(),
});
export type OpenRequest = z.infer<typeof OpenRequestSchema>;
export const OpenResponseSchema = z.object({
  /** Bearer token for chunk GETs; slides on use, at most 24 h after creation (R12). */
  downloadToken: OpaqueTokenSchema,
  expiresAt: IsoDateTimeSchema,
  downloadsRemaining: z.number().int().nonnegative(),
});
export type OpenResponse = z.infer<typeof OpenResponseSchema>;

/* POST /drops/:id/report -> 201; rate limit 5/h per IP */
export const ReportRequestSchema = z.object({
  reason: ReportReasonSchema,
  details: z.string().trim().max(LIMITS.MAX_REPORT_DETAILS_CHARS).optional(),
  /** b64url(DK), only when the reporter explicitly opts in so moderators can review (R13). */
  decryptionKey: B64Url32Schema.optional(),
});
export type ReportRequest = z.infer<typeof ReportRequestSchema>;
export const ReportResponseSchema = z.object({ id: z.string() });
export type ReportResponse = z.infer<typeof ReportResponseSchema>;
