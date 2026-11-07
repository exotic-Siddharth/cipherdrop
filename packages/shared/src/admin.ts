/**
 * Admin contracts (spec section 10 "Admin", R13). Every admin route requires role ADMIN.
 */
import { z } from 'zod';
import {
  DropIdSchema,
  DropStatusSchema,
  IdSchema,
  IsoDateTimeSchema,
  OpaqueTokenSchema,
  PageQuerySchema,
  ReportReasonSchema,
  ReportStatusSchema,
  RoleSchema,
  EncryptedManifestSchema,
  pageSchema,
} from './common';

/* GET /admin/stats */
export const AdminStatsSchema = z.object({
  users: z.number().int().nonnegative(),
  activeDrops: z.number().int().nonnegative(),
  totalDrops: z.number().int().nonnegative(),
  storageBytes: z.number().int().nonnegative(),
  openReports: z.number().int().nonnegative(),
  /** Exactly 14 entries, oldest first; date = YYYY-MM-DD (UTC). */
  uploadsLast14d: z
    .array(
      z.object({
        date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
        drops: z.number().int().nonnegative(),
        bytes: z.number().int().nonnegative(),
      }),
    )
    .length(14),
});
export type AdminStats = z.infer<typeof AdminStatsSchema>;

/* GET /admin/reports?status&page&pageSize -> Page<AdminReport> */
export const AdminReportsQuerySchema = PageQuerySchema.extend({
  status: ReportStatusSchema.optional(),
});
export type AdminReportsQuery = z.infer<typeof AdminReportsQuerySchema>;

export const AdminReportSchema = z.object({
  id: IdSchema,
  reason: ReportReasonSchema,
  details: z.string().nullable(),
  status: ReportStatusSchema,
  createdAt: IsoDateTimeSchema,
  hasKey: z.boolean(),
  /** The reporter-supplied drop key (b64url); exposed only on this admin endpoint. */
  decryptionKey: z.string().nullable(),
  drop: z.object({
    id: DropIdSchema,
    status: DropStatusSchema,
    fileCount: z.number().int().nonnegative(),
    totalBytes: z.number().int().nonnegative(),
    ownerEmail: z.string().nullable(),
    createdAt: IsoDateTimeSchema,
  }),
});
export type AdminReport = z.infer<typeof AdminReportSchema>;
export const AdminReportPageSchema = pageSchema(AdminReportSchema);
export type AdminReportPage = z.infer<typeof AdminReportPageSchema>;

/* POST /admin/reports/:id/resolve -> 204 */
export const ReportIdParamsSchema = z.object({ id: IdSchema });
export const AdminResolveRequestSchema = z.object({ action: z.enum(['DISABLE_DROP', 'DISMISS']) });
export type AdminResolveRequest = z.infer<typeof AdminResolveRequestSchema>;

/* POST /admin/drops/:id/grant -> non-consuming review grant (audited) (R13) */
export const AdminGrantResponseSchema = z.object({
  downloadToken: OpaqueTokenSchema,
  expiresAt: IsoDateTimeSchema,
  encryptedManifest: EncryptedManifestSchema,
});
export type AdminGrantResponse = z.infer<typeof AdminGrantResponseSchema>;

/* GET /admin/users?search&page&pageSize -> Page<AdminUser>; PATCH /admin/users/:id -> {user} */
export const AdminUsersQuerySchema = PageQuerySchema.extend({
  search: z.string().trim().max(254).optional(),
});
export type AdminUsersQuery = z.infer<typeof AdminUsersQuerySchema>;

export const AdminUserSchema = z.object({
  id: IdSchema,
  email: z.string(),
  role: RoleSchema,
  totpEnabled: z.boolean(),
  storageQuotaBytes: z.number().int().nonnegative(),
  storageUsedBytes: z.number().int().nonnegative(),
  dropCount: z.number().int().nonnegative(),
  lockedUntil: IsoDateTimeSchema.nullable(),
  createdAt: IsoDateTimeSchema,
});
export type AdminUser = z.infer<typeof AdminUserSchema>;
export const AdminUserPageSchema = pageSchema(AdminUserSchema);
export type AdminUserPage = z.infer<typeof AdminUserPageSchema>;

export const UserIdParamsSchema = z.object({ id: IdSchema });
export const AdminUserPatchRequestSchema = z
  .object({
    role: RoleSchema.optional(),
    storageQuotaBytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
  })
  .refine((v) => v.role !== undefined || v.storageQuotaBytes !== undefined, {
    message: 'Provide role and/or storageQuotaBytes',
  });
export type AdminUserPatchRequest = z.infer<typeof AdminUserPatchRequestSchema>;
export const AdminUserResponseSchema = z.object({ user: AdminUserSchema });
export type AdminUserResponse = z.infer<typeof AdminUserResponseSchema>;
