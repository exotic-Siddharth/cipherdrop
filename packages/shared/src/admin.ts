/**
 * Admin contracts (spec section 10 "Admin", R13). Every admin route requires role ADMIN.
 */
import { z } from 'zod';
import {
  AuditActionSchema,
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
import { ADMIN_AUDIT_ACTIONS } from './constants';

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
  /**
   * The stored quota: the value PATCH storageQuotaBytes sets, and the one that applies once the new-account
   * probation is over.
   */
  storageQuotaBytes: z.number().int().nonnegative(),
  /** The quota that applies now: storageQuotaBytes, capped while the new-account probation lasts. */
  effectiveQuotaBytes: z.number().int().nonnegative(),
  storageUsedBytes: z.number().int().nonnegative(),
  /** When the new-account probation ends; null when none applies. A quota edit ends it at once. */
  quotaProbationEndsAt: IsoDateTimeSchema.nullable(),
  dropCount: z.number().int().nonnegative(),
  lockedUntil: IsoDateTimeSchema.nullable(),
  /** Set while the account is suspended (server-6): it cannot sign in or refresh. */
  suspendedAt: IsoDateTimeSchema.nullable(),
  suspendedReason: z.string().nullable(),
  createdAt: IsoDateTimeSchema,
});
export type AdminUser = z.infer<typeof AdminUserSchema>;
export const AdminUserPageSchema = pageSchema(AdminUserSchema);
export type AdminUserPage = z.infer<typeof AdminUserPageSchema>;

export const UserIdParamsSchema = z.object({ id: IdSchema });
/** Moderation reasons (suspension, takedown): shown to admins in the Audit tab, never to the public. */
export const ModerationReasonSchema = z.string().trim().min(1).max(500);

export const AdminUserPatchRequestSchema = z
  .object({
    role: RoleSchema.optional(),
    storageQuotaBytes: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).optional(),
    /** true suspends (and signs out every session), false lifts the suspension (server-6). */
    suspended: z.boolean().optional(),
    /** Required with suspended: true. */
    suspendedReason: ModerationReasonSchema.optional(),
  })
  .refine(
    (v) => v.role !== undefined || v.storageQuotaBytes !== undefined || v.suspended !== undefined,
    { message: 'Provide role, storageQuotaBytes and/or suspended' },
  )
  .refine((v) => v.suspended !== true || v.suspendedReason !== undefined, {
    message: 'A suspension needs a reason',
    path: ['suspendedReason'],
  });
export type AdminUserPatchRequest = z.infer<typeof AdminUserPatchRequestSchema>;
export const AdminUserResponseSchema = z.object({ user: AdminUserSchema });
export type AdminUserResponse = z.infer<typeof AdminUserResponseSchema>;

/* POST /admin/drops/:id/disable -> 204: a takedown without a report (server-6), audited as ADMIN_DROP_DISABLED */
export const AdminDropDisableRequestSchema = z.object({ reason: ModerationReasonSchema });
export type AdminDropDisableRequest = z.infer<typeof AdminDropDisableRequestSchema>;

/* GET /admin/audit?action&actorId&userId&dropId&page&pageSize -> Page<AdminAuditEvent> (server-4). Admin and
   operator actions only: an account's own activity (sign-ins, opens of its drops) stays readable by its owner
   alone, through /me/audit. */
export const AdminAuditQuerySchema = PageQuerySchema.extend({
  action: z.enum(ADMIN_AUDIT_ACTIONS).optional(),
  /** The acting admin. */
  actorId: IdSchema.optional(),
  /** The account an admin action targeted. */
  userId: IdSchema.optional(),
  dropId: DropIdSchema.optional(),
});
export type AdminAuditQuery = z.infer<typeof AdminAuditQuerySchema>;

export const AdminAuditEventSchema = z.object({
  id: IdSchema,
  action: AuditActionSchema,
  createdAt: IsoDateTimeSchema,
  /** The acting admin; null for a user's own actions, jobs, the operator CLI and admins who deleted their account. */
  actor: z.object({ id: IdSchema, email: z.string() }).nullable(),
  /** Recorded by the operator CLI (npm run cli), not through the API. */
  byOperator: z.boolean(),
  /** The account the event is about (the subject's own log, or the target of an admin action). */
  subject: z.object({ id: IdSchema, email: z.string().nullable() }).nullable(),
  dropId: z.string().nullable(),
  ipPrefix: z.string().nullable(),
  userAgent: z.string().nullable(),
  /** Never holds plaintext names, keys or tokens (audit service rule). */
  metadata: z.record(z.string(), z.unknown()).nullable(),
});
export type AdminAuditEvent = z.infer<typeof AdminAuditEventSchema>;
export const AdminAuditPageSchema = pageSchema(AdminAuditEventSchema);
export type AdminAuditPage = z.infer<typeof AdminAuditPageSchema>;
