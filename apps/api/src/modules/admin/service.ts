/**
 * Admin logic (spec section 10 "Admin", R13). Every caller is already an ADMIN (requireRole re-checks the DB).
 *
 * The reporter-supplied decryption key (Report.providedKey) is returned ONLY by listReports. Review grants
 * never consume a download and are audited (ADMIN_REVIEW_GRANT with metadata {adminReview: true} on the admin).
 */
import {
  ADMIN_AUDIT_ACTIONS,
  type AdminAuditEvent,
  type AdminAuditQuery,
  type AdminGrantResponse,
  type AdminReport,
  type AdminReportsQuery,
  type AdminStats,
  type AdminUser,
  type AdminUserPatchRequest,
  type AdminUsersQuery,
  type AuditAction,
  type Page,
} from '@cipherdrop/shared';
import { Prisma, type User } from '@prisma/client';
import type { Request } from 'express';
import type { AppContext } from '../../context';
import { conflict, gone, notFound, stepUpRequired, validationError } from '../../lib/errors';
import { sha256B64url } from '../../lib/hash';
import { ipPrefix } from '../../lib/ip';
import { paginate, toPage } from '../../lib/pagination';
import { effectiveQuotaBytes, probationEndsAt } from '../../lib/quota';
import { randomToken } from '../../lib/tokens';
import type { AuthUser } from '../../types/express';
import { recordAfterCommit } from '../audit/service';
import { isRecentlyAuthenticated, revokeUserSessions } from '../auth/service';
import { goneReason, purgeDropBlobs } from '../drops/lifecycle';
import { grantExpiry } from '../drops/service';

const DAY_MS = 86_400_000;
const STATS_DAYS = 14;

type Req = Pick<Request, 'ip' | 'headers'>;

/**
 * Who performs an admin action (server-4): an admin through the API, or the operator CLI, which has no account
 * (npm run cli). Every admin action is one audit event with the actor in `actorId` (or metadata.operator) and
 * the account it targets in metadata.targetUserId, never in userId: no account deletion erases the trail.
 */
export type ModerationActor = AuthUser | 'operator';

const actorIdOf = (actor: ModerationActor) => (actor === 'operator' ? null : actor.id);

async function recordAdminAction(
  ctx: AppContext,
  actor: ModerationActor,
  action: AuditAction,
  input: {
    targetUserId?: string | null;
    dropId?: string | null;
    req?: Req;
    metadata?: Prisma.InputJsonObject;
  },
): Promise<void> {
  // A copy of who acted: actorId is SET NULL when the admin deletes their account, and that must not erase who
  // did it (server-4).
  const acting =
    actor === 'operator'
      ? null
      : await ctx.prisma.user.findUnique({
          where: { id: actor.id },
          select: { id: true, email: true },
        });
  // Not recordAfterCommit: a moderation action whose record fails must fail loudly (500), not go unrecorded.
  await ctx.audit.record({
    actorId: actorIdOf(actor),
    dropId: input.dropId ?? null,
    action,
    ...(input.req ? { req: input.req } : {}),
    metadata: {
      ...(input.targetUserId ? { targetUserId: input.targetUserId } : {}),
      ...(actor === 'operator' ? { operator: true } : {}),
      ...(acting ? { actorId: acting.id, actorEmail: acting.email } : {}),
      ...input.metadata,
    },
  });
}

const isoDay = (d: Date) => d.toISOString().slice(0, 10);

/* ---------------------------------------------------------------- stats */

export async function getStats(ctx: AppContext): Promise<AdminStats> {
  const now = ctx.now();
  const todayStart = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const start = new Date(todayStart - (STATS_DAYS - 1) * DAY_MS);

  const [users, activeDrops, totalDrops, stored, openReports, daily] = await Promise.all([
    ctx.prisma.user.count(),
    ctx.prisma.drop.count({ where: { status: { in: ['UPLOADING', 'READY'] } } }),
    ctx.prisma.drop.count(),
    ctx.prisma.drop.aggregate({
      _sum: { totalCiphertextBytes: true },
      where: { blobsDeletedAt: null, readyAt: { not: null } },
    }),
    ctx.prisma.report.count({ where: { status: 'OPEN' } }),
    // createdAt is a timestamp(3) holding UTC wall time, so its date part is the UTC day.
    ctx.prisma.$queryRaw<{ day: string; drops: number; bytes: bigint }[]>`
      SELECT to_char("createdAt", 'YYYY-MM-DD') AS "day",
             COUNT(*)::int AS "drops",
             COALESCE(SUM("totalCiphertextBytes"), 0)::bigint AS "bytes"
      FROM "Drop"
      WHERE "createdAt" >= (${start.toISOString()}::timestamptz AT TIME ZONE 'UTC')
      GROUP BY 1`,
  ]);

  const byDay = new Map(daily.map((r) => [r.day, r]));
  const uploadsLast14d = Array.from({ length: STATS_DAYS }, (_, i) => {
    const date = isoDay(new Date(start.getTime() + i * DAY_MS));
    const row = byDay.get(date);
    return { date, drops: row?.drops ?? 0, bytes: Number(row?.bytes ?? 0n) };
  });

  return {
    users,
    activeDrops,
    totalDrops,
    storageBytes: Number(stored._sum.totalCiphertextBytes ?? 0n),
    openReports,
    uploadsLast14d,
  };
}

/* ---------------------------------------------------------------- reports */

/** Reporters' keys, review grants and promotions need a recent authentication of the admin's session (server-3). */
export function hasAdminStepUp(ctx: AppContext, admin: AuthUser): Promise<boolean> {
  return isRecentlyAuthenticated(ctx, admin, ctx.env.ADMIN_STEP_UP_MINUTES);
}

/**
 * `withKeys` false (no recent step-up) withholds every decryption key: `hasKey` still says the report holds one, so
 * the console can ask for the step-up and fetch again.
 */
export async function listReports(
  ctx: AppContext,
  query: AdminReportsQuery,
  { withKeys }: { withKeys: boolean },
): Promise<Page<AdminReport>> {
  const p = paginate(query);
  const where: Prisma.ReportWhereInput = query.status ? { status: query.status } : {};
  const [rows, total] = await Promise.all([
    ctx.prisma.report.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      skip: p.skip,
      take: p.take,
      include: {
        drop: {
          select: {
            id: true,
            status: true,
            fileCount: true,
            totalCiphertextBytes: true,
            createdAt: true,
            owner: { select: { email: true } },
          },
        },
      },
    }),
    ctx.prisma.report.count({ where }),
  ]);
  const items: AdminReport[] = rows.map((r) => ({
    id: r.id,
    reason: r.reason,
    details: r.details,
    status: r.status,
    createdAt: r.createdAt.toISOString(),
    // The key is only for reviewing an OPEN report; closed reports never serve one.
    hasKey: r.status === 'OPEN' && r.providedKey !== null,
    decryptionKey: withKeys && r.status === 'OPEN' ? r.providedKey : null,
    drop: {
      id: r.drop.id,
      status: r.drop.status,
      fileCount: r.drop.fileCount,
      totalBytes: Number(r.drop.totalCiphertextBytes),
      ownerEmail: r.drop.owner?.email ?? null,
      createdAt: r.drop.createdAt.toISOString(),
    },
  }));
  return toPage(items, total, p);
}

export async function resolveReport(
  ctx: AppContext,
  reportId: string,
  action: 'DISABLE_DROP' | 'DISMISS',
  admin: ModerationActor,
  req?: Req,
): Promise<void> {
  const report = await ctx.prisma.report.findUnique({
    where: { id: reportId },
    select: { id: true, status: true, dropId: true },
  });
  if (!report) throw notFound('Unknown report');
  if (report.status !== 'OPEN') throw conflict('This report is already closed');
  const now = ctx.now();

  if (action === 'DISMISS') {
    const { count } = await ctx.prisma.report.updateMany({
      where: { id: reportId, status: 'OPEN' },
      data: {
        status: 'DISMISSED',
        resolvedAt: now,
        resolvedById: actorIdOf(admin),
        providedKey: null,
      },
    });
    if (count !== 1) throw conflict('This report is already closed');
    await recordAdminAction(ctx, admin, 'ADMIN_REPORT_DISMISSED', {
      dropId: report.dropId,
      ...(req ? { req } : {}),
      metadata: { reportId },
    });
    return;
  }

  await disableDrop(ctx, report.dropId, admin, { reason: null, reportId, req });
}

/**
 * Disable a drop (report resolution or a takedown by id, server-6): recipients get 410 DISABLED at once, its blobs
 * go right after, and every open report of the drop is resolved with it. With `requireChange`, a drop that is
 * already disabled or deleted is a 409 (takedown); a report resolution closes its reports either way.
 */
export async function disableDrop(
  ctx: AppContext,
  dropId: string,
  admin: ModerationActor,
  opts: {
    reason: string | null;
    reportId?: string;
    req?: Req | undefined;
    requireChange?: boolean;
  },
): Promise<void> {
  const now = ctx.now();
  const drop = await ctx.prisma.drop.findUnique({
    where: { id: dropId },
    select: { id: true, ownerId: true },
  });
  if (!drop) throw notFound('Unknown drop');
  const { count } = await ctx.prisma.drop.updateMany({
    where: { id: drop.id, status: { notIn: ['DELETED', 'DISABLED'] } },
    data: { status: 'DISABLED' },
  });
  if (count !== 1 && opts.requireChange) {
    throw conflict('This drop is already disabled or deleted');
  }
  const reports = await ctx.prisma.report.updateMany({
    where: { dropId: drop.id, status: 'OPEN' },
    data: {
      status: 'RESOLVED',
      resolvedAt: now,
      resolvedById: actorIdOf(admin),
      providedKey: null,
    },
  });
  if (count === 1) {
    // The owner's own log says what happened to their drop (never who did it).
    await recordAfterCommit(ctx, {
      userId: drop.ownerId,
      dropId: drop.id,
      action: 'DROP_DISABLED',
    });
    await recordAdminAction(ctx, admin, 'ADMIN_DROP_DISABLED', {
      targetUserId: drop.ownerId,
      dropId: drop.id,
      ...(opts.req ? { req: opts.req } : {}),
      metadata: {
        ...(opts.reportId ? { reportId: opts.reportId } : {}),
        ...(opts.reason ? { reason: opts.reason } : {}),
        reportsResolved: reports.count,
      },
    });
  }
  await purgeDropBlobs(ctx, drop.id, now);
}

/* ---------------------------------------------------------------- review grant */

export async function reviewGrant(
  ctx: AppContext,
  dropId: string,
  admin: AuthUser,
  req: Req,
): Promise<AdminGrantResponse> {
  if (!(await hasAdminStepUp(ctx, admin))) throw stepUpRequired();
  const drop = await ctx.prisma.drop.findUnique({ where: { id: dropId } });
  if (!drop || drop.status === 'UPLOADING') throw notFound('Unknown drop');
  // An EXPIRED drop is reviewable while its blobs are still there (the evidence hold, server-5).
  if (drop.status === 'DELETED' || drop.status === 'DISABLED') throw gone(drop.status);
  if (drop.blobsDeletedAt) throw gone(goneReason(drop, ctx.now()) ?? 'EXPIRED');

  const now = ctx.now();
  const downloadToken = randomToken();
  const expiresAt = grantExpiry(ctx, now, now);
  await ctx.prisma.downloadGrant.create({
    data: {
      dropId,
      tokenHash: sha256B64url(downloadToken),
      isAdmin: true,
      ipPrefix: ipPrefix(req.ip),
      createdAt: now,
      expiresAt,
    },
  });
  // An admin action (actor, never the owner's log), so it is not mistaken for a download.
  await recordAdminAction(ctx, admin, 'ADMIN_REVIEW_GRANT', {
    targetUserId: drop.ownerId,
    dropId,
    req,
    metadata: { adminReview: true },
  });
  return {
    downloadToken,
    expiresAt: expiresAt.toISOString(),
    encryptedManifest: drop.encryptedManifest,
  };
}

/* ---------------------------------------------------------------- users */

type UserWithCount = User & { _count: { drops: number } };

function toAdminUser(ctx: AppContext, u: UserWithCount): AdminUser {
  const now = ctx.now();
  return {
    id: u.id,
    email: u.email,
    role: u.role,
    totpEnabled: u.totpEnabledAt !== null,
    // The stored quota, which the edit dialog changes, and the one that applies now (Me reports only the
    // latter: it is the user's quota).
    storageQuotaBytes: Number(u.storageQuotaBytes),
    effectiveQuotaBytes: Number(effectiveQuotaBytes(u, ctx.env, now)),
    storageUsedBytes: Number(u.storageUsedBytes),
    quotaProbationEndsAt: probationEndsAt(u, now)?.toISOString() ?? null,
    dropCount: u._count.drops,
    lockedUntil: u.lockedUntil ? u.lockedUntil.toISOString() : null,
    suspendedAt: u.suspendedAt ? u.suspendedAt.toISOString() : null,
    suspendedReason: u.suspendedReason,
    createdAt: u.createdAt.toISOString(),
  };
}

export async function listUsers(ctx: AppContext, query: AdminUsersQuery): Promise<Page<AdminUser>> {
  const p = paginate(query);
  const where: Prisma.UserWhereInput = query.search
    ? { email: { contains: query.search, mode: 'insensitive' } }
    : {};
  const [rows, total] = await Promise.all([
    ctx.prisma.user.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      skip: p.skip,
      take: p.take,
      include: { _count: { select: { drops: true } } },
    }),
    ctx.prisma.user.count({ where }),
  ]);
  return toPage(
    rows.map((u) => toAdminUser(ctx, u)),
    total,
    p,
  );
}

/** 409 for a promotion of an account without two-step verification (see patchUser). */
const ADMIN_NEEDS_MFA =
  'This account needs two-step verification before it can be an admin. Ask its owner to turn it on in Settings, Security.';

/**
 * Role, quota and suspension edits, each audited as an admin action (server-4, server-6).
 *
 * Only an account with two-step verification can become an admin (review of server-3): the admin routes need it
 * anyway (requireRole), and an admin account without it is open to anyone who knows its password, who could enrol
 * their own authenticator and then open the console. The write is conditional, so a TOTP disable racing the
 * promotion cannot leave an admin without it either (TOTP disable refuses admins in turn).
 *
 * A suspension signs out every session of the account (its access tokens die with the sid denylist); login and
 * refresh then refuse it. Admins are not suspended (demote first), nor is a suspended account promoted.
 *
 * A promotion needs the same recent step-up as the reporters' keys: otherwise a stale admin session could promote
 * an account of its own and sign in to it, which opens a fresh session that reaches the keys.
 */
export async function patchUser(
  ctx: AppContext,
  userId: string,
  patch: AdminUserPatchRequest,
  admin: ModerationActor,
  req?: Req,
): Promise<AdminUser> {
  const self = admin !== 'operator' && userId === admin.id;
  if (self && patch.role !== undefined && patch.role !== 'ADMIN') {
    throw validationError('Admins cannot remove their own admin role');
  }
  if (self && patch.suspended === true) {
    throw validationError('Admins cannot suspend their own account');
  }
  const target = await ctx.prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      role: true,
      totpEnabledAt: true,
      storageQuotaBytes: true,
      suspendedAt: true,
    },
  });
  if (!target) throw notFound('Unknown user');
  const promoting = patch.role === 'ADMIN';
  // `role: 'ADMIN'` sent for an admin (with a quota edit) needs no step-up; the write then requires the role to be
  // unchanged, so a demotion racing it cannot turn it into a promotion without one.
  const keepsAdmin = promoting && target.role === 'ADMIN';
  // The operator CLI runs with shell access to the server and has no session to step up.
  if (promoting && !keepsAdmin && admin !== 'operator' && !(await hasAdminStepUp(ctx, admin))) {
    throw stepUpRequired();
  }
  if (promoting && target.totpEnabledAt === null) throw conflict(ADMIN_NEEDS_MFA);
  const nextRole = patch.role ?? target.role;
  const nextSuspended = patch.suspended ?? target.suspendedAt !== null;
  if (nextRole === 'ADMIN' && nextSuspended) {
    throw conflict(
      target.role === 'ADMIN'
        ? 'Remove the admin role before suspending this account.'
        : 'Lift the suspension before making this account an admin.',
    );
  }
  const suspending = patch.suspended === true && target.suspendedAt === null;
  const unsuspending = patch.suspended === false && target.suspendedAt !== null;
  const now = ctx.now();
  const updated = await ctx.prisma.user.updateMany({
    where: {
      id: userId,
      ...(promoting ? { totpEnabledAt: { not: null }, suspendedAt: null } : {}),
      ...(keepsAdmin ? { role: 'ADMIN' as const } : {}),
      ...(suspending && patch.role === undefined ? { role: 'USER' as const } : {}),
    },
    data: {
      ...(patch.role !== undefined ? { role: patch.role } : {}),
      // An admin's quota edit overrides the new-account probation: their value applies at once.
      ...(patch.storageQuotaBytes !== undefined
        ? { storageQuotaBytes: BigInt(patch.storageQuotaBytes), quotaProbationEndsAt: null }
        : {}),
      ...(suspending ? { suspendedAt: now, suspendedReason: patch.suspendedReason ?? null } : {}),
      ...(unsuspending ? { suspendedAt: null, suspendedReason: null } : {}),
    },
  });
  if (updated.count !== 1) {
    if (keepsAdmin)
      throw conflict('This account changed meanwhile. Reload the list and try again.');
    if (promoting) throw conflict(ADMIN_NEEDS_MFA);
    if (suspending) throw conflict('Remove the admin role before suspending this account.');
    throw notFound('Unknown user');
  }

  const reqOpt = req ? { req } : {};
  const roleChanged = patch.role !== undefined && patch.role !== target.role;
  const quotaChanged =
    patch.storageQuotaBytes !== undefined &&
    BigInt(patch.storageQuotaBytes) !== target.storageQuotaBytes;
  if (roleChanged || quotaChanged) {
    await recordAdminAction(ctx, admin, 'ADMIN_USER_UPDATED', {
      targetUserId: userId,
      ...reqOpt,
      metadata: {
        ...(roleChanged ? { role: { from: target.role, to: patch.role ?? target.role } } : {}),
        ...(quotaChanged
          ? {
              storageQuotaBytes: {
                from: Number(target.storageQuotaBytes),
                to: patch.storageQuotaBytes ?? 0,
              },
            }
          : {}),
      },
    });
  }
  if (suspending) {
    const revoked = await revokeUserSessions(ctx, userId);
    await recordAdminAction(ctx, admin, 'ADMIN_USER_SUSPENDED', {
      targetUserId: userId,
      ...reqOpt,
      metadata: { reason: patch.suspendedReason ?? null, revokedSessions: revoked.length },
    });
  }
  if (unsuspending) {
    await recordAdminAction(ctx, admin, 'ADMIN_USER_UNSUSPENDED', {
      targetUserId: userId,
      ...reqOpt,
    });
  }
  const user = await ctx.prisma.user.findUniqueOrThrow({
    where: { id: userId },
    include: { _count: { select: { drops: true } } },
  });
  return toAdminUser(ctx, user);
}

/**
 * Sign out every session of one account, or of every account (`userId` null: incident response, operator CLI).
 * Revoked sids are denylisted, so access tokens stop at once too.
 */
export async function revokeSessions(
  ctx: AppContext,
  userId: string | null,
  actor: ModerationActor,
  req?: Req,
): Promise<number> {
  let count: number;
  if (userId) {
    const exists = await ctx.prisma.user.count({ where: { id: userId } });
    if (exists === 0) throw notFound('Unknown user');
    count = (await revokeUserSessions(ctx, userId)).length;
  } else {
    const users = await ctx.prisma.session.findMany({
      where: { revokedAt: null },
      distinct: ['userId'],
      select: { userId: true },
    });
    count = 0;
    for (const u of users) count += (await revokeUserSessions(ctx, u.userId)).length;
  }
  await recordAdminAction(ctx, actor, 'ADMIN_SESSIONS_REVOKED', {
    targetUserId: userId,
    ...(req ? { req } : {}),
    metadata: { allUsers: userId === null, revokedSessions: count },
  });
  return count;
}

/* ---------------------------------------------------------------- audit */

const ADMIN_ACTIONS: AuditAction[] = [...ADMIN_AUDIT_ACTIONS];

/**
 * The instance audit log for admins (server-4), newest first: admin and operator actions only, never an
 * account's own activity (that is the owner's, through /me/audit). `userId` matches the actions that targeted it.
 */
export async function listAudit(
  ctx: AppContext,
  query: AdminAuditQuery,
): Promise<Page<AdminAuditEvent>> {
  const p = paginate(query);
  const and: Prisma.AuditEventWhereInput[] = [{ action: { in: ADMIN_ACTIONS } }];
  if (query.action) and.push({ action: query.action });
  if (query.actorId) and.push({ actorId: query.actorId });
  if (query.dropId) and.push({ dropId: query.dropId });
  if (query.userId) and.push({ metadata: { path: ['targetUserId'], equals: query.userId } });
  const where: Prisma.AuditEventWhereInput = { AND: and };
  const [rows, total] = await Promise.all([
    ctx.prisma.auditEvent.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      skip: p.skip,
      take: p.take,
      include: { actor: { select: { id: true, email: true } } },
    }),
    ctx.prisma.auditEvent.count({ where }),
  ]);
  const meta = (m: Prisma.JsonValue | null) =>
    m && typeof m === 'object' && !Array.isArray(m) ? (m as Record<string, unknown>) : null;
  const subjectIds = new Set<string>();
  for (const r of rows) {
    const target = meta(r.metadata)?.targetUserId;
    const id = r.userId ?? (typeof target === 'string' ? target : null);
    if (id) subjectIds.add(id);
  }
  const subjects = await ctx.prisma.user.findMany({
    where: { id: { in: [...subjectIds] } },
    select: { id: true, email: true },
  });
  const emailOf = new Map(subjects.map((u) => [u.id, u.email]));
  const items: AdminAuditEvent[] = rows.map((r) => {
    const m = meta(r.metadata);
    const target = typeof m?.targetUserId === 'string' ? m.targetUserId : null;
    const subjectId = r.userId ?? target;
    return {
      id: r.id,
      action: r.action,
      createdAt: r.createdAt.toISOString(),
      // The metadata copy keeps the actor of an admin who deleted their account.
      actor: r.actor
        ? { id: r.actor.id, email: r.actor.email }
        : typeof m?.actorId === 'string' && typeof m.actorEmail === 'string'
          ? { id: m.actorId, email: m.actorEmail }
          : null,
      byOperator: m?.operator === true,
      // A deleted account keeps its id here and loses its email.
      subject: subjectId ? { id: subjectId, email: emailOf.get(subjectId) ?? null } : null,
      dropId: r.dropId,
      ipPrefix: r.ipPrefix,
      userAgent: r.userAgent,
      metadata: m,
    };
  });
  return toPage(items, total, p);
}

/**
 * Clear the sign-in lockout of an account (server-2): the failed-login counter and `lockedUntil`. The lock is
 * account-wide, so anyone who knows an email can keep its owner out by re-locking it every 15 minutes; this is
 * the owner's way back in, through an admin, until the lock itself is scoped per device. Audited twice: the owner
 * sees ACCOUNT_LOCK_CLEARED in Activity (no admin id, IP prefix or User-Agent), and ADMIN_LOCK_CLEARED names the
 * acting admin in the admin audit log.
 */
export async function clearUserLock(
  ctx: AppContext,
  userId: string,
  admin: AuthUser,
  req: Req,
): Promise<AdminUser> {
  const before = await ctx.prisma.user.findUnique({
    where: { id: userId },
    select: { lockedUntil: true, failedLoginCount: true },
  });
  if (!before) throw notFound('Unknown user');
  const user = await ctx.prisma.user.update({
    where: { id: userId },
    data: { failedLoginCount: 0, lockedUntil: null },
    include: { _count: { select: { drops: true } } },
  });
  const wasLocked = before.lockedUntil !== null && before.lockedUntil > ctx.now();
  // No `req` on the owner's row (unless the admin cleared their own): its IP prefix and User-Agent would be the
  // admin's, shown to the owner in Activity.
  await recordAfterCommit(ctx, {
    userId,
    action: 'ACCOUNT_LOCK_CLEARED',
    ...(admin.id === userId ? { req } : {}),
    metadata: { byAdmin: true, wasLocked, failedLogins: before.failedLoginCount },
  });
  // The admin's side is an admin action like any other (server-4): it names the acting admin and lands in the
  // admin audit log, GET /admin/audit, not in the admin's personal Activity.
  await recordAdminAction(ctx, admin, 'ADMIN_LOCK_CLEARED', {
    targetUserId: userId,
    req,
    metadata: { wasLocked, failedLogins: before.failedLoginCount },
  });
  return toAdminUser(ctx, user);
}
