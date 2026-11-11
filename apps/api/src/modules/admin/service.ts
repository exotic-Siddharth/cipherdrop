/**
 * Admin logic (spec section 10 "Admin", R13). Every caller is already an ADMIN (requireRole re-checks the DB).
 *
 * The reporter-supplied decryption key (Report.providedKey) is returned ONLY by listReports. Review grants
 * never consume a download and are audited (ADMIN_REVIEW_GRANT with metadata {adminReview: true} on the admin).
 */
import type {
  AdminGrantResponse,
  AdminReport,
  AdminReportsQuery,
  AdminStats,
  AdminUser,
  AdminUserPatchRequest,
  AdminUsersQuery,
  Page,
} from '@cipherdrop/shared';
import { Prisma, type User } from '@prisma/client';
import type { Request } from 'express';
import type { AppContext } from '../../context';
import { conflict, gone, notFound, validationError } from '../../lib/errors';
import { sha256B64url } from '../../lib/hash';
import { ipPrefix } from '../../lib/ip';
import { paginate, toPage } from '../../lib/pagination';
import { randomToken } from '../../lib/tokens';
import type { AuthUser } from '../../types/express';
import { recordAfterCommit } from '../audit/service';
import { goneReason, purgeDropBlobs } from '../drops/lifecycle';
import { grantExpiry } from '../drops/service';

const DAY_MS = 86_400_000;
const STATS_DAYS = 14;

type Req = Pick<Request, 'ip' | 'headers'>;

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

export async function listReports(
  ctx: AppContext,
  query: AdminReportsQuery,
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
    decryptionKey: r.status === 'OPEN' ? r.providedKey : null,
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
  admin: AuthUser,
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
      data: { status: 'DISMISSED', resolvedAt: now, resolvedById: admin.id, providedKey: null },
    });
    if (count !== 1) throw conflict('This report is already closed');
    return;
  }

  // DISABLE_DROP: recipients get 410 DISABLED at once; blobs go right after; every open report of the drop
  // is resolved with this one.
  const drop = await ctx.prisma.drop.findUniqueOrThrow({
    where: { id: report.dropId },
    select: { id: true, ownerId: true },
  });
  const { count } = await ctx.prisma.drop.updateMany({
    where: { id: drop.id, status: { notIn: ['DELETED', 'DISABLED'] } },
    data: { status: 'DISABLED' },
  });
  await ctx.prisma.report.updateMany({
    where: { dropId: drop.id, status: 'OPEN' },
    data: { status: 'RESOLVED', resolvedAt: now, resolvedById: admin.id, providedKey: null },
  });
  if (count === 1) {
    await recordAfterCommit(ctx, {
      userId: drop.ownerId,
      dropId: drop.id,
      action: 'DROP_DISABLED',
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
  const drop = await ctx.prisma.drop.findUnique({ where: { id: dropId } });
  if (!drop || drop.status === 'UPLOADING') throw notFound('Unknown drop');
  if (drop.status === 'DELETED' || drop.status === 'DISABLED' || drop.status === 'EXPIRED') {
    throw gone(drop.status);
  }
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
  // Recorded on the admin's own log (never the owner's), so it is not mistaken for a download.
  await ctx.audit.record({
    userId: admin.id,
    dropId,
    action: 'ADMIN_REVIEW_GRANT',
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

function toAdminUser(u: UserWithCount): AdminUser {
  return {
    id: u.id,
    email: u.email,
    role: u.role,
    totpEnabled: u.totpEnabledAt !== null,
    storageQuotaBytes: Number(u.storageQuotaBytes),
    storageUsedBytes: Number(u.storageUsedBytes),
    dropCount: u._count.drops,
    lockedUntil: u.lockedUntil ? u.lockedUntil.toISOString() : null,
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
  return toPage(rows.map(toAdminUser), total, p);
}

export async function patchUser(
  ctx: AppContext,
  userId: string,
  patch: AdminUserPatchRequest,
  admin: AuthUser,
): Promise<AdminUser> {
  if (userId === admin.id && patch.role !== undefined && patch.role !== 'ADMIN') {
    throw validationError('Admins cannot remove their own admin role');
  }
  const exists = await ctx.prisma.user.findUnique({ where: { id: userId }, select: { id: true } });
  if (!exists) throw notFound('Unknown user');
  const user = await ctx.prisma.user.update({
    where: { id: userId },
    data: {
      ...(patch.role !== undefined ? { role: patch.role } : {}),
      ...(patch.storageQuotaBytes !== undefined
        ? { storageQuotaBytes: BigInt(patch.storageQuotaBytes) }
        : {}),
    },
    include: { _count: { select: { drops: true } } },
  });
  return toAdminUser(user);
}
