/**
 * Drop lifecycle helpers shared by the drops routes, the admin routes and the cleanup job (spec section 9).
 *
 * purgeDropBlobs() is the ONLY place that deletes a drop's blobs: it deletes them from storage first
 * (idempotent), then sets blobsDeletedAt with a conditional update, so the owner's quota is released exactly
 * once even when cleanup, an owner delete and an admin disable race.
 */
import type { GoneReason } from '@cipherdrop/shared';
import type { DropStatus, Prisma, PrismaClient } from '@prisma/client';
import type { AppContext } from '../../context';
import { metrics } from '../../lib/metrics';

export type LifecycleContext = Pick<AppContext, 'prisma' | 'storage'>;

/** Why a drop is no longer available to recipients, or null while it is available (READY, not expired). */
export function goneReason(
  drop: { status: DropStatus; expiresAt: Date },
  now: Date,
): GoneReason | null {
  switch (drop.status) {
    case 'DELETED':
    case 'DISABLED':
    case 'EXPIRED':
    case 'EXHAUSTED':
      return drop.status;
    case 'READY':
      return drop.expiresAt.getTime() <= now.getTime() ? 'EXPIRED' : null;
    default:
      return null;
  }
}

/** Remaining downloads, never negative. */
export const downloadsRemaining = (drop: { maxDownloads: number; downloadCount: number }) =>
  Math.max(0, drop.maxDownloads - drop.downloadCount);

export interface PurgeResult {
  /** This call set blobsDeletedAt (false when another caller already purged the drop). */
  purged: boolean;
  /** Bytes given back to the owner's quota (0 for anonymous drops and drops that never reached READY). */
  quotaBytesReleased: number;
}

/**
 * Delete every blob of the drop, then mark blobsDeletedAt (once) and release the owner's quota if the drop's
 * bytes were counted (it reached READY).
 */
export async function purgeDropBlobs(
  ctx: LifecycleContext,
  dropId: string,
  now: Date,
): Promise<PurgeResult> {
  await ctx.storage.deleteDrop(dropId);
  const result = await ctx.prisma.$transaction(async (tx) => {
    await scrubPurgedDrop(tx, dropId);
    const drop = await tx.drop.findUnique({
      where: { id: dropId },
      select: { ownerId: true, readyAt: true, totalCiphertextBytes: true },
    });
    if (!drop) return { purged: false, counted: 0n, quota: 0n };
    const { count } = await tx.drop.updateMany({
      where: { id: dropId, blobsDeletedAt: null },
      data: { blobsDeletedAt: now },
    });
    if (count !== 1) return { purged: false, counted: 0n, quota: 0n };
    if (!drop.readyAt) return { purged: true, counted: 0n, quota: 0n };
    const bytes = drop.totalCiphertextBytes;
    if (drop.ownerId) await releaseQuota(tx, drop.ownerId, bytes);
    return { purged: true, counted: bytes, quota: drop.ownerId ? bytes : 0n };
  });
  if (result.counted > 0n) metrics.storageBytes.dec(Number(result.counted));
  return { purged: result.purged, quotaBytesReleased: Number(result.quota) };
}

/**
 * What a drop row keeps once its blobs are gone (retention): status, expiresAt and the counters stay (the 410
 * reason, the owner's history). The password verifier and wrapped drop key are useless then, so they go (a DB
 * leak must not allow offline guessing for a deleted drop); chunk rows go; a reporter's key goes. The
 * manifest and the owner's wrapped key are wiped for DELETED drops (never listed again) and anonymous ones
 * (nobody can list them); EXPIRED / EXHAUSTED / DISABLED owned drops keep them for the owner's history.
 */
async function scrubPurgedDrop(
  tx: Pick<Prisma.TransactionClient, 'drop' | 'dropChunk' | 'report'>,
  dropId: string,
): Promise<void> {
  await tx.drop.updateMany({
    where: { id: dropId, OR: [{ wrappedDropKey: { not: null } }, { authKeyHash: { not: null } }] },
    data: {
      wrappedDropKey: null,
      authKeyHash: null,
      pwKdfSalt: null,
      pwKdfMemoryKiB: null,
      pwKdfIterations: null,
      pwKdfParallelism: null,
    },
  });
  await tx.drop.updateMany({
    where: {
      id: dropId,
      OR: [{ status: 'DELETED' }, { ownerId: null }],
      NOT: { encryptedManifest: '' },
    },
    data: { encryptedManifest: '', ownerWrappedKey: null },
  });
  await tx.dropChunk.deleteMany({ where: { dropId } });
  await tx.report.updateMany({
    where: { dropId, providedKey: { not: null } },
    data: { providedKey: null },
  });
}

type Tx = Pick<PrismaClient, '$executeRaw'>;

/** storageUsedBytes -= bytes, floored at 0. */
async function releaseQuota(tx: Tx, userId: string, bytes: bigint): Promise<void> {
  await tx.$executeRaw`
    UPDATE "User" SET "storageUsedBytes" = GREATEST(0, "storageUsedBytes" - ${bytes}), "updatedAt" = (NOW() AT TIME ZONE 'UTC')
    WHERE "id" = ${userId}`;
}

/** Recompute the storage_bytes gauge from the database (bytes of READY-or-later drops whose blobs exist). */
export async function refreshStorageGauge(prisma: PrismaClient): Promise<void> {
  const agg = await prisma.drop.aggregate({
    _sum: { totalCiphertextBytes: true },
    where: { blobsDeletedAt: null, readyAt: { not: null } },
  });
  metrics.storageBytes.set(Number(agg._sum.totalCiphertextBytes ?? 0n));
}
