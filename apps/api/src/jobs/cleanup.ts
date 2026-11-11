/**
 * Cleanup job (spec section 9, R12):
 * - READY drops past expiresAt -> EXPIRED, delete blobs;
 * - EXHAUSTED drops with no unexpired grant -> delete blobs (status stays EXHAUSTED);
 * - UPLOADING drops older than 24 h -> DELETED, delete blobs;
 * - EXPIRED / DELETED / DISABLED drops whose blobs are still there (an earlier purge failed) -> delete blobs;
 * - release quota (storageUsedBytes), audit DROP_EXPIRED / DROP_EXHAUSTED to the owner, set blobsDeletedAt;
 * - grants expired for more than 24 h are removed;
 * - metrics.cleanupRuns / metrics.cleanupDeletedDrops / metrics.storageBytes.
 * The scheduler runs runCleanup(now) every CLEANUP_INTERVAL_SEC under the Redis lock `${KEY_PREFIX}:lock:cleanup`
 * and is stopped on shutdown (index.ts calls stop()).
 *
 * Every state change is a conditional update, so overlapping runs (or a run racing an owner delete or an
 * admin disable) never double-count: purgeDropBlobs releases quota exactly once.
 */
import type { DropStatus, Prisma } from '@prisma/client';
import type { AppContext } from '../context';
import { createContext } from '../context';
import { metrics } from '../lib/metrics';
import { acquireLock, releaseLock } from '../lib/redis';
import { purgeDropBlobs, refreshStorageGauge } from '../modules/drops/lifecycle';

export interface CleanupReport {
  /** READY -> EXPIRED */
  expired: number;
  /** EXHAUSTED drops whose blobs were deleted */
  exhaustedBlobsDeleted: number;
  /** stale UPLOADING -> DELETED */
  staleDeleted: number;
  /** quota bytes released to owners */
  bytesReleased: number;
}

export type CleanupContext = Pick<AppContext, 'prisma' | 'storage' | 'audit' | 'logger'>;
export type SchedulerContext = Pick<
  AppContext,
  'prisma' | 'redis' | 'storage' | 'audit' | 'logger' | 'env'
>;

export interface CleanupScheduler {
  stop(): Promise<void>;
}

const BATCH = 100;
const HOUR_MS = 3_600_000;
const STALE_UPLOAD_MS = 24 * HOUR_MS;
const GRANT_RETENTION_MS = 24 * HOUR_MS;
const LOCK_NAME = 'cleanup';

interface Candidate {
  id: string;
  ownerId: string | null;
}

/** Walk the drops matching `where` in id order, in batches (a failed drop is skipped, never retried in-run). */
async function* candidates(
  ctx: CleanupContext,
  where: Prisma.DropWhereInput,
): AsyncGenerator<Candidate> {
  let after: string | undefined;
  for (;;) {
    const batch = await ctx.prisma.drop.findMany({
      where: after ? { AND: [where, { id: { gt: after } }] } : where,
      select: { id: true, ownerId: true },
      orderBy: { id: 'asc' },
      take: BATCH,
    });
    for (const d of batch) yield d;
    if (batch.length < BATCH) return;
    after = batch[batch.length - 1]?.id;
  }
}

/** One cleanup pass at `now`. `ctx` defaults to the process-wide context (createContext()). */
export async function runCleanup(now: Date, ctx?: CleanupContext): Promise<CleanupReport> {
  const c: CleanupContext = ctx ?? createContext();
  const report: CleanupReport = {
    expired: 0,
    exhaustedBlobsDeleted: 0,
    staleDeleted: 0,
    bytesReleased: 0,
  };
  let purgedDrops = 0;
  metrics.cleanupRuns.inc();

  /** Purge one drop; storage errors are logged and left for the next run (orphan sweep). */
  const purge = async (dropId: string): Promise<boolean> => {
    try {
      const r = await purgeDropBlobs(c, dropId, now);
      report.bytesReleased += r.quotaBytesReleased;
      if (r.purged) purgedDrops += 1;
      return r.purged;
    } catch (err) {
      c.logger.error(
        { dropId, err: { message: (err as Error).message } },
        'cleanup: blob deletion failed',
      );
      return false;
    }
  };

  /** Move a drop from `from` to `to` if it still matches; true when this run made the change. */
  const transition = async (
    id: string,
    from: Prisma.DropWhereInput,
    data: { status: DropStatus; deletedAt?: Date },
  ): Promise<boolean> => {
    const { count } = await c.prisma.drop.updateMany({ where: { AND: [{ id }, from] }, data });
    return count === 1;
  };

  // 1. READY past expiresAt -> EXPIRED.
  const expiredWhere: Prisma.DropWhereInput = { status: 'READY', expiresAt: { lte: now } };
  for await (const d of candidates(c, expiredWhere)) {
    if (!(await transition(d.id, expiredWhere, { status: 'EXPIRED' }))) continue;
    report.expired += 1;
    await purge(d.id);
    if (d.ownerId)
      await c.audit.record({ userId: d.ownerId, dropId: d.id, action: 'DROP_EXPIRED' });
  }

  // 2. EXHAUSTED with no live grant -> blobs deleted (R12: kept while any grant lives).
  const exhaustedWhere: Prisma.DropWhereInput = {
    status: 'EXHAUSTED',
    blobsDeletedAt: null,
    grants: { none: { expiresAt: { gt: now } } },
  };
  for await (const d of candidates(c, exhaustedWhere)) {
    if (!(await purge(d.id))) continue;
    report.exhaustedBlobsDeleted += 1;
    if (d.ownerId) {
      await c.audit.record({ userId: d.ownerId, dropId: d.id, action: 'DROP_EXHAUSTED' });
    }
  }

  // 3. UPLOADING for more than 24 h -> DELETED.
  const staleWhere: Prisma.DropWhereInput = {
    status: 'UPLOADING',
    createdAt: { lte: new Date(now.getTime() - STALE_UPLOAD_MS) },
  };
  for await (const d of candidates(c, staleWhere)) {
    if (!(await transition(d.id, staleWhere, { status: 'DELETED', deletedAt: now }))) continue;
    report.staleDeleted += 1;
    await purge(d.id);
  }

  // 4. Orphans: terminal drops whose blobs are still there (an earlier purge failed or was interrupted).
  const orphanWhere: Prisma.DropWhereInput = {
    status: { in: ['EXPIRED', 'DELETED', 'DISABLED'] },
    blobsDeletedAt: null,
  };
  for await (const d of candidates(c, orphanWhere)) await purge(d.id);

  // 5. Housekeeping: grants long past their expiry are useless.
  await c.prisma.downloadGrant.deleteMany({
    where: { expiresAt: { lt: new Date(now.getTime() - GRANT_RETENTION_MS) } },
  });

  if (purgedDrops > 0) metrics.cleanupDeletedDrops.inc(purgedDrops);
  await refreshStorageGauge(c.prisma);
  if (purgedDrops > 0 || report.expired > 0) {
    c.logger.info({ ...report, purgedDrops }, 'cleanup run');
  }
  return report;
}

/**
 * One scheduled pass: runs runCleanup(now) only if this process wins the Redis lock (several API instances
 * may run the scheduler). Returns null when another holder has the lock.
 */
export async function runScheduledCleanup(
  ctx: SchedulerContext,
  now: Date = new Date(),
): Promise<CleanupReport | null> {
  const ttlMs = Math.max(5 * 60_000, ctx.env.CLEANUP_INTERVAL_SEC * 2000);
  const token = await acquireLock(ctx.redis, LOCK_NAME, ttlMs);
  if (!token) return null;
  try {
    return await runCleanup(now, ctx);
  } finally {
    await releaseLock(ctx.redis, LOCK_NAME, token).catch(() => false);
  }
}

export interface SchedulerOptions {
  /** Called after every tick with its report (null when the lock was held elsewhere or the run failed). */
  onTick?: (report: CleanupReport | null) => void;
}

/** Start the interval + Redis-lock scheduler: a first pass right away, then every CLEANUP_INTERVAL_SEC. */
export function startCleanupScheduler(
  ctx: SchedulerContext,
  options: SchedulerOptions = {},
): CleanupScheduler {
  let stopped = false;
  let running: Promise<void> | null = null;

  const tick = () => {
    if (stopped || running) return; // never overlap in-process
    running = (async () => {
      let report: CleanupReport | null = null;
      try {
        report = await runScheduledCleanup(ctx);
      } catch (err) {
        ctx.logger.error({ err: { message: (err as Error).message } }, 'cleanup run failed');
      } finally {
        running = null;
      }
      options.onTick?.(report);
    })();
  };

  const timer = setInterval(tick, ctx.env.CLEANUP_INTERVAL_SEC * 1000);
  timer.unref();
  const first = setTimeout(tick, 0);
  first.unref();

  return {
    async stop() {
      stopped = true;
      clearInterval(timer);
      clearTimeout(first);
      if (running) await running;
    },
  };
}
