/* eslint-disable @typescript-eslint/no-unused-vars -- S4 stubs: B2 implements this file (remove this line then). */
/**
 * Cleanup job (spec section 9), implemented by B2:
 * - READY drops past expiresAt -> EXPIRED, delete blobs;
 * - EXHAUSTED drops with no unexpired grant -> delete blobs (status stays EXHAUSTED);
 * - UPLOADING drops older than 24 h -> DELETED, delete blobs;
 * - release quota (storageUsedBytes), audit DROP_EXPIRED / DROP_EXHAUSTED to the owner, set blobsDeletedAt;
 * - metrics.cleanupRuns / metrics.cleanupDeletedDrops (lib/metrics.ts).
 * The scheduler runs runCleanup(now) every CLEANUP_INTERVAL_SEC under the Redis lock `${KEY_PREFIX}:lock:cleanup`
 * (lib/redis.ts acquireLock/releaseLock) and is stopped on shutdown (index.ts calls stop()).
 */
import type { AppContext } from '../context';

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

/** One cleanup pass at `now`. `ctx` defaults to the process-wide context (createContext()). */
export async function runCleanup(now: Date, ctx?: CleanupContext): Promise<CleanupReport> {
  throw new Error('not implemented: runCleanup (B2)');
}

/** Start the interval + Redis-lock scheduler. Stub: schedules nothing (so the API boots before B2 lands). */
export function startCleanupScheduler(ctx: SchedulerContext): CleanupScheduler {
  ctx.logger.warn('cleanup scheduler not implemented yet (B2): no cleanup will run');
  return { stop: async () => {} };
}
