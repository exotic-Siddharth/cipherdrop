/**
 * runCleanup(now) and the scheduler (spec section 9 "Cleanup", R12).
 */
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../test/app';
import { resetTables } from '../../test/db';
import { authHeader, createUserRecord } from '../../test/factories';
import { isAppError } from '../lib/errors';
import { acquireLock, releaseLock } from '../lib/redis';
import {
  chunkData,
  createBody,
  createDropOk,
  createReadyDrop,
  fakeWrappedKey,
  HOUR,
  metricValue,
  MIN,
  openDrop,
  putChunk,
  testClock,
  testFile,
} from '../modules/drops/test-utils';
import { runCleanup, runScheduledCleanup, startCleanupScheduler } from './cleanup';

const T0 = new Date('2026-11-08T08:00:00.000Z');
const at = (ms: number) => new Date(T0.getTime() + ms);

describe('cleanup job', () => {
  let t: TestApp;
  const clock = testClock(T0);

  beforeAll(async () => {
    t = await createTestApp({ now: clock.now });
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(async () => {
    await resetTables(t.prisma);
    clock.set(T0);
  });

  async function blobExists(dropId: string, fileId: string): Promise<boolean> {
    try {
      (await t.storage.getChunkStream(dropId, fileId, 0)).destroy();
      return true;
    } catch (err) {
      if (isAppError(err) && err.code === 'NOT_FOUND') return false;
      throw err;
    }
  }

  async function ownedReadyDrop(body: Record<string, unknown> = {}) {
    const user = await createUserRecord(t.prisma);
    const drop = await createReadyDrop(t.app, {
      body: { ownerWrappedKey: fakeWrappedKey(), ...body },
      headers: { Authorization: authHeader(user) },
    });
    return { user, drop };
  }

  const usedBytes = async (userId: string) =>
    Number((await t.prisma.user.findUniqueOrThrow({ where: { id: userId } })).storageUsedBytes);

  it('expires READY drops past expiresAt: EXPIRED, blobs deleted, quota released, DROP_EXPIRED audited', async () => {
    const { user, drop } = await ownedReadyDrop({ expiresInHours: 1 });
    const keep = await ownedReadyDrop({ expiresInHours: 2 });
    const fileId = drop.files[0]!.id;
    expect(await usedBytes(user.id)).toBe(drop.files[0]!.ciphertextBytes);

    const early = await runCleanup(at(HOUR - 1000), t.ctx);
    expect(early.expired).toBe(0);
    expect(await blobExists(drop.dropId, fileId)).toBe(true);

    const report = await runCleanup(at(HOUR), t.ctx);
    expect(report).toEqual({
      expired: 1,
      exhaustedBlobsDeleted: 0,
      staleDeleted: 0,
      bytesReleased: drop.files[0]!.ciphertextBytes,
    });
    const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
    expect(row.status).toBe('EXPIRED');
    expect(row.blobsDeletedAt?.toISOString()).toBe(at(HOUR).toISOString());
    expect(await blobExists(drop.dropId, fileId)).toBe(false);
    expect(await usedBytes(user.id)).toBe(0);
    const ev = await t.prisma.auditEvent.findFirstOrThrow({
      where: { userId: user.id, action: 'DROP_EXPIRED' },
    });
    expect(ev.dropId).toBe(drop.dropId);

    // The other drop is untouched.
    expect(
      (await t.prisma.drop.findUniqueOrThrow({ where: { id: keep.drop.dropId } })).status,
    ).toBe('READY');
    expect(await blobExists(keep.drop.dropId, keep.drop.files[0]!.id)).toBe(true);

    clock.set(at(HOUR));
    const meta = await request(t.app).get(`/api/drops/${drop.dropId}`);
    expect(meta.status).toBe(410);
    expect(meta.body.error.details.reason).toBe('EXPIRED');

    // A second pass finds nothing to do and never releases bytes twice.
    expect(await runCleanup(at(HOUR + MIN), t.ctx)).toEqual({
      expired: 0,
      exhaustedBlobsDeleted: 0,
      staleDeleted: 0,
      bytesReleased: 0,
    });
  });

  it('deletes the blobs of EXHAUSTED drops once no grant is live (status stays EXHAUSTED)', async () => {
    const { user, drop } = await ownedReadyDrop({ maxDownloads: 1, expiresInHours: 24 });
    const fileId = drop.files[0]!.id;
    const open = await openDrop(t.app, drop.dropId);
    expect(open.status).toBe(200);

    // Grant still live (it expires at T0 + 30 min): blobs are kept so the download can resume.
    const kept = await runCleanup(at(10 * MIN), t.ctx);
    expect(kept.exhaustedBlobsDeleted).toBe(0);
    expect(await blobExists(drop.dropId, fileId)).toBe(true);

    const report = await runCleanup(at(30 * MIN), t.ctx);
    expect(report.exhaustedBlobsDeleted).toBe(1);
    expect(report.bytesReleased).toBe(drop.files[0]!.ciphertextBytes);
    const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
    expect(row.status).toBe('EXHAUSTED');
    expect(row.blobsDeletedAt).toBeInstanceOf(Date);
    expect(await blobExists(drop.dropId, fileId)).toBe(false);
    expect(await usedBytes(user.id)).toBe(0);
    expect(
      await t.prisma.auditEvent.count({ where: { userId: user.id, action: 'DROP_EXHAUSTED' } }),
    ).toBe(1);
  });

  it('keeps an EXHAUSTED drop while a slid grant is live', async () => {
    const { drop } = await ownedReadyDrop({ maxDownloads: 1 });
    const tok = (await openDrop(t.app, drop.dropId)).body.downloadToken as string;
    clock.set(at(25 * MIN));
    const res = await request(t.app)
      .get(`/api/drops/${drop.dropId}/files/${drop.files[0]!.id}/chunks/0`)
      .set('Authorization', `Bearer ${tok}`);
    expect(res.status).toBe(200);
    // The grant now lives until T0 + 55 min.
    expect((await runCleanup(at(40 * MIN), t.ctx)).exhaustedBlobsDeleted).toBe(0);
    expect((await runCleanup(at(55 * MIN), t.ctx)).exhaustedBlobsDeleted).toBe(1);
  });

  it('marks UPLOADING drops older than 24 h DELETED and removes their blobs', async () => {
    const f = testFile(4 * 1024 * 1024 + 10);
    const user = await createUserRecord(t.prisma);
    const drop = await createDropOk(t.app, createBody([f], { ownerWrappedKey: fakeWrappedKey() }), {
      Authorization: authHeader(user),
    });
    expect(
      (await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 1, chunkData(f, 1))).status,
    ).toBe(204);

    expect((await runCleanup(at(24 * HOUR - 1000), t.ctx)).staleDeleted).toBe(0);
    const report = await runCleanup(at(24 * HOUR), t.ctx);
    expect(report.staleDeleted).toBe(1);
    expect(report.bytesReleased).toBe(0); // never counted: it never reached READY
    const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
    expect(row.status).toBe('DELETED');
    expect(row.deletedAt).toBeInstanceOf(Date);
    expect(row.blobsDeletedAt).toBeInstanceOf(Date);
    try {
      (await t.storage.getChunkStream(drop.dropId, f.id, 1)).destroy();
      expect.unreachable('chunk should be gone');
    } catch (err) {
      expect(isAppError(err) && err.code).toBe('NOT_FOUND');
    }
    expect(await usedBytes(user.id)).toBe(0);
  });

  it('retries blob deletion for drops whose earlier purge did not finish', async () => {
    const { user, drop } = await ownedReadyDrop();
    // Simulate a disable whose blob deletion failed: status set, blobs still there.
    await t.prisma.drop.update({ where: { id: drop.dropId }, data: { status: 'DISABLED' } });
    await runCleanup(at(MIN), t.ctx);
    const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
    expect(row.blobsDeletedAt).toBeInstanceOf(Date);
    expect(await blobExists(drop.dropId, drop.files[0]!.id)).toBe(false);
    expect(await usedBytes(user.id)).toBe(0);
  });

  it('counts runs and deleted drops in the metrics', async () => {
    const runs = await metricValue(t.app, 'cleanup_runs_total');
    const deleted = await metricValue(t.app, 'cleanup_deleted_drops_total');
    await ownedReadyDrop({ expiresInHours: 1 });
    await runCleanup(at(2 * HOUR), t.ctx);
    expect((await metricValue(t.app, 'cleanup_runs_total')) - runs).toBe(1);
    expect((await metricValue(t.app, 'cleanup_deleted_drops_total')) - deleted).toBe(1);
  });

  describe('scheduler', () => {
    it('skips a run while another instance holds the Redis lock', async () => {
      await ownedReadyDrop({ expiresInHours: 1 });
      const lock = await acquireLock(t.redis, 'cleanup', 60_000);
      expect(lock).not.toBeNull();
      try {
        expect(await runScheduledCleanup(t.ctx, at(2 * HOUR))).toBeNull();
        expect(await t.prisma.drop.count({ where: { status: 'EXPIRED' } })).toBe(0);
      } finally {
        await releaseLock(t.redis, 'cleanup', lock as string);
      }
      const report = await runScheduledCleanup(t.ctx, at(2 * HOUR));
      expect(report?.expired).toBe(1);
      // The lock is released after the run.
      const again = await acquireLock(t.redis, 'cleanup', 1000);
      expect(again).not.toBeNull();
      await releaseLock(t.redis, 'cleanup', again as string);
    });

    it('two concurrent scheduled runs: exactly one runs', async () => {
      await ownedReadyDrop({ expiresInHours: 1 });
      const results = await Promise.all([
        runScheduledCleanup(t.ctx, at(2 * HOUR)),
        runScheduledCleanup(t.ctx, at(2 * HOUR)),
      ]);
      expect(results.filter((r) => r !== null)).toHaveLength(1);
      expect(results.find((r) => r !== null)?.expired).toBe(1);
    });

    it('runs on an interval and stop() halts it', async () => {
      const ticks: unknown[] = [];
      const scheduler = startCleanupScheduler(
        { ...t.ctx, env: { ...t.ctx.env, CLEANUP_INTERVAL_SEC: 1 } },
        { onTick: (r) => ticks.push(r) },
      );
      const deadline = Date.now() + 5000;
      while (ticks.length < 2 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 100));
      }
      await scheduler.stop();
      expect(ticks.length).toBeGreaterThanOrEqual(2);
      const seen = ticks.length;
      await new Promise((r) => setTimeout(r, 1300));
      expect(ticks.length).toBe(seen);
    });
  });
});
