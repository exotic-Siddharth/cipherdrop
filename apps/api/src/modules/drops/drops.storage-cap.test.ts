/**
 * ops-3: instance-wide storage controls. GLOBAL_STORAGE_CAP_BYTES caps the bytes of every drop not purged
 * yet; STORAGE_MIN_FREE_BYTES refuses new drops before the blob volume (shared with Postgres) fills up. Both
 * answer 507 STORAGE_FULL, with no numbers.
 */
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { removeDir, tempStorageDir } from '../../../test/storage';
import { authHeader, createUserRecord } from '../../../test/factories';
import { env } from '../../config/env';
import { createStorage, type StorageDriver } from '../../storage';
import {
  chunkData,
  createBody,
  createDropOk,
  createReadyDrop,
  fakeWrappedKey,
  metricValue,
  postDrop,
  putChunk,
  testClock,
  testFile,
} from './test-utils';
import { UPLOAD_ACTIVE_MS } from './service';

/** testFile(2000) is 2016 bytes of ciphertext. */
const FILE = 2000;
const CT = 2016;

const anonDrop = (t: TestApp, ip = '198.51.100.40') =>
  postDrop(t.app, createBody([testFile(FILE)]), { 'X-Forwarded-For': ip });
const userDrop = (t: TestApp, auth: string) =>
  postDrop(t.app, createBody([testFile(FILE)], { ownerWrappedKey: fakeWrappedKey() }), {
    Authorization: auth,
  });

/** The node types of every plan node that reads `relation` (EXPLAIN FORMAT JSON). */
function scans(plan: unknown, relation: string): string[] {
  const out: string[] = [];
  const walk = (node: unknown) => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (!node || typeof node !== 'object') return;
    const n = node as Record<string, unknown>;
    if (n['Relation Name'] === relation) out.push(String(n['Node Type']));
    Object.values(n).forEach(walk);
  };
  walk(plan);
  return out;
}

function expectStorageFull(res: request.Response) {
  expect(res.status).toBe(507);
  expect(res.body).toEqual({
    error: {
      code: 'STORAGE_FULL',
      message: expect.stringMatching(/storage is full/i),
    },
  });
}

describe('GLOBAL_STORAGE_CAP_BYTES', () => {
  let t: TestApp;
  let auth: string;
  beforeAll(async () => {
    t = await createTestApp({ env: { GLOBAL_STORAGE_CAP_BYTES: 2 * CT + 100 } });
  });
  beforeEach(async () => {
    await resetTables(t.prisma);
    auth = authHeader(await createUserRecord(t.prisma));
  });
  afterAll(async () => {
    await resetTables(t.prisma);
    await t.close();
  });

  it('counts anonymous and signed-in drops together and answers 507 STORAGE_FULL beyond it', async () => {
    expect((await anonDrop(t)).status).toBe(201);
    expect((await userDrop(t, auth)).status).toBe(201);
    const before = await metricValue(t.app, 'drops_refused_total', 'reason="global_cap"');
    expectStorageFull(await userDrop(t, auth));
    expectStorageFull(await anonDrop(t, '198.51.100.41'));
    expect(await metricValue(t.app, 'drops_refused_total', 'reason="global_cap"')).toBe(before + 2);
  });

  it('counts a drop until its blobs are purged, whatever its status', async () => {
    const held = await createDropOk(t.app, createBody([testFile(FILE)]));
    expect((await anonDrop(t)).status).toBe(201);
    await t.prisma.drop.update({ where: { id: held.dropId }, data: { status: 'EXPIRED' } });
    expectStorageFull(await anonDrop(t));
    await t.prisma.drop.update({
      where: { id: held.dropId },
      data: { blobsDeletedAt: new Date() },
    });
    expect((await anonDrop(t)).status).toBe(201);
  });

  it('parallel creates cannot overshoot it', async () => {
    const results = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        i % 2 === 0 ? anonDrop(t, `198.51.100.${50 + i}`) : userDrop(t, auth),
      ),
    );
    const statuses = results.map((r) => r.status);
    expect(statuses.filter((s) => s === 201)).toHaveLength(2);
    expect(statuses.filter((s) => s === 507)).toHaveLength(6);
    const held = await t.prisma.drop.aggregate({ _sum: { totalCiphertextBytes: true } });
    expect(Number(held._sum.totalCiphertextBytes)).toBeLessThanOrEqual(2 * CT + 100);
  });

  it("counts a READY account drop through its owner's used storage until the drop is deleted", async () => {
    const user = await createUserRecord(t.prisma);
    const owner = { Authorization: authHeader(user) };
    const ready = await createReadyDrop(t.app, {
      files: [testFile(FILE)],
      body: { ownerWrappedKey: fakeWrappedKey() },
      headers: owner,
    });
    expect((await anonDrop(t)).status).toBe(201);
    expectStorageFull(await anonDrop(t, '198.51.100.42'));
    const del = await request(t.app).delete(`/api/drops/${ready.dropId}`).set(owner);
    expect(del.status).toBe(204);
    expect((await anonDrop(t, '198.51.100.42')).status).toBe(201);
  });

  it('reads the account uploads through an index, however many purged drops history holds', async () => {
    await t.prisma.$executeRaw`
      INSERT INTO "Drop" ("id", "ownerTokenHash", "uploadTokenHash", "status", "encryptedManifest",
        "totalCiphertextBytes", "fileCount", "maxDownloads", "expiresAt", "blobsDeletedAt")
      SELECT 'purged-' || g, 'x', 'x', 'DELETED'::"DropStatus", 'm', 1000, 1, 1, now(), now()
      FROM generate_series(1, 5000) AS g`;
    await t.prisma.$executeRawUnsafe('ANALYZE "Drop"');
    const rows = await t.prisma.$queryRaw<{ 'QUERY PLAN': unknown }[]>`
      EXPLAIN (FORMAT JSON) SELECT SUM("totalCiphertextBytes") FROM "Drop"
      WHERE "status" = 'UPLOADING'::"DropStatus" AND "ownerId" IS NOT NULL AND "blobsDeletedAt" IS NULL`;
    const plan = JSON.stringify(rows[0]?.['QUERY PLAN']);
    expect(plan).not.toContain('Seq Scan');
    expect(plan).toContain('Drop_status_expiresAt_idx');
  });
});

describe('STORAGE_MIN_FREE_BYTES (free-disk floor, local storage)', () => {
  const FLOOR = 1_000_000;
  const dirs: string[] = [];
  let free = 0;

  /** Local storage whose free space the test sets (`undefined` = a driver without freeBytes, like S3). */
  function stubStorage(withFreeBytes = true): StorageDriver {
    const dir = tempStorageDir();
    dirs.push(dir);
    const real = createStorage({ ...env, STORAGE_DRIVER: 'local', STORAGE_DIR: dir });
    const { freeBytes: _omit, ...rest } = real;
    return withFreeBytes ? { ...rest, freeBytes: async () => free } : rest;
  }

  let t: TestApp;
  beforeAll(async () => {
    t = await createTestApp({
      storage: stubStorage(),
      env: { STORAGE_MIN_FREE_BYTES: FLOOR, GLOBAL_STORAGE_CAP_BYTES: 0 },
    });
  });
  beforeEach(async () => {
    await resetTables(t.prisma);
  });
  afterAll(async () => {
    await resetTables(t.prisma);
    await t.close();
    for (const d of dirs) await removeDir(d);
  });

  it('refuses a new drop that would take free space below the floor, counting uploads in progress', async () => {
    free = FLOOR + CT + 1000; // room for one drop, not two
    const first = await createDropOk(t.app, createBody([testFile(FILE)]));
    const before = await metricValue(t.app, 'drops_refused_total', 'reason="disk_floor"');
    // Free space has not moved yet (nothing written), but the first drop's bytes are still to come.
    expectStorageFull(await anonDrop(t));
    const user = await createUserRecord(t.prisma);
    expectStorageFull(await userDrop(t, authHeader(user)));
    expect(await metricValue(t.app, 'drops_refused_total', 'reason="disk_floor"')).toBe(before + 2);
    // Once that upload is no longer in progress, its bytes are on disk and in the free-space figure.
    await t.prisma.drop.update({ where: { id: first.dropId }, data: { status: 'READY' } });
    expect((await anonDrop(t)).status).toBe(201);
  });

  it('stops counting an upload idle for UPLOAD_ACTIVE_MS, so reservations that write nothing cannot hold it', async () => {
    const clock = testClock(new Date('2026-11-20T08:00:00.000Z'));
    const idle = await createTestApp({
      now: clock.now,
      storage: stubStorage(),
      env: { STORAGE_MIN_FREE_BYTES: FLOOR, GLOBAL_STORAGE_CAP_BYTES: 0, ANON_BYTES_PER_CLIENT: 0 },
    });
    try {
      free = FLOOR + 3 * CT + 1000; // room for three drops
      for (let i = 0; i < 3; i++) {
        expect((await anonDrop(idle, `198.51.100.${60 + i}`)).status).toBe(201);
      }
      // Three reservations, not a byte written: while they are fresh they hold the floor.
      expectStorageFull(await anonDrop(idle, '198.51.100.63'));
      clock.advance(UPLOAD_ACTIVE_MS - 1000);
      expectStorageFull(await anonDrop(idle, '198.51.100.63'));
      // Idle for UPLOAD_ACTIVE_MS: they no longer count, and new drops are accepted again.
      clock.advance(1000);
      expect((await anonDrop(idle, '198.51.100.63')).status).toBe(201);
      expect((await anonDrop(idle, '198.51.100.64')).status).toBe(201);
    } finally {
      await idle.close();
    }
  });

  it('keeps counting an upload while it stores chunks', async () => {
    const clock = testClock(new Date('2026-11-20T08:00:00.000Z'));
    const active = await createTestApp({
      now: clock.now,
      storage: stubStorage(),
      env: { STORAGE_MIN_FREE_BYTES: FLOOR, GLOBAL_STORAGE_CAP_BYTES: 0, ANON_BYTES_PER_CLIENT: 0 },
    });
    try {
      free = FLOOR + CT + 1000; // room for one drop
      const f = testFile(FILE);
      const drop = await createDropOk(active.app, createBody([f]));
      clock.advance(UPLOAD_ACTIVE_MS - 60_000);
      const put = await putChunk(
        active.app,
        drop.dropId,
        drop.uploadToken,
        f.id,
        0,
        chunkData(f, 0),
      );
      expect(put.status).toBe(204);
      // Created more than UPLOAD_ACTIVE_MS ago, but it stored a chunk since: still counted.
      clock.advance(UPLOAD_ACTIVE_MS - 1000);
      expectStorageFull(await anonDrop(active));
      clock.advance(1000);
      expect((await anonDrop(active)).status).toBe(201);
    } finally {
      await active.close();
    }
  });

  it('finds the chunk activity of each upload through the (dropId, storedAt) index', async () => {
    // History: 2000 READY drops of 20 chunks each, and a few uploads in progress.
    await t.prisma.$executeRaw`
      INSERT INTO "Drop" ("id", "ownerTokenHash", "uploadTokenHash", "status", "encryptedManifest",
        "totalCiphertextBytes", "fileCount", "maxDownloads", "expiresAt", "createdAt")
      SELECT 'd-' || g, 'x', 'x',
        (CASE WHEN g <= 5 THEN 'UPLOADING' ELSE 'READY' END)::"DropStatus", 'm', 1000, 1, 1,
        now() + interval '1 day', now() - interval '1 hour'
      FROM generate_series(1, 2000) AS g`;
    await t.prisma.$executeRaw`
      INSERT INTO "DropChunk" ("dropId", "fileId", "index", "size", "sha256", "storedAt")
      SELECT 'd-' || g, 'f', i, 1000, 'h', now() - interval '1 hour'
      FROM generate_series(1, 2000) AS g, generate_series(0, 19) AS i`;
    await t.prisma.$executeRawUnsafe('ANALYZE "Drop"');
    await t.prisma.$executeRawUnsafe('ANALYZE "DropChunk"');
    const rows = await t.prisma.$queryRaw<{ 'QUERY PLAN': unknown }[]>`
      EXPLAIN (FORMAT JSON) SELECT SUM(d."totalCiphertextBytes") FROM "Drop" d
      WHERE d."status" = 'UPLOADING'::"DropStatus" AND d."blobsDeletedAt" IS NULL
        AND (d."createdAt" > now() - interval '10 minutes' OR EXISTS (
          SELECT 1 FROM "DropChunk" c
          WHERE c."storedAt" > now() - interval '10 minutes' AND d."id" = c."dropId"))`;
    const plan = JSON.stringify(rows[0]?.['QUERY PLAN']);
    expect(plan).toContain('DropChunk_dropId_storedAt_idx');
    expect(scans(rows[0]?.['QUERY PLAN'], 'DropChunk')).not.toContain('Seq Scan');
  });

  it('never refuses the chunks of a drop it already accepted', async () => {
    free = FLOOR + CT + 1000;
    const f = testFile(FILE);
    const drop = await createDropOk(t.app, createBody([f]));
    free = 0;
    const put = await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 0, chunkData(f, 0));
    expect(put.status).toBe(204);
  });

  it('0 turns it off', async () => {
    const off = await createTestApp({ storage: stubStorage(), env: { STORAGE_MIN_FREE_BYTES: 0 } });
    try {
      free = 0;
      expect((await anonDrop(off)).status).toBe(201);
    } finally {
      await off.close();
    }
  });

  it('does not apply to a driver that reports no free space (S3)', async () => {
    const s3Like = await createTestApp({
      storage: stubStorage(false),
      env: { STORAGE_MIN_FREE_BYTES: Number.MAX_SAFE_INTEGER },
    });
    try {
      expect((await anonDrop(s3Like)).status).toBe(201);
    } finally {
      await s3Like.close();
    }
  });
});

describe('storage control defaults', () => {
  it('ship with no global cap and a 1 GiB free-disk floor, which the real test disk clears', async () => {
    const t = await createTestApp();
    try {
      expect(t.ctx.env.GLOBAL_STORAGE_CAP_BYTES).toBe(0);
      expect(t.ctx.env.STORAGE_MIN_FREE_BYTES).toBe(1024 ** 3);
      await resetTables(t.prisma);
      expect((await anonDrop(t)).status).toBe(201);
    } finally {
      await resetTables(t.prisma);
      await t.close();
    }
  });
});
