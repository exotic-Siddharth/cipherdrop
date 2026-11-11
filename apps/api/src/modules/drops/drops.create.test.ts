/**
 * POST /api/drops: validation, anonymous and user limits, quota, R7 (owner wrap), audit, metrics, rate limit.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { authHeader, createUserRecord } from '../../../test/factories';
import { sha256B64url } from '../../lib/hash';
import {
  createBody,
  fakeManifest,
  fakeWrappedKey,
  id16,
  passwordFixture,
  postDrop,
  testFile,
  HOUR,
  testClock,
  metricValue,
  toJson,
} from './test-utils';

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;

/** A file of exactly `ct` ciphertext bytes (largest plaintext that fits). */
function fileWithCiphertext(ct: number) {
  const chunkCount = Math.ceil(ct / (4 * MiB + 16));
  return { id: id16(), ciphertextBytes: ct, chunkCount };
}

describe('POST /api/drops', () => {
  let t: TestApp;
  const clock = testClock(new Date('2026-11-08T10:00:00.000Z'));

  beforeAll(async () => {
    t = await createTestApp({ now: clock.now });
    await resetTables(t.prisma);
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(() => {
    clock.set(new Date('2026-11-08T10:00:00.000Z'));
  });

  describe('anonymous', () => {
    it('creates an UPLOADING drop and returns the tokens (stored only as hashes)', async () => {
      const files = [testFile(10), testFile(0)];
      const before = await metricValue(t.app, 'drops_created_total', 'anon="true"');
      const res = await postDrop(
        t.app,
        createBody(files, { expiresInHours: 72, maxDownloads: 10 }),
      );
      expect(res.status).toBe(201);
      expect(res.body).toEqual({
        dropId: expect.stringMatching(/^[A-Za-z0-9_-]{22}$/),
        ownerToken: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
        uploadToken: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
        expiresAt: '2026-11-11T10:00:00.000Z',
      });
      const drop = await t.prisma.drop.findUniqueOrThrow({
        where: { id: res.body.dropId },
        include: { files: true },
      });
      expect(drop.status).toBe('UPLOADING');
      expect(drop.ownerId).toBeNull();
      expect(drop.ownerTokenHash).toBe(sha256B64url(res.body.ownerToken));
      expect(drop.uploadTokenHash).toBe(sha256B64url(res.body.uploadToken));
      expect(toJson(drop)).not.toContain(res.body.ownerToken);
      expect(toJson(drop)).not.toContain(res.body.uploadToken);
      expect(drop.fileCount).toBe(2);
      expect(Number(drop.totalCiphertextBytes)).toBe(
        files[0]!.ciphertextBytes + files[1]!.ciphertextBytes,
      );
      expect(drop.files.map((f) => f.id).sort()).toEqual(files.map((f) => f.id).sort());
      expect(drop.createdAt.toISOString()).toBe('2026-11-08T10:00:00.000Z');
      const after = await metricValue(t.app, 'drops_created_total', 'anon="true"');
      expect(after - before).toBe(1);
    });

    it('rejects more than 100 MiB of ciphertext with 413 PAYLOAD_TOO_LARGE', async () => {
      const ok = await postDrop(t.app, createBody([], { files: [fileWithCiphertext(100 * MiB)] }));
      expect(ok.status).toBe(201);
      const res = await postDrop(
        t.app,
        createBody([], { files: [fileWithCiphertext(100 * MiB + 1)] }),
      );
      expect(res.status).toBe(413);
      expect(res.body.error.code).toBe('PAYLOAD_TOO_LARGE');
    });

    it('rejects more than 10 downloads and more than 72 hours', async () => {
      const files = [testFile(5)];
      const many = await postDrop(t.app, createBody(files, { maxDownloads: 20 }));
      expect(many.status).toBe(400);
      expect(many.body.error.code).toBe('VALIDATION_ERROR');
      const long = await postDrop(t.app, createBody(files, { expiresInHours: 73 }));
      expect(long.status).toBe(400);
      expect(long.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('rejects an ownerWrappedKey without a session', async () => {
      const res = await postDrop(
        t.app,
        createBody([testFile(5)], { ownerWrappedKey: fakeWrappedKey() }),
      );
      expect(res.status).toBe(400);
    });

    it('stores password protection fields', async () => {
      const pw = passwordFixture();
      const res = await postDrop(t.app, createBody([testFile(5)], { password: pw.password }));
      expect(res.status).toBe(201);
      const drop = await t.prisma.drop.findUniqueOrThrow({ where: { id: res.body.dropId } });
      expect(drop.passwordProtected).toBe(true);
      expect(drop.pwKdfSalt).toBe(pw.password.kdf.salt);
      expect(drop.pwKdfMemoryKiB).toBe(19456);
      expect(drop.wrappedDropKey).toBe(pw.password.wrappedDropKey);
      expect(drop.authKeyHash).toBe(pw.password.authKeyHash);
    });

    it('rejects weak KDF params (below KDF_MIN)', async () => {
      const pw = passwordFixture();
      const res = await postDrop(
        t.app,
        createBody([testFile(5)], {
          password: { ...pw.password, kdf: { ...pw.password.kdf, memoryKiB: 1024 } },
        }),
      );
      expect(res.status).toBe(400);
    });
  });

  describe('shape validation', () => {
    it('rejects 21 files', async () => {
      const files = Array.from({ length: 21 }, () => testFile(1));
      const res = await postDrop(t.app, createBody(files));
      expect(res.status).toBe(400);
    });

    it('honours a lower MAX_FILES_PER_DROP from env', async () => {
      const t2 = await createTestApp({ env: { ...t.ctx.env, MAX_FILES_PER_DROP: 2 } });
      try {
        const res = await postDrop(t2.app, createBody([testFile(1), testFile(1), testFile(1)]));
        expect(res.status).toBe(400);
        expect((await postDrop(t2.app, createBody([testFile(1), testFile(1)]))).status).toBe(201);
      } finally {
        await t2.close();
      }
    });

    it('rejects zero files and duplicate file ids', async () => {
      expect((await postDrop(t.app, createBody([]))).status).toBe(400);
      const f = testFile(3);
      expect((await postDrop(t.app, createBody([f, f]))).status).toBe(400);
    });

    it('rejects ciphertextBytes inconsistent with chunkCount', async () => {
      const f = testFile(10);
      const res = await postDrop(
        t.app,
        createBody([], { files: [{ id: f.id, ciphertextBytes: 10 * MiB, chunkCount: 1 }] }),
      );
      expect(res.status).toBe(400);
      const res2 = await postDrop(
        t.app,
        createBody([], { files: [{ id: f.id, ciphertextBytes: 26, chunkCount: 2 }] }),
      );
      expect(res2.status).toBe(400);
    });

    it('rejects a manifest above 64 KiB and accepts one at the limit', async () => {
      const tooBig = 'A'.repeat(64 * 1024 + 1);
      expect(
        (await postDrop(t.app, createBody([testFile(1)], { encryptedManifest: tooBig }))).status,
      ).toBe(400);
      const atLimit = 'A'.repeat(64 * 1024);
      expect(
        (await postDrop(t.app, createBody([testFile(1)], { encryptedManifest: atLimit }))).status,
      ).toBe(201);
    });

    it('rejects maxDownloads outside DOWNLOAD_OPTIONS and non-integer expiry', async () => {
      expect(
        (await postDrop(t.app, createBody([testFile(1)], { maxDownloads: 4 as never }))).status,
      ).toBe(400);
      expect(
        (await postDrop(t.app, createBody([testFile(1)], { expiresInHours: 1.5 }))).status,
      ).toBe(400);
      expect((await postDrop(t.app, createBody([testFile(1)], { expiresInHours: 0 }))).status).toBe(
        400,
      );
    });
  });

  describe('signed in', () => {
    it('requires ownerWrappedKey (R7)', async () => {
      const user = await createUserRecord(t.prisma);
      const res = await postDrop(t.app, createBody([testFile(5)]), {
        Authorization: authHeader(user),
      });
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('allows 100 downloads and 720 hours, links the owner and audits DROP_CREATED', async () => {
      const user = await createUserRecord(t.prisma);
      const owk = fakeWrappedKey();
      const res = await postDrop(
        t.app,
        createBody([testFile(5)], { maxDownloads: 100, expiresInHours: 720, ownerWrappedKey: owk }),
        { Authorization: authHeader(user), 'X-Forwarded-For': '198.51.100.23' },
      );
      expect(res.status).toBe(201);
      expect(res.body.expiresAt).toBe(new Date(clock.now().getTime() + 720 * HOUR).toISOString());
      const drop = await t.prisma.drop.findUniqueOrThrow({ where: { id: res.body.dropId } });
      expect(drop.ownerId).toBe(user.id);
      expect(drop.ownerWrappedKey).toBe(owk);
      const events = await t.prisma.auditEvent.findMany({ where: { userId: user.id } });
      expect(events.map((e) => e.action)).toEqual(['DROP_CREATED']);
      expect(events[0]!.dropId).toBe(drop.id);
      expect(events[0]!.ipPrefix).toBe('198.51.100.0/24');
      expect(JSON.stringify(events[0]!.metadata ?? {})).not.toContain(owk);
    });

    it('rejects more than 720 hours', async () => {
      const user = await createUserRecord(t.prisma);
      const res = await postDrop(
        t.app,
        createBody([testFile(5)], { expiresInHours: 721, ownerWrappedKey: fakeWrappedKey() }),
        { Authorization: authHeader(user) },
      );
      expect(res.status).toBe(400);
    });

    it('rejects more than USER_MAX_DROP_BYTES with 413 PAYLOAD_TOO_LARGE', async () => {
      const user = await createUserRecord(t.prisma, { storageQuotaBytes: BigInt(10 * GiB) });
      const res = await postDrop(
        t.app,
        createBody([], {
          files: [fileWithCiphertext(2 * GiB + 1)],
          ownerWrappedKey: fakeWrappedKey(),
        }),
        { Authorization: authHeader(user) },
      );
      expect(res.status).toBe(413);
      expect(res.body.error.code).toBe('PAYLOAD_TOO_LARGE');
    });

    it('enforces the storage quota with 413 QUOTA_EXCEEDED, counting pending uploads', async () => {
      const user = await createUserRecord(t.prisma, {
        storageQuotaBytes: BigInt(10_000),
        storageUsedBytes: BigInt(6_000),
      });
      const auth = { Authorization: authHeader(user) };
      const over = await postDrop(
        t.app,
        createBody([], { files: [fileWithCiphertext(4_001)], ownerWrappedKey: fakeWrappedKey() }),
        auth,
      );
      expect(over.status).toBe(413);
      expect(over.body.error.code).toBe('QUOTA_EXCEEDED');

      const fits = await postDrop(
        t.app,
        createBody([], { files: [fileWithCiphertext(3_000)], ownerWrappedKey: fakeWrappedKey() }),
        auth,
      );
      expect(fits.status).toBe(201);
      // 6000 used + 3000 pending: a second 1001-byte drop no longer fits.
      const pending = await postDrop(
        t.app,
        createBody([], { files: [fileWithCiphertext(1_001)], ownerWrappedKey: fakeWrappedKey() }),
        auth,
      );
      expect(pending.status).toBe(413);
      expect(pending.body.error.code).toBe('QUOTA_EXCEEDED');
    });

    it('parallel creates cannot overshoot the quota (check and insert are serialised per user)', async () => {
      const user = await createUserRecord(t.prisma, { storageQuotaBytes: BigInt(10_000) });
      const auth = { Authorization: authHeader(user) };
      const results = await Promise.all(
        Array.from({ length: 8 }, () =>
          postDrop(
            t.app,
            createBody([], {
              files: [fileWithCiphertext(4_000)],
              ownerWrappedKey: fakeWrappedKey(),
            }),
            auth,
          ),
        ),
      );
      const ok = results.filter((r) => r.status === 201);
      expect(ok).toHaveLength(2); // floor(10000 / 4000)
      for (const r of results.filter((x) => x.status !== 201)) {
        expect(r.status).toBe(413);
        expect(r.body.error.code).toBe('QUOTA_EXCEEDED');
      }
      const pending = await t.prisma.drop.aggregate({
        _sum: { totalCiphertextBytes: true },
        where: { ownerId: user.id, status: 'UPLOADING' },
      });
      expect(Number(pending._sum.totalCiphertextBytes)).toBeLessThanOrEqual(10_000);
    });

    it('rejects an invalid or revoked access token instead of acting anonymously', async () => {
      const res = await postDrop(t.app, createBody([testFile(5)]), {
        Authorization: 'Bearer nope',
      });
      expect(res.status).toBe(401);
    });
  });

  describe('rate limits', () => {
    it('anonymous creates are limited to 10/h per IP', async () => {
      const rl = await createTestApp({ rateLimits: { createDropAnon: true } });
      try {
        const ip = { 'X-Forwarded-For': '192.0.2.77' };
        for (let i = 0; i < 10; i++) {
          expect((await postDrop(rl.app, createBody([testFile(1)]), ip)).status).toBe(201);
        }
        const res = await postDrop(rl.app, createBody([testFile(1)]), ip);
        expect(res.status).toBe(429);
        expect(res.body.error.code).toBe('RATE_LIMITED');
        expect(res.headers['retry-after']).toBeDefined();
        // Another IP is unaffected.
        expect(
          (await postDrop(rl.app, createBody([testFile(1)]), { 'X-Forwarded-For': '192.0.2.78' }))
            .status,
        ).toBe(201);
      } finally {
        await rl.close();
      }
    });

    it('signed-in creates use the per-user limiter (60/h)', async () => {
      const rl = await createTestApp({ rateLimits: { createDropUser: true } });
      try {
        const user = await createUserRecord(rl.prisma);
        const res = await postDrop(
          rl.app,
          createBody([testFile(1)], { ownerWrappedKey: fakeWrappedKey() }),
          { Authorization: authHeader(user) },
        );
        expect(res.status).toBe(201);
        expect(String(res.headers['ratelimit-policy'])).toContain('60');
      } finally {
        await rl.close();
      }
    });
  });

  it('never stores the manifest anywhere but the drop row', async () => {
    const manifest = fakeManifest(200);
    const res = await postDrop(t.app, createBody([testFile(1)], { encryptedManifest: manifest }));
    expect(res.status).toBe(201);
    const audit = await t.prisma.auditEvent.findMany({ where: { dropId: res.body.dropId } });
    expect(JSON.stringify(audit)).not.toContain(manifest);
  });
});
