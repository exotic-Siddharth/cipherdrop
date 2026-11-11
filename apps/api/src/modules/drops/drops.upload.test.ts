/**
 * Upload side: chunk PUT (token first, exact sizes, R5 sha, idempotent re-PUT, 409 after READY),
 * upload-status (R11) and complete (409 with the missing chunks; READY, quota, audit).
 */
import { randomBytes } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { authHeader, createUserRecord } from '../../../test/factories';
import { isAppError } from '../../lib/errors';
import {
  chunkBlobFiles,
  chunkData,
  complete,
  createBody,
  createDropOk,
  CT_CHUNK,
  fakeWrappedKey,
  id16,
  putChunk,
  sha256Hex,
  testFile,
  token32,
  uploadAll,
  metricValue,
} from './test-utils';

const MiB = 1024 * 1024;

describe('drop upload', () => {
  let t: TestApp;

  beforeAll(async () => {
    t = await createTestApp();
    await resetTables(t.prisma);
  });
  afterAll(async () => {
    await t.close();
  });

  async function storedChunk(
    dropId: string,
    fileId: string,
    index: number,
  ): Promise<Buffer | null> {
    // The blob the DropChunk row points at (C-R2-01: each PUT attempt writes its own version).
    const row = await t.prisma.dropChunk.findUnique({
      where: { dropId_fileId_index: { dropId, fileId, index } },
      select: { blobVersion: true },
    });
    if (!row) return null;
    try {
      const stream = await t.storage.getChunkStream(
        dropId,
        fileId,
        index,
        row.blobVersion ?? undefined,
      );
      const parts: Buffer[] = [];
      for await (const p of stream) parts.push(Buffer.from(p as Uint8Array));
      return Buffer.concat(parts);
    } catch (err) {
      if (isAppError(err) && err.code === 'NOT_FOUND') return null;
      throw err;
    }
  }

  describe('PUT /drops/:id/files/:fileId/chunks/:index', () => {
    it('stores a chunk and records its size and sha256', async () => {
      const f = testFile(1234);
      const drop = await createDropOk(t.app, createBody([f]));
      const data = chunkData(f, 0);
      const before = await metricValue(t.app, 'chunk_bytes_uploaded_total');
      const res = await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 0, data);
      expect(res.status).toBe(204);
      expect((await storedChunk(drop.dropId, f.id, 0))?.equals(data)).toBe(true);
      const row = await t.prisma.dropChunk.findUniqueOrThrow({
        where: { dropId_fileId_index: { dropId: drop.dropId, fileId: f.id, index: 0 } },
      });
      expect(row.size).toBe(data.length);
      expect(row.sha256).toBe(sha256Hex(data));
      expect((await metricValue(t.app, 'chunk_bytes_uploaded_total')) - before).toBe(data.length);
    });

    it('rejects a missing or wrong upload token with 401 before reading the body', async () => {
      const f = testFile(10);
      const drop = await createDropOk(t.app, createBody([f]));
      const other = await createDropOk(t.app, createBody([testFile(10)]));
      const data = chunkData(f, 0);
      for (const tok of [null, token32(), other.uploadToken, drop.ownerToken]) {
        const res = await putChunk(t.app, drop.dropId, tok, f.id, 0, data);
        expect(res.status).toBe(401);
        expect(res.body.error.code).toBe('UNAUTHORIZED');
      }
      // Unknown drop: same answer (no drop enumeration through this route).
      expect((await putChunk(t.app, id16(), drop.uploadToken, f.id, 0, data)).status).toBe(401);
      expect(await storedChunk(drop.dropId, f.id, 0)).toBeNull();
    });

    it('rejects a malformed X-Chunk-SHA256 (missing, uppercase, short) with 400', async () => {
      const f = testFile(10);
      const drop = await createDropOk(t.app, createBody([f]));
      const data = chunkData(f, 0);
      for (const sha of [
        null,
        sha256Hex(data).toUpperCase(),
        sha256Hex(data).slice(0, 63),
        'zz'.repeat(32),
      ]) {
        const res = await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 0, data, sha);
        expect(res.status).toBe(400);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
      }
      expect(await storedChunk(drop.dropId, f.id, 0)).toBeNull();
    });

    it('rejects a sha256 mismatch with 400 and stores nothing', async () => {
      const f = testFile(10);
      const drop = await createDropOk(t.app, createBody([f]));
      const data = chunkData(f, 0);
      const res = await putChunk(
        t.app,
        drop.dropId,
        drop.uploadToken,
        f.id,
        0,
        data,
        sha256Hex(randomBytes(26)),
      );
      expect(res.status).toBe(400);
      expect(res.body.error.code).toBe('VALIDATION_ERROR');
      expect(await storedChunk(drop.dropId, f.id, 0)).toBeNull();
      expect(await t.prisma.dropChunk.count({ where: { dropId: drop.dropId } })).toBe(0);
    });

    it('rejects wrong chunk sizes with 400 (exact non-final and final sizes)', async () => {
      const f = testFile(4 * MiB + 100); // chunk 0: CT_CHUNK bytes, chunk 1: 116 bytes
      expect(f.chunkSizes).toEqual([CT_CHUNK, 116]);
      const drop = await createDropOk(t.app, createBody([f]));
      const cases: [number, number][] = [
        [0, CT_CHUNK - 1],
        [0, 116],
        [1, 115],
        [1, 117],
        [1, 16],
        [1, 0],
      ];
      for (const [index, size] of cases) {
        const res = await putChunk(
          t.app,
          drop.dropId,
          drop.uploadToken,
          f.id,
          index,
          randomBytes(size),
        );
        expect(res.status, `index ${index} size ${size}`).toBe(400);
        expect(res.body.error.code).toBe('VALIDATION_ERROR');
      }
      expect(await t.prisma.dropChunk.count({ where: { dropId: drop.dropId } })).toBe(0);
      // The exact sizes are accepted.
      expect(
        (await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 1, randomBytes(116))).status,
      ).toBe(204);
      expect(
        (await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 0, randomBytes(CT_CHUNK)))
          .status,
      ).toBe(204);
    });

    it('accepts the 16-byte chunk of an empty file', async () => {
      const f = testFile(0);
      const drop = await createDropOk(t.app, createBody([f]));
      expect(
        (await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 0, randomBytes(16))).status,
      ).toBe(204);
    });

    it('rejects a body larger than CHUNK_SIZE+16 with 413', async () => {
      const f = testFile(9 * MiB);
      const drop = await createDropOk(t.app, createBody([f]));
      const res = await putChunk(
        t.app,
        drop.dropId,
        drop.uploadToken,
        f.id,
        0,
        randomBytes(CT_CHUNK + 1),
      );
      expect(res.status).toBe(413);
      expect(res.body.error.code).toBe('PAYLOAD_TOO_LARGE');
    });

    it('rejects an index out of range (400), an unknown file (404) and a non-octet-stream body (400)', async () => {
      const f = testFile(10);
      const drop = await createDropOk(t.app, createBody([f]));
      const data = chunkData(f, 0);
      expect((await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 1, data)).status).toBe(
        400,
      );
      expect((await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, '-1', data)).status).toBe(
        400,
      );
      expect((await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, '01', data)).status).toBe(
        400,
      );
      expect((await putChunk(t.app, drop.dropId, drop.uploadToken, id16(), 0, data)).status).toBe(
        404,
      );
      const res = await request(t.app)
        .put(`/api/drops/${drop.dropId}/files/${f.id}/chunks/0`)
        .set('Authorization', `Bearer ${drop.uploadToken}`)
        .set('X-Chunk-SHA256', sha256Hex(data))
        .set('Content-Type', 'text/plain')
        .send(data.toString('latin1'));
      expect(res.status).toBe(400);
    });

    it('re-PUT of the same index overwrites (idempotent retries)', async () => {
      const f = testFile(50);
      const drop = await createDropOk(t.app, createBody([f]));
      const first = chunkData(f, 0);
      const second = chunkData(f, 0);
      expect((await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 0, first)).status).toBe(
        204,
      );
      expect((await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 0, first)).status).toBe(
        204,
      );
      expect((await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 0, second)).status).toBe(
        204,
      );
      const rows = await t.prisma.dropChunk.findMany({ where: { dropId: drop.dropId } });
      expect(rows).toHaveLength(1);
      expect(rows[0]!.sha256).toBe(sha256Hex(second));
      expect((await storedChunk(drop.dropId, f.id, 0))?.equals(second)).toBe(true);
      // The superseded versions are deleted: one blob on disk.
      expect(await chunkBlobFiles(t.storageDir, drop.dropId, f.id, 0)).toHaveLength(1);
    });

    it('answers 409 after the drop is READY (upload token is useless)', async () => {
      const f = testFile(10);
      const drop = await createDropOk(t.app, createBody([f]));
      await uploadAll(t.app, drop, [f]);
      expect((await complete(t.app, drop)).status).toBe(200);
      const res = await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 0, chunkData(f, 0));
      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('CONFLICT');
    });

    it('uses the per-token chunkPut limiter (R10)', async () => {
      const rl = await createTestApp({ rateLimits: { chunkPut: true } });
      try {
        const f = testFile(10);
        const drop = await createDropOk(rl.app, createBody([f]));
        const res = await putChunk(rl.app, drop.dropId, drop.uploadToken, f.id, 0, chunkData(f, 0));
        expect(res.status).toBe(204);
        expect(String(res.headers['ratelimit-policy'])).toContain('1200');
      } finally {
        await rl.close();
      }
    });
  });

  describe('GET /drops/:id/upload-status', () => {
    it('lists the received chunks with their sha256 per file (R11)', async () => {
      const a = testFile(4 * MiB + 1); // 2 chunks
      const b = testFile(3);
      const drop = await createDropOk(t.app, createBody([a, b]));
      const a1 = chunkData(a, 1);
      const b0 = chunkData(b, 0);
      await putChunk(t.app, drop.dropId, drop.uploadToken, a.id, 1, a1);
      await putChunk(t.app, drop.dropId, drop.uploadToken, b.id, 0, b0);

      const res = await request(t.app)
        .get(`/api/drops/${drop.dropId}/upload-status`)
        .set('Authorization', `Bearer ${drop.uploadToken}`);
      expect(res.status).toBe(200);
      const byId = new Map(
        (res.body.files as { id: string; chunkCount: number; received: unknown[] }[]).map((x) => [
          x.id,
          x,
        ]),
      );
      expect(byId.get(a.id)).toEqual({
        id: a.id,
        chunkCount: 2,
        received: [{ index: 1, sha256: sha256Hex(a1) }],
      });
      expect(byId.get(b.id)).toEqual({
        id: b.id,
        chunkCount: 1,
        received: [{ index: 0, sha256: sha256Hex(b0) }],
      });
      expect(res.body.files).toHaveLength(2);
    });

    it('requires the upload token', async () => {
      const drop = await createDropOk(t.app, createBody([testFile(3)]));
      const res = await request(t.app)
        .get(`/api/drops/${drop.dropId}/upload-status`)
        .set('Authorization', `Bearer ${token32()}`);
      expect(res.status).toBe(401);
    });
  });

  describe('POST /drops/:id/complete', () => {
    it('answers 409 with the missing chunks', async () => {
      const a = testFile(2 * 4 * MiB + 5); // 3 chunks
      const b = testFile(1);
      const drop = await createDropOk(t.app, createBody([a, b]));
      await putChunk(t.app, drop.dropId, drop.uploadToken, a.id, 1, chunkData(a, 1));
      const res = await complete(t.app, drop);
      expect(res.status).toBe(409);
      expect(res.body.error.code).toBe('CONFLICT');
      const missing = (
        res.body.error.details.missing as { fileId: string; indexes: number[] }[]
      ).sort((x, y) => (x.fileId === a.id ? -1 : y.fileId === a.id ? 1 : 0));
      expect(missing).toEqual([
        { fileId: a.id, indexes: [0, 2] },
        { fileId: b.id, indexes: [0] },
      ]);
      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
      expect(row.status).toBe('UPLOADING');
    });

    it('moves the drop to READY, adds the bytes to the owner quota and audits DROP_COMPLETED', async () => {
      const user = await createUserRecord(t.prisma, { storageUsedBytes: BigInt(100) });
      const f = testFile(777);
      const drop = await createDropOk(
        t.app,
        createBody([f], { ownerWrappedKey: fakeWrappedKey() }),
        {
          Authorization: authHeader(user),
        },
      );
      await uploadAll(t.app, drop, [f]);
      const res = await complete(t.app, drop);
      expect(res.status).toBe(200);
      expect(res.body).toEqual({ status: 'READY' });

      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
      expect(row.status).toBe('READY');
      expect(row.readyAt).toBeInstanceOf(Date);
      const owner = await t.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
      expect(Number(owner.storageUsedBytes)).toBe(100 + f.ciphertextBytes);
      const actions = (
        await t.prisma.auditEvent.findMany({
          where: { userId: user.id },
          orderBy: { createdAt: 'asc' },
        })
      ).map((e) => e.action);
      expect(actions).toEqual(['DROP_CREATED', 'DROP_COMPLETED']);

      // A retried complete is idempotent and does not count the bytes twice.
      expect((await complete(t.app, drop)).status).toBe(200);
      const again = await t.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
      expect(Number(again.storageUsedBytes)).toBe(100 + f.ciphertextBytes);
    });

    it('requires the upload token', async () => {
      const drop = await createDropOk(t.app, createBody([testFile(3)]));
      expect((await complete(t.app, { dropId: drop.dropId, uploadToken: token32() })).status).toBe(
        401,
      );
    });

    it('answers 409 for a drop that is no longer uploading (deleted)', async () => {
      const f = testFile(3);
      const drop = await createDropOk(t.app, createBody([f]));
      await uploadAll(t.app, drop, [f]);
      await t.prisma.drop.update({ where: { id: drop.dropId }, data: { status: 'DELETED' } });
      expect((await complete(t.app, drop)).status).toBe(409);
    });
  });
});
