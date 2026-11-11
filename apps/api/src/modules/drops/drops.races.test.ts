/**
 * Upload lifecycle edges: chunk PUT racing delete / account deletion (a blob must never be written after
 * the drop left UPLOADING), and uploads that outlive their expiry (410 EXPIRED, nothing completes).
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { isAppError } from '../../lib/errors';
import type { StorageDriver } from '../../storage';
import { bearer, registerViaApi } from '../auth/testkit';
import {
  chunkData,
  complete,
  createBody,
  createDropOk,
  createReadyDrop,
  fakeWrappedKey,
  HOUR,
  putChunk,
  sha256Hex,
  testClock,
  testFile,
} from './test-utils';

const T0 = new Date('2026-11-08T12:00:00.000Z');

describe('drop upload lifecycle edges', () => {
  let t: TestApp;
  let gated: TestApp;
  const clock = testClock(T0);

  /** putChunk of the next armed call parks until released (see parkNextPut). */
  const gate = { armed: false, enter: () => {}, wait: Promise.resolve() };

  beforeAll(async () => {
    t = await createTestApp({ now: clock.now });
    await resetTables(t.prisma);
    const storage: StorageDriver = {
      ...t.storage,
      async putChunk(dropId, fileId, index, data) {
        if (gate.armed) {
          gate.armed = false;
          gate.enter();
          await gate.wait;
        }
        return t.storage.putChunk(dropId, fileId, index, data);
      },
    };
    gated = await createTestApp({ now: clock.now, storage, prisma: t.prisma, redis: t.redis });
  });
  afterAll(async () => {
    await gated.close();
    await t.close();
  });
  beforeEach(() => {
    clock.set(T0);
  });

  async function blobExists(dropId: string, fileId: string, index = 0) {
    try {
      (await t.storage.getChunkStream(dropId, fileId, index)).destroy();
      return true;
    } catch (err) {
      if (isAppError(err) && err.code === 'NOT_FOUND') return false;
      throw err;
    }
  }

  /** Park the next putChunk of the gated app; `entered` resolves once it is parked. */
  function parkNextPut() {
    let release!: () => void;
    let enter!: () => void;
    gate.wait = new Promise<void>((r) => (release = r));
    const entered = new Promise<void>((r) => (enter = r));
    gate.enter = enter;
    gate.armed = true;
    return { entered, release };
  }

  describe('chunk PUT vs delete', () => {
    it('a delete that lands while a chunk is being stored leaves no orphan blob', async () => {
      const f = testFile(1000);
      const drop = await createDropOk(gated.app, createBody([f]));
      const { entered, release } = parkNextPut();
      const put = putChunk(gated.app, drop.dropId, drop.uploadToken, f.id, 0, chunkData(f, 0)).then(
        (r) => r,
      );
      await entered;
      const del = request(gated.app)
        .delete(`/api/drops/${drop.dropId}`)
        .set('X-Owner-Token', drop.ownerToken)
        .then((r) => r);
      await sleep(300);
      release();
      const [putRes, delRes] = await Promise.all([put, del]);
      expect(delRes.status).toBe(204);
      expect([204, 409]).toContain(putRes.status);
      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
      expect(row.status).toBe('DELETED');
      expect(row.blobsDeletedAt).not.toBeNull();
      expect(await blobExists(drop.dropId, f.id)).toBe(false);
    });

    it('a delete during the body read makes the PUT answer 409 and stores nothing', async () => {
      const f = testFile(1000);
      const drop = await createDropOk(t.app, createBody([f]));
      const data = chunkData(f, 0);
      const server = t.app.listen(0, '127.0.0.1');
      await new Promise<void>((r) => server.once('listening', () => r()));
      try {
        const port = (server.address() as AddressInfo).port;
        const status = await new Promise<number>((resolve, reject) => {
          const req = http.request(
            {
              host: '127.0.0.1',
              port,
              method: 'PUT',
              path: `/api/drops/${drop.dropId}/files/${f.id}/chunks/0`,
              headers: {
                'Content-Type': 'application/octet-stream',
                'Content-Length': data.length,
                'X-Chunk-SHA256': sha256Hex(data),
                Authorization: bearer(drop.uploadToken),
              },
            },
            (res) => {
              res.resume();
              resolve(res.statusCode ?? 0);
            },
          );
          req.on('error', reject);
          req.write(data.subarray(0, 500));
          void (async () => {
            await sleep(300); // the handler has passed its pre-body checks by now
            const del = await request(t.app)
              .delete(`/api/drops/${drop.dropId}`)
              .set('X-Owner-Token', drop.ownerToken);
            expect(del.status).toBe(204);
            req.end(data.subarray(500));
          })().catch(reject);
        });
        expect(status).toBe(409);
      } finally {
        await new Promise<void>((r) => server.close(() => r()));
      }
      expect(await blobExists(drop.dropId, f.id)).toBe(false);
    });

    it('DELETE /me while a chunk is being stored leaves no orphan blob and no 500', async () => {
      const u = await registerViaApi(t.app);
      const f = testFile(1000);
      const drop = await createDropOk(
        gated.app,
        createBody([f], { ownerWrappedKey: fakeWrappedKey() }),
        {
          Authorization: bearer(u.accessToken),
        },
      );
      const { entered, release } = parkNextPut();
      const put = putChunk(gated.app, drop.dropId, drop.uploadToken, f.id, 0, chunkData(f, 0)).then(
        (r) => r,
      );
      await entered;
      const del = request(gated.app)
        .delete('/api/me')
        .set('Authorization', bearer(u.accessToken))
        .send({ authKey: u.authKey })
        .then((r) => r);
      await sleep(300);
      release();
      const [putRes, delRes] = await Promise.all([put, del]);
      expect(delRes.status).toBe(204);
      expect(putRes.status).toBeLessThan(500);
      expect(await blobExists(drop.dropId, f.id)).toBe(false);
    });
  });

  describe('uploads that outlive their expiry', () => {
    it('rejects chunk PUT, upload-status and complete with 410 EXPIRED', async () => {
      const f = testFile(1000);
      const drop = await createDropOk(t.app, createBody([f], { expiresInHours: 1 }));
      expect(
        (await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 0, chunkData(f, 0))).status,
      ).toBe(204);
      clock.advance(2 * HOUR);

      const put = await putChunk(t.app, drop.dropId, drop.uploadToken, f.id, 0, chunkData(f, 0));
      expect(put.status).toBe(410);
      expect(put.body.error.details).toEqual({ reason: 'EXPIRED' });
      const status = await request(t.app)
        .get(`/api/drops/${drop.dropId}/upload-status`)
        .set('Authorization', bearer(drop.uploadToken));
      expect(status.status).toBe(410);
      const done = await complete(t.app, drop);
      expect(done.status).toBe(410);
      expect(done.body.error.details).toEqual({ reason: 'EXPIRED' });
      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: drop.dropId } });
      expect(row.status).toBe('UPLOADING');
    });

    it('keeps complete idempotent for a drop that is already READY', async () => {
      const drop = await createReadyDrop(t.app, { body: { expiresInHours: 1 } });
      clock.advance(2 * HOUR);
      const again = await complete(t.app, drop);
      expect(again.status).toBe(200);
      expect(again.body).toEqual({ status: 'READY' });
    });
  });
});
