/**
 * DELETE /drops/:id (X-Owner-Token or owner session; 403 for others; blobs gone; quota released) and
 * POST /drops/:id/report (stored; key only when provided; rate limited).
 */
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestApp, type TestApp } from '../../../test/app';
import { resetTables } from '../../../test/db';
import { authHeader, createAdminRecord, createUserRecord } from '../../../test/factories';
import { isAppError } from '../../lib/errors';
import {
  createBody,
  createDropOk,
  createReadyDrop,
  fakeWrappedKey,
  id16,
  testFile,
  token32,
  uploadAll,
} from './test-utils';

describe('drop management', () => {
  let t: TestApp;

  beforeAll(async () => {
    t = await createTestApp();
    await resetTables(t.prisma);
  });
  afterAll(async () => {
    await t.close();
  });

  const del = (id: string, headers: Record<string, string> = {}) =>
    request(t.app).delete(`/api/drops/${id}`).set(headers);

  async function blobExists(dropId: string, fileId: string): Promise<boolean> {
    try {
      const s = await t.storage.getChunkStream(dropId, fileId, 0);
      s.destroy();
      return true;
    } catch (err) {
      if (isAppError(err) && err.code === 'NOT_FOUND') return false;
      throw err;
    }
  }

  describe('DELETE /drops/:id', () => {
    it('deletes an anonymous drop with X-Owner-Token and removes its blobs', async () => {
      const d = await createReadyDrop(t.app);
      const fileId = d.files[0]!.id;
      expect(await blobExists(d.dropId, fileId)).toBe(true);
      const res = await del(d.dropId, { 'X-Owner-Token': d.ownerToken });
      expect(res.status).toBe(204);
      const row = await t.prisma.drop.findUniqueOrThrow({ where: { id: d.dropId } });
      expect(row.status).toBe('DELETED');
      expect(row.deletedAt).toBeInstanceOf(Date);
      expect(row.blobsDeletedAt).toBeInstanceOf(Date);
      expect(await blobExists(d.dropId, fileId)).toBe(false);
      const meta = await request(t.app).get(`/api/drops/${d.dropId}`);
      expect(meta.status).toBe(410);
      expect(meta.body.error.details.reason).toBe('DELETED');
      // Idempotent.
      expect((await del(d.dropId, { 'X-Owner-Token': d.ownerToken })).status).toBe(204);
    });

    it('deletes a drop still uploading', async () => {
      const f = testFile(5);
      const d = await createDropOk(t.app, createBody([f]));
      await uploadAll(t.app, d, [f]);
      expect((await del(d.dropId, { 'X-Owner-Token': d.ownerToken })).status).toBe(204);
      expect(await blobExists(d.dropId, f.id)).toBe(false);
    });

    it('deletes via the owner session, releases the quota and audits DROP_DELETED', async () => {
      const user = await createUserRecord(t.prisma);
      const d = await createReadyDrop(t.app, {
        body: { ownerWrappedKey: fakeWrappedKey() },
        headers: { Authorization: authHeader(user) },
      });
      const used = Number(
        (await t.prisma.user.findUniqueOrThrow({ where: { id: user.id } })).storageUsedBytes,
      );
      expect(used).toBe(d.files[0]!.ciphertextBytes);
      const res = await del(d.dropId, { Authorization: authHeader(user) });
      expect(res.status).toBe(204);
      const after = await t.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
      expect(Number(after.storageUsedBytes)).toBe(0);
      expect(await blobExists(d.dropId, d.files[0]!.id)).toBe(false);
      const actions = (await t.prisma.auditEvent.findMany({ where: { userId: user.id } })).map(
        (e) => e.action,
      );
      expect(actions).toContain('DROP_DELETED');
      // Deleting again never releases the bytes twice.
      expect((await del(d.dropId, { Authorization: authHeader(user) })).status).toBe(204);
      expect(
        Number(
          (await t.prisma.user.findUniqueOrThrow({ where: { id: user.id } })).storageUsedBytes,
        ),
      ).toBe(0);
    });

    it('answers 403 to any other user (admins included) and to a wrong owner token', async () => {
      const owner = await createUserRecord(t.prisma);
      const stranger = await createUserRecord(t.prisma);
      const admin = await createAdminRecord(t.prisma);
      const d = await createReadyDrop(t.app, {
        body: { ownerWrappedKey: fakeWrappedKey() },
        headers: { Authorization: authHeader(owner) },
      });
      expect((await del(d.dropId, { Authorization: authHeader(stranger) })).status).toBe(403);
      expect((await del(d.dropId, { Authorization: authHeader(admin) })).status).toBe(403);
      expect((await del(d.dropId, { 'X-Owner-Token': token32() })).status).toBe(403);
      const anon = await createReadyDrop(t.app);
      expect((await del(anon.dropId, { Authorization: authHeader(stranger) })).status).toBe(403);
      expect((await del(anon.dropId, { 'X-Owner-Token': d.ownerToken })).status).toBe(403);
      expect((await t.prisma.drop.findUniqueOrThrow({ where: { id: d.dropId } })).status).toBe(
        'READY',
      );
      expect(await blobExists(d.dropId, d.files[0]!.id)).toBe(true);
    });

    it('answers 401 without credentials and 404 for an unknown drop', async () => {
      const d = await createReadyDrop(t.app);
      expect((await del(d.dropId)).status).toBe(401);
      expect((await del(id16(), { 'X-Owner-Token': d.ownerToken })).status).toBe(404);
    });
  });

  describe('POST /drops/:id/report', () => {
    const report = (
      id: string,
      body: Record<string, unknown>,
      headers: Record<string, string> = {},
    ) => request(t.app).post(`/api/drops/${id}/report`).set(headers).send(body);

    it('stores a report without a key', async () => {
      const d = await createReadyDrop(t.app);
      const res = await report(
        d.dropId,
        { reason: 'PHISHING', details: '  fake bank login  ' },
        {
          'X-Forwarded-For': '203.0.113.50',
        },
      );
      expect(res.status).toBe(201);
      expect(res.body).toEqual({ id: expect.any(String) });
      const row = await t.prisma.report.findUniqueOrThrow({ where: { id: res.body.id } });
      expect(row).toMatchObject({
        dropId: d.dropId,
        reason: 'PHISHING',
        details: 'fake bank login',
        providedKey: null,
        reporterIpPrefix: '203.0.113.0/24',
        status: 'OPEN',
      });
    });

    it('stores the decryption key only when the reporter provides it', async () => {
      const owner = await createUserRecord(t.prisma);
      const d = await createReadyDrop(t.app, {
        body: { ownerWrappedKey: fakeWrappedKey() },
        headers: { Authorization: authHeader(owner) },
      });
      const key = token32();
      const res = await report(d.dropId, { reason: 'MALWARE', decryptionKey: key });
      expect(res.status).toBe(201);
      const row = await t.prisma.report.findUniqueOrThrow({ where: { id: res.body.id } });
      expect(row.providedKey).toBe(key);
      // The owner is told about the report, without the reporter's IP or the key.
      const ev = await t.prisma.auditEvent.findFirstOrThrow({
        where: { userId: owner.id, action: 'DROP_REPORTED' },
      });
      expect(ev.ipPrefix).toBeNull();
      expect(JSON.stringify(ev)).not.toContain(key);
    });

    it('validates the reason, the details length and the key format (b64url, 43 chars)', async () => {
      const d = await createReadyDrop(t.app);
      expect((await report(d.dropId, { reason: 'SPAM' })).status).toBe(400);
      expect((await report(d.dropId, { reason: 'OTHER', details: 'x'.repeat(1001) })).status).toBe(
        400,
      );
      expect((await report(d.dropId, { reason: 'OTHER', decryptionKey: 'abc' })).status).toBe(400);
      expect(
        (await report(d.dropId, { reason: 'OTHER', decryptionKey: `${token32()}A` })).status,
      ).toBe(400);
      expect((await report(id16(), { reason: 'OTHER' })).status).toBe(404);
    });

    it('is rate limited to 5/h per IP', async () => {
      const rl = await createTestApp({ rateLimits: { report: true } });
      try {
        const d = await createReadyDrop(rl.app);
        const ip = { 'X-Forwarded-For': '192.0.2.99' };
        for (let i = 0; i < 5; i++) {
          const res = await request(rl.app)
            .post(`/api/drops/${d.dropId}/report`)
            .set(ip)
            .send({ reason: 'OTHER' });
          expect(res.status).toBe(201);
        }
        const res = await request(rl.app)
          .post(`/api/drops/${d.dropId}/report`)
          .set(ip)
          .send({ reason: 'OTHER' });
        expect(res.status).toBe(429);
      } finally {
        await rl.close();
      }
    });
  });
});
